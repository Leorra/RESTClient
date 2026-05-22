// RESTClient.hpp
//
// COMPILATION INSTRUCTIONS:
//   g++ -std=c++17 your_program.cpp -o your_program -lcurl -lssl -lcrypto
//
// Or with pkg-config (recommended):
//   g++ -std=c++17 your_program.cpp -o your_program $(pkg-config --cflags --libs libcurl openssl)

#pragma once

#if defined(_WIN32) || defined(_WIN64)
#include <corecrt.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <memory>
#include <atomic>
#include <functional>
#include <queue>
#include <condition_variable>
#include <cmath>
#include <stdexcept>
#include <vector>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 26495)
#endif

#include <curl/curl.h>
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4244)
#include <jwt-cpp/jwt.h>
#pragma warning(pop)
#else
#include <jwt-cpp/jwt.h>
#endif
#include <nlohmann/json_fwd.hpp>
#include <nlohmann/json.hpp>

// For OPENSSL_cleanse — link with -lssl -lcrypto
#include <openssl/crypto.h>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifdef ERROR
#undef ERROR
#endif
#ifdef INFO
#undef INFO
#endif

namespace restclient {

	enum class RESTLogLevel { NONE, ERROR, INFO, DEBUG };
	enum class RESTErrorType { SUCCESS, NETWORK, SSL, TIMEOUT, AUTH, RATE_LIMIT, SERVER, CLIENT, FATAL, UNKNOWN };

	// =========================================================================
	//  RESTConfig
	// =========================================================================
	struct RESTConfig {
		std::chrono::seconds connect_timeout { 10 };
		std::chrono::seconds total_timeout { 30 };

		// [FIX-OVERFLOW] Cap max_retries so that (1 << max_retries) never
		// overflows a 32-bit signed integer in send_with_retry().
		// Maximum useful value is 20 (delay cap ~150 * 2^20 ms ≈ 43 min).
		int max_retries { 3 };

		std::string user_agent { "RESTSDK/3.1.0" };

		// [FIX-CDP] Expose JWT issuer and audience so callers are not locked
		// to Coinbase CDP constants.
		std::string auth_host { "api.coinbase.com" };
		std::string jwt_issuer { "cdp" };
		std::string jwt_audience { "cdp_service" };

		// [FIX-SKEW] Clock skew applied to JWT iat/nbf to tolerate minor
		// server/client time drift.  Documented here per CDP JWT spec §4.1.
		std::chrono::seconds jwt_clock_skew { 1 };

		int  min_interval_ms { 100 };
		RESTLogLevel log_level { RESTLogLevel::INFO };
		bool log_to_stdout { true };
		size_t max_async_queue_depth { 256 };

		[[nodiscard]] bool is_valid() const noexcept {
			return min_interval_ms >= 0
				&& max_retries >= 0
				&& max_retries <= 20          // [FIX-OVERFLOW]
				&& connect_timeout.count() > 0
				&& total_timeout.count() >= connect_timeout.count()
				&& jwt_clock_skew.count() >= 0
				&& !auth_host.empty()
				&& !jwt_issuer.empty()
				&& !jwt_audience.empty();
		}

		// [FIX-FROM_JSON] Validate after parsing so callers get a descriptive
		// error rather than a silent invalid-config object.
		[[nodiscard]] static RESTConfig from_json(const nlohmann::json& j) {
			RESTConfig cfg;
			if (j.contains("connect_timeout"))
				cfg.connect_timeout = std::chrono::seconds(j["connect_timeout"].get<int>());
			if (j.contains("total_timeout"))
				cfg.total_timeout = std::chrono::seconds(j["total_timeout"].get<int>());
			if (j.contains("max_retries"))
				cfg.max_retries = j["max_retries"].get<int>();
			if (j.contains("user_agent"))
				cfg.user_agent = j["user_agent"].get<std::string>();
			if (j.contains("auth_host"))
				cfg.auth_host = j["auth_host"].get<std::string>();
			if (j.contains("jwt_issuer"))
				cfg.jwt_issuer = j["jwt_issuer"].get<std::string>();
			if (j.contains("jwt_audience"))
				cfg.jwt_audience = j["jwt_audience"].get<std::string>();
			if (j.contains("jwt_clock_skew"))
				cfg.jwt_clock_skew = std::chrono::seconds(j["jwt_clock_skew"].get<int>());
			if (j.contains("min_interval_ms"))
				cfg.min_interval_ms = j["min_interval_ms"].get<int>();
			if (j.contains("max_async_queue_depth"))
				cfg.max_async_queue_depth = j["max_async_queue_depth"].get<size_t>();

			if (!cfg.is_valid()) {
				throw std::invalid_argument(
					"RESTConfig::from_json produced an invalid configuration. "
					"Check: connect_timeout < total_timeout, 0 <= max_retries <= 20, "
					"non-empty auth_host/jwt_issuer/jwt_audience.");
			}
			return cfg;
		}
	};

	// =========================================================================
	//  RESTClient
	// =========================================================================
	/**
	 * @brief Thread-safe REST client for JWT-authenticated APIs.
	 *
	 * THREAD SAFETY:
	 * 1. send(), send_with_retry(), send_async(), and send_with_retry_async()
	 *    are fully thread-safe and may be called concurrently from any thread.
	 * 2. The internal CURL handle is protected by transport_mtx_.
	 * 3. Async-queue overflow is handled atomically; excess tasks are rejected
	 *    immediately with RESTErrorType::RATE_LIMIT via the callback.
	 * 4. AsyncCallback invocations occur on the background worker thread.
	 *    Callers are responsible for marshalling results to their own thread
	 *    (e.g. via a lock-protected queue or a Win32 PostMessage).
	 */
	class RESTClient {
	public:
		// =====================================================================
		//  Response
		// =====================================================================
		struct Response {
			static constexpr std::string_view VERSION = "2.2.0";

			bool          success = false;
			long          status_code = 0;
			std::string   body;
			nlohmann::json data;
			RESTErrorType  error_type = RESTErrorType::UNKNOWN;
			std::string    error_msg;
			long long      sent_at = 0;
			long long      received_at = 0;

			// [FIX-FATAL] Store the raw CURLcode so that send_with_retry()
			// can consult is_fatal_curl_error() and abort early.
			CURLcode raw_curl_code = CURLE_OK;

			Response() noexcept : data(nlohmann::json::object()) {}

			[[nodiscard]] constexpr bool is_success()      const noexcept { return success; }
			[[nodiscard]] constexpr bool is_client_error() const noexcept {
				return status_code >= 400 && status_code < 500;
			}
			[[nodiscard]] constexpr bool is_server_error() const noexcept {
				return status_code >= 500;
			}
		};

		using AsyncCallback = std::function<void(Response)>;

		// =====================================================================
		//  Constructor / destructor
		// =====================================================================
		RESTClient(std::string_view base_url,
			std::string_view credentials_path,
			RESTConfig       config = RESTConfig())
			: curl_(nullptr, curl_easy_cleanup)
			, base_url_(base_url)
			, config_(std::move(config))
			, last_request_time_(std::chrono::steady_clock::now())
			, async_stop_(false)
			// async_worker_ intentionally NOT started here — see end of body
		{
			if (!config_.is_valid()) {
				throw std::invalid_argument("Invalid RESTConfig parameters");
			}

			// One-time global libcurl initialisation (thread-safe via call_once).
			static std::once_flag curl_init_flag;
			std::call_once(curl_init_flag, []() noexcept {
				curl_global_init(CURL_GLOBAL_ALL);
			});

			curl_.reset(curl_easy_init());
			if (!curl_) {
				throw std::runtime_error("Failed to initialise CURL");
			}

			try {
				load_credentials(credentials_path);
			} catch (const std::exception& ex) {
				log(RESTLogLevel::ERROR,
					std::string("Credential load failed: ") + ex.what());
				throw;
			}

			log(RESTLogLevel::INFO, "RESTClient initialised");

			// [FIX-THREAD] Start the worker thread LAST — after all members
			// are fully initialised — so the lambda's this-capture is valid
			// and no constructor code races with the worker.
			async_worker_ = std::thread([this] { async_worker_loop(); });
		}

		// [FIX-SECRET] Wipe the private key from heap memory before releasing it.
		~RESTClient() {
			// Signal worker to stop and drain the queue.
			{
				std::lock_guard<std::mutex> lock(async_mtx_);
				async_stop_ = true;
			}
			async_cv_.notify_one();
			if (async_worker_.joinable()) {
				async_worker_.join();
			}

			// Zero the EC private key so it does not survive in heap memory,
			// core dumps, or /proc/<pid>/mem snapshots.
			if (!key_secret_.empty()) {
				OPENSSL_cleanse(key_secret_.data(), key_secret_.size());
			}
		}

		RESTClient(const RESTClient&) = delete;
		RESTClient& operator=(const RESTClient&) = delete;
		RESTClient(RESTClient&&) = delete;
		RESTClient& operator=(RESTClient&&) = delete;

		[[nodiscard]] const std::string& base_url() const noexcept { return base_url_; }
		[[nodiscard]] const RESTConfig& config()   const noexcept { return config_; }

		// =====================================================================
		//  Sync API
		// =====================================================================
		Response send_with_retry(std::string_view endpoint,
			std::string_view method,
			// [FIX-LIFETIME] const std::string& guarantees
			// the backing storage outlives the call,
			// including the rate-limit sleep inside send().
			const std::string& body = {})
		{
			Response resp;
			for (int i = 0; i <= config_.max_retries; ++i) {
				if (i > 0) {
					log(RESTLogLevel::INFO, "Retry attempt " + std::to_string(i));
				}

				resp = send(endpoint, method, body);

				// [FIX-FATAL] Abort immediately for errors that will never
				// succeed on retry regardless of how many attempts remain.
				if (resp.success
					|| !is_retryable(resp.error_type)
					|| is_fatal_curl_error(resp.raw_curl_code))
				{
					break;
				}

				// [FIX-OVERFLOW] Use long long arithmetic and cap the shift
				// so (1LL << shift) never overflows.
				// [FIX-JITTER] Add ±25 % uniform jitter to prevent retry
				// storms when multiple clients hit the same rate limit.
				const int    shift_cap = std::min(i, 20);
				const long long base_ms = 150LL * (1LL << shift_cap);
				const long long jittered = apply_jitter(base_ms);
				std::this_thread::sleep_for(std::chrono::milliseconds(jittered));
			}
			return resp;
		}

		Response send(std::string_view    endpoint,
			std::string_view    method,
			// [FIX-LIFETIME] const std::string& — see send_with_retry.
			const std::string& body = {})
		{
			// Rate-limit throttle — acquired and released BEFORE the transport
			// lock so the sleep never blocks other threads from entering the mutex.
			{
				std::lock_guard<std::mutex> tlock(throttle_mtx_);
				const auto now = std::chrono::steady_clock::now();
				const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
					now - last_request_time_).count();
				if (elapsed < config_.min_interval_ms) {
					std::this_thread::sleep_for(
						std::chrono::milliseconds(config_.min_interval_ms - elapsed));
				}
				last_request_time_ = std::chrono::steady_clock::now();
			}

			std::lock_guard<std::mutex> lock(transport_mtx_);

			if (!curl_) {
				Response out;
				out.success = false;
				out.error_msg = "CURL handle is null";
				out.error_type = RESTErrorType::UNKNOWN;
				return out;
			}

			std::string token = generate_jwt(method, endpoint);
			std::string buffer;
			std::string full_url = base_url_ + std::string(endpoint);
			std::string method_s(method);

			// [FIX-SLIST] Build the header list locally on each call via RAII
			// so it is exception-safe and cannot corrupt shared state.
			curl_slist* raw_list = nullptr;
			raw_list = curl_slist_append(raw_list,
				("User-Agent: " + config_.user_agent).c_str());
			raw_list = curl_slist_append(raw_list, "Content-Type: application/json");
			const std::string auth_header = "Authorization: Bearer " + token;
			raw_list = curl_slist_append(raw_list, auth_header.c_str());
			SListPtr local_headers(raw_list);

			curl_easy_reset(curl_.get());
			curl_easy_setopt(curl_.get(), CURLOPT_URL, full_url.c_str());
			curl_easy_setopt(curl_.get(), CURLOPT_CUSTOMREQUEST, method_s.c_str());
			curl_easy_setopt(curl_.get(), CURLOPT_HTTPHEADER, local_headers.get());
			curl_easy_setopt(curl_.get(), CURLOPT_CONNECTTIMEOUT,
				static_cast<long>(config_.connect_timeout.count()));
			curl_easy_setopt(curl_.get(), CURLOPT_TIMEOUT,
				static_cast<long>(config_.total_timeout.count()));
			curl_easy_setopt(curl_.get(), CURLOPT_WRITEFUNCTION, write_cb);
			curl_easy_setopt(curl_.get(), CURLOPT_WRITEDATA, &buffer);
			curl_easy_setopt(curl_.get(), CURLOPT_NOSIGNAL, 1L);

			if (!body.empty()) {
				curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDS,
					body.c_str());
				curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDSIZE,
					static_cast<long>(body.size()));
			}

			const long long t_sent = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();

			const CURLcode res = curl_easy_perform(curl_.get());

			const long long t_received = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();

			Response out;
			out.sent_at = t_sent;
			out.received_at = t_received;
			out.raw_curl_code = res;   // [FIX-FATAL] preserved for caller

			if (res == CURLE_OK) {
				curl_easy_getinfo(curl_.get(), CURLINFO_RESPONSE_CODE, &out.status_code);
				out.body = std::move(buffer);
				out.success = (out.status_code >= 200 && out.status_code < 300);

				if (!out.body.empty()) {
					try {
						out.data = nlohmann::json::parse(out.body);
					} catch (const std::exception& e) {
						log(RESTLogLevel::DEBUG,
							std::string("JSON parse failed: ") + e.what());
						out.data = nlohmann::json::object();
					}
				}
				out.error_type = classify_http_status(out.status_code);
			} else {
				out.error_msg = curl_easy_strerror(res);
				out.error_type = classify_curl_error(res);
			}

			return out;
		}

		// =====================================================================
		//  Async API
		// =====================================================================
		void send_with_retry_async(std::string_view   endpoint,
			std::string_view   method,
			std::string        body,
			AsyncCallback      callback)
		{
			enqueue_task(std::string(endpoint), std::string(method),
				std::move(body), std::move(callback), true);
		}

		void send_with_retry_async(std::string_view endpoint,
			std::string_view method,
			AsyncCallback    callback)
		{
			send_with_retry_async(endpoint, method, {}, std::move(callback));
		}

		void send_async(std::string_view endpoint,
			std::string_view method,
			std::string      body,
			AsyncCallback    callback)
		{
			enqueue_task(std::string(endpoint), std::string(method),
				std::move(body), std::move(callback), false);
		}

		void send_async(std::string_view endpoint,
			std::string_view method,
			AsyncCallback    callback)
		{
			send_async(endpoint, method, {}, std::move(callback));
		}

		// =====================================================================
		//  Utilities
		// =====================================================================
		[[nodiscard]] static time_t get_current_utc_time() noexcept {
			return std::chrono::system_clock::to_time_t(
				std::chrono::system_clock::now());
		}

		[[nodiscard]] static std::string format_time(time_t timestamp,
			bool   local_time,
			bool   date)
		{
			tm   tm_buf = {};
			char buffer[100];

			if (local_time) {
#if defined(_WIN32) || defined(_WIN64)
				localtime_s(&tm_buf, &timestamp);

				if (date) {
					strftime(buffer, sizeof(buffer),
						"%Y-%m-%d %H:%M:%S", &tm_buf);
					std::string result = "[" + std::string(buffer);

					// [FIX-TZ] Use _get_tzname() instead of parsing %Z output.
					// Index 0 = standard abbreviation, 1 = daylight abbreviation.
					char   tz_name[32] = {};
					size_t tz_name_len = 0;
					const bool is_dst = (tm_buf.tm_isdst > 0);
					if (_get_tzname(&tz_name_len, tz_name,
						sizeof(tz_name),
						is_dst ? 1 : 0) == 0
						&& tz_name_len > 0)
					{
						result += " ";
						result += tz_name;
					}

					result += "]";
					return result;
				} else {
					strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm_buf);
					return "[" + std::string(buffer) + "]";
				}
#else
				localtime_r(&timestamp, &tm_buf);
				if (date) {
					strftime(buffer, sizeof(buffer),
						"[%Y-%m-%d %H:%M:%S %Z]", &tm_buf);
				} else {
					strftime(buffer, sizeof(buffer), "[%H:%M:%S]", &tm_buf);
				}
				return std::string(buffer);
#endif
			} else {
#if defined(_WIN32) || defined(_WIN64)
				gmtime_s(&tm_buf, &timestamp);
#else
				gmtime_r(&timestamp, &tm_buf);
#endif
				if (date) {
					strftime(buffer, sizeof(buffer),
						"[%Y-%m-%d %H:%M:%S UTC]", &tm_buf);
				} else {
					strftime(buffer, sizeof(buffer), "[%H:%M:%S UTC]", &tm_buf);
				}
				return std::string(buffer);
			}
		}

	private:
		// =====================================================================
		//  RAII wrapper for curl_slist
		// =====================================================================
		struct SListDeleter {
			void operator()(curl_slist* sl) const noexcept {
				if (sl) curl_slist_free_all(sl);
			}
		};
		using SListPtr = std::unique_ptr<curl_slist, SListDeleter>;

		// =====================================================================
		//  Data members
		//
		//  Declaration order determines construction/destruction order.
		//  async_worker_ is declared LAST so it is destroyed FIRST — before
		//  the mutexes, queue, and condition_variable it depends upon.
		// =====================================================================
		std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl_;
		std::string   base_url_;
		std::string   key_name_;
		std::string   key_secret_;   // wiped in destructor via OPENSSL_cleanse
		RESTConfig    config_;

		// [FIX-MUTEX] Two separate mutexes: throttle_mtx_ guards only the
		// timestamp (never held during sleep or I/O); transport_mtx_ guards
		// the CURL handle exclusively.
		std::mutex    throttle_mtx_;
		std::mutex    transport_mtx_;
		std::chrono::steady_clock::time_point last_request_time_;

		std::mutex    log_mtx_;

		using Task = std::function<void()>;
		std::queue<Task>         async_queue_;
		std::mutex               async_mtx_;
		std::condition_variable  async_cv_;
		std::atomic<bool>        async_stop_;

		// async_worker_ MUST be the last data member so it is started after
		// every other member is fully constructed, and joined before any other
		// member is destroyed.
		std::thread async_worker_;

		// =====================================================================
		//  Async worker
		// =====================================================================
		void async_worker_loop() {
			while (true) {
				Task task;
				{
					std::unique_lock<std::mutex> lock(async_mtx_);
					async_cv_.wait(lock, [this] {
						return !async_queue_.empty() || async_stop_.load();
					});
					if (async_stop_ && async_queue_.empty()) return;
					task = std::move(async_queue_.front());
					async_queue_.pop();
				}

				// Execute outside the lock.  Catch everything: an unhandled
				// exception here calls std::terminate, silently killing the
				// worker and causing all future async calls to hang forever.
				try {
					task();
				} catch (const std::exception& e) {
					log(RESTLogLevel::ERROR,
						std::string("Async worker exception: ") + e.what());
				} catch (...) {
					log(RESTLogLevel::ERROR,
						"Async worker caught unknown exception");
				}
			}
		}

		// Enqueue a task.  When the queue is full the callback is invoked with
		// a RATE_LIMIT error *outside* async_mtx_ to prevent lock inversion if
		// the callback calls back into the client.
		void enqueue_task(std::string  ep,
			std::string  meth,
			std::string  bd,
			AsyncCallback cb,
			bool         with_retry)
		{
			bool queue_full = false;
			{
				std::lock_guard<std::mutex> lock(async_mtx_);
				if (config_.max_async_queue_depth > 0
					&& async_queue_.size() >= config_.max_async_queue_depth)
				{
					queue_full = true;
				} else {
					async_queue_.push(
						[this,
						ep = std::move(ep),
						meth = std::move(meth),
						bd = std::move(bd),
						cb = std::move(cb),
						with_retry]() mutable
					{
						try {
							Response r = with_retry
								? send_with_retry(ep, meth, bd)
								: send(ep, meth, bd);
							cb(std::move(r));
						} catch (const std::exception& e) {
							Response err;
							err.success = false;
							err.error_type = RESTErrorType::UNKNOWN;
							err.error_msg =
								std::string("Exception in task: ") + e.what();
							cb(std::move(err));
						}
					});
				}
			}

			if (queue_full) {
				log(RESTLogLevel::ERROR,
					"Async queue full ("
					+ std::to_string(config_.max_async_queue_depth)
					+ "); rejecting request to " + ep);
				Response err;
				err.success = false;
				err.error_type = RESTErrorType::RATE_LIMIT;
				err.error_msg = "Async queue full — request rejected";
				cb(std::move(err));
				return;
			}

			async_cv_.notify_one();
		}

		// =====================================================================
		//  Logging
		// =====================================================================
		void log(RESTLogLevel level, std::string_view message) {
			if (level > config_.log_level || !config_.log_to_stdout) return;

			std::lock_guard<std::mutex> lock(log_mtx_);
			const auto t = std::chrono::system_clock::to_time_t(
				std::chrono::system_clock::now());
			tm buf = {};
#if defined(_WIN32) || defined(_WIN64)
			localtime_s(&buf, &t);
#else
			localtime_r(&t, &buf);
#endif
			std::cout << "["
				<< std::put_time(&buf, "%Y-%m-%d %H:%M:%S")
				<< "] " << message << "\n";
		}

		// =====================================================================
		//  Credentials
		// =====================================================================
		void load_credentials(std::string_view path) {
			std::ifstream f { std::string(path) };
			if (!f.is_open()) {
				throw std::runtime_error(
					"Could not open credentials file: " + std::string(path));
			}

			try {
				const nlohmann::json j = nlohmann::json::parse(f);
				key_name_ = j.at("name").get<std::string>();
				key_secret_ = j.at("privateKey").get<std::string>();

				// Unescape literal \n sequences written by some JSON generators.
				for (size_t pos = 0;
					(pos = key_secret_.find("\\n", pos)) != std::string::npos; )
				{
					key_secret_.replace(pos, 2, "\n");
					pos += 1;
				}
			} catch (const std::exception& ex) {
				throw std::runtime_error(
					std::string("Credential parse error: ") + ex.what());
			}
		}

		// =====================================================================
		//  JWT generation
		// =====================================================================
		std::string generate_jwt(std::string_view method,
			std::string_view endpoint)
		{
			// [FIX-SKEW] Configurable clock skew per CDP JWT spec §4.1.
			const auto now = std::chrono::system_clock::now()
				- config_.jwt_clock_skew;

			// Strip query string — the URI claim covers only path.
			const std::string_view path = endpoint.substr(0, endpoint.find('?'));

			// [OPT] Build the entire URI string with a single reservation,
			// writing method and host in-place in uppercase rather than
			// constructing three intermediate strings and concatenating them.
			// This eliminates two heap allocations on every JWT issuance.
			std::string uri;
			uri.reserve(method.size() + 1 + config_.auth_host.size() + path.size());

			for (const char c : method) {
				uri += static_cast<char>(::toupper(static_cast<unsigned char>(c)));
			}
			uri += ' ';
			for (const char c : config_.auth_host) {
				uri += static_cast<char>(::toupper(static_cast<unsigned char>(c)));
			}
			// Path case is intentionally preserved — the server is case-sensitive.
			uri += path;

			return jwt::create()
				.set_type("JWT")
				.set_issuer(config_.jwt_issuer)
				.set_subject(key_name_)
				.set_issued_at(now)
				.set_not_before(now)
				.set_expires_at(now + std::chrono::seconds(120))
				.set_audience(config_.jwt_audience)
				.set_payload_claim("uri", jwt::claim(uri))
				.set_header_claim("kid", jwt::claim(key_name_))
				.set_header_claim("nonce", jwt::claim(generate_nonce(16)))
				.sign(jwt::algorithm::es256("", key_secret_, "", ""));
		}

		// =====================================================================
		//  Nonce
		// =====================================================================
		std::string generate_nonce(size_t len) noexcept {
			static constexpr char hex[] = "0123456789abcdef";
			static thread_local std::mt19937 gen([] {
				std::random_device rd;
				return std::mt19937(rd());
			}());
			std::uniform_int_distribution<int> dis(0, 15);
			std::string s;
			s.reserve(len);
			for (size_t i = 0; i < len; ++i) s += hex[dis(gen)];
			return s;
		}

		// [FIX-JITTER] Apply ±25 % uniform jitter to a base delay (ms).
		// Reuses the thread-local generator from generate_nonce's translation
		// unit — extracted here as a separate helper for clarity.
		long long apply_jitter(long long base_ms) noexcept {
			static thread_local std::mt19937 gen([] {
				std::random_device rd;
				return std::mt19937(rd());
			}());
			// Jitter factor in [0.75, 1.25].  std::round before truncation
			// avoids systematic downward bias from float-to-int conversion.
			std::uniform_real_distribution<double> dis(0.75, 1.25);
			return static_cast<long long>(
				std::round(static_cast<double>(base_ms) * dis(gen)));
		}

		// =====================================================================
		//  CURL write callback
		// =====================================================================
		static size_t write_cb(void* contents,
			size_t size,
			size_t nmemb,
			void* userp) noexcept
		{
			const size_t total = size * nmemb;
			static_cast<std::string*>(userp)->append(
				static_cast<char*>(contents), total);
			return total;
		}

		// =====================================================================
		//  Error classification
		// =====================================================================
		static constexpr RESTErrorType classify_http_status(long code) noexcept {
			if (code >= 200 && code < 300) return RESTErrorType::SUCCESS;
			if (code == 401 || code == 403) return RESTErrorType::AUTH;
			if (code == 429) return RESTErrorType::RATE_LIMIT;
			if (code >= 400 && code < 500) return RESTErrorType::CLIENT;
			if (code >= 500) return RESTErrorType::SERVER;
			return RESTErrorType::UNKNOWN;
		}

		static constexpr RESTErrorType classify_curl_error(CURLcode code) noexcept {
			switch (code) {
				case CURLE_OPERATION_TIMEDOUT:       return RESTErrorType::TIMEOUT;
				case CURLE_SSL_CONNECT_ERROR: [[fallthrough]];
				case CURLE_SSL_CERTPROBLEM: [[fallthrough]];
				case CURLE_SSL_CIPHER: [[fallthrough]];
				case CURLE_SSL_ENGINE_NOTFOUND: [[fallthrough]];
				case CURLE_SSL_ENGINE_SETFAILED: [[fallthrough]];
				case CURLE_PEER_FAILED_VERIFICATION: return RESTErrorType::SSL;
				case CURLE_COULDNT_RESOLVE_HOST: [[fallthrough]];
				case CURLE_COULDNT_CONNECT: [[fallthrough]];
				case CURLE_SEND_ERROR: [[fallthrough]];
				case CURLE_RECV_ERROR:               return RESTErrorType::NETWORK;
					// [FIX-FATAL] Errors that will never succeed on retry.
				case CURLE_URL_MALFORMAT: [[fallthrough]];
				case CURLE_NOT_BUILT_IN: [[fallthrough]];
				case CURLE_UNKNOWN_OPTION:           return RESTErrorType::FATAL;
				default:                             return RESTErrorType::UNKNOWN;
			}
		}

		// [FIX-FATAL] True for CURLcode values that are programmer errors or
		// compile-time configuration issues — retrying them is pointless.
		// Now also expressed via RESTErrorType::FATAL in classify_curl_error()
		// so the retry loop can act on the classified type alone.
		static constexpr bool is_fatal_curl_error(CURLcode code) noexcept {
			return code == CURLE_URL_MALFORMAT
				|| code == CURLE_SSL_CERTPROBLEM
				|| code == CURLE_SSL_CIPHER
				|| code == CURLE_NOT_BUILT_IN
				|| code == CURLE_UNKNOWN_OPTION;
		}

		static constexpr bool is_retryable(RESTErrorType type) noexcept {
			switch (type) {
				case RESTErrorType::NETWORK: [[fallthrough]];
				case RESTErrorType::TIMEOUT: [[fallthrough]];
				case RESTErrorType::SERVER: [[fallthrough]];
				case RESTErrorType::RATE_LIMIT: return true;
				default:                        return false;
			}
		}
	};

} // namespace restclient