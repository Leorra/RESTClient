#pragma once

#if defined(_WIN32) || defined(_WIN64)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

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
#include <openssl/rand.h>
#include <openssl/evp.h>

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

#ifdef _MSC_VER
#pragma warning(pop)
#endif

using json = nlohmann::json;

#ifdef ERROR
#undef ERROR
#endif
#ifdef INFO
#undef INFO
#endif

namespace restclient {

	enum class RESTLogLevel { NONE, ERROR, INFO, DEBUG };
	enum class RESTErrorType { SUCCESS, NETWORK, SSL, TIMEOUT, AUTH, RATE_LIMIT, SERVER, CLIENT, UNKNOWN };

	struct RESTConfig {
		std::chrono::seconds timeout { 30 };
		int max_retries { 3 };
		std::string user_agent { "RESTSDK/3.1.0" };
		std::string auth_host { "api.coinbase.com" };
		int min_interval_ms { 100 };
		RESTLogLevel log_level { RESTLogLevel::INFO };
		bool log_to_stdout { true };
		// Maximum number of tasks allowed in the async queue at any one time.
		// Enqueue attempts beyond this limit are dropped and logged.
		// 0 means unbounded (not recommended for production).
		size_t max_async_queue_depth { 256 };

		[[nodiscard]] bool is_valid() const noexcept {
			return min_interval_ms >= 0 && max_retries >= 0 && timeout.count() > 0;
		}
	};

	class RESTClient {
	public:
		struct Response {
			static constexpr std::string_view VERSION = "3.1.0";

			bool success = false;
			long status_code = 0;
			std::string body;
			json data;
			RESTErrorType error_type = RESTErrorType::UNKNOWN;
			std::string error_msg;
			long long sent_at = 0;
			long long received_at = 0;

			Response() noexcept : data(json::object()) {}

			[[nodiscard]] constexpr bool is_success() const noexcept { return success; }
			[[nodiscard]] constexpr bool is_client_error() const noexcept {
				return status_code >= 400 && status_code < 500;
			}
			[[nodiscard]] constexpr bool is_server_error() const noexcept {
				return status_code >= 500;
			}
		};

		using AsyncCallback = std::function<void(Response)>;

		RESTClient(std::string_view base_url, std::string_view credentials_path, RESTConfig config = RESTConfig())
			: curl_(nullptr, curl_easy_cleanup)
			, static_headers_(nullptr)
			, static_headers_tail_(nullptr)
			, base_url_(base_url)
			, config_(std::move(config))
			, last_request_time_(std::chrono::steady_clock::now())
			, async_stop_(false) {
			if (!config_.is_valid()) {
				throw std::invalid_argument("Invalid RESTConfig parameters");
			}

			static std::once_flag curl_init_flag;
			std::call_once(curl_init_flag, []() noexcept {
				curl_global_init(CURL_GLOBAL_ALL);
			});

			curl_.reset(curl_easy_init());
			if (!curl_) {
				throw std::runtime_error("Failed to initialize CURL");
			}

			try {
				load_credentials(credentials_path);
			} catch (const std::exception& ex) {
				log(RESTLogLevel::ERROR, std::string("Credential load failed: ") + ex.what());
				throw;
			}

			{
				curl_slist* head = nullptr;
				head = curl_slist_append(head, ("User-Agent: " + config_.user_agent).c_str());
				head = curl_slist_append(head, "Content-Type: application/json");

				// Walk to tail
				curl_slist* tail = head;
				while (tail && tail->next) tail = tail->next;

				static_headers_ = SListPtr(head);
				static_headers_tail_ = tail; // raw observer pointer - lifetime tied to static_headers_
			}

			async_worker_ = std::thread([this] { async_worker_loop(); });

			log(RESTLogLevel::INFO, "RESTClient initialized");
		}

		~RESTClient() {
			{
				std::lock_guard<std::mutex> lock(async_mtx_);
				async_stop_ = true;
			}
			async_cv_.notify_one();
			if (async_worker_.joinable()) async_worker_.join();
		}

		RESTClient(const RESTClient&) = delete;
		RESTClient& operator=(const RESTClient&) = delete;

		// Move is deleted: async_worker_ runs a lambda capturing `this`, and
		// static_headers_tail_ is a raw pointer into static_headers_' owned memory.
		// Both become invalid if the object is relocated.
		RESTClient(RESTClient&&) = delete;
		RESTClient& operator=(RESTClient&&) = delete;

		[[nodiscard]] const std::string& base_url() const noexcept { return base_url_; }
		[[nodiscard]] const RESTConfig& config() const noexcept { return config_; }

		// =========================================================
		//  SYNC API
		// =========================================================
		Response send_with_retry(std::string_view endpoint, std::string_view method, std::string_view body = "") {
			Response resp;
			for (int i = 0; i <= config_.max_retries; ++i) {
				if (i > 0) {
					log(RESTLogLevel::INFO, "Retry attempt " + std::to_string(i));
				}
				resp = send(endpoint, method, body);

				if (resp.success || !is_retryable(resp.error_type)) {
					break;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(150 * (1 << i)));
			}
			return resp;
		}

		Response send(std::string_view endpoint, std::string_view method, std::string_view body = "") {
			{
				std::lock_guard<std::mutex> tlock(throttle_mtx_);
				auto now = std::chrono::steady_clock::now();
				auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
					now - last_request_time_).count();
				if (elapsed < config_.min_interval_ms) {
					std::this_thread::sleep_for(
						std::chrono::milliseconds(config_.min_interval_ms - elapsed));
				}
				last_request_time_ = std::chrono::steady_clock::now();
			}

			std::lock_guard<std::mutex> lock(transport_mtx_);

			std::string token = generate_jwt(method, endpoint);

			if (!curl_) {
				Response out;
				out.success = false;
				out.error_msg = "CURL handle error";
				out.error_type = RESTErrorType::UNKNOWN;
				return out;
			}

			std::string buffer;
			std::string full_url = base_url_ + std::string(endpoint);
			std::string method_s(method);

			std::string auth_header = "Authorization: Bearer " + token;
			curl_slist* auth_node = curl_slist_append(nullptr, auth_header.c_str());

			// Link: static tail -> auth_node (auth_node->next remains nullptr)
			if (static_headers_tail_) {
				static_headers_tail_->next = auth_node;
			}

			curl_easy_reset(curl_.get());
			curl_easy_setopt(curl_.get(), CURLOPT_URL, full_url.c_str());
			curl_easy_setopt(curl_.get(), CURLOPT_CUSTOMREQUEST, method_s.c_str());
			curl_easy_setopt(curl_.get(), CURLOPT_HTTPHEADER,
				static_headers_ ? static_headers_.get() : auth_node);
			curl_easy_setopt(curl_.get(), CURLOPT_TIMEOUT, static_cast<long>(config_.timeout.count()));
			curl_easy_setopt(curl_.get(), CURLOPT_WRITEFUNCTION, write_cb);
			curl_easy_setopt(curl_.get(), CURLOPT_WRITEDATA, &buffer);
			curl_easy_setopt(curl_.get(), CURLOPT_NOSIGNAL, 1L);

			if (!body.empty()) {
				curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDS, body.data());
				curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
			}

			long long t_sent = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();

			CURLcode res = curl_easy_perform(curl_.get());

			if (static_headers_tail_) {
				static_headers_tail_->next = nullptr;
			}
			curl_slist_free_all(auth_node);

			long long t_received = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();

			Response out;
			out.sent_at = t_sent;
			out.received_at = t_received;

			if (res == CURLE_OK) {
				curl_easy_getinfo(curl_.get(), CURLINFO_RESPONSE_CODE, &out.status_code);
				out.body = std::move(buffer);
				out.success = (out.status_code >= 200 && out.status_code < 300);

				if (!out.body.empty()) {
					try {
						out.data = json::parse(out.body);
					} catch (const std::exception& e) {
						log(RESTLogLevel::DEBUG, std::string("JSON parse failed: ") + e.what());
						out.data = json::object();
					}
				}
				out.error_type = classify_http_status(out.status_code);
			} else {
				out.error_msg = curl_easy_strerror(res);
				out.error_type = classify_curl_error(res);
			}

			return out;
		}

		// =========================================================
		//  ASYNC API
		//
		//  All async calls are enqueued to a single background worker thread
		//  instead of spawning and detaching one thread per call.
		//  This bounds resource usage and preserves natural request serialisation.
		//
		//  NOTE: callback is still invoked from the background worker thread.
		//        Use PostMessage(hwnd, ...) to marshal back to a Win32 UI thread.
		// =========================================================
		void send_with_retry_async(std::string_view endpoint,
			std::string_view method,
			std::string_view body,
			AsyncCallback callback) {
			enqueue_task(std::string(endpoint), std::string(method),
				std::string(body), std::move(callback), true);
		}

		void send_with_retry_async(std::string_view endpoint,
			std::string_view method,
			AsyncCallback callback) {
			send_with_retry_async(endpoint, method, "", std::move(callback));
		}

		void send_async(std::string_view endpoint,
			std::string_view method,
			std::string_view body,
			AsyncCallback callback) {
			enqueue_task(std::string(endpoint), std::string(method),
				std::string(body), std::move(callback), false);
		}

		void send_async(std::string_view endpoint,
			std::string_view method,
			AsyncCallback callback) {
			send_async(endpoint, method, "", std::move(callback));
		}


	private:
		struct SListDeleter {
			void operator()(curl_slist* sl) const noexcept {
				if (sl) curl_slist_free_all(sl);
			}
		};
		using SListPtr = std::unique_ptr<curl_slist, SListDeleter>;

		std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl_;
		SListPtr     static_headers_;
		curl_slist* static_headers_tail_;
		std::string  base_url_;
		std::string  key_name_;
		std::string  key_secret_;
		RESTConfig   config_;

		std::mutex   throttle_mtx_;
		std::mutex   transport_mtx_;
		std::chrono::steady_clock::time_point last_request_time_;

		std::mutex   log_mtx_;

		using Task = std::function<void()>;
		std::queue<Task>        async_queue_;
		std::mutex              async_mtx_;
		std::condition_variable async_cv_;
		std::atomic<bool>       async_stop_;
		std::thread             async_worker_;

		void async_worker_loop() {
			while (true) {
				Task task;
				{
					std::unique_lock<std::mutex> lock(async_mtx_);
					async_cv_.wait(lock, [this] {
						return !async_queue_.empty() || async_stop_;
					});
					if (async_stop_ && async_queue_.empty()) return;
					task = std::move(async_queue_.front());
					async_queue_.pop();
				}
				// Execute outside the queue lock.
				// Catch all exceptions: an unhandled throw here would call std::terminate
				// and silently kill the worker, causing all subsequent async calls to hang.
				try {
					task();
				} catch (const std::exception& e) {
					log(RESTLogLevel::ERROR, std::string("Async callback exception: ") + e.what());
				} catch (...) {
					log(RESTLogLevel::ERROR, "Async callback threw unknown exception");
				}
			}
		}

		void enqueue_task(std::string ep, std::string meth, std::string bd,
			AsyncCallback cb, bool with_retry) {
			bool queue_full = false;
			{
				std::lock_guard<std::mutex> lock(async_mtx_);
				if (config_.max_async_queue_depth > 0 &&
					async_queue_.size() >= config_.max_async_queue_depth) {
					queue_full = true;
				} else {
					async_queue_.push([this,
						ep = std::move(ep),
						meth = std::move(meth),
						bd = std::move(bd),
						cb = std::move(cb),
						with_retry]() mutable {
						cb(with_retry ? send_with_retry(ep, meth, bd)
							: send(ep, meth, bd));
					});
				}
			}

			if (queue_full) {
				log(RESTLogLevel::ERROR,
					"Async queue full (" + std::to_string(config_.max_async_queue_depth) +
					"); rejecting request to " + ep);
				Response err;
				err.success = false;
				err.error_type = RESTErrorType::RATE_LIMIT;
				err.error_msg = "Async queue full - request rejected";
				cb(std::move(err));
				return;
			}

			async_cv_.notify_one();
		}

		void log(RESTLogLevel level, std::string_view message) {
			if (level > config_.log_level || !config_.log_to_stdout) {
				return;
			}
			std::lock_guard<std::mutex> lock(log_mtx_);
			auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
			struct tm buf = {};
#if defined(_WIN32) || defined(_WIN64)
			localtime_s(&buf, &t);
#else
			localtime_r(&t, &buf);
#endif
			std::cout << "[" << std::put_time(&buf, "%Y-%m-%d %H:%M:%S") << "] " << message << std::endl;
		}

		void load_credentials(std::string_view path) {
			std::string path_str(path);
			std::ifstream f(path_str);
			if (!f.is_open()) {
				throw std::runtime_error("Could not open credentials file: " + std::string(path));
			}

			try {
				json j = json::parse(f);
				key_name_ = j.at("name").get<std::string>();
				key_secret_ = j.at("privateKey").get<std::string>();

				size_t pos = 0;
				while ((pos = key_secret_.find("\\n", pos)) != std::string::npos) {
					key_secret_.replace(pos, 2, "\n");
					pos += 1;
				}
			} catch (const std::exception& ex) {
				throw std::runtime_error(std::string("Credential parse error: ") + ex.what());
			}
		}

		std::string generate_jwt(std::string_view method, std::string_view endpoint) const {
			auto now = std::chrono::system_clock::now() - std::chrono::seconds(1);

			std::string path(endpoint.substr(0, endpoint.find('?')));
			std::string meth_u(method);
			std::transform(meth_u.begin(), meth_u.end(), meth_u.begin(), ::toupper);

			std::string host_u = config_.auth_host;
			std::transform(host_u.begin(), host_u.end(), host_u.begin(), ::toupper);

			std::string uri = meth_u + " " + host_u + path;

			return jwt::create()
				.set_type("JWT")
				.set_issuer("cdp")
				.set_subject(key_name_)
				.set_issued_at(now)
				.set_not_before(now)
				.set_expires_at(now + std::chrono::seconds(120))
				.set_audience("cdp_service")
				.set_payload_claim("uri", jwt::claim(uri))
				.set_header_claim("kid", jwt::claim(key_name_))
				.set_header_claim("nonce", jwt::claim(generate_nonce()))
				.sign(jwt::algorithm::es256(key_name_, key_secret_));
		}

		std::string generate_nonce() const {
			unsigned char nonce_raw[16];
			if (RAND_bytes(nonce_raw, sizeof(nonce_raw)) != 1) {
				throw std::runtime_error("RAND_bytes failed");
			}

			std::string encoded;
			encoded.resize(EVP_ENCODE_LENGTH(sizeof(nonce_raw)));
			int actual_len = EVP_EncodeBlock(
				reinterpret_cast<unsigned char*>(&encoded[0]),
				nonce_raw,
				sizeof(nonce_raw)
			);
			encoded.resize(actual_len);
			return encoded;
		}

		static size_t write_cb(void* contents, size_t size, size_t nmemb, void* userp) noexcept {
			size_t total_size = size * nmemb;
			static_cast<std::string*>(userp)->append(static_cast<char*>(contents), total_size);
			return total_size;
		}

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
				case CURLE_OPERATION_TIMEDOUT: return RESTErrorType::TIMEOUT;
				case CURLE_SSL_CONNECT_ERROR: [[fallthrough]];
				case CURLE_SSL_CERTPROBLEM: [[fallthrough]];
				case CURLE_SSL_CIPHER: [[fallthrough]];
				case CURLE_SSL_ENGINE_NOTFOUND: [[fallthrough]];
				case CURLE_SSL_ENGINE_SETFAILED: [[fallthrough]];
					// CURLE_SSL_CACERT (deprecated) == CURLE_PEER_FAILED_VERIFICATION == 60;
					// using only the canonical name avoids a duplicate-case-value error.
				case CURLE_PEER_FAILED_VERIFICATION: return RESTErrorType::SSL;
				case CURLE_COULDNT_RESOLVE_HOST: [[fallthrough]];
				case CURLE_COULDNT_CONNECT: [[fallthrough]];
				case CURLE_SEND_ERROR: [[fallthrough]];
				case CURLE_RECV_ERROR: return RESTErrorType::NETWORK;
				default: return RESTErrorType::UNKNOWN;
			}
		}

		static constexpr bool is_retryable(RESTErrorType type) noexcept {
			switch (type) {
				case RESTErrorType::NETWORK: [[fallthrough]];
				case RESTErrorType::TIMEOUT: [[fallthrough]];
				case RESTErrorType::SERVER: [[fallthrough]];
				case RESTErrorType::RATE_LIMIT: return true;
				default: return false;
			}
		}
	};

} // namespace restclient