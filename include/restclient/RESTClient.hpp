// RESTClient.hpp
//
// A thread-safe, production-ready REST API client library with JWT authentication,
// async support, automatic retries, and rate limiting.
//
// COMPILATION INSTRUCTIONS:
//   g++ -std=c++17 your_program.cpp -o your_program -lcurl
//
// Or with pkg-config (recommended):
//   g++ -std=c++17 your_program.cpp -o your_program $(pkg-config --cflags --libs libcurl)
//
// Dependencies:
//   - libcurl (https://curl.se/libcurl/)
//   - nlohmann/json (https://github.com/nlohmann/json)
//   - jwt-cpp (https://github.com/Thalhammer/jwt-cpp)
//
// License: MIT
// Version: 3.1.0

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
#include <cmath>

#ifdef ERROR
#undef ERROR
#endif
#ifdef INFO
#undef INFO
#endif

namespace restclient {

    /// Log levels for runtime diagnostic output
    enum class RESTLogLevel { NONE, ERROR, INFO, DEBUG };

    /// Categorized error types for programmatic error handling
    enum class RESTErrorType { SUCCESS, NETWORK, SSL, TIMEOUT, AUTH, RATE_LIMIT, SERVER, CLIENT, UNKNOWN };

    /// Configuration structure for RESTClient behavior
    struct RESTConfig {
        std::chrono::seconds timeout { 30 };           ///< Request timeout in seconds
        int max_retries { 3 };                         ///< Maximum number of retry attempts
        std::string user_agent { "RESTSDK/3.1.0" };    ///< User-Agent header value
        std::string auth_host { "api.coinbase.com" };  ///< Authentication host for JWT
        int min_interval_ms { 100 };                   ///< Minimum time between requests (rate limiting)
        RESTLogLevel log_level { RESTLogLevel::INFO }; ///< Logging verbosity level
        bool log_to_stdout { true };                   ///< Enable/disable console logging
        size_t max_async_queue_depth { 256 };          ///< Maximum async queue size (0 = unbounded)

        /// Validates configuration parameters
        [[nodiscard]] bool is_valid() const noexcept {
            return min_interval_ms >= 0 && max_retries >= 0 && timeout.count() > 0;
        }
    };

    /// Thread-safe REST client with synchronous and asynchronous APIs
    class RESTClient {
    public:
        /// Response structure containing HTTP request results
        struct Response {
            static constexpr std::string_view VERSION = "2.0.0";

            bool success = false;           ///< True if request succeeded (2xx status)
            long status_code = 0;           ///< HTTP status code
            std::string body;               ///< Raw response body
            nlohmann::json data;            ///< Parsed JSON response (if applicable)
            RESTErrorType error_type = RESTErrorType::UNKNOWN;  ///< Categorized error type
            std::string error_msg;          ///< Human-readable error message
            long long sent_at = 0;          ///< Request timestamp (ms since epoch)
            long long received_at = 0;      ///< Response timestamp (ms since epoch)

            Response() noexcept : data(nlohmann::json::object()) {}

            [[nodiscard]] constexpr bool is_success() const noexcept { return success; }
            [[nodiscard]] constexpr bool is_client_error() const noexcept {
                return status_code >= 400 && status_code < 500;
            }
            [[nodiscard]] constexpr bool is_server_error() const noexcept {
                return status_code >= 500;
            }
        };

        using AsyncCallback = std::function<void(Response)>;

        /// Constructs a RESTClient instance
        /// @param base_url Base URL for all requests (e.g., "https://api.example.com")
        /// @param credentials_path Path to JSON file containing authentication credentials
        /// @param config Configuration parameters (optional)
        RESTClient(std::string_view base_url, std::string_view credentials_path, RESTConfig config = RESTConfig())
            : curl_(nullptr, curl_easy_cleanup)
            , base_url_(base_url)
            , config_(std::move(config))
            , last_request_time_(std::chrono::steady_clock::now())
            , async_stop_(false)
            , auth_host_upper_(config_.auth_host)
        {
            if (!config_.is_valid()) {
                throw std::invalid_argument("Invalid RESTConfig parameters");
            }

            // Pre-uppercase auth_host for JWT generation
            std::transform(auth_host_upper_.begin(), auth_host_upper_.end(),
                auth_host_upper_.begin(), ::toupper);

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

        // Copy operations disabled - contains thread and CURL handle
        RESTClient(const RESTClient&) = delete;
        RESTClient& operator=(const RESTClient&) = delete;

        // Move operations disabled - async_worker_ captures 'this'
        RESTClient(RESTClient&&) = delete;
        RESTClient& operator=(RESTClient&&) = delete;

        [[nodiscard]] const std::string& base_url() const noexcept { return base_url_; }
        [[nodiscard]] const RESTConfig& config() const noexcept { return config_; }

        // =========================================================
        //  SYNC API
        // =========================================================

        /// Sends a request with automatic retry on retryable errors
        /// @param endpoint API endpoint (e.g., "/api/v1/data")
        /// @param method HTTP method (GET, POST, PUT, DELETE)
        /// @param body Request body (optional, ignored for GET)
        /// @return Response structure with request results
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

        /// Sends a single request without retry
        /// @param endpoint API endpoint (e.g., "/api/v1/data")
        /// @param method HTTP method (GET, POST, PUT, DELETE)
        /// @param body Request body (optional, ignored for GET)
        /// @return Response structure with request results
        Response send(std::string_view endpoint, std::string_view method, std::string_view body = "") {

            // Rate limiting: ensure minimum interval between requests
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

            // Build complete header list for this request (thread-safe)
            curl_slist* headers = nullptr;

            // Add static headers
            headers = curl_slist_append(headers, ("User-Agent: " + config_.user_agent).c_str());
            headers = curl_slist_append(headers, "Content-Type: application/json");

            // Add authorization header
            std::string auth_header = "Authorization: Bearer " + token;
            headers = curl_slist_append(headers, auth_header.c_str());

            curl_easy_reset(curl_.get());
            curl_easy_setopt(curl_.get(), CURLOPT_URL, full_url.c_str());
            curl_easy_setopt(curl_.get(), CURLOPT_CUSTOMREQUEST, method_s.c_str());
            curl_easy_setopt(curl_.get(), CURLOPT_HTTPHEADER, headers);
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

            // Clean up headers
            curl_slist_free_all(headers);

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
                        out.data = nlohmann::json::parse(out.body);
                    } catch (const std::exception& e) {
                        log(RESTLogLevel::DEBUG, std::string("JSON parse failed: ") + e.what());
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

        // =========================================================
        //  ASYNC API
        // =========================================================

        /// Asynchronously sends a request with automatic retry
        /// @param endpoint API endpoint
        /// @param method HTTP method
        /// @param body Request body
        /// @param callback Function called with response when request completes
        void send_with_retry_async(std::string_view endpoint,
            std::string_view method,
            std::string_view body,
            AsyncCallback callback)
        {
            enqueue_task(std::string(endpoint), std::string(method),
                std::string(body), std::move(callback), true);
        }

        /// Asynchronously sends a request with automatic retry (no body)
        void send_with_retry_async(std::string_view endpoint,
            std::string_view method,
            AsyncCallback callback)
        {
            send_with_retry_async(endpoint, method, "", std::move(callback));
        }

        /// Asynchronously sends a single request without retry
        void send_async(std::string_view endpoint,
            std::string_view method,
            std::string_view body,
            AsyncCallback callback)
        {
            enqueue_task(std::string(endpoint), std::string(method),
                std::string(body), std::move(callback), false);
        }

        /// Asynchronously sends a single request without retry (no body)
        void send_async(std::string_view endpoint,
            std::string_view method,
            AsyncCallback callback)
        {
            send_async(endpoint, method, "", std::move(callback));
        }

        // =========================================================
        //  UTILITIES
        // =========================================================

        /// Returns current UTC time as time_t
        [[nodiscard]] static time_t get_current_utc_time() noexcept {
            const auto current_now = std::chrono::system_clock::now();
            return std::chrono::system_clock::to_time_t(current_now);
        }

        /// Formats a timestamp for display
        /// @param timestamp Unix timestamp
        /// @param local_time If true, use local timezone; otherwise UTC
        /// @param date If true, include date; otherwise time only
        [[nodiscard]] static std::string format_time(time_t timestamp, bool local_time, bool date) {
            tm tm_buf = {};
            char buffer[100];

            if (local_time) {
#ifdef _WIN32
                localtime_s(&tm_buf, &timestamp);

                if (date) {
                    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_buf);
                    std::string result = "[" + std::string(buffer);

                    char tz_buffer[64] = { 0 };
                    strftime(tz_buffer, sizeof(tz_buffer), "%Z", &tm_buf);
                    std::string tz_full(tz_buffer);

                    if (!tz_full.empty()) {
                        std::string tz_abbr;
                        for (size_t i = 0; i < tz_full.length(); ++i) {
                            if (i == 0 || (i > 0 && tz_full[i - 1] == ' ')) {
                                if (isalpha(tz_full[i])) {
                                    tz_abbr += toupper(tz_full[i]);
                                }
                            }
                        }
                        result += " " + (tz_abbr.empty() ? tz_full : tz_abbr);
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
                    strftime(buffer, sizeof(buffer), "[%Y-%m-%d %H:%M:%S %Z]", &tm_buf);
                } else {
                    strftime(buffer, sizeof(buffer), "[%H:%M:%S]", &tm_buf);
                }
                return std::string(buffer);
#endif
            } else {
#ifdef _WIN32
                gmtime_s(&tm_buf, &timestamp);
#else
                gmtime_r(&timestamp, &tm_buf);
#endif
                if (date) {
                    strftime(buffer, sizeof(buffer), "[%Y-%m-%d %H:%M:%S UTC]", &tm_buf);
                } else {
                    strftime(buffer, sizeof(buffer), "[%H:%M:%S UTC]", &tm_buf);
                }
                return std::string(buffer);
            }
        }

    private:
        struct SListDeleter {
            void operator()(curl_slist* sl) const noexcept {
                if (sl) curl_slist_free_all(sl);
            }
        };
        using SListPtr = std::unique_ptr<curl_slist, SListDeleter>;

        std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl_;
        std::string  base_url_;
        std::string  key_name_;
        std::string  key_secret_;
        RESTConfig   config_;
        std::string  auth_host_upper_;  ///< Cached uppercase auth host for JWT generation

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

        /// Background worker thread that processes queued async requests
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
                try {
                    task();
                } catch (const std::exception& e) {
                    log(RESTLogLevel::ERROR, std::string("Async callback exception: ") + e.what());
                } catch (...) {
                    log(RESTLogLevel::ERROR, "Async callback threw unknown exception");
                }
            }
        }

        /// Enqueues an async task with bounded queue size
        void enqueue_task(std::string ep, std::string meth, std::string bd,
            AsyncCallback cb, bool with_retry)
        {
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
                nlohmann::json j = nlohmann::json::parse(f);

                if (!j.contains("name")) {
                    throw std::runtime_error("Missing 'name' field in credentials file");
                }
                if (!j.contains("privateKey")) {
                    throw std::runtime_error("Missing 'privateKey' field in credentials file");
                }

                key_name_ = j.at("name").get<std::string>();
                key_secret_ = j.at("privateKey").get<std::string>();

                size_t pos = 0;
                while ((pos = key_secret_.find("\\n", pos)) != std::string::npos) {
                    key_secret_.replace(pos, 2, "\n");
                    pos += 1;
                }
            } catch (const nlohmann::json::exception& e) {
                throw std::runtime_error(std::string("JSON parse error: ") + e.what());
            }
        }

        std::string generate_jwt(std::string_view method, std::string_view endpoint) {
            auto now = std::chrono::system_clock::now() - std::chrono::seconds(1);

            std::string path(endpoint.substr(0, endpoint.find('?')));

            // Convert method to uppercase without heap allocation
            char meth_upper[8] = { 0 };
            size_t meth_len = std::min(method.size(), sizeof(meth_upper) - 1);
            for (size_t i = 0; i < meth_len; ++i) {
                meth_upper[i] = static_cast<char>(std::toupper(method[i]));
            }
            std::string_view meth_u(meth_upper, meth_len);

            // Use cached uppercase auth host
            std::string uri = std::string(meth_u) + " " + auth_host_upper_ + path;

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
                .set_header_claim("nonce", jwt::claim(generate_nonce(16)))
                .sign(jwt::algorithm::es256("", key_secret_, "", ""));
        }

        std::string generate_nonce(size_t len) noexcept {
            static constexpr char hex[] = "0123456789abcdef";
            static thread_local std::mt19937 gen([]() {
                std::random_device rd;
                return std::mt19937(rd());
            }());
            std::uniform_int_distribution<> dis(0, 15);
            std::string s;
            s.reserve(len);
            for (size_t i = 0; i < len; ++i) {
                s += hex[dis(gen)];
            }
            return s;
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