#pragma once

// =========================================================
//  Platform preamble
//  Must appear before any system / third-party headers.
// =========================================================
#if defined(_WIN32) || defined(_WIN64)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>    // MSVC: localtime_s lives here
#endif

// =========================================================
//  Standard library
// =========================================================
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>
#include <thread>
#include <cctype>
#include <exception>
#include <stdexcept>
#include <utility>

// =========================================================
//  Third-party – OpenSSL
// =========================================================
#include <openssl/evp.h>
#include <openssl/rand.h>

// =========================================================
//  Third-party – libcurl
//  <curl/curl.h> already transitively includes <curl/easy.h>;
//  the redundant include is omitted.
// =========================================================
#include <curl/curl.h>

// =========================================================
//  Third-party – jwt-cpp
//  Suppress MSVC warning C4244 (possible loss of data) that
//  originates inside jwt-cpp headers, not in our code.
// =========================================================
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable : 4244 26495)
#endif
#include <jwt-cpp/jwt.h>
#ifdef _MSC_VER
#  pragma warning(pop)
#endif

// =========================================================
//  Third-party – nlohmann/json
// =========================================================
#include <nlohmann/json.hpp>

// =========================================================
//  Undefine Win32 macros that collide with our enum values.
//  Done after all includes so nothing internal relies on them.
// =========================================================
#ifdef ERROR
#  undef ERROR
#endif
#ifdef INFO
#  undef INFO
#endif

using json = nlohmann::json;

namespace restclient {

// =========================================================
//  Enumerations
// =========================================================
enum class RESTLogLevel  { NONE, ERROR, INFO, DEBUG };
enum class RESTErrorType { SUCCESS, NETWORK, SSL, TIMEOUT, AUTH, RATE_LIMIT, SERVER, CLIENT, UNKNOWN };

// =========================================================
//  RESTConfig
// =========================================================
struct RESTConfig {
    std::chrono::seconds timeout          { 30 };
    int                  max_retries      { 3 };
    std::string          user_agent       { "RESTSDK/3.1.0" };
    std::string          auth_host        { "api.coinbase.com" };
    int                  min_interval_ms  { 100 };
    RESTLogLevel         log_level        { RESTLogLevel::INFO };
    bool                 log_to_stdout    { true };

    /// Maximum number of tasks allowed in the async queue at any one time.
    /// Enqueue attempts beyond this limit are rejected and logged.
    /// 0 means unbounded (not recommended for production).
    std::size_t max_async_queue_depth { 256 };

    [[nodiscard]] bool is_valid() const noexcept {
        return min_interval_ms >= 0 && max_retries >= 0 && timeout.count() > 0;
    }
};

// =========================================================
//  RESTClient
//
//  Thread-safety contract
//  ----------------------
//  send() / send_with_retry()             – may be called from any thread;
//                                           serialised internally via transport_mtx_.
//  send_async() / send_with_retry_async() – enqueue to a single worker thread;
//                                           callbacks are invoked from that worker.
//  Destructor                             – drains and joins the worker thread.
//
//  The object is non-copyable and non-movable: the async worker captures
//  `this`, and static_headers_tail_ is a raw pointer into memory owned by
//  static_headers_.  Both are invalidated by relocation.
// =========================================================
class RESTClient {
public:
    // ---------------------------------------------------------
    //  Public types
    // ---------------------------------------------------------
    static constexpr std::string_view SDK_VERSION = "3.1.0";

    struct Response {
        bool          success      = false;
        long          status_code  = 0;
        std::string   body;
        json          data;
        RESTErrorType error_type   = RESTErrorType::UNKNOWN;
        std::string   error_msg;
        long long     sent_at      = 0;
        long long     received_at  = 0;

        Response() noexcept : data(json::object()) {}

        [[nodiscard]] constexpr bool is_success()      const noexcept { return success; }
        [[nodiscard]] constexpr bool is_client_error() const noexcept {
            return status_code >= 400 && status_code < 500;
        }
        [[nodiscard]] constexpr bool is_server_error() const noexcept {
            return status_code >= 500;
        }
    };

    using AsyncCallback = std::function<void(Response)>;

    // ---------------------------------------------------------
    //  Construction / destruction
    // ---------------------------------------------------------
    RESTClient(std::string_view base_url,
               std::string_view credentials_path,
               RESTConfig       config = RESTConfig())
        : curl_(nullptr, curl_easy_cleanup)
        , static_headers_(nullptr)
        , static_headers_tail_(nullptr)
        , base_url_(base_url)
        , config_(std::move(config))
        , last_request_time_(std::chrono::steady_clock::now())
        , async_stop_(false)
    {
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

            curl_slist* tail = head;
            while (tail && tail->next) { tail = tail->next; }

            static_headers_      = SListPtr(head);
            static_headers_tail_ = tail;   // raw observer – lifetime tied to static_headers_
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
        if (async_worker_.joinable()) { async_worker_.join(); }
    }

    RESTClient(const RESTClient&)            = delete;
    RESTClient& operator=(const RESTClient&) = delete;
    RESTClient(RESTClient&&)                 = delete;
    RESTClient& operator=(RESTClient&&)      = delete;

    // ---------------------------------------------------------
    //  Accessors
    // ---------------------------------------------------------
    [[nodiscard]] const std::string& base_url() const noexcept { return base_url_; }
    [[nodiscard]] const RESTConfig&  config()   const noexcept { return config_; }

    // ---------------------------------------------------------
    //  Synchronous API
    // ---------------------------------------------------------

    /// Attempts the request up to (1 + max_retries) times with exponential
    /// back-off.  Only NETWORK, TIMEOUT, SERVER, and RATE_LIMIT errors are
    /// retried; AUTH and CLIENT errors are returned immediately.
    [[nodiscard]] Response send_with_retry(std::string_view endpoint,
                                           std::string_view method,
                                           std::string_view body = "")
    {
        // Cap the back-off to avoid integer overflow in 150 * (1 << i) for
        // large max_retries values.  2^10 * 150 ms ≈ 2.5 min per attempt.
        static constexpr int kMaxBackoffShift = 10;

        Response resp;
        for (int i = 0; i <= config_.max_retries; ++i) {
            if (i > 0) {
                const int shift = std::min(i - 1, kMaxBackoffShift);
                std::this_thread::sleep_for(std::chrono::milliseconds(150LL * (1LL << shift)));
                log(RESTLogLevel::INFO, "Retry attempt " + std::to_string(i));
            }
            resp = send(endpoint, method, body);
            if (resp.success || !is_retryable(resp.error_type)) { break; }
        }
        return resp;
    }

    [[nodiscard]] Response send(std::string_view endpoint,
                                std::string_view method,
                                std::string_view body = "")
    {
        // --- Rate throttling (does not hold the transport lock) ---
        {
            std::lock_guard<std::mutex> tlock(throttle_mtx_);
            const auto now     = std::chrono::steady_clock::now();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     now - last_request_time_).count();
            if (elapsed < config_.min_interval_ms) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(config_.min_interval_ms - elapsed));
            }
            last_request_time_ = std::chrono::steady_clock::now();
        }

        // --- Transport (serialises CURL handle access and header-list mutation) ---
        std::lock_guard<std::mutex> transport_lock(transport_mtx_);

        if (!curl_) {
            Response out;
            out.success    = false;
            out.error_msg  = "CURL handle is null";
            out.error_type = RESTErrorType::UNKNOWN;
            return out;
        }

        const std::string token    = generate_jwt(method, endpoint);
        const std::string full_url = base_url_ + std::string(endpoint);
        const std::string method_str(method);

        // Build a per-request auth node.  We extend the static list temporarily
        // to avoid rebuilding it on every call.  The tail's ->next pointer is
        // always nullptr outside this critical section (guarded by transport_mtx_).
        const std::string auth_header = "Authorization: Bearer " + token;
        curl_slist* auth_node = curl_slist_append(nullptr, auth_header.c_str());
        if (!auth_node) {
            Response out;
            out.success    = false;
            out.error_msg  = "curl_slist_append returned null for auth header";
            out.error_type = RESTErrorType::UNKNOWN;
            return out;
        }

        if (static_headers_tail_) {
            static_headers_tail_->next = auth_node;
        }

        std::string buffer;

        curl_easy_reset(curl_.get());
        curl_easy_setopt(curl_.get(), CURLOPT_URL,           full_url.c_str());
        curl_easy_setopt(curl_.get(), CURLOPT_CUSTOMREQUEST, method_str.c_str());
        curl_easy_setopt(curl_.get(), CURLOPT_HTTPHEADER,
                         static_headers_ ? static_headers_.get() : auth_node);
        curl_easy_setopt(curl_.get(), CURLOPT_TIMEOUT,       static_cast<long>(config_.timeout.count()));
        curl_easy_setopt(curl_.get(), CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl_.get(), CURLOPT_WRITEDATA,     &buffer);
        curl_easy_setopt(curl_.get(), CURLOPT_NOSIGNAL,      1L);

        if (!body.empty()) {
            curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDS,    body.data());
            curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        }

        const long long t_sent = epoch_ms();
        const CURLcode  res    = curl_easy_perform(curl_.get());
        const long long t_recv = epoch_ms();

        // Restore the static list tail before releasing auth_node.
        if (static_headers_tail_) { static_headers_tail_->next = nullptr; }
        curl_slist_free_all(auth_node);

        Response out;
        out.sent_at     = t_sent;
        out.received_at = t_recv;

        if (res == CURLE_OK) {
            curl_easy_getinfo(curl_.get(), CURLINFO_RESPONSE_CODE, &out.status_code);
            out.body    = std::move(buffer);
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
            out.error_msg  = curl_easy_strerror(res);
            out.error_type = classify_curl_error(res);
        }

        return out;
    }

    // ---------------------------------------------------------
    //  Asynchronous API
    //
    //  All async calls are serialised through a single background worker
    //  thread rather than spawning per-call threads.  This bounds resource
    //  usage and preserves natural request serialisation within a client.
    //
    //  NOTE: callbacks are invoked from the worker thread.
    //        On Win32 UI threads, use PostMessage / PostThreadMessage to
    //        marshal the result back to the message loop.
    // ---------------------------------------------------------
    void send_with_retry_async(std::string_view endpoint,
                               std::string_view method,
                               std::string_view body,
                               AsyncCallback    callback)
    {
        enqueue_task(std::string(endpoint), std::string(method),
                     std::string(body), std::move(callback), /*with_retry=*/true);
    }

    void send_with_retry_async(std::string_view endpoint,
                               std::string_view method,
                               AsyncCallback    callback)
    {
        send_with_retry_async(endpoint, method, "", std::move(callback));
    }

    void send_async(std::string_view endpoint,
                    std::string_view method,
                    std::string_view body,
                    AsyncCallback    callback)
    {
        enqueue_task(std::string(endpoint), std::string(method),
                     std::string(body), std::move(callback), /*with_retry=*/false);
    }

    void send_async(std::string_view endpoint,
                    std::string_view method,
                    AsyncCallback    callback)
    {
        send_async(endpoint, method, "", std::move(callback));
    }

private:
    // ---------------------------------------------------------
    //  Private types
    // ---------------------------------------------------------
    struct SListDeleter {
        void operator()(curl_slist* sl) const noexcept {
            if (sl) { curl_slist_free_all(sl); }
        }
    };
    using SListPtr = std::unique_ptr<curl_slist, SListDeleter>;
    using Task     = std::function<void()>;

    // ---------------------------------------------------------
    //  Data members
    // ---------------------------------------------------------
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl_;
    SListPtr    static_headers_;
    curl_slist* static_headers_tail_;   // raw observer – lifetime tied to static_headers_

    std::string base_url_;
    std::string key_name_;
    std::string key_secret_;
    RESTConfig  config_;

    std::mutex                            throttle_mtx_;
    std::chrono::steady_clock::time_point last_request_time_;

    std::mutex                            transport_mtx_;

    mutable std::mutex                    log_mtx_;   // mutable: locked inside const log()

    std::queue<Task>                      async_queue_;
    std::mutex                            async_mtx_;
    std::condition_variable               async_cv_;
    bool                                  async_stop_;   // guarded by async_mtx_
    std::thread                           async_worker_;

    // ---------------------------------------------------------
    //  Async worker
    // ---------------------------------------------------------
    void async_worker_loop() {
        while (true) {
            Task task;
            {
                std::unique_lock<std::mutex> lock(async_mtx_);
                async_cv_.wait(lock, [this] {
                    return !async_queue_.empty() || async_stop_;
                });
                if (async_stop_ && async_queue_.empty()) { return; }
                task = std::move(async_queue_.front());
                async_queue_.pop();
            }
            // Execute outside the queue lock.
            // Catching all exceptions is mandatory: an unhandled throw here
            // calls std::terminate, silently killing the worker and causing
            // all subsequent async calls to pend indefinitely.
            try {
                task();
            } catch (const std::exception& e) {
                log(RESTLogLevel::ERROR,
                    std::string("Async callback threw std::exception: ") + e.what());
            } catch (...) {
                log(RESTLogLevel::ERROR, "Async callback threw unknown exception");
            }
        }
    }

    void enqueue_task(std::string   ep,
                      std::string   meth,
                      std::string   bd,
                      AsyncCallback cb,
                      bool          with_retry)
    {
        bool queue_full = false;
        {
            std::lock_guard<std::mutex> lock(async_mtx_);
            if (config_.max_async_queue_depth > 0 &&
                async_queue_.size() >= config_.max_async_queue_depth)
            {
                queue_full = true;
            } else {
                async_queue_.push(
                    [this,
                     ep        = std::move(ep),
                     meth      = std::move(meth),
                     bd        = std::move(bd),
                     cb        = std::move(cb),
                     with_retry]() mutable
                    {
                        cb(with_retry ? send_with_retry(ep, meth, bd)
                                      : send(ep, meth, bd));
                    });
            }
        }

        if (queue_full) {
            log(RESTLogLevel::ERROR,
                "Async queue full (" +
                std::to_string(config_.max_async_queue_depth) +
                "); rejecting request to " + ep);
            Response err;
            err.success    = false;
            err.error_type = RESTErrorType::RATE_LIMIT;
            err.error_msg  = "Async queue full - request rejected";
            cb(std::move(err));
            return;
        }

        async_cv_.notify_one();
    }

    // ---------------------------------------------------------
    //  Logging
    //  Cross-platform localtime:
    //    MSVC / MinGW  → localtime_s(&buf, &t)   (ISO C11 Annex K, Windows)
    //    POSIX          → localtime_r(&t, &buf)
    // ---------------------------------------------------------
    void log(RESTLogLevel level, std::string_view message) const {
        if (static_cast<int>(level) > static_cast<int>(config_.log_level) ||
            !config_.log_to_stdout)
        {
            return;
        }
        std::lock_guard<std::mutex> lock(log_mtx_);
        const auto t = std::chrono::system_clock::to_time_t(
                           std::chrono::system_clock::now());
        struct tm buf = {};
#if defined(_WIN32) || defined(_WIN64)
        localtime_s(&buf, &t);
#else
        localtime_r(&t, &buf);
#endif
        std::cout << '[' << std::put_time(&buf, "%Y-%m-%d %H:%M:%S") << "] "
                  << message << '\n';
    }

    // ---------------------------------------------------------
    //  Credentials
    // ---------------------------------------------------------
    void load_credentials(std::string_view path) {
        std::ifstream f { std::string(path) };
        if (!f.is_open()) {
            throw std::runtime_error(
                "Could not open credentials file: " + std::string(path));
        }

        try {
            const json j = json::parse(f);
            key_name_   = j.at("name").get<std::string>();
            key_secret_ = j.at("privateKey").get<std::string>();

            // Unescape literal "\n" sequences embedded in JSON string values.
            std::string out;
            out.reserve(key_secret_.size());
            for (std::size_t i = 0; i < key_secret_.size(); ++i) {
                if (key_secret_[i] == '\\' &&
                    i + 1 < key_secret_.size() &&
                    key_secret_[i + 1] == 'n')
                {
                    out += '\n';
                    ++i;
                } else {
                    out += key_secret_[i];
                }
            }
            key_secret_ = std::move(out);
        } catch (const std::exception& ex) {
            throw std::runtime_error(
                std::string("Credential parse error: ") + ex.what());
        }
    }

    // ---------------------------------------------------------
    //  JWT generation
    // ---------------------------------------------------------
    [[nodiscard]] std::string generate_jwt(std::string_view method,
                                           std::string_view endpoint) const
    {
        // Back-date by one second to tolerate minor server clock skew.
        const auto now = std::chrono::system_clock::now() - std::chrono::seconds(1);

        // Strip query string from the path component of the URI claim.
        std::string path(endpoint.substr(0, endpoint.find('?')));

        // Build the URI claim: "<METHOD> <host><path>" – all uppercase per CDP spec.
        std::string method_upper(method);
        std::transform(method_upper.begin(), method_upper.end(),
                       method_upper.begin(), [](unsigned char c) {
                           return static_cast<char>(std::toupper(c));
                       });

        std::string host_upper = config_.auth_host;
        std::transform(host_upper.begin(), host_upper.end(),
                       host_upper.begin(), [](unsigned char c) {
                           return static_cast<char>(std::toupper(c));
                       });

        const std::string uri = method_upper + ' ' + host_upper + path;

        return jwt::create()
            .set_type("JWT")
            .set_issuer("cdp")
            .set_subject(key_name_)
            .set_issued_at(now)
            .set_not_before(now)
            .set_expires_at(now + std::chrono::seconds(120))
            .set_audience("cdp_service")
            .set_payload_claim("uri",   jwt::claim(uri))
            .set_header_claim("kid",    jwt::claim(key_name_))
            .set_header_claim("nonce",  jwt::claim(generate_nonce()))
            .sign(jwt::algorithm::es256(key_name_, key_secret_));
    }

    [[nodiscard]] std::string generate_nonce() const {
        static constexpr int kRawBytes = 16;

        unsigned char raw[kRawBytes];
        if (RAND_bytes(raw, kRawBytes) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }

        // Standard base64 output length: ceil(n/3)*4 bytes, no newline padding.
        // EVP_ENCODE_LENGTH(n) adds one extra byte for a trailing newline;
        // we use the exact formula to avoid a stray '\n' in the nonce.
        const int b64_len = ((kRawBytes + 2) / 3) * 4;
        std::string encoded(static_cast<std::size_t>(b64_len), '\0');

        const int actual = EVP_EncodeBlock(
            reinterpret_cast<unsigned char*>(encoded.data()),
            raw,
            kRawBytes);

        encoded.resize(static_cast<std::size_t>(actual));
        return encoded;
    }

    // ---------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------
    static std::size_t write_cb(void* contents, std::size_t size,
                                std::size_t nmemb, void* userp) noexcept
    {
        const std::size_t total = size * nmemb;
        static_cast<std::string*>(userp)->append(
            static_cast<char*>(contents), total);
        return total;
    }

    static long long epoch_ms() noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static constexpr RESTErrorType classify_http_status(long code) noexcept {
        if (code >= 200 && code < 300)  return RESTErrorType::SUCCESS;
        if (code == 401 || code == 403) return RESTErrorType::AUTH;
        if (code == 429)                return RESTErrorType::RATE_LIMIT;
        if (code >= 400 && code < 500)  return RESTErrorType::CLIENT;
        if (code >= 500)                return RESTErrorType::SERVER;
        return RESTErrorType::UNKNOWN;
    }

    static constexpr RESTErrorType classify_curl_error(CURLcode code) noexcept {
        switch (code) {
            case CURLE_OPERATION_TIMEDOUT:
                return RESTErrorType::TIMEOUT;

            case CURLE_SSL_CONNECT_ERROR:
                [[fallthrough]];
            case CURLE_SSL_CERTPROBLEM:
                [[fallthrough]];
            case CURLE_SSL_CIPHER:
                [[fallthrough]];
            case CURLE_SSL_ENGINE_NOTFOUND:
                [[fallthrough]];
            case CURLE_SSL_ENGINE_SETFAILED:
                [[fallthrough]];
            // CURLE_PEER_FAILED_VERIFICATION (60) is the canonical name for
            // the deprecated CURLE_SSL_CACERT; use only the canonical form.
            case CURLE_PEER_FAILED_VERIFICATION:
                return RESTErrorType::SSL;

            case CURLE_COULDNT_RESOLVE_HOST:
                [[fallthrough]];
            case CURLE_COULDNT_CONNECT:
                [[fallthrough]];
            case CURLE_SEND_ERROR:
                [[fallthrough]];
            case CURLE_RECV_ERROR:
                return RESTErrorType::NETWORK;

            default:
                return RESTErrorType::UNKNOWN;
        }
    }

    static constexpr bool is_retryable(RESTErrorType type) noexcept {
        switch (type) {
            case RESTErrorType::NETWORK:
                [[fallthrough]];
            case RESTErrorType::TIMEOUT:
                [[fallthrough]];
            case RESTErrorType::SERVER:
                [[fallthrough]];
            case RESTErrorType::RATE_LIMIT:
                return true;
            default:
                return false;
        }
    }
};

} // namespace restclient