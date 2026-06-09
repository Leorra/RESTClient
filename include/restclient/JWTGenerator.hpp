#pragma once

#include <chrono>
#include <cstddef>
#include <fstream>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4244)
#include <jwt-cpp/jwt.h>
#pragma warning(pop)
#else
#include <jwt-cpp/jwt.h>
#endif

#include <nlohmann/json.hpp>

namespace jwt_util {

    // =========================================================
    //  JWTGenerator
    //
    //  Generates ES256 JWTs for the Coinbase CDP REST API.
    //
    //  Two construction modes:
    //    1. File path  -- reads "name" and "privateKey" from a
    //                     Coinbase CDP JSON credentials file.
    //    2. Direct     -- accepts the key name and PEM private
    //                     key string directly (useful for tests).
    //
    //  create_jwt() is thread-safe (const, no mutable state).
    // =========================================================
    class JWTGenerator {
    public:
        // ---------------------------------------------------------
        //  Construction
        // ---------------------------------------------------------

        /// Load credentials from a Coinbase CDP JSON file.
        explicit JWTGenerator(const std::string& cdp_filename) {
            load_credentials(cdp_filename);
        }

        /// Construct directly from a key name and PEM private key.
        /// Useful for unit tests or programmatic credential injection.
        JWTGenerator(std::string key_name, std::string private_key)
            : key_name_(std::move(key_name))
            , key_private_(std::move(private_key))
        {
            if (key_name_.empty()) {
                throw std::invalid_argument("Key name cannot be empty");
            }
            if (key_private_.empty()) {
                throw std::invalid_argument("Private key cannot be empty");
            }
        }

        // Rule of Five -- all defaulted; no owning raw resources.
        JWTGenerator(const JWTGenerator&) = default;
        JWTGenerator& operator=(const JWTGenerator&) = default;
        JWTGenerator(JWTGenerator&&) noexcept = default;
        JWTGenerator& operator=(JWTGenerator&&) noexcept = default;
        ~JWTGenerator() = default;

        // ---------------------------------------------------------
        //  JWT creation
        //
        //  uri  -- optional URI claim ("<METHOD> <HOST><PATH>").
        //          Pass an empty string to omit.
        //
        //  The token is back-dated by kSkewBuffer seconds on both
        //  iat and nbf to tolerate minor server clock skew, while
        //  the expiry is kept at a full 120 s from `now`.
        // ---------------------------------------------------------
        [[nodiscard]] std::string create_jwt(const std::string& uri = "") const {
            const std::string nonce = generate_nonce();

            // Back-date by kSkewBuffer to tolerate server clock skew.
            const auto now = std::chrono::system_clock::now();
            const auto backdated = now - std::chrono::seconds { kSkewBuffer };

            try {
                auto token = ::jwt::create();

                token.set_type("JWT");
                token.set_issuer("cdp");
                token.set_subject(key_name_);
                token.set_issued_at(backdated);
                token.set_not_before(backdated);
                token.set_expires_at(now + std::chrono::seconds { 120 });
                token.set_audience("cdp_service");

                if (!uri.empty()) {
                    token.set_payload_claim("uri", ::jwt::claim(uri));
                }

                token.set_header_claim("kid", ::jwt::claim(key_name_));
                token.set_header_claim("nonce", ::jwt::claim(nonce));

                return token.sign(::jwt::algorithm::es256(key_name_, key_private_));

            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("JWT signing failed: ") + e.what());
            }
        }

    private:
        // Number of seconds to back-date iat/nbf to tolerate clock skew.
        static constexpr int kSkewBuffer = 1;

        // Base64 output length for kNonceBytes raw bytes: ceil(n/3)*4.
        // Deliberately avoiding EVP_ENCODE_LENGTH which adds a newline slot.
        static constexpr std::size_t kNonceBytes = 16;
        static constexpr std::size_t kNonceB64Len = ((kNonceBytes + 2) / 3) * 4;

        std::string key_name_;     // CDP API key name (used as sub and kid)
        std::string key_private_;  // PEM-encoded EC private key

        // ---------------------------------------------------------
        //  Credential loading
        // ---------------------------------------------------------
        void load_credentials(const std::string& filename) {
            std::ifstream file(filename);
            if (!file.is_open()) {
                throw std::runtime_error("Failed to open CDP credentials file: " + filename);
            }

            try {
                const nlohmann::json j = nlohmann::json::parse(file);

                key_name_ = j.at("name").get<std::string>();
                key_private_ = j.at("privateKey").get<std::string>();

                if (key_name_.empty()) {
                    throw std::runtime_error("Field 'name' is empty in credentials file");
                }
                if (key_private_.empty()) {
                    throw std::runtime_error("Field 'privateKey' is empty in credentials file");
                }

                // Unescape literal "\\n" sequences that some CDP SDK tooling
                // writes into the JSON value instead of real newlines.
                // nlohmann correctly handles JSON "\n" -> '\n'; this pass
                // handles the case where the raw string contains backslash-n.
                unescape_newlines(key_private_);

            } catch (const nlohmann::json::exception& e) {
                throw std::runtime_error(std::string("Credentials JSON parse error: ") + e.what());
            }
        }

        // Replace all literal two-character sequences "\n" (0x5C 0x6E)
        // with a real newline (0x0A) in `s`.
        static void unescape_newlines(std::string& s) {
            std::string out;
            out.reserve(s.size());
            for (std::size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == 'n') {
                    out += '\n';
                    ++i;
                } else {
                    out += s[i];
                }
            }
            s = std::move(out);
        }

        // ---------------------------------------------------------
        //  Nonce generation
        // ---------------------------------------------------------
        [[nodiscard]] std::string generate_nonce() const {
            unsigned char raw[kNonceBytes];
            if (RAND_bytes(raw, static_cast<int>(kNonceBytes)) != 1) {
                throw std::runtime_error("RAND_bytes failed -- cannot generate nonce");
            }

            // Exact base64 length: no newline, no over-allocation.
            std::string encoded(kNonceB64Len, '\0');
            const int actual = EVP_EncodeBlock(
                reinterpret_cast<unsigned char*>(encoded.data()),
                raw,
                static_cast<int>(kNonceBytes));

            if (actual < 0) {
                throw std::runtime_error("EVP_EncodeBlock failed");
            }

            encoded.resize(static_cast<std::size_t>(actual));
            return encoded;
        }
    };

} // namespace jwt_util