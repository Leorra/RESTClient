#pragma once

#include <chrono>
#include <fstream>
#include <stdexcept>
#include <string>

#include <jwt-cpp/jwt.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

class JWTGenerator {
public:
	// Constructor with file path
	explicit JWTGenerator(const std::string& cdp_filename)
		: key_public(""), key_private("") {
		load_credentials(cdp_filename);
	}

	// Constructor with direct credentials (for testing or programmatic use)
	JWTGenerator(std::string public_key, std::string private_key)
		: key_public(std::move(public_key)),
		key_private(std::move(private_key)) {
		if (key_public.empty() || key_private.empty()) {
			throw std::runtime_error("Public and private keys cannot be empty");
		}
	}

	// Rule of Five - proper resource management
	JWTGenerator(const JWTGenerator&) = default;
	JWTGenerator& operator=(const JWTGenerator&) = default;
	JWTGenerator(JWTGenerator&&) noexcept = default;
	JWTGenerator& operator=(JWTGenerator&&) noexcept = default;
	~JWTGenerator() = default;

	std::string create_jwt(const std::string& uri = "") const {

		std::string nonce = generate_nonce();
		auto now = std::chrono::system_clock::now();

		try {
			// Avoid accidental copy from a chained temporary by creating the builder
			// first and then calling mutating methods on it.
			auto token = ::jwt::create();
			if (!uri.empty())
				token.set_payload_claim("uri", ::jwt::claim(uri));
			token.set_subject(key_public);
			token.set_issuer("cdp");
			token.set_not_before(now - std::chrono::seconds { skew_buffer });
			token.set_expires_at(now + std::chrono::seconds { 120 - skew_buffer });
			token.set_header_claim("kid", ::jwt::claim(key_public));
			token.set_header_claim("nonce", ::jwt::claim(nonce));

			return token.sign(::jwt::algorithm::es256(key_public, key_private));

		} catch (const std::exception& e) {
			throw std::runtime_error(std::string("JWT signing failed: ") + e.what());
		}
	}

private:
	static constexpr int DEFAULT_NONCE_SIZE = 16;
	static constexpr int skew_buffer = 1;

	std::string key_public;
	std::string key_private;

	// Load credentials from JSON file
	void load_credentials(const std::string& filename) {
		json jsonData;
		std::ifstream file(filename);

		if (!file.is_open()) {
			throw std::runtime_error("Failed to open CDP file: " + filename);
		}

		try {
			file >> jsonData;

			// Check for required fields
			if (!jsonData.contains("name")) {
				throw std::runtime_error("Missing required field: 'name'");
			}
			if (!jsonData.contains("privateKey")) {
				throw std::runtime_error("Missing required field: 'privateKey'");
			}

			key_public = jsonData.at("name").get<std::string>();
			key_private = jsonData.at("privateKey").get<std::string>();

			if (key_public.empty()) throw std::runtime_error("Public key cannot be empty");
			if (key_private.empty()) throw std::runtime_error("Private key cannot be empty");

		} catch (const json::exception& e) {
			throw std::runtime_error(std::string("JSON parsing failed: ") + e.what());
		}
	}

	// Generate cryptographically secure random nonce
	std::string generate_nonce() const {
		unsigned char nonce_raw[DEFAULT_NONCE_SIZE];

		if (RAND_bytes(nonce_raw, static_cast<int>(sizeof(nonce_raw))) != 1) {
			throw std::runtime_error("Failed to generate random nonce: RAND_bytes failed");
		}

		// Base64 encoding
		std::string encoded;
		encoded.resize(EVP_ENCODE_LENGTH(static_cast<int>(sizeof(nonce_raw))));
		int actual_len = EVP_EncodeBlock(
			reinterpret_cast<unsigned char*>(&encoded[0]),
			nonce_raw,
			static_cast<int>(sizeof(nonce_raw))
		);
		if (actual_len < 0) {
			throw std::runtime_error("EVP_EncodeBlock failed");
		}
		encoded.resize(static_cast<size_t>(actual_len));

		return encoded;
	}
};