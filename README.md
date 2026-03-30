# RESTClient - Professional C++ REST API Client

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()

A thread-safe, production-ready REST API client library with JWT authentication, async support, automatic retries, and rate limiting. Designed for high-frequency trading and financial applications.

## Features

- **Thread-safe** - Full mutex protection for concurrent requests
- **Async API** - Single worker thread with bounded queue
- **Automatic retries** - Exponential backoff on retryable errors
- **Rate limiting** - Configurable minimum interval between requests
- **JWT authentication** - Built-in support for Coinbase CDP API
- **Cross-platform** - Windows and Linux support
- **Header-only** - Easy integration with any C++17 project
- **High performance** - Thread-local nonce generation, no heap allocations in hot path

## Quick Start

```cpp
#include <restclient/RESTClient.hpp>

int main() {
    restclient::RESTConfig config;
    config.log_level = restclient::RESTLogLevel::INFO;
    
    restclient::RESTClient client(
        "https://api.coinbase.com",
        "/path/to/credentials.json",
        config
    );
    
    auto response = client.send_with_retry("/api/v3/brokerage/key_permissions", "GET");
    
    if (response.success) {
        std::cout << "Success: " << response.body << std::endl;
    }
    
    return 0;
}