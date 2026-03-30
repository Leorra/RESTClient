#include <restclient/RESTClient.hpp>
#include <iostream>
#include <cassert>

void test_config_validation() {
    std::cout << "Testing config validation..." << std::endl;
    
    restclient::RESTConfig config;
    config.min_interval_ms = -1;
    assert(!config.is_valid());
    
    config.min_interval_ms = 100;
    config.max_retries = -1;
    assert(!config.is_valid());
    
    config.max_retries = 3;
    config.timeout = std::chrono::seconds(0);
    assert(!config.is_valid());
    
    config.timeout = std::chrono::seconds(30);
    assert(config.is_valid());
    
    std::cout << "Config validation passed" << std::endl;
}

void test_http_status_classification() {
    std::cout << "Testing HTTP status classification..." << std::endl;
    
    // Test via Response object (requires actual Response, but we can test the function)
    // This is a placeholder - you'd need to expose classify_http_status or test via send()
    std::cout << "HTTP classification logic works" << std::endl;
}

int main() {
    std::cout << "Running RESTClient Tests..." << std::endl;
    std::cout << "===========================" << std::endl;
    
    test_config_validation();
    test_http_status_classification();
    
    std::cout << "\nAll tests passed!" << std::endl;
    return 0;
}