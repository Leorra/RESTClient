#include <restclient/RESTClient.hpp>
#include <iostream>

int main() {
    std::cout << "RESTClient Example - Coinbase CDP API" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    // Configure the client
    restclient::RESTConfig config;
    config.log_level = restclient::RESTLogLevel::INFO;
    config.timeout = std::chrono::seconds(30);
    config.max_retries = 3;
    
    try {
        // Create client instance (requires credentials.json)
        restclient::RESTClient client(
            "https://api.coinbase.com",
            "credentials.json",  // Path to your credentials file
            config
        );
        
        // Fetch accounts
        std::cout << "\nFetching accounts..." << std::endl;
        auto response = client.send_with_retry("/v2/accounts", "GET");
        
        if (response.success) {
            std::cout << "Success! Status: " << response.status_code << std::endl;
            std::cout << "Response: " << response.body << std::endl;
        } else {
            std::cout << "Error: " << response.error_msg << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}