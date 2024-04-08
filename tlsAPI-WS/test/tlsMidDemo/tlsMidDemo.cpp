#include <cstdint>
#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

#include <ara/core/initialization.h>
#include <ara/log/logging.h>
#include <ara/exec/application_client.h>

#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "TLSResult.h"
#include "InetAddress.h"
#include "TLSSockets.h"

using namespace vwg::tls;

// Global flag to control the running state of the server and client.
std::atomic<bool> g_running(true);

// Configuration constants for the network connection.
constexpr char SERVER_ADDRESS[] = "127.0.0.1";
constexpr uint16_t SERVER_PORT = 1337;
constexpr size_t BUFFER_SIZE = 1024;
constexpr char SERVER_PSK_ID[] = "1001";
constexpr char CLIENT_PSK_ID[] = "0001";

// Function to create and return a reference to a Logger instance for consistent logging.
inline ara::log::Logger& getLogger() noexcept {
    static ara::log::Logger& logger = ara::log::CreateLogger("MID", "Messaging System");
    return logger;
}

// Signal handler function to gracefully shutdown the application on interrupt signals.
void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_running = false;
        getLogger().LogInfo() << "Signal received. Shutting down...";
    }
}

// Forward declarations for the server and client run functions.
int runServer();
int runClient();

namespace {
// RAII class for automatic initialization and deinitialization of the ARA core environment.
class AraCoreScopedInitializer {
public:
    AraCoreScopedInitializer() {
        auto init_result = ara::core::Initialize();
        if (!init_result) {
            auto& err = init_result.Error();
            std::cerr << "Initialization failed. Error: " 
                      << err.Message() << ", " << err.UserMessage() << std::endl;
            ara::core::Abort("Initialization failed");
        }
    }

    ~AraCoreScopedInitializer() {
        ara::core::Deinitialize().InspectError([](const ara::core::ErrorCode& error) {
            std::cerr << "Deinitialization failed. Error: " 
                      << error.Message() << ", " << error.UserMessage() << std::endl;
        });
    }

    // Delete copy constructor and assignment operator to prevent copying.
    AraCoreScopedInitializer(const AraCoreScopedInitializer&) = delete;
    AraCoreScopedInitializer& operator=(const AraCoreScopedInitializer&) = delete;
};
} // anonymous namespace

int main(int argc, char* argv[]) {
    // Check for the correct number of command-line arguments.
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " [server|client]" << std::endl;
        return 1;
    }

    std::string mode(argv[1]);
    AraCoreScopedInitializer araInit{}; // Ensures ARA Core is initialized at the start and deinitialized at the end.

    // Setup signal handling for graceful shutdown.
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // Decide whether to run as a server or client based on the command-line argument.
    int result = 1; // Default to error state.
    if (mode == "server") {
        result = runServer();
    } else if (mode == "client") {
        result = runClient();
    } else {
        std::cerr << "Invalid mode specified. Use 'server' or 'client'." << std::endl;
    }

    return result;
}

int runServer() {
    getLogger().LogInfo() << "Server starting...";
    auto socketFactory_rc = initTLSLib(); // Initialize the TLS library.
    if (socketFactory_rc.failed()) {
        getLogger().LogError() << "Error initializing socket factory: " << socketFactory_rc.getErrorCode();
        return socketFactory_rc.getErrorCode();
    }

    // Create an IP address instance for the server.
    auto inet_rc = InetAddressFactory::makeIPAddress(SERVER_ADDRESS);
    if (inet_rc.failed()) {
        getLogger().LogError() << "Error initializing IP address: " << inet_rc.getErrorCode();
        return inet_rc.getErrorCode();
    }
    auto address = inet_rc.getPayload();

    // Create a server socket with the specified address and port.
    auto serverSocket_rc = socketFactory_rc.getPayload()->createServerSocket(address, SERVER_PORT, SERVER_PSK_ID, CONFIDENTIAL_WITHPSK);
    if (serverSocket_rc.failed()) {
        getLogger().LogError() << "Error creating server socket: " << serverSocket_rc.getErrorCode();
        return serverSocket_rc.getErrorCode();
    }

    getLogger().LogInfo() << "Waiting for client to connect";
    auto session_ep_rc = serverSocket_rc.getPayload()->accept(); // Wait for a client connection.
    if (session_ep_rc.failed()) {
        getLogger().LogError() << "Error accepting connection: " << session_ep_rc.getErrorCode();
        return session_ep_rc.getErrorCode();
    }
    getLogger().LogInfo() << "Received new connection from client";

    auto sessionEP = session_ep_rc.getPayload(); // Establish a session endpoint for communication.
    int messageCounter = 0; // Counter to make each message unique.

    while (g_running) {
        std::string message = "Hello, Client! " + std::to_string(++messageCounter); // Construct a unique message.
        getLogger().LogInfo() << "Sending: " << message;
        sessionEP->send(reinterpret_cast<const Byte*>(message.c_str()), message.size() + 1); // Send the message.

        uint8_t buffer[BUFFER_SIZE] = {0};
        auto receivedLen = sessionEP->receive(buffer, sizeof(buffer)); // Receive response.
        if (receivedLen < 0) {
            getLogger().LogError() << "Error receiving data from session";
            break; // Exit on error.
        }
        getLogger().LogInfo() << "Received: " << buffer;
        std::this_thread::sleep_for(std::chrono::seconds(1)); // Throttle messages for readability.
    }

    sessionEP->shutdown(); // Close the session properly.
    cleanupTLSLib(); // Cleanup TLS resources.
    getLogger().LogInfo() << "Server shutdown.";
    return 0;
}

int runClient() {
    getLogger().LogInfo() << "Client starting...";
    auto socketFactory_rc = initTLSLib(); // Initialize the TLS library.
    if (socketFactory_rc.failed()) {
        getLogger().LogError() << "Error initializing socket factory: " << socketFactory_rc.getErrorCode();
        return socketFactory_rc.getErrorCode();
    }

    // Create an IP address instance for the client to connect to.
    auto inet_rc = InetAddressFactory::makeIPAddress(SERVER_ADDRESS);
    if (inet_rc.failed()) {
        getLogger().LogError() << "Error initializing IP address: " << inet_rc.getErrorCode();
        return inet_rc.getErrorCode();
    }
    auto address = inet_rc.getPayload();

    // Create a client socket to connect to the server.
    auto clientSocket_rc = socketFactory_rc.getPayload()->createClientSocket(address, SERVER_PORT, CLIENT_PSK_ID, CONFIDENTIAL_WITHPSK);
    if (clientSocket_rc.failed()) {
        getLogger().LogError() << "Error creating client socket: " << clientSocket_rc.getErrorCode();
        return clientSocket_rc.getErrorCode();
    }

    // Attempt to connect to the server.
    auto session_ep_rc = clientSocket_rc.getPayload()->connect();
    if (session_ep_rc.failed()) {
        getLogger().LogError() << "Error connecting to server: " << session_ep_rc.getErrorCode();
        return session_ep_rc.getErrorCode();
    }
    getLogger().LogInfo() << "Connected to server";

    auto sessionEP = session_ep_rc.getPayload(); // Establish a session endpoint for communication.
    int messageCounter = 0; // Counter to make each message unique.

    while (g_running) {
        uint8_t buffer[BUFFER_SIZE];
        auto actualLength = sessionEP->receive(buffer, sizeof(buffer)); // Receive a message from the server.
        if (actualLength < 0) {
            getLogger().LogError() << "Error receiving data from session";
            break; // Exit on error.
        }
        getLogger().LogInfo() << "Received: " << buffer;

        std::string response = "Hello, Server! " + std::to_string(++messageCounter); // Construct a unique response.
        getLogger().LogInfo() << "Sending: " << response;
        sessionEP->send(reinterpret_cast<const Byte*>(response.c_str()), response.size() + 1); // Send the response.

        std::this_thread::sleep_for(std::chrono::seconds(1)); // Throttle messages for readability.
    }

    sessionEP->shutdown(); // Close the session properly.
    cleanupTLSLib(); // Cleanup TLS resources.
    getLogger().LogInfo() << "Client shutdown.";
    return 0;
}
