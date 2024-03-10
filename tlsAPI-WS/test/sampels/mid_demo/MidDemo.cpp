
#include <cstdint>
#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>
#include <thread>
#include <cstring>
#include <string>

#include <ara/core/initialization.h>
#include <ara/log/logging.h>
#include <ara/exec/application_client.h>

#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "Globals.hpp"
#include "TLSResult.h"
#include "InetAddress.h"
#include "TLSSockets.h"

using vwg::tls::TLSResult;
using vwg::tls::InetAddressFactory;
using vwg::tls::IInetAddressResult;
using vwg::tls::SPIInetAddress;
using vwg::tls::ITLSSocketFactory;
using vwg::tls::TLSServerSocketResult;
using vwg::tls::ITLSSessionEndpoint;
using vwg::tls::initTLSLib;
using vwg::tls::cleanupTLSLib;

std::atomic<bool> g_running(true);

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_running.store(false);
    }
}

class AraCoreScopedInitializer {
public:
    AraCoreScopedInitializer() {
        auto init_result = ara::core::Initialize();
        if (!init_result) {
            std::cerr << "ARA Core initialization failed: " << init_result.Error().Message() << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }
    
    ~AraCoreScopedInitializer() {
        auto deinit_result = ara::core::Deinitialize();
        if (!deinit_result) {
            std::cerr << "ARA Core deinitialization failed: " << deinit_result.Error().Message() << std::endl;
        }
    }
};

void runServer() {
    ara::log::getLogger()& getLogger() = ara::log::CreategetLogger()("TLSServer", "Main", ara::log::LogLevel::kInfo);
    getLogger().LogInfo() << "Server mode activated.";
    TLSResult<std::shared_ptr<ITLSSocketFactory>> socketFactoryResult = initTLSLib();
    if (socketFactoryResult.failed()) {
        getLogger().LogError() << "Failed to initialize TLS library: " << socketFactoryResult.getErrorCode();
        return;
    }

    auto socketFactory = socketFactoryResult.getPayload();
    IInetAddressResult inetAddressResult = InetAddressFactory::makeIPAddress("127.0.0.1");
    if (inetAddressResult.failed()) {
        getLogger().LogError() << "Failed to create IP address: " << inetAddressResult.getErrorCode();
        return;
    }

    auto address = inetAddressResult.getPayload();
    TLSServerSocketResult serverSocketResult = socketFactory->createServerSocket(address, 1337, "1001", CONFIDENTIAL_WITHPSK);
    if (serverSocketResult.failed()) {
        getLogger().LogError() << "Failed to create server socket: " << serverSocketResult.getErrorCode();
        return;
    }

    getLogger().LogInfo() << "Waiting for client to connect.";
    while (g_running.load()) {
        TLSResult<std::shared_ptr<ITLSSessionEndpoint>> sessionEndpointResult = serverSocketResult.getPayload()->accept();
        if (sessionEndpointResult.failed()) {
            getLogger().LogError() << "Error accepting connection: " << sessionEndpointResult.getErrorCode();
            continue;
        }

        auto sessionEndpoint = sessionEndpointResult.getPayload();
        getLogger().LogInfo() << "Received new connection from client.";

        const char* message = "Hello, Client!";
        sessionEndpoint->send(reinterpret_cast<const uint8_t*>(message), std::strlen(message) + 1);
        getLogger().LogInfo() << "Message sent to client.";

        uint8_t buffer[1024] = {0};
        int32_t receivedLength = sessionEndpoint->receive(buffer, sizeof(buffer));
        if (receivedLength > 0) {
            std::string receivedMessage(reinterpret_cast<char*>(buffer), receivedLength);
            getLogger().LogInfo() << "Message received from client: " << receivedMessage;
        } else {
            getLogger().LogError() << "Failed to receive data from client.";
        }

        sessionEndpoint->shutdown();
        getLogger().LogInfo() << "Session with client ended.";
    }

    cleanupTLSLib();
    getLogger().LogInfo() << "TLS resources cleaned up and server shutting down.";
}

void runClient() {
    ara::log::getLogger()& getLogger() = ara::log::CreategetLogger()("TLSClient", "Main", ara::log::LogLevel::kInfo);
    getLogger().LogInfo() << "Client mode activated.";
    TLSResult<std::shared_ptr<ITLSSocketFactory>> socketFactoryResult = initTLSLib();
    if (socketFactoryResult.failed()) {
        getLogger().LogError() << "Failed to initialize TLS library: " << socketFactoryResult.getErrorCode();
        return;
    }

    auto socketFactory = socketFactoryResult.getPayload();
    IInetAddressResult inetAddressResult = InetAddressFactory::makeIPAddress("127.0.0.1");
    if (inetAddressResult.failed()) {
        getLogger().LogError() << "Failed to create

 IP address: " << inetAddressResult.getErrorCode();
        return;
    }

    auto address = inetAddressResult.getPayload();
    TLSClientSocketResult clientSocketResult = socketFactory->createClientSocket(address, 1337, "TLS_PSK", CONFIDENTIAL_WITHPSK);
    if (clientSocketResult.failed()) {
        getLogger().LogError() << "Failed to create client socket: " << clientSocketResult.getErrorCode();
        return;
    }

    auto clientSocket = clientSocketResult.getPayload();
    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> sessionEndpointResult = clientSocket->connect();
    if (sessionEndpointResult.failed()) {
        getLogger().LogError() << "Failed to connect: " << sessionEndpointResult.getErrorCode();
        return;
    }

    auto sessionEndpoint = sessionEndpointResult.getPayload();
    getLogger().LogInfo() << "Successfully connected to the server.";

    const char* message = "Hello, Server!";
    sessionEndpoint->send(reinterpret_cast<const uint8_t*>(message), std::strlen(message) + 1);
    getLogger().LogInfo() << "Sent message to the server.";

    uint8_t buffer[1024] = {0};
    int32_t receivedLength = sessionEndpoint->receive(buffer, sizeof(buffer));
    if (receivedLength > 0) {
        std::string receivedMessage(reinterpret_cast<char*>(buffer), receivedLength);
        getLogger().LogInfo() << "Received message from server: " << receivedMessage;
    } else {
        getLogger().LogError() << "Failed to receive data from server.";
    }

    sessionEndpoint->shutdown();
    getLogger().LogInfo() << "Disconnected from the server.";
    cleanupTLSLib();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " [server|client]" << std::endl;
        return 1;
    }

    std::string mode(argv[1]);
    AraCoreScopedInitializer araInit{};
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    ara::exec::ApplicationClient appClient();
    appClient.ReportApplicationState(ara::exec::ApplicationState::kRunning);

    if (mode == "server") {
        runServer();
    } else if (mode == "client") {
        runClient();
    } else {
        std::cerr << "Invalid mode specified. Use 'server' or 'client'." << std::endl;
        return 1;
    }

    appClient.ReportApplicationState(ara::exec::ApplicationState::kTerminating);
    return 0;
}
