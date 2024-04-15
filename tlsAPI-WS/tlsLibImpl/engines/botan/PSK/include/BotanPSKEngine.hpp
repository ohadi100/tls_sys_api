/**
 * @file BotanPSKEngine.hpp
 * 
 * @brief Provides an implementation of the `TLSEngine` interface using Botan for Pre-Shared Key (PSK) encryption.
 * 
 * This file defines the `BotanPSKEngine` class which facilitates TLS communication using Pre-Shared Keys (PSK)
 * with the Botan cryptographic library. It supports both client and server modes within secure communications,
 * emphasizing confidentiality and integrity using TLS standards.
 *
 * @version 1.0
 * @date 2023
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the license agreement which accompanies this distribution.
 */

#ifndef SACCESSLIB_BOTANPSKENGINE_HPP
#define SACCESSLIB_BOTANPSKENGINE_HPP

#include <functional>
#include <string>
#include <vector>
#include <botan/tls_client.h>
#include "TLSEngine.hpp"
#include "ITLSEngine.hpp"
#include "TLSTEEAPI.h"
#if defined(UNIT_TEST)
#include "MockBotanChannel.hpp"
#endif

using namespace std;

namespace vwg {
namespace tls {
namespace impl {

/**
 * @class BotanPSKEngine
 * @brief Botan implementation of `TLSEngine` for handling TLS connections with Pre-Shared Key (PSK) authentication.
 *
 * The `BotanPSKEngine` provides an interface to initialize, send, and receive data over a secure connection
 * established using PSK. It encapsulates the setup and management of a TLS session, leveraging the Botan library
 * for all cryptographic functions.
 */
class BotanPSKEngine : public TLSEngine {
public:
    /**
     * @brief Constructs a `BotanPSKEngine` with specific configurations.
     *
     * @param stream The underlying IO stream interface used for actual input/output operations.
     * @param isServer Specifies whether this engine acts as a server (true) or as a client (false).
     * @param hint A hint provided to the remote side during PSK negotiation.
     * @param confidentiality The confidentiality level required for the PSK connection.
     */
    BotanPSKEngine(std::shared_ptr<IOStreamIf> stream, bool isServer, const std::string &hint, SecurityLevel confidentiality);

    /**
     * @brief Destructor that cleans up resources.
     */
    virtual ~BotanPSKEngine();

    /**
     * @brief Performs the TLS handshake using PSK.
     *
     * Initializes the TLS session using predefined PSK settings and performs the handshake process to securely
     * establish the connection.
     * 
     * @return A `TLSEngineError` indicating the success or failure of the handshake.
     */
    virtual TLSEngineError DoSSLHandshake() override;

    /**
     * @brief Sends data securely over the established TLS connection.
     *
     * @param data Pointer to the data buffer to send.
     * @param bufLength The length of the data buffer.
     * @param actualLength The actual length of data successfully sent.
     * @return A `TLSEngineError` indicating the success or failure of the operation.
     */
    virtual TLSEngineError Send(const uint8_t *data, int32_t bufLength, int32_t &actualLength) override;

    /**
     * @brief Receives data securely from the established TLS connection.
     *
     * @param buffer Buffer to store the received data.
     * @param bufLength The size of the buffer provided.
     * @param actualLength The actual length of data successfully read.
     * @return A `TLSEngineError` indicating the success or failure of the operation.
     */
    virtual TLSEngineError Receive(uint8_t *buffer, int32_t bufLength, int32_t &actualLength) override;

    /**
     * @brief Shuts down the TLS connection gracefully.
     *
     * @return A `TLSEngineError` indicating the success or failure of the shutdown operation.
     */
    virtual TLSEngineError Shutdown() override;

    /**
     * @brief Closes the TLS connection and releases all associated resources.
     */
    virtual void Close() override;

    /**
     * @brief Gets the hint used during PSK negotiation.
     *
     * @return The PSK hint.
     */
    const string GetRemoteHintName() const override;

    /**
     * @brief Gets the PSK hint that this engine is configured to use.
     *
     * @return The PSK hint.
     */
    const string GetHintName() const override;

    /**
     * @brief Retrieves the supported ALPN protocol mode.
     *
     * @return The currently configured ALPN mode.
     */
    virtual const AlpnMode& getUsedAlpnMode() const override;

    /**
     * @brief Retrieves the protocol used based on IANA standards.
     *
     * @return The protocol currently in use as specified by IANA.
     */
    virtual IANAProtocol getUsedProtocol() const override;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * @brief Initiates the drop of the TLS connection, reducing it to a non-secure connection.
     *
     * @return A `TLSEngineError` indicating the success or failure of the operation.
     */
    virtual TLSEngineError DropTLS() override;
#endif

private:
    // Implementation-specific private members and helper functions.
};

} // namespace impl
} // namespace tls
} // namespace vwg

#endif // SACCESSLIB_BOTANPSKENGINE_HPP
