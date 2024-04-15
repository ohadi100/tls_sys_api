/**
 * @file WolfSSLPSKEngine.hpp
 * 
 * @brief Defines the WolfSSLPSKEngine class, an implementation of TLSEngine using WolfSSL with Pre-Shared Key support.
 * 
 * This class handles TLS operations using the WolfSSL library, specifically configured to use pre-shared keys for
 * encryption. This includes functionalities such as initiating and performing TLS handshakes, encrypting and decrypting data,
 * and handling session continuity with pre-shared keys.
 *
 * @version 1.0
 * @date 2023
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All information and materials herein, including intellectual and technical concepts,
 * are the property of CARIAD SE and protected by trade secrets, copyright, and patent laws.
 * Unauthorized use, modification, or distribution of this software or its components is strictly prohibited and
 * punishable by law.
 *
 * This file and the information contained within it are confidential and intended solely for the use of CARIAD SE.
 * Disclosure outside of CARIAD SE is not permitted without prior written consent.
 */

#ifndef SACCESSLIB_WOLFSSLPSKENGINE_HPP
#define SACCESSLIB_WOLFSSLPSKENGINE_HPP

#include <functional>
#include <string>
#include <vector>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "IOStreamIf.hpp"
#include "TLSEngine.hpp"

namespace vwg {
namespace tls {
namespace impl {

/**
 * @class WolfSSLPSKEngine
 * @brief The WolfSSLPSKEngine class implements TLSEngine specifically for using Pre-Shared Keys with WolfSSL.
 *
 * This class provides the necessary functionality to handle TLS communication using pre-shared keys,
 * including initiating connections, performing handshakes, and data transmission while ensuring encrypted communication.
 */
class WolfSSLPSKEngine : public TLSEngine {
public:
    /**
     * @brief Constructor to initialize a WolfSSL-based PSK TLS engine.
     * @param stream The IO stream interface for data transmission.
     * @param isServer Flag indicating if this engine acts as a server.
     * @param hint PSK identity hint to use.
     * @param confidentiality The security level for the connection.
     */
    WolfSSLPSKEngine(const std::shared_ptr<IOStreamIf>& stream, bool isServer, const std::string& hint, SecurityLevel confidentiality);

    /**
     * @brief Destructor that cleans up WolfSSL resources.
     */
    virtual ~WolfSSLPSKEngine();

    /**
     * @brief Performs the SSL/TLS handshake using PSK.
     * @return TLSEngineError indicating the result of the handshake process.
     */
    virtual TLSEngineError DoSSLHandshake() override;

    /**
     * @brief Sends data over the established TLS connection.
     * @param data Pointer to the data buffer to send.
     * @param bufLength Length of the data to send.
     * @param actualLength Length of the data actually sent.
     * @return TLSEngineError indicating the result of the send operation.
     */
    virtual TLSEngineError Send(const uint8_t* data, int32_t bufLength, int32_t& actualLength) override;

    /**
     * @brief Receives data from the established TLS connection.
     * @param buffer Buffer to receive the data.
     * @param bufLength Length of the buffer.
     * @param actualLength Length of the data actually received.
     * @return TLSEngineError indicating the result of the receive operation.
     */
    virtual TLSEngineError Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) override;

    /**
     * @brief Sets the blocking mode on the underlying connection.
     * @param blocking True to set blocking mode, false for non-blocking.
     * @return TLSEngineError indicating the result of the operation.
     */
    virtual TLSEngineError SetBlocking(bool blocking) override;

    /**
     * @brief Shuts down the TLS connection.
     * @return TLSEngineError indicating the result of the shutdown operation.
     */
    virtual TLSEngineError Shutdown() override;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * @brief Drops the TLS layer from the connection, leaving a plain text connection.
     * @return TLSEngineError indicating the result of the drop operation.
     */
    virtual TLSEngineError DropTLS() override;
#endif

    /**
     * @brief Retrieves the hint name used for the PSK.
     * @return The PSK hint name.
     */
    const std::string GetRemoteHintName() const override;

    /**
     * @brief Retrieves the local hint name.
     * @return The local PSK hint name.
     */
    const std::string GetHintName() const override;

    /**
     * @brief Closes the TLS connection and cleans up resources.
     */
    virtual void Close() override;

    /**
     * @brief Retrieves the configured ALPN mode.
     * @return The configured ALPN mode.
     */
    virtual const AlpnMode& getUsedAlpnMode() const override;

    /**
     * @brief Retrieves the IANA protocol used in the current connection.
     * @return The IANA protocol.
     */
    virtual IANAProtocol getUsedProtocol() const override;

#ifndef UNIT_TEST
private:
#endif
    TLSEngineError WolfSSLToEngineError();
    TLSEngineError ctxInit();

    /** m_ctx and m_ssl cannot be unique_ptr because wolfssl does not allow direct access to the internal structures
     * and it must have access to the pointer
     */
    std::shared_ptr<WOLFSSL_CTX> m_ctx;
    std::shared_ptr<WOLFSSL> m_ssl;

    pskData m_keys;
    bool m_isServer;
    SecurityLevel m_confidentiality;
    bool m_isDropped;
 };

} // namespace impl
} // namespace tls
} // namespace vwg

#endif //SACCESSLIB_WOLFSSLPSKENGINE_HPP
