/**
 * @file BotanCertEngine.hpp
 * 
 * @brief Defines the BotanCertEngine class, which is a Botan library implementation of TLSCertEngine.
 * 
 * This class provides TLS operations using Botan, supporting advanced features such as HTTP Public Key Pinning (HPKP),
 * Online Certificate Status Protocol (OCSP) validation, and configurable cipher suites. It's designed for use
 * with both client and server TLS applications.
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

#ifndef SACCESSLIB_BOTANCERTENGINE_HPP
#define SACCESSLIB_BOTANCERTENGINE_HPP

#include <functional>
#include <string>
#include <vector>
#include <sstream>
#include <botan/tls_client.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>
#include "CipherSuitesDefenitions.h"
#include "TLSCertEngine.hpp"
#include "TLSTEEAPI.h"
#ifdef UNIT_TEST
#include "MockBotanChannel.hpp"
#endif

namespace vwg {
namespace tls {
namespace impl {

/**
 * @class BotanCertEngine
 * @brief Implementation of TLSCertEngine using the Botan cryptography library.
 *
 * This class integrates the Botan library to provide TLS functionalities such as
 * creating secure connections, handling certifications, and performing network data encryption
 * and decryption in compliance with TLS protocols.
 */
class BotanCertEngine : public TLSCertEngine {
public:
    /**
     * @brief Constructs a BotanCertEngine with configuration for TLS operations.
     * 
     * @param stream Underlying IO stream for network communication.
     * @param hostName Hostname for the TLS connection.
     * @param certStoreId Identifier for the certificate store.
     * @param clientCertificateSetID ID for the client certificate set.
     * @param httpPublicKeyPinningHashs List of public key pinning hashes.
     * @param revocationCheckEnabled Flag to enable OCSP.
     * @param cipherSuiteIds List of cipher suites.
     * @param cipherSuiteSettings Settings for cipher suites.
     * @param alpnMode Application-Layer Protocol Negotiation mode.
     * @param checkTime Time check settings for certificate validation.
     * @param ocspHandler Handler for OCSP operations.
     * @param ocspTimeoutMs Timeout in milliseconds for OCSP operations.
     */
    BotanCertEngine(std::shared_ptr<IOStreamIf> stream,
                    const std::string& hostName,
                    std::string certStoreId,
                    std::string clientCertificateSetID,
                    const std::vector<HashSha256>& httpPublicKeyPinningHashs,
                    bool revocationCheckEnabled,
                    const CipherSuiteIds& cipherSuiteIds,
                    const TLSCipherSuiteUseCasesSettings& cipherSuiteSettings,
                    const AlpnMode& alpnMode,
                    const TimeCheckTime& checkTime,
                    std::shared_ptr<ITLSOcspHandler> ocspHandler,
                    uint32_t ocspTimeoutMs);

    /**
     * @brief Destructor that cleans up Botan-related resources.
     */
    virtual ~BotanCertEngine();

    /**
     * @brief Performs the TLS handshake using the configured settings.
     * @return TLSEngineError status of the handshake operation.
     */
    virtual TLSEngineError DoSSLHandshake() override;

    /**
     * @brief Sends encrypted data over the TLS connection.
     * @param data Pointer to the data to send.
     * @param bufLength Length of the data buffer.
     * @param actualLength Length of the data actually sent.
     * @return TLSEngineError status of the send operation.
     */
    virtual TLSEngineError Send(const uint8_t* data, int32_t bufLength, int32_t& actualLength) override;

    /**
     * @brief Receives encrypted data from the TLS connection.
     * @param buffer Buffer to receive the data.
     * @param bufLength Length of the buffer.
     * @param actualLength Length of the data actually received.
     * @return TLSEngineError status of the receive operation.
     */
    virtual TLSEngineError Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) override;

    /**
     * @brief Shuts down the TLS connection cleanly.
     * @return TLSEngineError status of the shutdown operation.
     */
    virtual TLSEngineError Shutdown() override;

    /**
     * @brief Closes the TLS connection and releases all associated resources.
     */
    virtual void Close() override;

    /**
     * @brief Retrieves the supported ALPN protocol mode.
     * @return AlpnMode currently configured.
     */
    virtual const AlpnMode& getUsedAlpnMode() const override;

    /**
     * @brief Retrieves the protocol used based on IANA standards.
     * @return IANAProtocol indicating the protocol in use.
     */
    virtual IANAProtocol getUsedProtocol() const override;
    
    // Additional methods to handle internal Botan functionalities could be added here.

private:
    // Private members and helper functions to manage Botan internals and state.
};

} // namespace impl
} // namespace tls
} // namespace vwg

#endif // SACCESSLIB_BOTANCERTENGINE_HPP
