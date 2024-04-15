/**
 * @file WolfSSLCertEngine.hpp
 *
 * @brief Implements the TLSCertEngine interface using the WolfSSL library for secure TLS communications.
 *
 * This class manages the TLS operations including certificate validation, session negotiation,
 * data transmission, and secure communication functionalities using the WolfSSL library. It supports
 * features such as OCSP stapling, certificate pinning, and advanced cipher suite management.
 *
 * @version 1.0
 * @date 2023
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All rights reserved. Unauthorized reproduction, dissemination, or modification is strictly prohibited
 * and punishable by law. This source code and its related information are confidential and proprietary to CARIAD SE.
 */

#ifndef SACCESSLIB_WOLFSSLCERTENGINE_H
#define SACCESSLIB_WOLFSSLCERTENGINE_H

#include <wolfssl/options.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/ssl.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "CipherSuitesDefinitions.h"
#include "IOStreamIf.hpp"
#include "TLSCertEngine.hpp"
#include "TLSTEEAPI.h"

namespace vwg {
namespace tls {
using HashSha256 = std::vector<char>;

namespace impl {

/**
 * @class WolfSSLCertEngine
 * @brief Implements the TLSCertEngine using WolfSSL to handle secure TLS communications.
 *
 * This class provides full integration with WolfSSL functionalities including certificate verification,
 * session negotiation, data encryption/decryption, and handling advanced security features like OCSP
 * stapling and certificate pinning according to RFC 7469.
 */
class WolfSSLCertEngine : public TLSCertEngine {
public:
    /**
     * @brief Constructor to initialize a WolfSSLCertEngine with specific TLS configurations.
     *
     * @param stream The IO stream interface used for data transmission.
     * @param hostName The server's host name for SNI and certificate validations.
     * @param certStoreId Identifier for the certificate store containing trusted CA certificates.
     * @param clientCertificateSetID Identifier for the client certificate set for mutual TLS.
     * @param httpPublicKeyPinningHashs List of public key pinning hashes for enhanced security.
     * @param revocationCheckEnabled Flag to enable OCSP revocation checking.
     * @param cipherSuiteIds List of cipher suites to be used if specified.
     * @param cipherSuiteSettings Settings for cipher suites if no specific list is provided.
     * @param alpnMode Configured ALPN mode for protocol negotiation.
     * @param timeCheck Configuration for time-based checks in certificate validation.
     * @param ocspHandler Handler for managing OCSP requests and responses.
     * @param ocspTimeoutMs Timeout in milliseconds for OCSP response wait time.
     */
    WolfSSLCertEngine(std::shared_ptr<IOStreamIf> stream,
                      const std::string& hostName,
                      std::string certStoreId,
                      std::string clientCertificateSetID,
                      const std::vector<HashSha256>& httpPublicKeyPinningHashs,
                      bool revocationCheckEnabled,
                      const CipherSuiteIds& cipherSuiteIds,
                      const TLSCipherSuiteUseCasesSettings& cipherSuiteSettings,
                      const AlpnMode& alpnMode,
                      const TimeCheckTime& timeCheck,
                      std::shared_ptr<ITLSOcspHandler>& ocspHandler,
                      uint32_t ocspTimeoutMs);

    /**
     * @brief Destructor to clean up resources and gracefully shut down the WolfSSL environment.
     */
    virtual ~WolfSSLCertEngine();

    /**
     * @brief Initiates and completes the TLS handshake process.
     *
     * @return TLSEngineError indicating the status of the handshake.
     */
    virtual TLSEngineError DoSSLHandshake() override;

    /**
     * @brief Sends encrypted data over the established TLS connection.
     *
     * @param data Pointer to the data buffer to send.
     * @param bufLength Length of the data buffer.
     * @param actualLength Actual length of the data sent.
     * @return TLSEngineError indicating success or type of failure.
     */
    virtual TLSEngineError Send(const uint8_t* data, int32_t bufLength, int32_t& actualLength) override;

    /**
     * @brief Receives decrypted data from the TLS connection.
     *
     * @param buffer Buffer to store the received data.
     * @param bufLength Maximum expected length of the data.
     * @param actualLength Actual length of the data received.
     * @return TLSEngineError indicating success or type of failure.
     */
    virtual TLSEngineError Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) override;

    /**
     * @brief Sets the blocking mode for the underlying IO operations.
     *
     * @param blocking True for blocking mode, false for non-blocking.
     * @return TLSEngineError reflecting the outcome of the operation.
     */
    virtual TLSEngineError SetBlocking(bool blocking) override;

    /**
     * @brief Shuts down the TLS connection.
     *
     * @return TLSEngineError indicating success or the type of failure encountered.
     */
    virtual TLSEngineError Shutdown() override;

    /**
     * @brief Closes the TLS connection and releases all associated resources.
     */
    virtual void Close() override;

    /**
     * @brief Retrieves the ALPN mode used in the current TLS connection.
     *
     * @return The configured ALPN mode.
     */
    virtual const AlpnMode& getUsedAlpnMode() const override;

    /**
     * @brief Retrieves the IANA protocol used in the current TLS connection.
     *
     * @return The IANA protocol used.
     */
    virtual IANAProtocol getUsedProtocol() const override;

private:
    // Helper methods and member variables for internal use
    void handleOcspCaching(bool remove);
    void setCipherSuitesListUseCase(const TLSCipherSuiteUseCasesSettings& cipherSuiteSettings);
    void filteredCiphers(const CipherSuiteIds& cipherSuiteIds);
    bool getAlpnProtocol(std::string& alpn) const;
    bool calculatePublicKeyPinHash(const std::vector<unsigned char>& SubjectPublicKeyInfo, std::vector<char>& certHashKey) const;
    TLSEngineError calculateCertificatesChainPinningHashes(std::vector<HashSha256>& pinningHashesVec);

    std::shared_ptr<WOLFSSL_CTX> m_ctx;
    std::shared_ptr<WOLFSSL> m_ssl;

    const std::string m_hostName;
    const std::string m_certStoreId;
    const std::string m_clientCertificateSetID;
    std::atomic<bool> m_sslInit;
    const std::vector<HashSha256> m_httpPublicKeyPinningHashes;
    std::string m_validCiphers;
    const AlpnMode m_alpnMode;
    std::vector<TLSOcspRequestResponse> m_ocspRequestsResponses;

    static const uint32_t EX_DATA_IDX_WOLFSSL_CERT_ENGINE_OBJ = 0;
    static const size_t MAX_X509_SIZE = 2048;
    static const uint32_t BASE64_SHA256_SIZE = 44;
};

}  // namespace impl
}  // namespace tls
}  // namespace vwg

#endif  // SACCESSLIB_WOLFSSLCERTENGINE_H
