/**
 *
 * \copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 *
 * All the information and materials contained herein, including the
 * intellectual and technical concepts, are the property of CARIAD SE and may
 * be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * The copyright notice above does not evidence any actual or intended
 * publication or disclosure of this source code, which includes information
 * and materials that are confidential and/or proprietary and trade secrets of
 * CARIAD SE.
 *
 * Any reproduction, dissemination, modification, distribution, public
 * performance, public display of or any other use of this source code and/or
 * any other information and/or material contained herein without the prior
 * written consent of CARIAD SE is strictly prohibited and in violation of
 * applicable laws.
 *
 * The receipt or possession of this source code and/or related information
 * does not convey or imply any rights to reproduce, disclose or distribute
 * its contents or to manufacture, use or sell anything that it may describe
 * in whole or in part.
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

#include "CipherSuitesDefenitions.h"
#include "IOStreamIf.hpp"
#include "TLSCertEngine.hpp"
#include "TLSTEEAPI.h"

namespace vwg
{
namespace tls
{
using HashSha256 = std::vector<char>;

namespace impl
{
/**
 * \class WolfSSLEngine
 *
 * \brief The WolfSSLEngine is the WolfSSL implementation of TLSCertEngine.
 */
class WolfSSLCertEngine : public TLSCertEngine
{
public:
    /**
     * \brief Constructor.
     *
     * \param[in] stream the underlying IOStream used by the engine to perform actual input/output.
     * \param[in] hostName host name.
     * \param[in] certStoreId server root certificate ID.
     * \param[in] clientCertificateSetID client certificate and key pair ID.
     * \param[in] httpPublicKeyPinningHashs  in case it is not empty, then supports the HTTP Public Key pinning according to
     * RFC 7469 (see https://tools.ietf.org/html/rfc7469 for the RFC and
     * https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning for more details). Basically this means that at least one
     * pin value must match any certificate in the full certificate chain.
     * This check can be omitted, by using an empty vector for this parameter.
     * \param[in] revocationCheckEnabled this is optional if set OCSP will be used.
     * \param[in] cipherSuiteIds A vector containing the list of supported cipher suites (ciphers defined in TLS- QLAH).
     * If the vector is empty , \param cipherSuiteSettings cipher set will be used.
     * If the vector contains only invalid options, CSUSDefault cipher set will be used.
     * \param[in] cipherSuiteSettings set of cipher suite used in case that \param cipherSuiteIds is empty.
     * \param[in] alpnMode Alpn mode.
     * \param[in] timeCheck  do the time check in addition to the certificate validity check. This check will verify
     * if the certificate check time. This check can be omitted, by using null for this parameter.
     * \param[in] ocspHandler ocspHandler OCSP handler.
     * \param[in] ocspTimeoutMs OCSP timeout in milliseconds.
     */
    WolfSSLCertEngine(std::shared_ptr<IOStreamIf>           stream,
                      const std::string&                    hostName,
                      std::string                           certStoreId,
                      std::string                           clientCertificateSetID,
                      const std::vector<HashSha256>&        httpPublicKeyPinningHashs,
                      bool                                  revocationCheckEnabled,
                      const CipherSuiteIds&                 cipherSuiteIds,
                      const TLSCipherSuiteUseCasesSettings& cipherSuiteSettings,
                      const AlpnMode&                       alpnMode,
                      const TimeCheckTime&                  timeCheck,
                      std::shared_ptr<ITLSOcspHandler>&     ocspHandler,
                      const uint32_t                        ocspTimeoutMs);

    /**
     * \brief Destructor. Calls WolfSSLEngine::Close().
     */
    virtual ~WolfSSLCertEngine();

    /**
     * \brief Performs the TLS handshake, according to the arguments provided in the constructor. Also
     * initializes some WolfSSL memory constructs.
     */
    virtual TLSEngineError DoSSLHandshake() override;

    /**
     * \brief Sends a buffer to the other side.
     *
     * \param[in] buffer an unencrypted buffer of size 'length', which will be encrypted and sent through the
     * underlying (inheriting) TLS engine. This argument must be pre-allocated (either statically or
     * dynamically) by the callee.
     * \param[in] bufLength length of unencrypted buffer.
     * \param[out] actualLength length of unencrypted buffer actually sent.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Send(const uint8_t* data, int32_t bufLength, int32_t& actualLength) override;

    /**
     * \brief Receives a buffer from the other side.
     * \param[in] buffer a buffer of size 'bufLength' to receive the data. 'buffer' should be pre-allocated (either
     * statically or dynamically) by the callee.
     * \param[in] bufLength length of buffer.
     * \param[out] actualLength length of unencrypted buffer actually read.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) override;

    virtual TLSEngineError SetBlocking(bool blocking) override;

    virtual TLSEngineError Shutdown() override;

    const std::string GetRemoteHintName() const override;

    const std::string GetHintName() const override;

    /**
     * \brief   Close the underlying TLS connection and release any resources that are used by WolfSSL.
     */
    virtual void Close() override;

    virtual const AlpnMode& getUsedAlpnMode() const override;

    virtual IANAProtocol getUsedProtocol() const override;

    /**
     * \brief validate hash pinning server's certificate chain follows https://datatracker.ietf.org/doc/html/rfc7469
     * (only in case that hash pinning is required).
     *
     * \note It checks that every hash pinning in m_httpPublicKeyPinningHashs member matches to any certificate's
     *  hash pinning in the server's certificate chain.
     *
     * \return RC_TLS_ENGINE_SUCCESSFUL if m_httpPublicKeyPinningHashs is valid, otherwise returns an error code.
     */
    TLSEngineError validateHashPinning();

    /**
     * \brief This method called by wolfssl's verifyCb method aka "verifyCallback" for further handling.
     *
     * \param[in] x509StorePtr Session's X509 certificate store context.
     *
     * \param[in] bool if there was failure and we just want to remove from cache
     *
     * \return true if successfully done handling otherwise False
     */
    bool postVerificationHandler(const WOLFSSL_X509_STORE_CTX* x509StorePtr, bool isFailure = false);

    /**
     * \brief Sets OCSP request-response vector for further handling.
     *
     * \param[in] ocspRequestsResponses Vector of OCSP request-response objects
     */
    void setOcspRequestResponseVector(const std::vector<TLSOcspRequestResponse>& ocspRequestsResponses);

    /**
     * \brief This callback called immediately after certificate verification by Wolfssl.
     *
     * \param[in] preverify parameter that indicates if certificate verification was successfully verified or not.
     * \param[in] x509StorePtr Session's X509 certificate store context.
     *
     * \return  WOLF_SUCCESS if successfully executed otherwise WOLF_FAILURE.
     */
    static int verifyCallback(int preverify, WOLFSSL_X509_STORE_CTX* x509StorePtr);

#ifndef UNIT_TEST
private:
#endif
    /**
     * \brief Checks that the response is valid and updates the cache if necessary.
     *
     * \param[in] true if there was a failure in verification, otherwise false.
     *
     * \return true if tha cache was updated, otherwise false.
     */
    bool handleOcspCaching(bool remove = false);

    void setCipherSuitesListUseCase(TLSCipherSuiteUseCasesSettings const& cipherSuiteSettings);
    void filteredCiphers(CipherSuiteIds const& cipherSuiteIds);
    bool getAlpnProtocol(std::string& alpn) const;

    /**
     * \brief Calculates public key hash pinning follows https://datatracker.ietf.org/doc/html/rfc7469,
     * basically is the calculation Base64(SHA256(SubjectPublicKeyInfo)).
     *
     * \param[in] SubjectPublicKeyInfo contains certificate's SubjectPublicKeyInfo .
     * \param[out] certHashKey out parameter that should contain the hash pinning value if calculated successfully.
     *
     * \return true if calculated successfully, otherwise false.
     */
    bool calculatePublicKeyPinHash(std::vector<unsigned char> const& SubjectPublicKeyInfo,
                                   std::vector<char>&                certHashKey) const;

    /**
     * \brief Calculates server's certificates hash pinning follows https://datatracker.ietf.org/doc/html/rfc7469,
     * basically is the calculation Base64(SHA256(SubjectPublicKeyInfo)).
     *
     * \param[out] pinningHashesVec contains servers certificates pinning hashes if calculated successfully.
     *
     * \return  RC_TLS_ENGINE_SUCCESSFUL if calculated successfully, otherwise an error code.
     */
    TLSEngineError calculateCertificatesChainPinningHashes(std::vector<HashSha256>& pinningHashesVec);

    TLSEngineError ctxInit();
    TLSEngineError sslInit();
    TLSEngineError ocspInit();
    TLSEngineError wolfsslConnect();
    TLSEngineError WolfSSLToEngineError();
    TLSEngineError teeInit();

    std::shared_ptr<WOLFSSL_CTX> m_ctx;
    std::shared_ptr<WOLFSSL>     m_ssl;

    const std::string                   m_hostName;
    const std::string                   m_certStoreId;
    const std::string                   m_clientCertificateSetID;
    std::atomic<bool>                   m_sslInit;
    const std::vector<HashSha256>       m_httpPublicKeyPinningHashes;
    std::string                         m_validCiphers;
    const AlpnMode                      m_alpnMode;
    std::vector<TLSOcspRequestResponse> m_ocspRequestsResponses;

    static const uint32_t EX_DATA_IDX_WOLFSSL_CERT_ENGINE_OBJ = 0;
    static const size_t   MAX_X509_SIZE                       = 2048;

    /**
     * \brief Contains the size of the calculation Base64(SHA256(x)) in bytes.
     * SHA256 output size is 32 bytes, so Base64 of 32 bytes is 44 bytes,
     * because Base64 output is 4*ceiling(n/3) when n is Base64 input size.
     */
    static const uint32_t BASE64_SHA256_SIZE = 44;
};

}  // namespace impl
}  // namespace tls
}  // namespace vwg

#endif  // SACCESSLIB_WOLFSSLCERTENGINE_HPP