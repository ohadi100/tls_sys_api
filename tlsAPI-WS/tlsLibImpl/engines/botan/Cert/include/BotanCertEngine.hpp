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

#ifndef SACCESSLIB_BOTANCERTENGINE_HPP
#define SACCESSLIB_BOTANCERTENGINE_HPP

#include <botan/tls_client.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>

#include <functional>
#include <string>
#include <vector>
#include <sstream>

#include "CipherSuitesDefenitions.h"
#include "TLSCertEngine.hpp"
#include "TLSTEEAPI.h"
#ifdef UNIT_TEST
#include "MockBotanChannel.hpp"
#endif

namespace vwg
{
namespace tls
{
using HashSha256 = std::vector<char>;

namespace impl
{
/**
 * \class BotanCertEngine
 *
 * \brief The BotanCertEngine is the Botan implementation of TLSCertEngine.
 */
class BotanCertEngine : public TLSCertEngine
{
public:
    using OcspRequestsCertsTuple = std::tuple<const TLSOcspRequest,
                                              const std::shared_ptr<const Botan::X509_Certificate>,
                                              const std::shared_ptr<const Botan::X509_Certificate>>;

public:
    /**
     * \brief Constructor.
     *
     * \param[in] stream the underlying IOStreamIf used by the engine to perform actual input/output.
     * \param[in] hostName host name.
     * \param[in] certStoreId server root certificate ID.
     * \param[in] clientCertificateSetID client certificate and key pair ID
     * \param[in] httpPublicKeyPinningHashs in case it is not empty, then supports the HTTP Public Key pinning according to
     * RFC 7469 (see https://tools.ietf.org/html/rfc7469 for the RFC and
     * https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning for more details). Basically this means that at least one
     * pin value must match any certificate in the full certificate chain.
     * This check can be omitted, by using an empty vector for this parameter.
     * \param[in] revocationCheckEnabled this is optional if set OCSP will be used.
     * \param[in] cipherSuiteIds A vector containing the list of supported cipher suites (ciphers defined in TLS- QLAH).
     * If vector is empty , \param cipherSuiteSettings cipher set will be used.
     * If vector contains only invalid options, CSUSDefault cipher set will be used.
     * \param[in] cipherSuiteSettings set of cipher suite used in case that \param cipherSuiteIds is empty.
     * \param[in] alpnMode Alpn mode.
     * \param[in] checkTime do the time check in addition to the certificate validity check. This check will verify
     * if the certificate check time. This check can be omitted, by using null for this parameter.
     * \param[in] ocspHandler OCSP handler.
     * \param[in] ocspTimeoutMs OCSP timeout in milliseconds.
     */

    BotanCertEngine(std::shared_ptr<IOStreamIf>               stream,
                    const std::string&                        hostName,
                    std::string                               certStoreId,
                    std::string                               clientCertificateSetID,
                    const std::vector<HashSha256>&            httpPublicKeyPinningHashs,
                    const bool                                revocationCheckEnabled,
                    const CipherSuiteIds&                     cipherSuiteIds,
                    const TLSCipherSuiteUseCasesSettings&     cipherSuiteSettings,
                    const AlpnMode&                           alpnMode,
                    const TimeCheckTime&                      checkTime,
                    std::shared_ptr<ITLSOcspHandler>&         ocspHandler,
                    const uint32_t                            ocspTimeoutMs);

    /**
     * \brief Destructor. Calls BotanEngine::Close().
     */
    virtual ~BotanCertEngine();

public:
    /**
     * \brief Performs the TLS handshake, according to the arguments provided in
     * the constructor. Also initializes some Botan memory constructs.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError DoSSLHandshake() override;

    /**
     * \brief Sends a buffer to the other side.
     *
     * \param[in] data - an unencrypted buffer of size 'length', which will be
     * encrypted and sent through the underlying (inheriting) TLS engine. This
     * argument must be pre-allocated (either statically or dynamically) by the callee.
     * \param[in] bufLength length of unencrypted buffer.
     * \param[out] actualLength length of unencrypted buffer actually sent.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Send(const uint8_t* data, int32_t bufLength, int32_t& actualLength) override;

    /**
     * \brief Receives a buffer from the other side.
     *
     * \param[in] buffer buffer of size 'bufLength' to receive the data.
     * 'buffer' should be pre-allocated (either statically or dynamically) by the callee.
     * \param[in] bufLength length of buffer.
     * \param[out] actualLength length of unencrypted buffer actually read.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) override;

    /**
     * \brief Shutdown the underlying TLS connection.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Shutdown() override;

    /**
     * \brief Close the underlying TLS connection and release any resources that
     * are used by Botan.
     */
    virtual void Close() override;

    const string
    GetRemoteHintName() const override
    {
        return {};
    }

    const string
    GetHintName() const override
    {
        return {};
    }

    virtual void
    SetReceivedAlert(Botan::TLS::Alert::Type type)
    {
        m_receivedAlert = type;
    }

    virtual const AlpnMode& getUsedAlpnMode() const override;
    virtual IANAProtocol    getUsedProtocol() const override;

    const string
    GetCertStoreId()
    {
        return m_certStoreId;
    }
    const string
    GetClientCertificate()
    {
        return m_clientCertificateSetID;
    }

    bool CheckOcspOnline(const Botan::Path_Validation_Result&                             pathValidationResult,
                         const std::vector<Botan::Certificate_Store*>&                    trustedRoots,
                         const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp) const;

    std::vector<uint8_t>                      m_plaintext;
    std::unique_ptr<Botan::Private_Key>       m_privateKey;
    std::unique_ptr<Botan::Certificate_Store> m_privateStore;
    const std::vector<HashSha256>             m_httpPublicKeyPinningHashes;
#ifndef UNIT_TEST
protected:
#endif
    void setCipherSuitesListUseCase(TLSCipherSuiteUseCasesSettings const& cipherSuiteSettings);
    void filteredCiphers(CipherSuiteIds const& cipherSuiteIds);

    /**
     * \brief Error status according to the provided alert type.
     *
     * \param[in] type The TLS alerts that want to Alert.
     *
     * \return error status according to the provided alert type.
     */
    static TLSEngineError AlertToEngineError(Botan::TLS::Alert::Type type);

    /**
     * \brief Receives data from the stream up to specific length.
     *
     * \param[in] len up to the max length of the expected received stream.
     *
     * \return RC_TLS_ENGINE_SUCCESSFUL on successful, error status of feed otherwise.
     */
    TLSEngineError feed(size_t len);

    /**
     * \brief Receives data from the stream up to the max size (size of the internal buffer).
     *
     * \return RC_TLS_ENGINE_SUCCESSFUL on successful, error status of feed otherwise.
     */
    TLSEngineError feed();

    /**
     * \brief Checks the client and server certificates data.
     *
     * \return RC_TLS_ENGINE_SUCCESSFUL on successful, error status of unknown certifications otherwise.
     */
    TLSEngineError checkTeeAndItsData();

    bool getAlpnProtocol(vector<string>& alpn) const;

    bool createOcspRequests(const std::vector<std::shared_ptr<const Botan::X509_Certificate>>& certChain,
                            const Botan::CertificatePathStatusCodes&                           certChainStatusCodes,
                            std::vector<TLSOcspRequest>&                                       outTlsOcspRequests,
                            std::vector<OcspRequestsCertsTuple>& outOcspRequestsCertsTupleVector) const;

    bool verifyNCreateCachedResponses(const std::vector<OcspRequestsCertsTuple>&    ocspRequestsCertsTupleVector,
                                      const std::vector<TLSOcspRequestResponse>&    tlsOcspResponses,
                                      const std::vector<Botan::Certificate_Store*>& trustedRoots,
                                      std::vector<TLSOcspCachedResponse>&           outTlsOcspCachedResponses) const;


#ifdef UNIT_TEST
    std::unique_ptr<BotanClientUT> m_client;
#else
    std::unique_ptr<Botan::TLS::Client> m_client;
#endif
    uint8_t                                       m_buffer[0x1000];
    std::unique_ptr<Botan::Credentials_Manager>   m_creds_mgr;
    std::unique_ptr<Botan::RandomNumberGenerator> m_rng;
    std::unique_ptr<Botan::TLS::Callbacks>        m_callbacks;
    std::unique_ptr<Botan::TLS::Session_Manager>  m_session_mgr;

    const std::string                        m_hostName;
    const std::string                        m_certStoreId;
    const std::string                        m_clientCertificateSetID;
    std::vector<uint16_t>                    m_ciphersuiteCodes;
    Botan::TLS::Alert::Type                  m_receivedAlert;
    const AlpnMode                           m_alpnMode;
};

/**
 * \class strict_policy_with_ocsp_config
 *
 * \brief This class manages the policy with OCSP configuration for BotanCertEngine.
 */
class strict_policy_with_ocsp_config : public Botan::TLS::Strict_Policy
{
public:
    strict_policy_with_ocsp_config();

    void set_cert_status(bool cert_status_policy);

    /**
     * \brief This function returns all ciphers that the user has entered as input and
     * filtered as valid
     */
    std::vector<uint16_t> ciphersuite_list(Botan::TLS::Protocol_Version version, bool have_srp) const override;

    /**
     * \brief This function set the ciphers list
     */
    void set_ciphersuite_list(const std::vector<uint16_t>& cipherSuiteIds);

#ifndef UNIT_TEST
private:
#endif

    bool                  m_cert_status_policy = false;
    std::vector<uint16_t> ciphersuite_codes;

    bool support_cert_status_message() const;
};

/**
 * \class CallbacksCert
 *
 * \brief This class manages the callbacks for BotanCertEngine class.
 */
class CallbacksCert : public Botan::TLS::Callbacks
{
public:
    explicit CallbacksCert(BotanCertEngine* engine)
      : Botan::TLS::Callbacks()
      , m_engine(engine)
    {
    }

    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>&                      cert_chain,
                               const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp,
                               const std::vector<Botan::Certificate_Store*>&                    trusted_roots,
                               Botan::Usage_Type                                                usage,
                               const std::string&                                               hostname,
                               const Botan::TLS::Policy&                                        policy) override;

    void tls_emit_data(const uint8_t buf[], size_t length) override;

    void tls_record_received(uint64_t rec, const uint8_t data[], size_t len) override;

    void tls_alert(Botan::TLS::Alert alert) override;

    bool tls_session_established(const Botan::TLS::Session&) override;

#ifndef UNIT_TEST
private:
#endif

    virtual std::vector<char> calculate_public_key_hash(std::vector<uint8_t> buf);

    BotanCertEngine* m_engine;
};

/**
 * \class ClientCredsManager
 *
 * \brief This class manages the certificates and keys for BotanCertEngine class.
 */
class ClientCredsManager : public Botan::Credentials_Manager
{
public:
    explicit ClientCredsManager(BotanCertEngine* engine);
    virtual ~ClientCredsManager();

    std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type,
                                                                           const std::string& context) override;

    std::vector<Botan::X509_Certificate> cert_chain(const std::vector<std::string>& cert_key_types,
                                                    const std::string&              type,
                                                    const std::string&              context) override;

    Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
                                        const std::string&             type,
                                        const std::string&             context) override;
#ifndef UNIT_TEST
private:
#endif
    BotanCertEngine*                     m_engine;
    std::shared_ptr<vwg::tee::TLSTEEAPI> m_tlsTeeApi;
};

}  // namespace impl
}  // namespace tls
}  // namespace vwg

#endif  // SACCESSLIB_BOTANCERTENGINE_HPP