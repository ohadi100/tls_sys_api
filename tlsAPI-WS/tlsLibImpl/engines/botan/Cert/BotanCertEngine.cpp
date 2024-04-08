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

#include "BotanCertEngine.hpp"

#include <TLSReturnCodes.h>
#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/ber_dec.h>
#include <botan/cert_status.h>
#include <botan/data_src.h>
#include <botan/exceptn.h>
#include <botan/ocsp.h>
#include <botan/ocsp_types.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/sha2_32.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/x509path.h>
#include <sys/socket.h>

#include <cstdint>
#include <functional>
#include <list>
#include <vector>
#include <sstream>

#include "Logger.hpp"

#include "ITLSEngine.hpp"

#include "engineCommon.hpp"

using namespace Botan;
using vwg::tls::impl::BotanCertEngine;
using vwg::tls::impl::CallbacksCert;
using vwg::tls::impl::ClientCredsManager;
using vwg::tls::impl::strict_policy_with_ocsp_config;
using vwg::tls::impl::TLSEngine;
using vwg::tls::impl::TLSEngineError;
using namespace vwg::tls;

class BotanEngineError : public std::runtime_error
{
public:
    explicit BotanEngineError(const std::string& s)
      : std::runtime_error(s)
    {
    }
};

ClientCredsManager::ClientCredsManager(BotanCertEngine* engine)
  : m_engine(engine)
  , m_tlsTeeApi(vwg::tee::TLSTEEAPI::get_instance())
{
}

ClientCredsManager::~ClientCredsManager()
{
    if (nullptr != m_tlsTeeApi) {
        m_tlsTeeApi.reset();
    }
}

std::vector<Botan::Certificate_Store*>
ClientCredsManager::trusted_certificate_authorities(const std::string& type, const std::string& context)
{
    (void)type;
    (void)context;

    std::vector<Botan::Certificate_Store*> tempVector;
    string                                 serverCert = m_tlsTeeApi->get_root_cert_bundle(m_engine->GetCertStoreId());

    if (!m_engine->m_privateStore) {
        if (!serverCert.empty()) {
            try {
                std::vector<uint8_t>    vec(serverCert.begin(), serverCert.end());
                Botan::X509_Certificate cert(vec);
                m_engine->m_privateStore = std::make_unique<Botan::Certificate_Store_In_Memory>(cert);
            } catch (exception& e) {
                FND_LOG_ERROR << e.what();
            }
        }
    }

    if (m_engine->m_privateStore) {
        tempVector.push_back(m_engine->m_privateStore.get());
    }

    return tempVector;
}

std::vector<Botan::X509_Certificate>
ClientCredsManager::cert_chain(const std::vector<std::string>& cert_key_types,
                               const std::string&              type,
                               const std::string&              context)
{
    (void)cert_key_types;
    (void)type;
    (void)context;

    std::string clientCert = m_engine->GetClientCertificate();
    if (clientCert.empty()) {
        return {};
    }
    string clientCertificateStr = m_tlsTeeApi->get_client_cert(clientCert);

    std::vector<uint8_t> vec(clientCertificateStr.begin(), clientCertificateStr.end());

    try {
        Botan::X509_Certificate tempCert(vec);
        return {tempCert};
    } catch (exception& e) {
        FND_LOG_ERROR << e.what();
    }

    return {};
}

Botan::Private_Key*
ClientCredsManager::private_key_for(const Botan::X509_Certificate& cert,
                                    const std::string&             type,
                                    const std::string&             context)
{
    (void)cert;
    (void)type;
    (void)context;

    if (!m_engine->m_privateKey) {
        std::string clientCert = m_engine->GetClientCertificate();
        if (clientCert.empty()) {
            return {};
        }
        string clientPrivateKeyStr = m_tlsTeeApi->get_client_cert_private_key(clientCert);
        try {
            Botan::DataSource_Memory tempKey(clientPrivateKeyStr);
            m_engine->m_privateKey = Botan::PKCS8::load_key(tempKey);
        } catch (exception& e) {
            FND_LOG_ERROR << e.what();
        }
    }

    return m_engine->m_privateKey.get();
}

//--------------strict_policy_with_ocsp_config functions--------------

strict_policy_with_ocsp_config::strict_policy_with_ocsp_config()
{
    ciphersuite_codes.clear();
}

bool
strict_policy_with_ocsp_config::support_cert_status_message() const
{
    return m_cert_status_policy;
}

void
strict_policy_with_ocsp_config::set_cert_status(bool cert_status_policy)
{
    m_cert_status_policy = cert_status_policy;
}

/* This function returns all ciphers that the user has entered as input and
 * filtered as valid */
std::vector<uint16_t>
strict_policy_with_ocsp_config::ciphersuite_list(Botan::TLS::Protocol_Version version, bool have_srp) const
{
    (void)version;
    (void)have_srp;
    return ciphersuite_codes;
}

/* This function filters the ciphers that the user entered as input to a
 * vector */
void
strict_policy_with_ocsp_config::set_ciphersuite_list(const std::vector<uint16_t>& cipherSuiteIds)
{
    ciphersuite_codes = cipherSuiteIds;
}

//--------------CallbacksCert functions--------------

void
CallbacksCert::tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>&                      cert_chain,
                                     const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp,
                                     const std::vector<Botan::Certificate_Store*>&                    trusted_roots,
                                     Botan::Usage_Type                                                usage,
                                     const std::string&                                               hostname,
                                     const Botan::TLS::Policy&                                        policy)
{
    (void)policy;

    const size_t                              EXPECTED_NUM_OF_OCSP_RESPONSES = 1;
    const Botan::Path_Validation_Restrictions restrictions(false, 80);

    if (cert_chain.empty()) {
        throw std::invalid_argument("Certificate validation failure: Certificate chain was empty");
    }

    // Botan 2.8.0 supports only OCSP Stapling V1.
    // It means that we will have only 1 OCSP response stapled for sure - According to the RFC it's the EE certificate
    if (ocsp.size() > EXPECTED_NUM_OF_OCSP_RESPONSES) {
        throw std::invalid_argument("Certificate validation failure: invalid OCSP responses vector size");
    }

    if (trusted_roots.empty()) {
        throw Botan::Exception("Certificate validation failure: no Trusted roots found");
    }

    Botan::Path_Validation_Result result =
        x509_path_validate(cert_chain,
                           restrictions,
                           trusted_roots,
                           (usage == Botan::Usage_Type::TLS_SERVER_AUTH ? hostname : ""),
                           usage,
                           std::chrono::system_clock::now(),
                           std::chrono::milliseconds(0),
                           ocsp);

    if (!result.successful_validation()) {
        throw Botan::Exception("Certificate validation failure: " + result.result_string());
    }

    if (m_engine->IsHardFailFallbackMechanismActive()) {
#ifndef TLSAPI_ICAS3_TEST_STAPLING_HARDFAIL_NO_OCSP_FALLBACK
        FND_LOG_DEBUG << "OCSP fallback mechanism configured to Hard-Fail";
        if (!m_engine->CheckOcspOnline(result, trusted_roots, ocsp)) {
            throw Botan::Exception("Certificate validation failure: Check OCSP online failure");
        }
#else
        FND_LOG_DEBUG << "OCSP stapling mechanism configured to Hard-Fail";
        if (ocsp.empty()) {
            throw Botan::Exception("Certificate validation failure: No OCSP stapling from server");
        }
#endif
    } else {
        FND_LOG_DEBUG << "OCSP fallback mechanism configured to Soft-Fail";
    }

    if(0 < m_engine->m_httpPublicKeyPinningHashes.size())
    {
        std::vector<std::vector<char>> pinningHashesVec(cert_chain.size());
        for (size_t cert_num = 0; cert_num != cert_chain.size(); ++cert_num) {
            auto hashPublicKey =
                calculate_public_key_hash(cert_chain[cert_num].subject_public_key()->subject_public_key());

            pinningHashesVec[cert_num] = hashPublicKey;
        }

        if (!atLeastOneCommonMember(pinningHashesVec, m_engine->m_httpPublicKeyPinningHashes)) {
            throw vwg::tls::RC_TLS_PUBLIC_KEY_PINNING_FAILED;
        }
    }
}

void
CallbacksCert::tls_emit_data(const uint8_t buf[], size_t length)
{
    m_engine->GetIOStream()->send(buf, length);
}

void
CallbacksCert::tls_record_received(uint64_t rec, const uint8_t data[], size_t len)
{
    (void)rec;
    m_engine->m_plaintext.insert(m_engine->m_plaintext.end(), data, data + len);
}

void
CallbacksCert::tls_alert(Botan::TLS::Alert alert)
{
    // handle a tls alert received from the tls server
    FND_LOG_ERROR << "alert: " << alert.type_string().c_str();
    if (alert.is_fatal() && alert.type() != Botan::TLS::Alert::CLOSE_NOTIFY) {
        m_engine->SetReceivedAlert(alert.type());
    }
}

bool
CallbacksCert::tls_session_established(const Botan::TLS::Session&)
{
    // the session with the tls server was established
    // return false to prevent the session from being cached, true to
    // cache the session in the configured session manager
    return false;
}

std::vector<char>
CallbacksCert::calculate_public_key_hash(std::vector<uint8_t> buf)
{
    std::unique_ptr<HashFunction> sha256 = HashFunction::create_or_throw("SHA-256");
    sha256->update(buf);
    sha256->final(buf);
    std::string cert_hash_key = Botan::base64_encode(buf);
    return std::vector<char>(cert_hash_key.begin(), cert_hash_key.end());
}

//--------------BotanCertEngine functions--------------
BotanCertEngine::BotanCertEngine(std::shared_ptr<IOStreamIf>           stream,
                                 const std::string&                    hostName,
                                 std::string                           certStoreId,
                                 std::string                           clientCertificateSetID,
                                 const std::vector<HashSha256>&        httpPublicKeyPinningHashs,
                                 const bool                            revocationCheckEnabled,
                                 const CipherSuiteIds&                 cipherSuiteIds,
                                 const TLSCipherSuiteUseCasesSettings& cipherSuiteSettings,
                                 const AlpnMode&                       alpnMode,
                                 const TimeCheckTime&                  checkTime,
                                 std::shared_ptr<ITLSOcspHandler>&     ocspHandler,
                                 const uint32_t                        ocspTimeoutMs)
  : TLSCertEngine(stream, checkTime, ocspHandler, ocspTimeoutMs)
  , m_privateKey(nullptr)
  , m_privateStore(nullptr)
  , m_httpPublicKeyPinningHashes(httpPublicKeyPinningHashs)
  , m_hostName(hostName)
  , m_certStoreId(certStoreId)
  , m_clientCertificateSetID(clientCertificateSetID)
  , m_receivedAlert(Botan::TLS::Alert::NULL_ALERT)
  , m_alpnMode(alpnMode)
{
    if (cipherSuiteIds.empty()) {
        // init m_validCiphers member to be cipher suites list by cipherSuiteSettings.
        setCipherSuitesListUseCase(cipherSuiteSettings);
    } else {
        // Init the m_validCiphers member to be concatenation of all cipher suites that
        // the user has entered as input in cipherSuiteIds and filtered as valid.
        filteredCiphers(cipherSuiteIds);
    }
#ifdef UNIT_TEST
    strict_policy_with_ocsp_config policy;
    m_client.reset(new BotanClientUT(*m_callbacks, *m_session_mgr, *m_rng, policy));
#endif

    m_revocationCheckEnabled = revocationCheckEnabled;
}

void
BotanCertEngine::filteredCiphers(CipherSuiteIds const& cipherSuiteIds)
{
    size_t      pos = 0;
    std::string baseCiphers(cipherSuiteIds);
    if (!baseCiphers.empty()) {
        baseCiphers.append(":");
    }
    std::string token     = cipherSuiteIds;
    std::string delimiter = ":";
    while ((pos = baseCiphers.find(delimiter)) != std::string::npos) {
        token = baseCiphers.substr(0, pos);
        if (token == "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256") {
            m_ciphersuiteCodes.push_back(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        } else if (token == "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
            m_ciphersuiteCodes.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        } else if (token == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") {
            m_ciphersuiteCodes.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        } else if (token == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") {
            m_ciphersuiteCodes.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        } else if (token == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") {
            m_ciphersuiteCodes.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        } else if (token == "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384") {
            m_ciphersuiteCodes.push_back(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        } else if (token == "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256") {
            m_ciphersuiteCodes.push_back(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        }
        baseCiphers.erase(0, pos + delimiter.length());
    }

    // The cipher list input was empty or all invalid values
    if (0 == m_ciphersuiteCodes.size()) {
        // Sets default cipherSuites list
        setCipherSuitesListUseCase(CSUSDefault);
    }
}

void
BotanCertEngine::setCipherSuitesListUseCase(const TLSCipherSuiteUseCasesSettings& cipherSuiteSettings)
{
    std::vector<uint16_t> defaultCipherSuites = {TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                                 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                                 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                                 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                                 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                                 TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                                                 TLS_DHE_RSA_WITH_AES_256_GCM_SHA384};

    std::vector<uint16_t> ianaRecommendedCipherSuites(defaultCipherSuites);
    ianaRecommendedCipherSuites.insert(
        ianaRecommendedCipherSuites.end(),
        {TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256});

    switch (cipherSuiteSettings) {
    case CSUSLegacy:
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". CSUSLegacy cipher suite list.";
        m_ciphersuiteCodes = ianaRecommendedCipherSuites;
        m_ciphersuiteCodes.insert(m_ciphersuiteCodes.end(),
                                  {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                                   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                                   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                                   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                                   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                                   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                                   TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                                   TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                                   TLS_RSA_WITH_AES_128_GCM_SHA256,
                                   TLS_RSA_WITH_AES_256_GCM_SHA384,
                                   TLS_RSA_WITH_AES_128_CBC_SHA256,
                                   TLS_RSA_WITH_AES_256_CBC_SHA256,
                                   TLS_RSA_WITH_AES_128_CBC_SHA,
                                   TLS_RSA_WITH_AES_256_CBC_SHA,
                                   TLS_RSA_WITH_3DES_EDE_CBC_SHA});
        m_cipherSuiteUseCase = CSUSLegacy;
        break;

    case CSUSLongtermSecure:
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". CSUSLongtermSecure cipher suite list.";
        m_ciphersuiteCodes   = {TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                              TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                              TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                              TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                              TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                              TLS_DHE_RSA_WITH_AES_256_GCM_SHA384};
        m_cipherSuiteUseCase = CSUSLongtermSecure;
        break;

    case CSUSIanaRecommended:
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". CSUSIanaRecommended cipher suite list.";
        m_ciphersuiteCodes   = ianaRecommendedCipherSuites;
        m_cipherSuiteUseCase = CSUSIanaRecommended;
        break;

    case CSUSDefaultWithSoftFail:
        FND_LOG_DEBUG << "CSUSDefaultWithSoftFail cipher suite list";
        m_ciphersuiteCodes   = defaultCipherSuites;
        m_cipherSuiteUseCase = CSUSDefaultWithSoftFail;
        break;

    case CSUSDefault:
    default:
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". CSUSDefault cipher suite list.";
        m_ciphersuiteCodes   = defaultCipherSuites;
        m_cipherSuiteUseCase = CSUSDefault;
        break;
    }
}

TLSEngineError
BotanCertEngine::AlertToEngineError(Botan::TLS::Alert::Type type)
{
    switch (type) {
    case Botan::TLS::Alert::UNEXPECTED_MESSAGE:
        return RC_TLS_ENGINE_UNEXPECTED_MESSAGE;
    case Botan::TLS::Alert::BAD_RECORD_MAC:
        return RC_TLS_ENGINE_BAD_RECORD_MAC;
    case Botan::TLS::Alert::RECORD_OVERFLOW:
        return RC_TLS_ENGINE_RECORD_OVERFLOW;
    case Botan::TLS::Alert::DECOMPRESSION_FAILURE:
        return RC_TLS_ENGINE_DECOMPRESSION_FAILURE;
    case Botan::TLS::Alert::HANDSHAKE_FAILURE:
        return RC_TLS_ENGINE_HANDSHAKE_FAILURE;
    case Botan::TLS::Alert::BAD_CERTIFICATE:
        return RC_TLS_ENGINE_BAD_CERTIFICATE;
    case Botan::TLS::Alert::UNSUPPORTED_CERTIFICATE:
        return RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE;
    case Botan::TLS::Alert::CERTIFICATE_REVOKED:
        return RC_TLS_ENGINE_CERTIFICATE_REVOKED;
    case Botan::TLS::Alert::CERTIFICATE_EXPIRED:
        return RC_TLS_ENGINE_CERTIFICATE_EXPIRED;
    case Botan::TLS::Alert::CERTIFICATE_UNKNOWN:
        return RC_TLS_ENGINE_CERTIFICATE_UNKNOWN;
    case Botan::TLS::Alert::ILLEGAL_PARAMETER:
        return RC_TLS_ENGINE_ILLEGAL_PARAMETER;
    case Botan::TLS::Alert::UNKNOWN_CA:
        return RC_TLS_ENGINE_UNKNOWN_CA;
    case Botan::TLS::Alert::ACCESS_DENIED:
        return RC_TLS_ENGINE_ACCESS_DENIED;
    case Botan::TLS::Alert::DECODE_ERROR:
        return RC_TLS_ENGINE_DECODE_ERROR;
    case Botan::TLS::Alert::DECRYPT_ERROR:
        return RC_TLS_ENGINE_DECRYPT_ERROR;
    case Botan::TLS::Alert::PROTOCOL_VERSION:
        return RC_TLS_ENGINE_PROTOCOL_VERSION;
    case Botan::TLS::Alert::INSUFFICIENT_SECURITY:
        return RC_TLS_ENGINE_INSUFFICIENT_SECURITY;
    case Botan::TLS::Alert::NO_RENEGOTIATION:
        return RC_TLS_ENGINE_NO_RENEGOTIATION;
    case Botan::TLS::Alert::UNSUPPORTED_EXTENSION:
        return RC_TLS_ENGINE_UNSUPPORTED_EXTENSION;
    case Botan::TLS::Alert::CERTIFICATE_UNOBTAINABLE:
        return RC_TLS_ENGINE_CERTIFICATE_UNOBTAINABLE;
    case Botan::TLS::Alert::UNRECOGNIZED_NAME:
        return RC_TLS_ENGINE_UNRECOGNIZED_NAME;
    case Botan::TLS::Alert::BAD_CERTIFICATE_STATUS_RESPONSE:
        return RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE;
    case Botan::TLS::Alert::BAD_CERTIFICATE_HASH_VALUE:
        return RC_TLS_ENGINE_BAD_CERTIFICATE_HASH_VALUE;
    case Botan::TLS::Alert::NULL_ALERT:
        return RC_TLS_ENGINE_UNKNOWN_ERROR;
    default:
        return RC_TLS_ENGINE_SPECIFIC_ERROR;
    }
}


TLSEngineError
BotanCertEngine::feed()
{
    return feed(sizeof(m_buffer));
}

TLSEngineError
BotanCertEngine::feed(size_t len)
{
    size_t remaining = len;
    TLSEngineError res = RC_TLS_ENGINE_SUCCESSFUL;

    while ((remaining > 0) && (false == m_client->is_closed()) && (RC_TLS_ENGINE_SUCCESSFUL == res)) {
        int32_t received = m_stream->receive(m_buffer, std::min(sizeof(m_buffer), remaining));
        if (received < 0) {
            if (RC_STREAM_WOULD_BLOCK == received) {
                res = RC_TLS_ENGINE_WOULD_BLOCK_READ;
            } else {
                res = RC_TLS_ENGINE_SPECIFIC_ERROR;
            }
        } else if (received == 0) {
            /* Unexpected EOF */
            res = RC_TLS_ENGINE_PEER_CLOSED;
        } else {
            Botan::TLS::Alert::Type alert = Botan::TLS::Alert::NULL_ALERT;
            if (true == m_client->is_closed()) {
                FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". CHANNEL CLOSED.";
            } else {
                try {
                    remaining = std::min({m_client->received_data(m_buffer, received),remaining - static_cast<size_t>(received)});
                } catch (Botan::TLS::TLS_Exception& e) {
                    alert = e.type();
                } catch (Botan::Integrity_Failure&) {
                    alert = Botan::TLS::Alert::BAD_RECORD_MAC;
                } catch (Botan::Decoding_Error&) {
                    alert = Botan::TLS::Alert::DECODE_ERROR;
                } catch (...) {
                    alert = Botan::TLS::Alert::INTERNAL_ERROR;
                }
            }
            if (alert != Botan::TLS::Alert::NULL_ALERT) {
                FND_LOG_INFO << "connectionName: " << m_connectionLoggingName.c_str() << ". Client alert: " << alert << ".";
                res = AlertToEngineError(alert);
            }
        }
    }

    return res;
}

TLSEngineError
BotanCertEngine::checkTeeAndItsData()
{
    std::shared_ptr<vwg::tee::TLSTEEAPI> m_tlsTeeApi = vwg::tee::TLSTEEAPI::get_instance();
    if (!m_tlsTeeApi) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Fatal error: can't access TEE.";
        return RC_TLS_ENGINE_TEE_ACCESS_ERROR;
    }

    string serverCert = m_tlsTeeApi->get_root_cert_bundle(m_certStoreId);
    if (serverCert.empty()) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Fatal error: can't find root cert bundle.";
        return RC_TLS_ENGINE_CERTSTORE_NOT_FOUND;
    }

    if (!m_clientCertificateSetID.empty()) {
        string clientCertificateStr = m_tlsTeeApi->get_client_cert(m_clientCertificateSetID);
        if (clientCertificateStr.empty()) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Fatal error: can't find client cert";
            return RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID;
        }
        string clientPrivateKeyStr = m_tlsTeeApi->get_client_cert_private_key(m_clientCertificateSetID);
        if (clientPrivateKeyStr.empty()) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Fatal error: can't find client cert key";
            return RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID;
        }
    }

    return RC_TLS_ENGINE_SUCCESSFUL;
}

bool
BotanCertEngine::getAlpnProtocol(std::vector<std::string>& alpn) const
{
    if (m_alpnMode.userDefinedALPNisUsed()) {
        alpn = m_alpnMode.getUserDefinedAlpnSetting();
    } else {
        std::string               ianaString;
        IANAProtocolFunction      ianaProtocolFunction;
        std::vector<IANAProtocol> ianaProtocols = m_alpnMode.getSupportedProtocols();
        for_each(ianaProtocols.begin(), ianaProtocols.end(), [&](IANAProtocol enumPrt) {
            if (ianaProtocolFunction.toIANAProtocolName(enumPrt, ianaString)) {
                alpn.push_back(ianaString);
            }
        });
    }

    if (!alpn.empty()) {
        return true;
    }
    return false;
}

TLSEngineError
BotanCertEngine::DoSSLHandshake()
{
    TLSEngineError                 res = RC_TLS_ENGINE_UNKNOWN_ERROR;
    strict_policy_with_ocsp_config policy;

    TLSEngineError tee_check_ret_code = checkTeeAndItsData();
    if (tee_check_ret_code != RC_TLS_ENGINE_SUCCESSFUL) {
        return tee_check_ret_code;
    }

    policy.set_cert_status(m_revocationCheckEnabled);
    policy.set_ciphersuite_list(m_ciphersuiteCodes);

    m_rng.reset(new Botan::AutoSeeded_RNG);
    m_callbacks.reset(new CallbacksCert(this));
    m_session_mgr.reset(new Botan::TLS::Session_Manager_In_Memory(*m_rng));
    m_creds_mgr.reset(new ClientCredsManager(this));

    std::vector<std::string> alpn;
    if (getAlpnProtocol(alpn)) {
        FND_LOG_VERBOSE << "connectionName: " << m_connectionLoggingName.c_str() << ". ALPN is used.";
    } else {
        // A empty vector will cause to unused ALPN
        FND_LOG_VERBOSE << "connectionName: " << m_connectionLoggingName.c_str() << ". ALPN is unused.";
    }
#ifndef UNIT_TEST
    m_client.reset(new Botan::TLS::Client(*m_callbacks,
                                          *m_session_mgr,
                                          *m_creds_mgr,
                                          policy,
                                          *m_rng,
                                          TLS::Server_Information(m_hostName),
                                          Botan::TLS::Protocol_Version::latest_tls_version(),
                                          alpn));
#endif

    while (false == m_client->is_active()) {
        if (true == m_client->is_closed()) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". SSL Handshake Client failed - the channel closed";
            res = AlertToEngineError(m_receivedAlert);
            break;
        }

        res = feed();
        if (res != RC_TLS_ENGINE_SUCCESSFUL) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". feed failed";
            break;
        }
    }
    FND_LOG_INFO << "connectionName: " << m_connectionLoggingName.c_str() << ". SSL Handshake Client finished";

    return res;
}

BotanCertEngine::~BotanCertEngine()
{
    Close();
}

vwg::tls::impl::TLSEngineError
BotanCertEngine::Send(const uint8_t* buffer, int32_t bufLength, int32_t& actualLength)
{
    if (m_client->is_closed()) {
        return RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN;
    }

    if (bufLength > 0) {
        try {
            m_client->send(buffer, bufLength);
        } catch (...) {
            return RC_TLS_ENGINE_FATAL_ERROR;
        }
    }

    actualLength = bufLength;
    return RC_TLS_ENGINE_SUCCESSFUL;
}

vwg::tls::impl::TLSEngineError
BotanCertEngine::Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength)
{
    TLSEngineError res = RC_TLS_ENGINE_SUCCESSFUL;
    if (m_client->is_closed()) {
        return RC_TLS_ENGINE_SPECIFIC_ERROR;
    }

    while (m_plaintext.empty() && res == RC_TLS_ENGINE_SUCCESSFUL && !m_client->is_closed()) {
        res = feed(bufLength);
    }

    if (RC_TLS_ENGINE_SUCCESSFUL == res) {
        actualLength = std::min(bufLength, (int32_t)m_plaintext.size());
        memcpy(buffer, m_plaintext.data(), actualLength);
        m_plaintext.erase(m_plaintext.begin(), m_plaintext.begin() + actualLength);
        if (actualLength == 0 && m_client->is_closed() && m_receivedAlert != Botan::TLS::Alert::NULL_ALERT)
            res = AlertToEngineError(m_receivedAlert);
    }
    return res;
}

vwg::tls::impl::TLSEngineError
BotanCertEngine::Shutdown()
{
    try {
        if (m_client) {
            m_client->close();
        }
    } catch (...) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Shutdown engine failed";
    }
    return RC_TLS_ENGINE_SUCCESSFUL;
}

void
BotanCertEngine::Close()
{
    m_plaintext.clear();
    Shutdown();
}

const AlpnMode&
BotanCertEngine::getUsedAlpnMode() const
{
    return m_alpnMode;
}

IANAProtocol
BotanCertEngine::getUsedProtocol() const
{
    std::string protocol_name = m_client->application_protocol();

    FND_LOG_VERBOSE << "connectionName: " << m_connectionLoggingName.c_str() << ". Received ALPN protocol: " << protocol_name.c_str();
    if ("http/1.1" == protocol_name) {
        return HTTP;
    }
    if ("h2" == protocol_name) {
        return HTTP2;
    }
    return NONE;
}

bool
BotanCertEngine::createOcspRequests(const std::vector<std::shared_ptr<const X509_Certificate>>& certChain,
                                    const CertificatePathStatusCodes&                           certChainStatusCodes,
                                    std::vector<TLSOcspRequest>&                                outTlsOcspRequests,
                                    std::vector<OcspRequestsCertsTuple>& outOcspRequestsCertsTupleVector) const
{
    bool isErrorRaised = false;

    for (size_t i = 0; i < certChain.size() - 1; i++) {
        const std::shared_ptr<const X509_Certificate>& subject = certChain.at(i);
        const std::shared_ptr<const X509_Certificate>& issuer  = certChain.at(i + 1);
        if (nullptr == subject || nullptr == issuer) {
            isErrorRaised = true;
            continue;
        }

        if (subject->ocsp_responder().empty()) {
            isErrorRaised = true;
            continue;
        }

        Certificate_Status_Code overallStatus = Botan::PKIX::overall_status({certChainStatusCodes.at(i)});
        if (Certificate_Status_Code::OK != overallStatus) {
            isErrorRaised = true;
            continue;
        }

        Botan::OCSP::Request botanRequest(*issuer, *subject);
        TLSOcspRequest       tlsOcspRequest(subject->ocsp_responder(), botanRequest.BER_encode());
        outTlsOcspRequests.push_back(tlsOcspRequest);
        outOcspRequestsCertsTupleVector.push_back(
            std::make_tuple(tlsOcspRequest, certChain.at(i), certChain.at(i + 1)));
    }

    return !isErrorRaised;
}

bool
BotanCertEngine::verifyNCreateCachedResponses(const std::vector<OcspRequestsCertsTuple>& ocspRequestsCertsTupleVector,
                                              const std::vector<TLSOcspRequestResponse>& tlsOcspResponses,
                                              const std::vector<Botan::Certificate_Store*>& trustedRoots,
                                              std::vector<TLSOcspCachedResponse>& outTlsOcspCachedResponses) const
{
    if (ocspRequestsCertsTupleVector.size() != tlsOcspResponses.size()) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Invalid OCSP responses vector size";
        FND_LOG_DEBUG("connectionName: ", m_connectionLoggingName.c_str(),
                      ". ocspRequestsCertsTupleVector size = ", ocspRequestsCertsTupleVector.size(),
                      ", tlsOcspResponses size = ", tlsOcspResponses.size());
        return false;
    }

    bool isErrorRaised = false;

    for (size_t i = 0; i < tlsOcspResponses.size(); i++) {
        OcspRequestsCertsTuple                        ocspRequestsCertsTuple = ocspRequestsCertsTupleVector.at(i);
        const TLSOcspRequest                          tlsOcspRequest         = std::get<0>(ocspRequestsCertsTuple);
        const std::shared_ptr<const X509_Certificate> subject                = std::get<1>(ocspRequestsCertsTuple);
        const std::shared_ptr<const X509_Certificate> issuer                 = std::get<2>(ocspRequestsCertsTuple);

        TLSOcspRequestResponse tlsOcspResponse          = tlsOcspResponses.at(i);
        const UInt64           receivedResponseUniqueId = tlsOcspResponse.getRequestUniqueId();
        if (tlsOcspResponse.isCorrupted()) {
            std::stringstream xReceivedResponseUniqueId;
            xReceivedResponseUniqueId << std::hex << receivedResponseUniqueId;
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Received corrupted OCSP response";
            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". response ID " <<xReceivedResponseUniqueId.str();
            isErrorRaised = true;
            continue;
        }

        const UInt64 requestUniqueId = tlsOcspRequest.getUniqueId();
        if (requestUniqueId != receivedResponseUniqueId) {
            std::stringstream xRequestUniqueId, xReceivedResponseUniqueId;
            xRequestUniqueId << std::hex << requestUniqueId;
            xReceivedResponseUniqueId << std::hex << receivedResponseUniqueId;
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Received OCSP response not match to OCSP request";
            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". request ID " << xRequestUniqueId.str() << " << response ID " << xReceivedResponseUniqueId.str();
            isErrorRaised = true;
            continue;
        }

        Botan::OCSP::Response   botanResponse(tlsOcspResponse.getResponse());
        Certificate_Status_Code certStatus = botanResponse.check_signature(trustedRoots);
        if (Certificate_Status_Code::OCSP_SIGNATURE_OK != certStatus) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". OCSP Response check signature failure";
            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". Certificate status code is " << to_string(certStatus);
            //Delete from cache!
            isErrorRaised = true;
            continue;
        }

        certStatus = botanResponse.status_for(*issuer, *subject, std::chrono::system_clock::now());
        if (Certificate_Status_Code::OCSP_RESPONSE_GOOD != certStatus) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Bad certificate status";
            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". Certificate status code is " << to_string(certStatus);
            //Delete from cache!
            isErrorRaised = true;
            continue;
        }

        const std::vector<UInt8>& rawResponse       = tlsOcspResponse.getResponse();
        const std::string&        producedAtDate    = botanResponse.produced_at().to_string();
        const bool                isResponseInCache = tlsOcspResponse.getIsCached();

        // Botan doesn't export thisUpdate and nextUpdate parameters so we make them empty
        if (!isResponseInCache) {
            TLSOcspCachedResponse tlsOcspCachedResponse(rawResponse, receivedResponseUniqueId, producedAtDate, "", "");
            outTlsOcspCachedResponses.push_back(tlsOcspCachedResponse);
        }
    }

    return !isErrorRaised;
}

bool
BotanCertEngine::CheckOcspOnline(const Botan::Path_Validation_Result&                             pathValidationResult,
                                 const std::vector<Botan::Certificate_Store*>&                    trustedRoots,
                                 const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp) const
{
    bool                       isErrorRaised                       = false;
    CertificatePathStatusCodes certificatePathStatusCodes          = pathValidationResult.all_statuses();
    std::vector<std::shared_ptr<const X509_Certificate>> certChain = pathValidationResult.cert_path();

    if (1 >= certChain.size()) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Root certificate isn't included or empty chain";
        return false;
    }

    if (certChain.size() != certificatePathStatusCodes.size()) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Cert chain and Cert status codes size mismatch";
        return false;
    }

    std::shared_ptr<ITLSOcspHandler> ocspHandler = GetOcspHandler();
    if (nullptr == ocspHandler) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". OCSP handler is NULL";
        return false;
    }

    // If OCSP stapled vector is not empty and the cert status of the EE is OK it means it has good ocsp cert status
    // because it has valid OCSP stapled
    Certificate_Status_Code eeCertStatus = Botan::PKIX::overall_status({certificatePathStatusCodes.at(0)});
    if (!ocsp.empty() && Certificate_Status_Code::OK == eeCertStatus) {
        certChain.erase(certChain.begin());
        certificatePathStatusCodes.erase(certificatePathStatusCodes.begin());
    }

    std::vector<TLSOcspRequest>         tlsOcspRequestsVector;
    std::vector<OcspRequestsCertsTuple> ocspRequestsCertsTupleVector;
    if (!createOcspRequests(
            certChain, certificatePathStatusCodes, tlsOcspRequestsVector, ocspRequestsCertsTupleVector)) {
        isErrorRaised = true;
    }

    // This block of code is crucial. if it fails we must return false here and stop.
    std::chrono::milliseconds                        tout(GetOcspTimeout());
    std::future<std::vector<TLSOcspRequestResponse>> futureOcspProcessResult =
        ocspHandler->processRequests(tlsOcspRequestsVector);
    std::future_status futureStatus = futureOcspProcessResult.wait_for(tout);
    if (std::future_status::ready != futureStatus) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Timeout reached or the task has not been started yet";
        return false;
    }

    std::vector<TLSOcspCachedResponse>  tlsOcspCachedResponses;
    std::vector<TLSOcspRequestResponse> tlsOcspResponses = futureOcspProcessResult.get();
    if (!verifyNCreateCachedResponses(
            ocspRequestsCertsTupleVector, tlsOcspResponses, trustedRoots, tlsOcspCachedResponses)) {
        isErrorRaised = true;
    }

    if (!tlsOcspCachedResponses.empty()) {
        ocspHandler->cacheResponses(tlsOcspCachedResponses);
    }

    return !isErrorRaised;
}
