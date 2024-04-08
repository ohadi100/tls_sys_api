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


#include "WolfSSLCertEngine.hpp"
#include "WolfSSLCommon.hpp"
#include "engineCommon.hpp"

#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>
#include <sstream>

using std::function;
using std::string;
using std::vector;
using vwg::tls::impl::TLSCertEngine;
using vwg::tls::impl::WolfSSLCertEngine;

using namespace std;
using namespace vwg::tls;

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::WolfSSLToEngineError()
{
    int err = wolfSSL_get_error(m_ssl.get(), 0);
    
    char buffer[80];
    wolfSSL_ERR_error_string(err, buffer); 
    FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfssl error code: " << err << " << error message: " << buffer << "." ;

    switch (err) {
    case WOLFSSL_ERROR_WANT_READ:
        return RC_TLS_ENGINE_WOULD_BLOCK_READ;
    case WOLFSSL_ERROR_WANT_WRITE:
        return RC_TLS_ENGINE_WOULD_BLOCK_WRITE;
    case SOCKET_PEER_CLOSED_E:
        return RC_TLS_ENGINE_PEER_CLOSED;
    case ASN_NO_SIGNER_E:
        return RC_TLS_ENGINE_UNKNOWN_CA;
    case WOLFSSL_ERROR_ZERO_RETURN:
        return RC_TLS_ENGINE_SUCCESSFUL;
    default:
        WOLFSSL_ALERT_HISTORY history;
        if (wolfSSL_get_alert_history(m_ssl.get(), &history) == WOLFSSL_SUCCESS) {
            err = -1;
            if (history.last_rx.level == alert_fatal) {
                err = history.last_rx.code;
            } else if (history.last_tx.level == alert_fatal) {
                err = history.last_tx.code;
            }

            switch (err) {
            case unknown_ca:
                return RC_TLS_ENGINE_UNKNOWN_CA;
            case unexpected_message:
                return RC_TLS_ENGINE_UNEXPECTED_MESSAGE;
            case bad_record_mac:
                return RC_TLS_ENGINE_BAD_RECORD_MAC;
            case record_overflow:
                return RC_TLS_ENGINE_RECORD_OVERFLOW;
            case decompression_failure:
                return RC_TLS_ENGINE_DECOMPRESSION_FAILURE;
            case handshake_failure:
                return RC_TLS_ENGINE_HANDSHAKE_FAILURE;
            case bad_certificate:
                return RC_TLS_ENGINE_BAD_CERTIFICATE;
            case unsupported_certificate:
                return RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE;
            case certificate_revoked:
                return RC_TLS_ENGINE_CERTIFICATE_REVOKED;
            case certificate_expired:
                return RC_TLS_ENGINE_CERTIFICATE_EXPIRED;
            case certificate_unknown:
                return RC_TLS_ENGINE_CERTIFICATE_UNKNOWN;
            case illegal_parameter:
                return RC_TLS_ENGINE_ILLEGAL_PARAMETER;
            case decode_error:
                return RC_TLS_ENGINE_DECODE_ERROR;
            case decrypt_error:
                return RC_TLS_ENGINE_DECRYPT_ERROR;
            case protocol_version:
                return RC_TLS_ENGINE_PROTOCOL_VERSION;
            case no_renegotiation:
                return RC_TLS_ENGINE_NO_RENEGOTIATION;
            case unsupported_extension:
                return RC_TLS_ENGINE_UNSUPPORTED_EXTENSION;
            case unrecognized_name:
                return RC_TLS_ENGINE_UNRECOGNIZED_NAME;
            case bad_certificate_status_response:
                return RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE;
            case no_application_protocol:
                return RC_TLS_ENGINE_NO_APPLICATION_PROTOCOL;
                // Fall-through.
            }
        }

        return RC_TLS_ENGINE_FATAL_ERROR;
    }
}

void
WolfSSLCertEngine::setCipherSuitesListUseCase(TLSCipherSuiteUseCasesSettings const& cipherSuiteSettings)
{
    std::string defaultCipherSuites = "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:"
                                      "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
                                      "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:"
                                      "DHE-RSA-AES256-GCM-SHA384:TLS13-AES128-GCM-SHA256:"
                                      "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256";

    std::string ianaRecommendedCipherSuites = defaultCipherSuites +
                                              ":DHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                                              "TLS13-AES128-CCM-SHA256";

    // Init the m_validCiphers member to be concatenation of all ciphers of the use case that the user has entered as
    // input
    switch (cipherSuiteSettings) {
    case CSUSLegacy:
        FND_LOG_DEBUG << "CSUSLegacy cipher suite ids list";
        m_validCiphers = ianaRecommendedCipherSuites;
        m_validCiphers.append(":ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:"
                              "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:"
                              "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
                              "DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:"
                              "AES128-GCM-SHA256:AES256-GCM-SHA384:"
                              "AES128-SHA256:AES256-SHA256:"
                              "AES128-SHA:AES256-SHA:"
                              "DES-CBC3-SHA:TLS13-AES128-CCM-SHA256");
        m_cipherSuiteUseCase = CSUSLegacy;
        break;
    case CSUSLongtermSecure:
        FND_LOG_DEBUG << "CSUSLongtermSecure cipher suite ids list";
        m_validCiphers       = "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:"
                               "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:"
                               "DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384:"
                               "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256";
        m_cipherSuiteUseCase = CSUSLongtermSecure;
        break;
    case CSUSIanaRecommended:
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". CSUSIanaRecommended cipher suite ids list";
        m_validCiphers       = ianaRecommendedCipherSuites;
        m_cipherSuiteUseCase = CSUSIanaRecommended;
        break;

    case CSUSDefaultWithSoftFail:
        FND_LOG_DEBUG << "CSUSDefaultWithSoftFail cipher suite list";
        m_validCiphers       = defaultCipherSuites;
        m_cipherSuiteUseCase = CSUSDefaultWithSoftFail;
        break;

    case CSUSDefault:
    default:
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". CSUSDefault cipher suite ids list";
        m_validCiphers       = defaultCipherSuites;
        m_cipherSuiteUseCase = CSUSDefault;
        break;
    }
}

/* This function init the m_validCiphers member to be concatenation of all ciphers that the user has entered as input
 * and filtered as valid */
void
WolfSSLCertEngine::filteredCiphers(CipherSuiteIds const& cipherSuiteIds)
{
    // Will contain user ciphers input after filter duplicate
    std::unordered_set<std::string> validCiphersSet;

    size_t      pos = 0;
    std::string baseCiphers(cipherSuiteIds);
    std::string delimiter = ":";

    if (!baseCiphers.empty()) {
        baseCiphers.append(delimiter);
    }

    while ((pos = baseCiphers.find(delimiter)) != std::string::npos) {
        std::string token = baseCiphers.substr(0, pos);
        // TLSv12 cipherSuites
        if (token == "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256") {
            validCiphersSet.insert("ECDHE-ECDSA-CHACHA20-POLY1305:");
        } else if (token == "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
            validCiphersSet.insert("ECDHE-ECDSA-AES256-GCM-SHA384:");
        } else if (token == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") {
            validCiphersSet.insert("ECDHE-ECDSA-AES128-GCM-SHA256:");
        } else if (token == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") {
            validCiphersSet.insert("ECDHE-RSA-AES256-GCM-SHA384:");
        } else if (token == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") {
            validCiphersSet.insert("ECDHE-RSA-AES128-GCM-SHA256:");
        } else if (token == "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384") {
            validCiphersSet.insert("DHE-RSA-AES256-GCM-SHA384:");
        } else if (token == "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256") {
            validCiphersSet.insert("DHE-RSA-AES128-GCM-SHA256:");
        }
        baseCiphers.erase(0, pos + delimiter.length());
    }

    for (const auto& cipher : validCiphersSet) {
        m_validCiphers += cipher;
    }

    if (m_validCiphers.empty()) {
        // Sets default cipherSuites list
        setCipherSuitesListUseCase(CSUSDefault);
    } else {
        // always set those TLSv13 cipherSuites
        m_validCiphers.append("TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256");
    }
}

WolfSSLCertEngine::WolfSSLCertEngine(std::shared_ptr<IOStreamIf>           stream,
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
                                     const uint32_t                        ocspTimeoutMs)
  : TLSCertEngine(stream, timeCheck, ocspHandler, ocspTimeoutMs)
  , m_ctx(nullptr)
  , m_ssl(nullptr)
  , m_hostName(hostName)
  , m_certStoreId(certStoreId)
  , m_clientCertificateSetID(clientCertificateSetID)
  , m_sslInit(false)
  , m_httpPublicKeyPinningHashes(httpPublicKeyPinningHashs)
  , m_alpnMode(alpnMode)
{
    if (cipherSuiteIds.empty()) {
        // init m_validCiphers member to be cipher suites list by cipherSuiteSettings
        setCipherSuitesListUseCase(cipherSuiteSettings);
    } else {
        // Init the m_validCiphers member to be concatenation of all cipher suites that the
        // user has entered as input in cipherSuiteIds and filtered as valid
        filteredCiphers(cipherSuiteIds);
    }

    m_revocationCheckEnabled = revocationCheckEnabled;
}

bool
WolfSSLCertEngine::calculatePublicKeyPinHash(std::vector<unsigned char> const& SubjectPublicKeyInfo,
                                             std::vector<char>&                certHashKey) const
{
    // Calculate sha256 on the data
    byte shaSum[SHA256_DIGEST_SIZE];

    // fill buffer with data to hash
    if (0 != wc_Sha256Hash(
                 reinterpret_cast<const byte*>(SubjectPublicKeyInfo.data()), SubjectPublicKeyInfo.size(), shaSum)) {
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to calculate hash";
        return false;
    }

    certHashKey.resize(BASE64_SHA256_SIZE);
    word32 outLen = certHashKey.size();
    if (0 != Base64_Encode_NoNl(shaSum, sizeof(shaSum), reinterpret_cast<byte*>(certHashKey.data()), &outLen)) {
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to calculate base64";
        return false;
    }

    if (certHashKey.size() != outLen) {
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to calculate base64";
        return false;
    }

    return true;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::ctxInit()
{
    int res;

    m_ctx = std::shared_ptr<WOLFSSL_CTX>(wolfSSL_CTX_new(wolfSSLv23_client_method()), wolfSSL_CTX_free);
    if (!m_ctx) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfSSL_CTX_new failed.";
        return WolfSSLToEngineError();
    }

    // one context for each ssl connection to allow different certStoreId
    if (wolfSSL_CTX_SetMinVersion(m_ctx.get(), WOLFSSL_TLSV1_2) != WOLFSSL_SUCCESS) {
        m_ctx = nullptr;
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfSSL_CTX_SetMinVersion failed.";
        return WolfSSLToEngineError();
    }

    wolfSSL_SetIORecv(m_ctx.get(), recvIO);
    wolfSSL_SetIOSend(m_ctx.get(), sendIO);

    string serverCert = vwg::tee::TLSTEEAPI::get_instance()->get_root_cert_bundle(m_certStoreId);
    if (serverCert.empty()) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Can't find trust store: " << m_certStoreId.c_str() << ".";
        return RC_TLS_ENGINE_CERTSTORE_NOT_FOUND;
    }

    unsigned char certificate[serverCert.size()];
    std::copy(serverCert.begin(), serverCert.end(), certificate);
    res = wolfSSL_CTX_load_verify_buffer(m_ctx.get(), certificate, serverCert.size(), WOLFSSL_FILETYPE_PEM);
    if (WOLFSSL_SUCCESS != res) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Error loading CA certs from buffer";
        return WolfSSLToEngineError();
    }

    return RC_TLS_ENGINE_SUCCESSFUL;
}

bool
WolfSSLCertEngine::getAlpnProtocol(std::string& alpn) const
{
    if (m_alpnMode.userDefinedALPNisUsed()) {
        std::vector<std::string> userProtocols = m_alpnMode.getUserDefinedAlpnSetting();
        for_each(userProtocols.begin(), userProtocols.end(), [&](std::string protocol) {
            alpn += protocol;
            alpn += ",";
        });
    } else {
        std::string               ianaString;
        IANAProtocolFunction      ianaProtocolFunction;
        std::vector<IANAProtocol> ianaProtocols = m_alpnMode.getSupportedProtocols();
        for_each(ianaProtocols.begin(), ianaProtocols.end(), [&](IANAProtocol enumPrt) {
            // if NONE protocol is set - alpn mode is unused
            if (ianaProtocolFunction.toIANAProtocolName(enumPrt, ianaString)) {
                alpn += ianaString;
                alpn += ",";
            }
        });
    }

    if (!alpn.empty()) {
        return true;
    }
    return false;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::sslInit()
{
    m_ssl = std::shared_ptr<WOLFSSL>(wolfSSL_new(m_ctx.get()), wolfSSL_free);
    if (!m_ssl) {
        return WolfSSLToEngineError();
    }

    wolfSSL_SetIOReadCtx(m_ssl.get(), (void*)m_stream.get());
    wolfSSL_SetIOWriteCtx(m_ssl.get(), (void*)m_stream.get());

    if ((wolfSSL_UseSupportedCurve(m_ssl.get(), WOLFSSL_ECC_SECP256R1)) != WOLFSSL_SUCCESS ||
        (wolfSSL_UseSupportedCurve(m_ssl.get(), WOLFSSL_ECC_SECP384R1)) != WOLFSSL_SUCCESS ||
        (wolfSSL_UseSupportedCurve(m_ssl.get(), WOLFSSL_ECC_SECP521R1)) != WOLFSSL_SUCCESS) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". use wolfSSL_UseSupportedCurve failed";
        return WolfSSLToEngineError();
    }

    std::string alpn_list;
    if (getAlpnProtocol(alpn_list)) {
        FND_LOG_VERBOSE << "connectionName: " <<  m_connectionLoggingName.c_str() << ". ALPN is used.";

        // According to rfc7301, In the event that the server supports no protocols that the client advertises,
        // then the server SHALL respond with a fatal "no_application_protocol" alert.
        // That is why "WOLFSSL_ALPN_CONTINUE_ON_MISMATCH" flag was chosen.
        if (WOLFSSL_SUCCESS !=
            wolfSSL_UseALPN(
                m_ssl.get(), (char*)alpn_list.c_str(), alpn_list.size(), WOLFSSL_ALPN_CONTINUE_ON_MISMATCH)) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfSSL_UseALPN failed";
            return WolfSSLToEngineError();
        }
    } else {
        FND_LOG_VERBOSE << "connectionName: " <<  m_connectionLoggingName.c_str() << ". ALPN is unused.";
    }

    if ((m_hostName.size() > 0) &&
        (wolfSSL_UseSNI(m_ssl.get(), 0, m_hostName.c_str(), (word16)m_hostName.size()) != WOLFSSL_SUCCESS)) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". use SNI failed";
        return WolfSSLToEngineError();
    }

    if (wolfSSL_set_cipher_list(m_ssl.get(), m_validCiphers.c_str()) != WOLFSSL_SUCCESS) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Fatal error: can't set cipher list";
        return WolfSSLToEngineError();
    }

    if (wolfSSL_set_ex_data(m_ssl.get(), WolfSSLCertEngine::EX_DATA_IDX_WOLFSSL_CERT_ENGINE_OBJ, (void*)(this)) !=
        WOLFSSL_SUCCESS) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to set engine object in ssl context ex data";
        return WolfSSLToEngineError();
    }

    m_sslInit.store(true);

    wolfSSL_set_verify(m_ssl.get(), SSL_VERIFY_PEER, WolfSSLCertEngine::verifyCallback);

    return RC_TLS_ENGINE_SUCCESSFUL;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::teeInit()
{
    if (!m_clientCertificateSetID.empty()) {
        string clientCertificateStr = vwg::tee::TLSTEEAPI::get_instance()->get_client_cert(m_clientCertificateSetID);
        if (clientCertificateStr.empty()) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Cant find matching client certificate.";
            return RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID;
        }

        unsigned char certificateCert[clientCertificateStr.size()];
        std::copy(clientCertificateStr.begin(), clientCertificateStr.end(), certificateCert);
        string clientPrivateKeyStr =
            vwg::tee::TLSTEEAPI::get_instance()->get_client_cert_private_key(m_clientCertificateSetID);
        if (clientPrivateKeyStr.empty()) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Cant find matching client certificate key.";
            return RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID;
        }
        unsigned char clientKey[clientPrivateKeyStr.size()];
        std::copy(clientPrivateKeyStr.begin(), clientPrivateKeyStr.end(), clientKey);

        if (wolfSSL_use_certificate_buffer(
                m_ssl.get(), certificateCert, clientCertificateStr.size(), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Error loading client cert.";
            return WolfSSLToEngineError();
        }

        if (wolfSSL_use_PrivateKey_buffer(m_ssl.get(), clientKey, clientPrivateKeyStr.size(), WOLFSSL_FILETYPE_PEM) !=
            WOLFSSL_SUCCESS) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Error loading client key.";
            return WolfSSLToEngineError();
        }
    }
    return RC_TLS_ENGINE_SUCCESSFUL;
}


vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::ocspInit()
{
    if (m_revocationCheckEnabled) {
        if (wolfSSL_EnableOCSPStapling(m_ssl.get()) != WOLFSSL_SUCCESS) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to enable OCSP stapling.";
            return WolfSSLToEngineError();
        }

        if (wolfSSL_UseOCSPStapling(m_ssl.get(), WOLFSSL_CSR_OCSP, 0) != WOLFSSL_SUCCESS) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to use OCSP stapling.";
            return WolfSSLToEngineError();
        }

        if ((m_cipherSuiteUseCase != CSUSLegacy)) {
#ifndef TLSAPI_ICAS3_TEST_STAPLING_HARDFAIL_NO_OCSP_FALLBACK
            if (wolfSSL_EnableOCSP(m_ssl.get(), WOLFSSL_OCSP_NO_NONCE | WOLFSSL_OCSP_CHECKALL) != WOLFSSL_SUCCESS) {
                FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to enable online OCSP.";
                return WolfSSLToEngineError();
            }

            if (wolfSSL_SetOCSP_Cb(m_ssl.get(), ocspOnlineCallback, ocspResponseFreeCallback, this) !=
                WOLFSSL_SUCCESS) {
                FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to set online OCSP callback.";
                return WolfSSLToEngineError();
            }

            if (CSUSDefaultWithSoftFail !=m_cipherSuiteUseCase) {
                FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". OCSP fallback mechanism configured to Hard-Fail.";
            }
#else
            if (wolfSSL_CTX_EnableOCSPMustStaple(m_ctx.get()) != WOLFSSL_SUCCESS) {
                FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to enable hard-fail OCSP stapling.";
                return WolfSSLToEngineError();
            }

            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". OCSP stapling mechanism configured to Hard-Fail.";
#endif

        } else {
            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". OCSP fallback mechanism configured to Soft-Fail.";
        }
    }
    return RC_TLS_ENGINE_SUCCESSFUL;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::wolfsslConnect()
{
    // add the domain name check to the list of checks to perform (comparison between the subject and the server domain name)
    // SSL_FAILURE will be returned if a memory error was encountered.
    if (WOLFSSL_SUCCESS != wolfSSL_check_domain_name(m_ssl.get(), m_hostName.c_str()))
    {
        FND_LOG_FATAL << "connectionName: " <<m_connectionLoggingName.c_str() <<". wolfSSL_check_domain_name failed for domain name: " << m_hostName.c_str();
        return WolfSSLToEngineError();
    }

    if (WOLFSSL_SUCCESS != wolfSSL_connect(m_ssl.get())) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfSSL_connect failed.";
        return WolfSSLToEngineError();
    }

    return RC_TLS_ENGINE_SUCCESSFUL;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::calculateCertificatesChainPinningHashes(std::vector<HashSha256>& pinningHashesVec)
{
    std::vector<unsigned char> subjectPublicKeyInfo(WolfSSLCertEngine::MAX_X509_SIZE);
    int                        keySize = subjectPublicKeyInfo.size();

    WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_chain(m_ssl.get());
    if (nullptr == chain) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Get peer chain failed.";
        return WolfSSLToEngineError();
    }

    int count = wolfSSL_get_chain_count(chain);
    if (count <= 0) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Invalid certificate chain count.";
        return WolfSSLToEngineError();
    }

    for (int idx = 0; idx < count; ++idx) {
        std::shared_ptr<WOLFSSL_X509> cert =
            std::shared_ptr<WOLFSSL_X509>(wolfSSL_get_chain_X509(chain, idx), wolfSSL_X509_free);
        if (nullptr == cert) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Get certificate from chain has failed.";
            return WolfSSLToEngineError();
        }

        // extracts SubjectPuclicKeyInfo (which contains public key, algorithm and subjectPublicKey).
        if (WOLFSSL_SUCCESS != wolfSSL_X509_get_pubkey_buffer(cert.get(), subjectPublicKeyInfo.data(), &keySize)) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Extracting public key has failed.";
            return WolfSSLToEngineError();
        }

        if ((0 >= keySize) || (static_cast<int>(subjectPublicKeyInfo.size()) < keySize)) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Extracting public key has failed.";
            return RC_TLS_PUBLIC_KEY_PINNING_FAILED;
        }
        subjectPublicKeyInfo.resize(keySize);

        std::vector<char> hashKeyPinning;
        if (!calculatePublicKeyPinHash(subjectPublicKeyInfo, hashKeyPinning)) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Calculate certificate pinning failed.";
            return WolfSSLToEngineError();
        }

        pinningHashesVec.push_back(hashKeyPinning);
    }

    return RC_TLS_ENGINE_SUCCESSFUL;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::validateHashPinning()
{
    if (m_httpPublicKeyPinningHashes.size() > 0) {
        std::vector<HashSha256> actualHashPinning;
        auto                    validateHashPinningRC = calculateCertificatesChainPinningHashes(actualHashPinning);
        if (RC_TLS_ENGINE_SUCCESSFUL != validateHashPinningRC) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to calculate pinning hashed.";
            return validateHashPinningRC;
        }

        // checks if at least one Subject Public Key Info structure whose fingerprint (actualHashPinning)
        // matches one of the pinned fingerprints for that host (m_httpPublicKeyPinningHashes)
        if (!atLeastOneCommonMember(actualHashPinning, m_httpPublicKeyPinningHashes)) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Hash pinning failed.";
            return RC_TLS_PUBLIC_KEY_PINNING_FAILED;
        }
    }

    return RC_TLS_ENGINE_SUCCESSFUL;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::DoSSLHandshake()
{
    TLSEngineError returnVal;

    if (nullptr == m_ctx) {
        returnVal = ctxInit();
        if (RC_TLS_ENGINE_SUCCESSFUL != returnVal) {
            return returnVal;
        }
    }

    returnVal = sslInit();
    if (RC_TLS_ENGINE_SUCCESSFUL != returnVal) {
        Close();
        return returnVal;
    }

    returnVal = teeInit();
    if (RC_TLS_ENGINE_SUCCESSFUL != returnVal) {
        Close();
        return returnVal;
    }

    returnVal = ocspInit();
    if (RC_TLS_ENGINE_SUCCESSFUL != returnVal) {
        Close();
        return returnVal;
    }

    returnVal = wolfsslConnect();
    if (RC_TLS_ENGINE_SUCCESSFUL != returnVal) {
        Close();
        return returnVal;
    }

    returnVal = validateHashPinning();
    if (RC_TLS_ENGINE_SUCCESSFUL != returnVal) {
        Close();
        return returnVal;
    }

    FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". Client Handshake finished.";

    return RC_TLS_ENGINE_SUCCESSFUL;
}

WolfSSLCertEngine::~WolfSSLCertEngine()
{
    Close();
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::Send(const uint8_t* buffer, int32_t bufLength, int32_t& actualLength)
{
    if (nullptr == buffer) {
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    if (!m_ssl.get() || wolfSSL_get_shutdown(m_ssl.get()) == SSL_SENT_SHUTDOWN) {
        return RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN;
    }

    TLSEngineError res;

    if (bufLength > 0) {
        actualLength = wolfSSL_send(m_ssl.get(), buffer, bufLength, 0);
        if (actualLength > 0) {
            res = RC_TLS_ENGINE_SUCCESSFUL;
        } else {
            res = WolfSSLToEngineError();
        }
    } else {
        res = WolfSSLToEngineError();
    }

    return res;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength)
{
    if (nullptr == buffer) {
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    if (!m_ssl.get() || wolfSSL_get_shutdown(m_ssl.get()) & WOLFSSL_SENT_SHUTDOWN) {
        actualLength = 0;
        return RC_TLS_ENGINE_SPECIFIC_ERROR;
    }

    TLSEngineError res;

    actualLength = wolfSSL_recv(m_ssl.get(), buffer, bufLength, 0);

    if (actualLength > 0) {
        res = RC_TLS_ENGINE_SUCCESSFUL;
    } else {
        res = WolfSSLToEngineError();
    }
    return res;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::SetBlocking(bool blocking)
{
    TLSEngineError res = TLSCertEngine::SetBlocking(blocking);
    if (res != RC_TLS_ENGINE_SUCCESSFUL)
        return res;

    wolfSSL_set_using_nonblock(m_ssl.get(), !blocking);
    return RC_TLS_ENGINE_SUCCESSFUL;
}

vwg::tls::impl::TLSEngineError
WolfSSLCertEngine::Shutdown()
{
    if (!m_ssl.get() || wolfSSL_get_shutdown(m_ssl.get()) & WOLFSSL_SENT_SHUTDOWN) {
        return RC_TLS_ENGINE_SUCCESSFUL;
    }

    if (m_sslInit) {
        int res = wolfSSL_shutdown(m_ssl.get());
        if (WOLFSSL_SHUTDOWN_NOT_DONE != res)
        {
            char buffer[80];
            wolfSSL_ERR_error_string(wolfSSL_get_error(m_ssl.get(), 0), buffer); 
            FND_LOG_ERROR << "wolfSSL_shutdown failed: connectionName: " << m_connectionLoggingName.c_str() << " << wolfssl error code: " << res << " << error message: " << buffer << ".";
        }

        m_sslInit.store(false);
        m_ssl.reset();
    }

    return RC_TLS_ENGINE_SUCCESSFUL;
}

void
WolfSSLCertEngine::Close()
{
    if (m_sslInit) {
        (void)Shutdown();
    }
    m_ctx.reset();
}

const AlpnMode&
WolfSSLCertEngine::getUsedAlpnMode() const
{
    return m_alpnMode;
}

const std::string
WolfSSLCertEngine::GetRemoteHintName() const
{
    return std::string{};
}

const std::string
WolfSSLCertEngine::GetHintName() const
{
    return std::string{};
}

IANAProtocol
WolfSSLCertEngine::getUsedProtocol() const
{
    char*          protocol_name   = nullptr;
    unsigned short protocol_nameSz = 0;
    if (wolfSSL_ALPN_GetProtocol(m_ssl.get(), &protocol_name, &protocol_nameSz) != WOLFSSL_SUCCESS) {
        int res = wolfSSL_get_error(m_ssl.get(), 0);
        char buffer[80];
        wolfSSL_ERR_error_string(res, buffer); 
        FND_LOG_ERROR << "wolfSSL_ALPN_GetProtocol failed: connectionName: " << m_connectionLoggingName.c_str() << " << wolfssl error code: " << res << " << error message: " << buffer << ".";
        return NONE;
    }
    FND_LOG_VERBOSE << "connectionName: " << m_connectionLoggingName.c_str() << ". Received ALPN protocol: " << protocol_name;
    if ("http/1.1" == std::string(protocol_name)) {
        return HTTP;
    } else if ("h2" == std::string(protocol_name)) {
        return HTTP2;
    }
    return NONE;
}

void
WolfSSLCertEngine::setOcspRequestResponseVector(const std::vector<TLSOcspRequestResponse>& ocspRequestsResponses)
{
    m_ocspRequestsResponses = ocspRequestsResponses;
}

bool
WolfSSLCertEngine::handleOcspCaching(bool remove)
{
    if (!m_ocspRequestsResponses.empty()) {
        const std::shared_ptr<ITLSOcspHandler> ocspHandler = GetOcspHandler();
        if (nullptr == ocspHandler) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". OCSP Handler is NULL.";
            m_ocspRequestsResponses.clear();
            return false;
        }

        TLSOcspRequestResponse requestResponse = m_ocspRequestsResponses.front();
        if (requestResponse.isCorrupted()) {
            std::stringstream xRequestUniqueId;
            xRequestUniqueId << std::hex << requestResponse.getRequestUniqueId();
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Received OCSP Response is corrupted.";
            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". request ID "  << xRequestUniqueId.str();
            return false;
        }

        if (requestResponse.getIsCached()) {
            if (!remove)
            {
                FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". OCSP Response is already exist in cache. caching is not needed.";
                m_ocspRequestsResponses.clear();
                return true;
            }
            else
            {
                /**
                This is in case the cert is revoked,
                So we want to remove it from cache
                Removing is done by sending it without data
                **/
                TLSOcspCachedResponse cachedResponse(
                    std::vector<uint8_t>{}, requestResponse.getRequestUniqueId(), "", "", "");

                ocspHandler->cacheResponses(std::vector<TLSOcspCachedResponse>{cachedResponse});
                m_ocspRequestsResponses.clear();
            }
        }

        if (remove)
        {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Revoked OCSP response message.";
            return false;
        }

        std::vector<uint8_t> responseVector  = requestResponse.getResponse();
        const uint8_t*             rawResponseData = responseVector.data();
        const size_t               rawResponseSize = responseVector.size();
        if (nullptr == rawResponseData || 0 == rawResponseSize) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Invalid OCSP response message.";
            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". response pointer = " << rawResponseData << " << response size = " << rawResponseSize;
            m_ocspRequestsResponses.clear();
            return false;
        }

        OcspResponse* decodedResponse = wolfSSL_d2i_OCSP_RESPONSE(nullptr, &rawResponseData, rawResponseSize);
        if (nullptr == decodedResponse) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Decoded OCSP Response pointer is NULL.";
            m_ocspRequestsResponses.clear();
            return false;
        }

        if (nullptr == decodedResponse->single || nullptr == decodedResponse->single->status) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Decoded OCSP Response inner pointers are NULL.";
            FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". decodedResponse->single = " << decodedResponse->single <<" << decodedResponse->single->status = " << decodedResponse->single->status;
            m_ocspRequestsResponses.clear();
            return false;
        }

        std::string producedAtDate = (const char*)decodedResponse->producedDate;
        std::string thisUpdateData = (const char*)decodedResponse->single->status->thisDate;
        std::string nextUpdateData = (const char*)decodedResponse->single->status->nextDate;
        wolfSSL_OCSP_RESPONSE_free(decodedResponse);

        UInt64 requestUniqueId = requestResponse.getRequestUniqueId();

        TLSOcspCachedResponse cachedResponse(
            responseVector, requestUniqueId, producedAtDate, nextUpdateData, thisUpdateData);

        ocspHandler->cacheResponses(std::vector<TLSOcspCachedResponse>{cachedResponse});
        m_ocspRequestsResponses.clear();
    }

    return true;
}

bool
WolfSSLCertEngine::postVerificationHandler(const WOLFSSL_X509_STORE_CTX* x509StorePtr, bool isFailure)
{
    if (nullptr == x509StorePtr) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". X509 Store context is NULL.";
        return false;
    }

    if (IsHardFailFallbackMechanismActive()) {
        if (nullptr == x509StorePtr->current_cert) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Current certificate pointer is NULL.";
            return false;
        }
        
        if((!wolfSSL_X509_get_isCA(x509StorePtr->current_cert)) ||
            (wolfSSL_X509_check_issued(x509StorePtr->current_cert, x509StorePtr->current_cert) !=  X509_V_OK))
        {
            if (0 == wolfSSL_X509_ext_isSet_by_NID(x509StorePtr->current_cert, AUTH_INFO_OID)) {
                FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Current certificate does not contain an authInfo extension.";
                return false;
            }
            else
            {
                FND_LOG_INFO << "connectionName: " << m_connectionLoggingName.c_str() << ". authInfo exists";
            }
        }
        else
        {
            FND_LOG_INFO << "connectionName: " << m_connectionLoggingName.c_str() << ". skip authInfo check for root CA";
        }

        if (!handleOcspCaching(isFailure)) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Failed to handle OCSP Response caching.";
            return false;
        }
    }

    return true;
}

int
WolfSSLCertEngine::verifyCallback(int preverify, WOLFSSL_X509_STORE_CTX* x509StorePtr)
{
    // This function is called during the TLS handshake for each certificate in the received server's certificate chain, starting from the root CA.
    // If current certificate verification failure has occurred (for example: if the certificate is expired, not yet valid, OCSP response was not received (if OCSP is used for that certificate), certificate is revoked, etc.) then
    // WolfSSL will set preverify to 0.
    //
    // In addition to that, the engine will do the following depending on the OCSP revocation mode: 
    // 1. For OCSP soft-fail mode (CSUSDefaultWithSoftFail or CSUSLegacy):
    // Terminate the TLS connection when the current certificate was excplicitly revoked.
    // In case where the OCSP response is not present for the current certificate, assume the certificate is VALID.
    // 
    // 2. For OCSP hard-fail mode:
    // Terminate the TLS connection when the current certificate was revoked, or the revocation status is not present (for example when the OCSP service was not reachable).
    //
    // In postVerificationHandler we also check that all certificate apart from root CAs contain the authInfo extension.

    FND_LOG_DEBUG << "Revocation check: STARTED! (preverify = " << preverify << ")";

    bool isFailure = false;
    if (nullptr == x509StorePtr) {
        FND_LOG_FATAL << "Revocation check: FAILED! X509 store is NULL. The current certificate context was not provided as expected to the verify function. This is an internal wolfSSL FATAL error.";
        FND_LOG_FATAL << "preverify = " << preverify;
        return WOLFSSL_FAILURE;
    }

    FND_LOG_DEBUG << "WolfSSL verify result code for the current certificate is " << x509StorePtr->error << ".";

    WOLFSSL* sslCtx =
        (WOLFSSL*)wolfSSL_X509_STORE_CTX_get_ex_data(x509StorePtr, wolfSSL_get_ex_data_X509_STORE_CTX_idx());
    if (nullptr == sslCtx) {
        FND_LOG_FATAL << "Revocation check: FAILED! WOLFSSL context is NULL. Could not read external data from X509 store. This is an internal wolfSSL FATAL error.";
        FND_LOG_FATAL << "preverify = " << preverify;
        return WOLFSSL_FAILURE;
    }

    WolfSSLCertEngine* wolfCertEngine =
        (WolfSSLCertEngine*)wolfSSL_get_ex_data(sslCtx, WolfSSLCertEngine::EX_DATA_IDX_WOLFSSL_CERT_ENGINE_OBJ);
    if (nullptr == wolfCertEngine) {
        FND_LOG_ERROR << "Revocation check: FAILED! Engine object is NULL. Could not get engine object from the SSL session's context! Make sure the engine object was associated with the SSL session's context (wolfSSL_set_ex_data).";
        FND_LOG_ERROR << "preverify = " << preverify;
        return WOLFSSL_FAILURE;
    }

    WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_chain(sslCtx);
    if (nullptr == chain) {
        FND_LOG_FATAL << "Revocation check: FAILED! Peer certificate chain is NULL. This is an internal wolfSSL FATAL error.";
        FND_LOG_FATAL << "preverify = " << preverify;
        return WOLFSSL_FAILURE;
    }

    int count = wolfSSL_get_chain_count(chain);
    if (count <= 0) {
        FND_LOG_FATAL << "Revocation check: FAILED! wolfSSL reported an invalid number of certificates in peer chain (count = " << count << "). This is an internal wolfSSL FATAL error.";
        FND_LOG_FATAL << "preverify = " << preverify;
        return WOLFSSL_FAILURE;
    }

    FND_LOG_DEBUG << "Number of certificates in peer chain is " << count << ".";

    if (WOLFSSL_SUCCESS != preverify) {
        // WolfSSL reported verification failure for the current certificate!
        if ((TLSCipherSuiteUseCasesSettings::CSUSDefaultWithSoftFail == wolfCertEngine->GetCipherSuiteUseCase() ||
            TLSCipherSuiteUseCasesSettings::CSUSLegacy == wolfCertEngine->GetCipherSuiteUseCase()) &&
            (x509StorePtr->error == OCSP_CERT_UNKNOWN || x509StorePtr->error == OCSP_LOOKUP_FAIL || x509StorePtr->error == OCSP_INVALID_STATUS)) {
            // In soft-fail mode, consider the certificate valid when the OCSP response is not available or not known.
            FND_LOG_INFO << "Revocation check: COMPLETED SUCCESSFULLY! Soft-Fail state. Skip verification of OCSP response.";
            return WOLFSSL_SUCCESS;
        }
#if defined(TLSAPI_ENABLE_OE3_SPECIAL_CERT_HANLING)
        // as discused in this ticket, https://devstack.vwgroup.com/jira/browse/IMAN-91182,
        // for this special case, specific certificate verfication should be skipped
        if((TLSCipherSuiteUseCasesSettings::CSUSLegacy == wolfCertEngine->GetCipherSuiteUseCase()) &&
           (ASN_NO_SIGNER_E == x509StorePtr->error) &&
           (3 == x509StorePtr->depth) &&
           (x509StorePtr->certs[2].length == x509StorePtr->certs[0].length) &&
           (0 == memcmp(x509StorePtr->certs[2].buffer, x509StorePtr->certs[0].buffer, x509StorePtr->certs[0].length)))
        {
            FND_LOG_INFO << "Revocation check: COMPLETED SUCCESSFULLY! Skip verification. Will be verified by duplicated certificate.";
            return WOLFSSL_SUCCESS;
        }
#endif // TLSAPI_ENABLE_OE3_SPEZIAL_CERT_HANLING
        isFailure = true;
    }

    bool ret = wolfCertEngine->postVerificationHandler(x509StorePtr, isFailure);
    if (!ret) {
        FND_LOG_ERROR << "Revocation check: FAILED! Post verification handler failed.";
        FND_LOG_ERROR << "preverify = " << preverify;
        FND_LOG_ERROR << "Printing certificate chain in PEM format:";
        for (int i = 0; i < count; i++)
        {
            unsigned char certInPemFormat[2048] = {0};
            int certInPemFormatActualSize = 0;
            int getCertPemFormatRetVal = wolfSSL_get_chain_cert_pem(chain, i, certInPemFormat, sizeof(certInPemFormat), &certInPemFormatActualSize);
            if (getCertPemFormatRetVal == WOLFSSL_SUCCESS)
            {
                int rawCertificateSize = wolfSSL_get_chain_length(chain, i);
                FND_LOG_ERROR << "Certificate index = " << i << " << raw certificate length (Bytes) = " << rawCertificateSize << " << PEM format length (Bytes) = " << certInPemFormatActualSize << ":";
            }
        }
        return WOLFSSL_FAILURE;
    }
    if (isFailure) {
        FND_LOG_ERROR << "Revocation check: FAILED! wolfSSL reported that the current certificate verification has failed.";
        FND_LOG_ERROR << "preverify = " << preverify;
        FND_LOG_ERROR << "Printing certificate chain in PEM format:";
        for (int i = 0; i < count; i++)
        {
            unsigned char certInPemFormat[2048] = {0};
            int certInPemFormatActualSize = 0;
            int getCertPemFormatRetVal = wolfSSL_get_chain_cert_pem(chain, i, certInPemFormat, sizeof(certInPemFormat), &certInPemFormatActualSize);
            if (getCertPemFormatRetVal == WOLFSSL_SUCCESS)
            {
                int rawCertificateSize = wolfSSL_get_chain_length(chain, i);
                FND_LOG_ERROR << "Certificate index = " << i << " << raw certificate length (Bytes) = " << rawCertificateSize << " << PEM format length (Bytes) = " << certInPemFormatActualSize << ":";
            }
        }
        return WOLFSSL_FAILURE;
    }

    FND_LOG_DEBUG << "Revocation check: COMPLETED SUCCESSFULLY!";

    return WOLFSSL_SUCCESS;
}