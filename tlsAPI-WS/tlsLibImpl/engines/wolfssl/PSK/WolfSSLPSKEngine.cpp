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


#include "WolfSSLPSKEngine.hpp"
#include "WolfSSLCommon.hpp"

#include <cstdint>
#include <functional>
#include <vector>

#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>


enum AlertType { USER_CANCELED = 90 };

static constexpr char const* confidenitalCiphers = "PSK-AES128-GCM-SHA256";
static constexpr char const* authenticCiphers    = "PSK-NULL-SHA256";
using std::function;
using std::string;
using std::vector;
using vwg::tls::impl::TLSEngine;
using vwg::tls::impl::WolfSSLPSKEngine;
using namespace std;
using namespace vwg::tls;
using namespace vwg::tls::impl;


TLSEngineError
WolfSSLPSKEngine::WolfSSLToEngineError()
{
    WOLFSSL_ALERT_HISTORY history;
    int                   err = wolfSSL_get_error(m_ssl.get(), 0);

    char buffer[80];
    wolfSSL_ERR_error_string(err, buffer); 
    FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfssl error code: " << err << " << error message: " << buffer << ".";

    switch (err) {
    case WOLFSSL_ERROR_WANT_READ:
        return RC_TLS_ENGINE_WOULD_BLOCK_READ;
    case WOLFSSL_ERROR_WANT_WRITE:
        return RC_TLS_ENGINE_WOULD_BLOCK_WRITE;
    case WOLFSSL_ERROR_ZERO_RETURN:
        return RC_TLS_ENGINE_SUCCESSFUL;
    case SOCKET_PEER_CLOSED_E:
        return RC_TLS_ENGINE_PEER_CLOSED;

    default:
        if (wolfSSL_get_alert_history(m_ssl.get(), &history) == WOLFSSL_SUCCESS) {
            int code = -1;
            if (history.last_rx.level == alert_fatal)
                code = history.last_rx.code;
            else if (history.last_tx.level == alert_fatal)
                code = history.last_tx.code;
            switch (code) {
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
            case 48: /* TLS_ALERT_TYPE_UNKNOWN_CA */
                return RC_TLS_ENGINE_UNKNOWN_CA;
            case 49: /* TLS_ALERT_TYPE_ACCESS_DENIED */
                return RC_TLS_ENGINE_ACCESS_DENIED;
            case decode_error:
                return RC_TLS_ENGINE_DECODE_ERROR;
            case decrypt_error:
                return RC_TLS_ENGINE_DECRYPT_ERROR;
            case protocol_version:
                return RC_TLS_ENGINE_PROTOCOL_VERSION;
            case 71: /* TLS_ALERT_TYPE_INSUFFICIENT_SECURITY */
                return RC_TLS_ENGINE_INSUFFICIENT_SECURITY;
            case no_renegotiation:
                return RC_TLS_ENGINE_NO_RENEGOTIATION;
            case unsupported_extension:
                return RC_TLS_ENGINE_UNSUPPORTED_EXTENSION;
            case unrecognized_name:
                return RC_TLS_ENGINE_UNRECOGNIZED_NAME;
            case bad_certificate_status_response:
                return RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE;
            }
        }

        return RC_TLS_ENGINE_FATAL_ERROR;
    }
}

WolfSSLPSKEngine::WolfSSLPSKEngine(const std::shared_ptr<IOStreamIf>& stream,
                                   bool                               isServer,
                                   const std::string&                 hint,
                                   SecurityLevel                      confidentiality)
  : TLSEngine(stream)
  , m_ctx(nullptr)
  , m_ssl(nullptr)
  , m_isServer(isServer)
  , m_confidentiality(confidentiality)
  ,m_isDropped(false)
{
    m_keys.hint = hint;
}

TLSEngineError
WolfSSLPSKEngine::ctxInit()
{
    m_ctx = std::shared_ptr<WOLFSSL_CTX>(wolfSSL_CTX_new(wolfTLSv1_2_method()), wolfSSL_CTX_free);
    if (!m_ctx) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfSSL_CTX_new failed.";
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    wolfSSL_CTX_set_psk_server_callback(m_ctx.get(), ServerPSKCallback);
    wolfSSL_CTX_set_psk_client_callback(m_ctx.get(), ClientPSKCallback);

    if (wolfSSL_CTX_SetMinVersion(m_ctx.get(), WOLFSSL_TLSV1_2) != 1) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfSSL_CTX_SetMinVersion failed.";
        m_ctx = nullptr;
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    wolfSSL_SetIORecv(m_ctx.get(), recvIO);
    wolfSSL_SetIOSend(m_ctx.get(), sendIO);

    return RC_TLS_ENGINE_SUCCESSFUL;
}

TLSEngineError
WolfSSLPSKEngine::DoSSLHandshake()
{
    std::string    ciphers = (AUTHENTIC_WITHPSK == m_confidentiality) ? authenticCiphers : confidenitalCiphers;
    TLSEngineError returnVal;

    if (nullptr == m_ctx) {
        returnVal = ctxInit();
        if (RC_TLS_ENGINE_SUCCESSFUL != returnVal) {
            return returnVal;
        }
    }

    m_ssl = std::shared_ptr<WOLFSSL>(wolfSSL_new(m_ctx.get()), wolfSSL_free);
    if (!m_ssl) {
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    if (WOLFSSL_SUCCESS != wolfSSL_use_psk_identity_hint(m_ssl.get(), m_keys.hint.c_str())) {
        int res = wolfSSL_get_error(m_ssl.get(), 0);
        char buffer[80];
        wolfSSL_ERR_error_string(res, buffer); 
        FND_LOG_ERROR << "wolfSSL_use_psk_identity_hint failed: connectionName: " << m_connectionLoggingName.c_str() << " << wolfssl error code: " << res << " << error message: " << buffer << ".";
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    if (WOLFSSL_SUCCESS != wolfSSL_set_cipher_list(m_ssl.get(), ciphers.c_str())) {
        int res = wolfSSL_get_error(m_ssl.get(), 0);
        char buffer[80];
        wolfSSL_ERR_error_string(res, buffer); 
        FND_LOG_ERROR << "wolfSSL_set_cipher_list failed: connectionName: " << m_connectionLoggingName.c_str() << " << wolfssl error code: " << res << " << error message: " << buffer << ".";
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    wolfSSL_SetIOReadCtx(m_ssl.get(), (void*)m_stream.get());
    wolfSSL_SetIOWriteCtx(m_ssl.get(), (void*)m_stream.get());

    if ((WOLFSSL_SUCCESS !=
         wolfSSL_set_ex_data(m_ssl.get(), 0, const_cast<void*>(reinterpret_cast<const void*>(&m_keys)))) ||
        (WOLFSSL_SUCCESS != wolfSSL_set_ex_data(m_ssl.get(), 1, reinterpret_cast<void*>(this)))) {

        int res = wolfSSL_get_error(m_ssl.get(), 0);
        char buffer[80];
        wolfSSL_ERR_error_string(res, buffer); 
        FND_LOG_ERROR << "wolfSSL_set_ex_data failed: connectionName: " << m_connectionLoggingName.c_str() << " << wolfssl error code: " << res << " << error message: " << buffer << ".";
       
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    int  res;

    if (m_isServer) {
        res = wolfSSL_accept(m_ssl.get());
        if (WOLFSSL_SUCCESS != res) {
            FND_LOG_ERROR << "wolfSSL_accept failed.";
            return WolfSSLToEngineError();
        }
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfssl server handshake finished";
    } else {
        res = wolfSSL_connect(m_ssl.get());
        if (WOLFSSL_SUCCESS != res) {
            FND_LOG_ERROR << "wolfSSL_connect failed.";
            return WolfSSLToEngineError();
        }
        FND_LOG_DEBUG << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfssl client handshake finished";
    }

    return RC_TLS_ENGINE_SUCCESSFUL;
}

WolfSSLPSKEngine::~WolfSSLPSKEngine()
{
    Close();
}

TLSEngineError
WolfSSLPSKEngine::Send(const uint8_t* buffer, int32_t bufLength, int32_t& actualLength)
{
    if (nullptr == buffer) {
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    if (!m_ssl || wolfSSL_get_shutdown(m_ssl.get()) & WOLFSSL_SENT_SHUTDOWN) {
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

TLSEngineError
WolfSSLPSKEngine::Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength)
{
    if (nullptr == buffer) {
        return RC_TLS_ENGINE_FATAL_ERROR;
    }

    if (!m_ssl || wolfSSL_get_shutdown(m_ssl.get()) & WOLFSSL_SENT_SHUTDOWN) {
        if (!m_isDropped) {
            actualLength = 0;
            return RC_TLS_ENGINE_SPECIFIC_ERROR;
        }
    }

    actualLength = wolfSSL_recv(m_ssl.get(), buffer, bufLength, 0);
    if (actualLength > 0) {
        return RC_TLS_ENGINE_SUCCESSFUL;
    }

    return WolfSSLToEngineError();
}

TLSEngineError
WolfSSLPSKEngine::SetBlocking(bool blocking)
{
    TLSEngineError res = TLSEngine::SetBlocking(blocking);
    if (res != RC_TLS_ENGINE_SUCCESSFUL) {
        return res;
    }

    if (m_ssl) {
        wolfSSL_set_using_nonblock(m_ssl.get(), !blocking);
        return RC_TLS_ENGINE_SUCCESSFUL;
    }
    return RC_TLS_ENGINE_SPECIFIC_ERROR;
}

TLSEngineError
WolfSSLPSKEngine::Shutdown()
{
    if (!m_ssl || wolfSSL_get_shutdown(m_ssl.get()) & WOLFSSL_SENT_SHUTDOWN) {
        return RC_TLS_ENGINE_SUCCESSFUL;
    }

    int res = wolfSSL_shutdown(m_ssl.get());
    if (!m_isDropped && WOLFSSL_SHUTDOWN_NOT_DONE != res)
    {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". wolfSSL_shutdown returned " << res;
    }

    return RC_TLS_ENGINE_SUCCESSFUL;
}

#ifdef TLSAPI_WITH_DROP_SUPPORT
TLSEngineError
WolfSSLPSKEngine::DropTLS()
{
    m_isDropped = true;
    return Shutdown();
}
#endif

const std::string
WolfSSLPSKEngine::GetRemoteHintName() const
{
    return m_keys.remoteHint;
}

const std::string
WolfSSLPSKEngine::GetHintName() const
{
    return m_keys.hint;
}

void
WolfSSLPSKEngine::Close()
{
    Shutdown();

    m_keys.remoteHint.clear();
    m_keys.hint.clear();
    TLSEngine::Close();

    m_ssl.reset();
    m_ctx.reset();
}

const AlpnMode&
WolfSSLPSKEngine::getUsedAlpnMode() const
{
    return ALPN_OFF;
}

IANAProtocol
WolfSSLPSKEngine::getUsedProtocol() const
{
    return NONE;
}