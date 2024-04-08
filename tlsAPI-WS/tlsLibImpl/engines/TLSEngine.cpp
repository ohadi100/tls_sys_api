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

#include <string>

#include "TLSEngine.hpp"

using vwg::tls::impl::client_psk_cb;
using vwg::tls::impl::server_psk_cb;
using vwg::tls::impl::TLSEngine;
using vwg::tls::impl::TLSEngineContext;

using std::string;
using std::vector;

vwg::tls::TLSReturnCodes
vwg::tls::impl::EngineToTLSReturnCode(vwg::tls::impl::TLSEngineError err)
{
    switch (err) {
    case RC_TLS_ENGINE_SUCCESSFUL:
        return RC_TLS_SUCCESSFUL;
    case RC_TLS_ENGINE_WOULD_BLOCK_READ:
        return RC_TLS_WOULD_BLOCK_READ;
    case RC_TLS_ENGINE_WOULD_BLOCK_WRITE:
        return RC_TLS_WOULD_BLOCK_WRITE;
    case RC_TLS_ENGINE_PEER_CLOSED:
        return RC_TLS_PEER_CLOSED;
    case RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED:
        return RC_TLS_AUTHENTIC_TIMECHECK_FAILED;
    case RC_TLS_ENGINE_MAX_PERMITTED_DEVIATION:
        return RC_TLS_MAX_PERMITTED_DEVIATION;
    case RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN:
        return RC_TLS_SEND_AFTER_SHUTDOWN;
    case RC_TLS_ENGINE_NOT_SUPPORTED:
        return RC_TLS_DROPPING_NOTSUPPORTED;
    case RC_TLS_ENGINE_UNEXPECTED_MESSAGE:
        return RC_TLS_UNEXPECTED_MESSAGE;
    case RC_TLS_ENGINE_BAD_RECORD_MAC:
        return RC_TLS_BAD_RECORD_MAC;
    case RC_TLS_ENGINE_RECORD_OVERFLOW:
        return RC_TLS_RECORD_OVERFLOW;
    case RC_TLS_ENGINE_DECOMPRESSION_FAILURE:
        return RC_TLS_DECOMPRESSION_FAILURE;
    case RC_TLS_ENGINE_HANDSHAKE_FAILURE:
        return RC_TLS_HANDSHAKE_FAILURE;
    case RC_TLS_ENGINE_BAD_CERTIFICATE:
        return RC_TLS_BAD_CERTIFICATE;
    case RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE:
        return RC_TLS_UNSUPPORTED_CERTIFICATE;
    case RC_TLS_ENGINE_CERTIFICATE_REVOKED:
        return RC_TLS_CERTIFICATE_REVOKED;
    case RC_TLS_ENGINE_CERTIFICATE_EXPIRED:
        return RC_TLS_CERTIFICATE_EXPIRED;
    case RC_TLS_ENGINE_CERTIFICATE_UNKNOWN:
        return RC_TLS_CERTIFICATE_UNKNOWN;
    case RC_TLS_ENGINE_ILLEGAL_PARAMETER:
        return RC_TLS_ILLEGAL_PARAMETER;
    case RC_TLS_ENGINE_UNKNOWN_CA:
        return RC_TLS_UNKNOWN_CA;
    case RC_TLS_ENGINE_ACCESS_DENIED:
        return RC_TLS_ACCESS_DENIED;
    case RC_TLS_ENGINE_DECODE_ERROR:
        return RC_TLS_DECODE_ERROR;
    case RC_TLS_ENGINE_DECRYPT_ERROR:
        return RC_TLS_DECRYPT_ERROR;
    case RC_TLS_ENGINE_PROTOCOL_VERSION:
        return RC_TLS_PROTOCOL_VERSION;
    case RC_TLS_ENGINE_INSUFFICIENT_SECURITY:
        return RC_TLS_INSUFFICIENT_SECURITY;
    case RC_TLS_ENGINE_NO_RENEGOTIATION:
        return RC_TLS_NO_RENEGOTIATION;
    case RC_TLS_ENGINE_UNSUPPORTED_EXTENSION:
        return RC_TLS_UNSUPPORTED_EXTENSION;
    case RC_TLS_ENGINE_CERTIFICATE_UNOBTAINABLE:
        return RC_TLS_CERTIFICATE_UNOBTAINABLE;
    case RC_TLS_ENGINE_UNRECOGNIZED_NAME:
        return RC_TLS_UNRECOGNIZED_NAME;
    case RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE:
        return RC_TLS_BAD_CERTIFICATE_STATUS_RESPONSE;
    case RC_TLS_ENGINE_BAD_CERTIFICATE_HASH_VALUE:
        return RC_TLS_BAD_CERTIFICATE_HASH_VALUE;
    case RC_TLS_ENGINE_TEE_ACCESS_ERROR:
        return RC_TLS_TEE_ACCESS_ERROR;
    case RC_TLS_ENGINE_CERTSTORE_NOT_FOUND:
        return RC_TLS_CERTSTORE_NOT_FOUND;
    case RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID:
        return RC_TLS_UNKNOWN_CLIENT_CERTIFICATE_SET_ID;
    case RC_TLS_ENGINE_CLIENT_CERTIFICATE_SET_IDERROR:
        return RC_TLS_CLIENT_CERTIFICATE_SET_IDERROR;
    case RC_TLS_ENGINE_NO_APPLICATION_PROTOCOL:
        return RC_TLS_NO_APPLICATION_PROTOCOL;
    default:
        return RC_TLS_IO_ERROR;
    }
}

TLSEngineContext::TLSEngineContext(bool isDTLS, const std::string& hint)
  : m_isDTLS(isDTLS)
  , m_hint(hint)
{
}

const std::string&
TLSEngineContext::GetHint() const
{
    return m_hint;
}

const std::function<server_psk_cb>&
TLSEngineContext::GetServerCallback() const
{
    throw std::logic_error("Not implemented");
}

const std::function<client_psk_cb>&
TLSEngineContext::GetClientCallback() const
{
    throw std::logic_error("Not implemented");
}

TLSEngine::TLSEngine(std::shared_ptr<IOStreamIf> stream, std::shared_ptr<const TLSEngineContext> context)
  : m_stream(stream)
  , m_context(context)
  , m_connectionLoggingName(stream->getConnectionLoggingName())
{
}

TLSEngine::TLSEngine(std::shared_ptr<IOStreamIf> stream)
  : m_stream(stream)
  , m_connectionLoggingName(stream->getConnectionLoggingName())
{
}


TLSEngine::~TLSEngine()
{
    Close();
}

const std::shared_ptr<vwg::tls::IOStream>
TLSEngine::GetIOStream() const
{
    return m_stream;
}

void
TLSEngine::SetStream(std::shared_ptr<IOStreamIf> stream)
{
    m_stream = stream;
}

void
TLSEngine::Close()
{
    m_context = nullptr;
}

vwg::tls::impl::TLSEngineError
TLSEngine::SetBlocking(bool blocking)
{
    if (m_stream->SetBlocking(blocking)) {
        return RC_TLS_ENGINE_SUCCESSFUL;
    }
    return RC_TLS_ENGINE_FATAL_ERROR;
}