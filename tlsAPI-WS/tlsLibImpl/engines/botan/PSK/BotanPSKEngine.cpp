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

#include "BotanPSKEngine.hpp"


#include <cstdint>
#include <functional>
#include <list>
#include <vector>

#include <botan/auto_rng.h>
#include <botan/exceptn.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/tls_server.h>
#include <sys/socket.h>

#include "Logger.hpp"

using vwg::tls::impl::BotanPSKEngine;
using vwg::tls::impl::CallbacksPSK;
using vwg::tls::impl::PolicyPSK;
using vwg::tls::impl::pskData;
using vwg::tls::impl::ClientCredsPSK;
using vwg::tls::impl::ServerCredsPSK;
using vwg::tls::impl::TLSEngine;
using vwg::tls::impl::TLSEngineError;
using namespace vwg::tls;
using namespace vwg::tls::impl;

//--------------ClientCredsPSK functions------------------------

ClientCredsPSK::ClientCredsPSK(BotanPSKEngine *engine)
    : Botan::Credentials_Manager(), m_engine(engine) {
  m_tlsTeeApi = vwg::tee::TLSTEEAPI::get_instance();
}

ClientCredsPSK::~ClientCredsPSK() {
  if (NULL != m_tlsTeeApi) {
    m_tlsTeeApi.reset();
  }
}

std::string ClientCredsPSK::psk_identity_hint(const std::string &type,
                                              const std::string &context) {
  (void)type;
  (void)context;
  return m_engine->m_keys.hint;
}

std::string ClientCredsPSK::psk_identity(const std::string &type,
                                         const std::string &context,
                                         const std::string &identity_hint) {
  (void)type;
  (void)context;
  m_engine->m_keys.remoteHint = identity_hint;
  return m_engine->m_keys.hint;
}

Botan::SymmetricKey ClientCredsPSK::psk(const std::string &type,
                                        const std::string &context,
                                        const std::string &identity) {
  (void)type;
  (void)context;
  (void)identity;
  vwg::tee::SessionKey keyData;

  FND_LOG_DEBUG << "*** CLIENT ***";
  // get a derived session key from a PSK via MockTEE
  if (!m_tlsTeeApi->get_psk(m_engine->m_keys.remoteHint, m_engine->m_keys.hint,
                            &keyData)) {
    throw BotanEngineError("PSK session key not found");
  }
  return Botan::SymmetricKey(keyData.value, keyData.length);
}

//--------------ServerCredsPSK functions------------------------

ServerCredsPSK::ServerCredsPSK(BotanPSKEngine *engine) : m_engine(engine) {
  m_tlsTeeApi = vwg::tee::TLSTEEAPI::get_instance();
}

std::string ServerCredsPSK::psk_identity_hint(const std::string &type,
                                              const std::string &context) {
  (void)type;
  (void)context;

  return m_engine->m_keys.hint;
}

Botan::SymmetricKey ServerCredsPSK::psk(const std::string &type,
                                        const std::string &context,
                                        const std::string &identity) {
  vwg::tee::SessionKey keyData;
  if (type == "tls-server" && context == "session-ticket") {
    throw BotanEngineError("session ticket unsupported");
  }

  FND_LOG_DEBUG << "*** SERVER ***";
  m_engine->m_keys.remoteHint = identity;

  if (!m_tlsTeeApi->get_psk(m_engine->m_keys.remoteHint, m_engine->m_keys.hint,
                            &keyData)) {
    throw BotanEngineError("PSK session key not found");
  }

  return Botan::SymmetricKey(keyData.value, keyData.length);
}

//--------------PolicyPSK functions------------------------
std::vector<std::string> PolicyPSK::allowed_ciphers() const {
  return {"AES-128/GCM"};
}

std::vector<std::string> PolicyPSK::allowed_key_exchange_methods() const {
  return {"PSK"};
}

std::vector<std::string> PolicyPSK::allowed_signature_hashes() const {
  return {"SHA-256"};
}

bool PolicyPSK::allow_tls10() const { return false; }

bool PolicyPSK::allow_tls11() const { return false; }

bool PolicyPSK::allow_tls12() const { return true; }

//--------------CallbacksPSK functions------------------------
void CallbacksPSK::tls_emit_data(const uint8_t buf[], size_t length) {
#ifdef TLSAPI_WITH_DROP_SUPPORT
  if (!m_engine->GetDropSendStarted())
#endif
  {
    m_engine->GetIOStream()->send(buf, length);
  }
}

void CallbacksPSK::tls_alert(Botan::TLS::Alert alert) {
  // handle a tls alert received from the tls server
  FND_LOG_ERROR << "alert: " << alert.type_string().c_str();
  if (alert.is_fatal() && alert.type() != Botan::TLS::Alert::CLOSE_NOTIFY) {
    m_engine->SetReceivedAlert(alert.type());
  }
}

void CallbacksPSK::tls_record_received(uint64_t rec, const uint8_t data[],
                                       size_t len) {
  (void)rec;
  m_engine->m_plaintext.insert(m_engine->m_plaintext.end(), data, data + len);
}

bool CallbacksPSK::tls_session_established(const Botan::TLS::Session &) {
  // the session with the tls server was established
  // return false to prevent the session from being cached, true to
  // cache the session in the configured session manager
  return false;
}

static const PolicyPSK g_policy;

//--------------BotanPSKEngine functions------------------------
BotanPSKEngine::BotanPSKEngine(std::shared_ptr<IOStreamIf> stream,
                               bool isServer, const std::string &hint,
                               SecurityLevel confidentiality)
    : TLSEngine(stream), m_isServer(isServer),
      m_receivedAlert(Botan::TLS::Alert::NULL_ALERT)
#ifdef TLSAPI_WITH_DROP_SUPPORT
      ,
      m_dropSendStarted(false)
#endif
{

#if defined(UNIT_TEST)
  m_channel.reset(
      new BotanClientUT(*m_callbacks, *m_session_mgr, *m_rng, g_policy, false));
#endif
  m_keys.hint = hint;
  if (confidentiality != CONFIDENTIAL_WITHPSK) {
    throw runtime_error(
        "Can't use Botan with security level different from Confidential");
  }
}

TLSEngineError
BotanPSKEngine::AlertToEngineError(Botan::TLS::Alert::Type type) {
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
BotanPSKEngine::feed()
{
    return feed(sizeof(m_buffer));
}

TLSEngineError
BotanPSKEngine::feed(size_t len) {

  size_t remaining = len;
  TLSEngineError res = RC_TLS_ENGINE_SUCCESSFUL;

  while ((remaining > 0) && (false == m_channel->is_closed()) &&
         (RC_TLS_ENGINE_SUCCESSFUL == res)) {
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
      if (true == m_channel->is_closed()) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". CHANNEL CLOSED";
      } else {
        try {
            remaining = std::min({m_channel->received_data(m_buffer, received),remaining - static_cast<size_t>(received)});
        } catch (Botan::TLS::TLS_Exception &e) {
          alert = e.type();
        } catch (Botan::Integrity_Failure &) {
          alert = Botan::TLS::Alert::BAD_RECORD_MAC;
        } catch (Botan::Decoding_Error &) {
          alert = Botan::TLS::Alert::DECODE_ERROR;
        } catch (...) {
          alert = Botan::TLS::Alert::INTERNAL_ERROR;
        }
      }
      if (alert != Botan::TLS::Alert::NULL_ALERT) {
        if (m_isServer) {
          FND_LOG_INFO << "connectionName: " << m_connectionLoggingName.c_str() << ". Server alert: " << alert;
        } else {
          FND_LOG_INFO << "connectionName: " << m_connectionLoggingName.c_str() << ". Client alert: " << alert;
        }
        res = AlertToEngineError(alert);
      }
    }
  }

  return res;
}

TLSEngineError BotanPSKEngine::checkTeeAndItsData() {
  std::shared_ptr<vwg::tee::TLSTEEAPI> m_tlsTeeApi =
      vwg::tee::TLSTEEAPI::get_instance();
  if (!m_tlsTeeApi) {
    FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Fatal error: can't access TEE";
    return RC_TLS_ENGINE_TEE_ACCESS_ERROR;
  }

  return RC_TLS_ENGINE_SUCCESSFUL;
}

TLSEngineError BotanPSKEngine::doSSLHandshakeClient() {
  TLSEngineError res = RC_TLS_ENGINE_UNKNOWN_ERROR;
  static const PolicyPSK policy;

  TLSEngineError tee_check_ret_code = checkTeeAndItsData();
  if (tee_check_ret_code != RC_TLS_ENGINE_SUCCESSFUL) {
    return tee_check_ret_code;
  }

  m_callbacks.reset(new CallbacksPSK(this));
  m_session_mgr.reset(new Botan::TLS::Session_Manager_Noop);
  m_creds_mgr.reset(new ClientCredsPSK(this));
  m_rng.reset(new Botan::AutoSeeded_RNG);

#ifndef UNIT_TEST
  m_channel.reset(new Botan::TLS::Client(*m_callbacks, *m_session_mgr,
                                         *m_creds_mgr, policy, *m_rng));
#endif

  while (false == m_channel->is_active()) {
    if (true == m_channel->is_closed()) {
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

TLSEngineError BotanPSKEngine::doSSLHandshakeServer() {
  TLSEngineError res = RC_TLS_ENGINE_UNKNOWN_ERROR;
  m_callbacks.reset(new CallbacksPSK(this));
  m_creds_mgr.reset(new ServerCredsPSK(this));
  m_rng.reset(new Botan::AutoSeeded_RNG);
  m_session_mgr.reset(new Botan::TLS::Session_Manager_Noop);
#ifndef UNIT_TEST
  m_channel.reset(new Botan::TLS::Server(
      *m_callbacks, *m_session_mgr, *m_creds_mgr, g_policy, *m_rng, false));
#endif

  while (false == m_channel->is_active()) {
    if (true == m_channel->is_closed()) {
      FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". doSSLHandshakeServer failed - m_channel closed";
      res = AlertToEngineError(m_receivedAlert);
      break;
    }

    res = feed();
    if (res != RC_TLS_ENGINE_SUCCESSFUL) {
      FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". feed failed (res: " << res << ")" ;
      break;
    }
  }

  return res;
}

TLSEngineError BotanPSKEngine::DoSSLHandshake() {
  if (true == m_isServer) {
    return doSSLHandshakeServer();
  }
  return doSSLHandshakeClient();
}

BotanPSKEngine::~BotanPSKEngine() { Close(); }

TLSEngineError BotanPSKEngine::Send(const uint8_t *buffer,
                                                    int32_t bufLength,
                                                    int32_t &actualLength) {
  if (m_channel->is_closed()) {
    return RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN;
  }

  if (bufLength > 0) {
    try {
      m_channel->send(buffer, bufLength);
    } catch (...) {
      return RC_TLS_ENGINE_FATAL_ERROR;
    }
  }

  actualLength = bufLength;
  return RC_TLS_ENGINE_SUCCESSFUL;
}

TLSEngineError BotanPSKEngine::Receive(uint8_t *buffer,
                                                       int32_t bufLength,
                                                       int32_t &actualLength) {
  TLSEngineError res = RC_TLS_ENGINE_SUCCESSFUL;
  if (m_channel->is_closed()) {
    return RC_TLS_ENGINE_SPECIFIC_ERROR;
  }

  while (m_plaintext.empty() && res == RC_TLS_ENGINE_SUCCESSFUL &&
         !m_channel->is_closed()) {
    res = feed(bufLength);
  }

  if (RC_TLS_ENGINE_SUCCESSFUL == res) {
    actualLength = std::min(bufLength, (int32_t)m_plaintext.size());
    memcpy(buffer, m_plaintext.data(), actualLength);
    m_plaintext.erase(m_plaintext.begin(), m_plaintext.begin() + actualLength);
    if (actualLength == 0 && m_channel->is_closed() &&
        m_receivedAlert != Botan::TLS::Alert::NULL_ALERT)
      res = AlertToEngineError(m_receivedAlert);
  }
  return res;
}

TLSEngineError BotanPSKEngine::Shutdown() {
    try {
        m_channel->close();
    } catch (...) {
        FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". Shutdown engine failed";
    }
    return RC_TLS_ENGINE_SUCCESSFUL;
}

#ifdef TLSAPI_WITH_DROP_SUPPORT

TLSEngineError BotanPSKEngine::DropTLS() {
    if (!m_dropSendStarted) {
        try {
            m_channel->closeNoReset();
        } catch (...) {
            FND_LOG_ERROR << "connectionName: " << m_connectionLoggingName.c_str() << ". DropTLS failed";
        }
        m_dropSendStarted = true;
    }
    return RC_TLS_ENGINE_SUCCESSFUL;
}

#endif

void BotanPSKEngine::Close() {
  Shutdown();
  m_plaintext.clear();
  m_keys.remoteHint.clear();
  m_keys.hint.clear();
}

const AlpnMode& BotanPSKEngine::getUsedAlpnMode() const
{
    return ALPN_OFF;
}

IANAProtocol BotanPSKEngine::getUsedProtocol() const
{
    return NONE;
}