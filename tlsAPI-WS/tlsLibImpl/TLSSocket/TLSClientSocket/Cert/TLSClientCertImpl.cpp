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

#include "TLSClientCertImpl.hpp"

#include "TLSApiTypes.h"
#include "TLSClientSocketImpl.hpp"
#include "TLSResult.h"
#include "TLSSocketFactory.h"

#include <cstdint>
#include <functional>
#include <string>

#include "Logger.hpp"

#if defined(UNIT_TEST)
#include "MockCertEngine.hpp"
using SelectedEngine = vwg::tls::impl::CertEngineUT;
#elif defined(TLS_ENGINE_WOLFSSL)
#include "WolfSSLCertEngine.hpp"
using SelectedEngine = vwg::tls::impl::WolfSSLCertEngine;
#elif defined(TLS_ENGINE_BOTAN)
#include "BotanCertEngine.hpp"
using SelectedEngine = vwg::tls::impl::BotanCertEngine;
#else
#error "need a tls engine"
#endif

using vwg::tls::ITLSSessionEndpoint;
using vwg::tls::SocketType;
using vwg::tls::TLSResult;
using vwg::tls::impl::TLSClientCertImpl;
using vwg::tls::impl::TLSClientSocketImpl;

using std::function;
using std::string;

using vwg::tls::CipherSuiteIds;
using vwg::tls::ClientCertificateSetID;

using vwg::tls::CertStoreID;
using vwg::tls::HashSha256;
using vwg::tls::TimeCheckTime;

using namespace vwg::tls;

TLSResult<std::shared_ptr<ITLSSessionEndpoint>>
TLSClientCertImpl::createSession()
{
    m_engine            = make_shared<SelectedEngine>(m_stream,
                                           m_hostName,
                                           m_certStoreId,
                                           m_clientCertificateSetID,
                                           m_httpPublicKeyPinningHashs,
                                           m_revocationCheckEnabled,
                                           m_cipherSuiteIds,
                                           m_cipherSuiteSettings,
                                           m_alpnMode,
                                           m_checkTime,
                                           m_ocspHandler,
                                           m_ocspTimeoutMs);
    TLSReturnCodes hRes = EngineToTLSReturnCode(m_engine->CheckAuthenticTimeCheck());
    if (RC_TLS_SUCCESSFUL != hRes) {
        return TLSSessionEndpointResult(hRes);
    }
    hRes = EngineToTLSReturnCode(m_engine->DoSSLHandshake());
    if (RC_TLS_SUCCESSFUL != hRes) {
        FND_LOG_ERROR << "connectionName: " << m_stream->getConnectionLoggingName().c_str() << ". Client handshake failed";
        if (RC_TLS_IO_ERROR == hRes) {
            return TLSSessionEndpointResult(RC_TLS_HANDSHAKE_FAILURE);
        }
        return TLSSessionEndpointResult(hRes);
    }
    return TLSSessionEndpointResult(std::make_shared<TLSSessionEndpointImpl>(m_stream, m_engine, m_isFdManagedLocal));
}

TLSClientCertImpl::TLSClientCertImpl(const std::shared_ptr<IOStreamIf>&         stream,
                                     const std::string&                         hostName,
                                     const CertStoreID&                         certStoreId,
                                     const ClientCertificateSetID&              clientCertificateSetID,
                                     const CipherSuiteIds&                      cipherSuiteIds,
                                     const TLSCipherSuiteUseCasesSettings&      cipherSuiteSettings,
                                     const TimeCheckTime&                       checkTime,
                                     const std::vector<HashSha256>&             httpPublicKeyPinningHashs,
                                     const bool                                 revocationCheckEnabled,
                                     const std::shared_ptr<ITLSOcspHandler>&    ocspHandler,
                                     const uint32_t                             ocspTimeoutMs,
                                     bool                                       isFdManagedLocal,
                                     const AlpnMode&                            alpnMode) noexcept
  : m_stream(stream)
  , m_engine(nullptr)
  , m_hostName(hostName)
  , m_certStoreId(certStoreId)
  , m_clientCertificateSetID(clientCertificateSetID)
  , m_cipherSuiteIds(cipherSuiteIds)
  , m_cipherSuiteSettings(cipherSuiteSettings)
  , m_checkTime(checkTime)
  , m_httpPublicKeyPinningHashs(httpPublicKeyPinningHashs)
  , m_revocationCheckEnabled(revocationCheckEnabled)
  , m_isFdManagedLocal(isFdManagedLocal)
  , m_alpnMode(alpnMode)
  , m_ocspHandler(ocspHandler)
  , m_ocspTimeoutMs(ocspTimeoutMs)
{
}

TLSClientCertImpl::~TLSClientCertImpl()
{
    close();
}


TLSResult<std::shared_ptr<ITLSSessionEndpoint>>
TLSClientCertImpl::connect()
{
    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res;

    res = createSession();
    if (res.failed()) {
        close();
        addPendingError(res.getErrorCode());
    }

    return res;
}

Boolean
TLSClientCertImpl::isConnectionSocket()
{
    if (nullptr != m_stream) {
        return m_stream->isConnectionSocket();
    }
    return false;
}

void
TLSClientCertImpl::close()
{
    if (m_isFdManagedLocal && isOpen() && m_stream) {
        m_stream->close();
    }
}

Boolean
TLSClientCertImpl::isClosed()
{
    return !isOpen();
}

Boolean
TLSClientCertImpl::isOpen()
{
    if (nullptr != m_stream) {
        return m_stream->isOpen();
    }
    return false;
}

UInt16
TLSClientCertImpl::getLocalPort()
{
    if (nullptr != m_stream) {
        return m_stream->GetLocalPort();
    }
    return 0;
}

SPIInetAddress
TLSClientCertImpl::getLocalInetAddress()
{
    if (nullptr != m_stream) {
        return m_stream->GetLocalAddress();
    }
    return nullptr;
}

void
TLSClientCertImpl::setSoTimeout(Int32 timeout)
{
    if (nullptr != m_stream) {
        m_stream->setSoTimeout(timeout);
    }
}

int
TLSClientCertImpl::getSocketFD()
{
    if (nullptr != m_stream) {
        return m_stream->GetFD();
    }
    return 0;
}

const AlpnMode&
TLSClientCertImpl::getUsedAlpnMode() const
{
    if (nullptr != m_engine) {
        return m_engine->getUsedAlpnMode();
    }
    return ALPN_OFF;
}

IANAProtocol
TLSClientCertImpl::getUsedProtocol() const
{
    if (nullptr != m_engine) {
        return m_engine->getUsedProtocol();
    }
    return NONE;
}