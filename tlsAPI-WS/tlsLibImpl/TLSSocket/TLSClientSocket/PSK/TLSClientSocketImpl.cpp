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

#include "TLSClientSocketImpl.hpp"

#include "TLSApiTypes.h"
#include "TLSResult.h"

#include <functional>
#include <string>
#include "Logger.hpp"

#if defined(UNIT_TEST)
#include "MockPSKEngine.hpp"
using SelectedEngine = vwg::tls::impl::PSKEngineUT;
#elif defined(TLS_ENGINE_WOLFSSL)
#include "WolfSSLPSKEngine.hpp"
using SelectedEngine = vwg::tls::impl::WolfSSLPSKEngine;
#elif defined(TLS_ENGINE_BOTAN)
#include "BotanPSKEngine.hpp"
using SelectedEngine = vwg::tls::impl::BotanPSKEngine;
#else
#error "need a tls engine"
#endif

using vwg::tls::ITLSSessionEndpoint;
using vwg::tls::SocketType;
using vwg::tls::TLSResult;
using vwg::tls::impl::TLSClientSocketImpl;

using std::function;
using std::string;

using namespace vwg::tls;

TLSResult<std::shared_ptr<ITLSSessionEndpoint>>
TLSClientSocketImpl::createSession()
{
    TLSSessionEndpointResult res;

    m_engine            = std::make_shared<SelectedEngine>(m_stream, false /*client*/, m_hint, m_confidentiality);
    TLSReturnCodes hRes = EngineToTLSReturnCode(m_engine->DoSSLHandshake());
    if (hRes != RC_TLS_SUCCESSFUL)
    {
        FND_LOG_ERROR << "connectionName: " << m_stream->getConnectionLoggingName().c_str() << ". Client handshake failed";
        if (hRes == RC_TLS_IO_ERROR)
            return TLSSessionEndpointResult(RC_TLS_HANDSHAKE_FAILURE);
        else
            return TLSSessionEndpointResult(hRes);
    }
    return TLSSessionEndpointResult(std::make_shared<TLSSessionEndpointImpl>(m_stream, m_engine, m_isFdManagedLocal
#ifdef TLSAPI_WITH_DROP_SUPPORT
                                                                                , m_droppable
#endif
                                                                                ));
}

TLSClientSocketImpl::~TLSClientSocketImpl()
{
    close();
}

TLSClientSocketImpl::TLSClientSocketImpl(std::shared_ptr<IOStreamIf> stream,
                                         const std::string&          hint,
                                         SecurityLevel               confidentiality,
                                         bool                        isFdManagedLocal,
                                         bool                        droppable)
  : m_stream(stream)
  , m_engine(nullptr)
  , m_hint(hint)
  , m_confidentiality(confidentiality)
  , m_isFdManagedLocal(isFdManagedLocal)
#ifdef TLSAPI_WITH_DROP_SUPPORT
  , m_droppable(droppable)
#endif
{
}

void
TLSClientSocketImpl::setSoTimeout(Int32 timeout)
{
    if (nullptr != m_stream) {
        m_stream->setSoTimeout(timeout);
    }
}

int
TLSClientSocketImpl::getSocketFD()
{
    if (nullptr != m_stream) {
        return m_stream->GetFD();
    }
    return 0;
}

TLSResult<std::shared_ptr<ITLSSessionEndpoint>>
TLSClientSocketImpl::connect()
{
    TLSSessionEndpointResult res;

    res = createSession();
    if (res.failed()) {
        close();
        addPendingError(res.getErrorCode());
    }

    return res;
}

Boolean
TLSClientSocketImpl::isConnectionSocket()
{
    if (nullptr != m_stream) {
        return m_stream->GetConnectionType() == SocketType::SOCKETTYPE_STREAM;
    }
    return false;
}

void
TLSClientSocketImpl::close()
{
    if (m_isFdManagedLocal && isOpen() && m_stream) {
        m_stream->close();
    }
}

Boolean
TLSClientSocketImpl::isClosed()
{
    return !isOpen();
}

Boolean
TLSClientSocketImpl::isOpen()
{
    if (nullptr != m_stream) {
        return m_stream->isOpen();
    }
    return false;
}

UInt16
TLSClientSocketImpl::getLocalPort()
{
    if (nullptr != m_stream) {
        return m_stream->GetLocalPort();
    }
    return 0;
}

SPIInetAddress
TLSClientSocketImpl::getLocalInetAddress()
{
    if (nullptr != m_stream) {
        return m_stream->GetLocalAddress();
    }
    return nullptr;
}

const AlpnMode&
TLSClientSocketImpl::getUsedAlpnMode() const
{
    if (nullptr != m_engine) {
        return m_engine->getUsedAlpnMode();
    }
    return ALPN_OFF;
}

IANAProtocol
TLSClientSocketImpl::getUsedProtocol() const
{
    if (nullptr != m_engine) {
        return m_engine->getUsedProtocol();
    }
    return NONE;
}