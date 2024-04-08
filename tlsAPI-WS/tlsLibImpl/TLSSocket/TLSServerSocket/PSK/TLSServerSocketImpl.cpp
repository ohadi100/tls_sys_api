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

#include "TLSServerSocketImpl.hpp"


#include <exception>
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

using vwg::tls::IInetAddress;
using vwg::tls::SPIInetAddress;
using vwg::tls::TLSResult;
using vwg::tls::SocketType;
using vwg::tls::ITLSSessionEndpoint;
using vwg::tls::ITLSSocketBase;
using vwg::tls::IOStream;
using vwg::tls::impl::TLSServerSocketImpl;

using std::string;
using namespace vwg::tls;

TLSResult<std::shared_ptr<ITLSSessionEndpoint>> TLSServerSocketImpl::createSession(std::shared_ptr<InternIOStream> stream)
{
    TLSSessionEndpointResult res;

    std::shared_ptr<ITLSEngine> tempEngine = std::make_shared<SelectedEngine>(stream, true/*server*/, m_hint, m_confidentiality);
    TLSReturnCodes hRes = EngineToTLSReturnCode(tempEngine->DoSSLHandshake());
    if (hRes != RC_TLS_SUCCESSFUL)
    {
        FND_LOG_ERROR << "connectionName: " << stream->getConnectionLoggingName().c_str() << ". Server handshake failed";
        if (hRes == RC_TLS_IO_ERROR)
            return TLSSessionEndpointResult(RC_TLS_HANDSHAKE_FAILURE);
        else
            return TLSSessionEndpointResult(hRes);
    }
    return TLSSessionEndpointResult(std::make_shared<TLSSessionEndpointImpl>(stream, std::move(tempEngine), m_isFdManagedLocal
#ifdef TLSAPI_WITH_DROP_SUPPORT
                                       , m_droppable
#endif
                                       ));
}

TLSServerSocketImpl::TLSServerSocketImpl(std::shared_ptr<InternIOStream> stream, const string &hint, SecurityLevel confidentiality, bool isFdManagedLocal, bool droppable, bool isConnectionFd)
            : m_stream(stream)
            , m_hint(hint)
            , m_confidentiality(confidentiality)
            , m_isFdManagedLocal(isFdManagedLocal)
#ifdef TLSAPI_WITH_DROP_SUPPORT
            , m_droppable(droppable)
#endif
            , m_isConnectionFd(isConnectionFd)
{}

void TLSServerSocketImpl::setSoTimeout(__attribute__((unused)) Int32 timeout)
{

}

TLSServerSocketImpl::~TLSServerSocketImpl()
{
    close();
}

int TLSServerSocketImpl::getSocketFD()
{
    return m_stream->GetFD();
}

TLSResult<std::shared_ptr<ITLSSessionEndpoint>> TLSServerSocketImpl::accept()
{
    std::shared_ptr<InternIOStream> workingStream = m_stream;
    TLSSessionEndpointResult res;

    if (!m_isConnectionFd)
    {
        workingStream = m_stream->Accept();
        if (nullptr == workingStream)
        {
            res = TLSSessionEndpointResult(RC_TLS_ACCEPT_FAILED);
            addPendingError(res.getErrorCode());
            return res;
        }
    }

    res = createSession(workingStream);
    if (res.failed())
    {
        addPendingError(res.getErrorCode());
    }

    return res;
}

Boolean TLSServerSocketImpl::isConnectionSocket()
{
    return SocketType::SOCKETTYPE_STREAM == m_stream->GetConnectionType();
}

void TLSServerSocketImpl::close()
{
    if(m_isFdManagedLocal && isOpen())
    {
        m_stream->close();
    }
}

Boolean TLSServerSocketImpl::isClosed()
{
    return !isOpen();
}

Boolean TLSServerSocketImpl::isOpen()
{
    return m_stream->isOpen();
}

UInt16 TLSServerSocketImpl::getLocalPort()
{
    return m_stream->GetLocalPort();
}

SPIInetAddress TLSServerSocketImpl::getLocalInetAddress()
{
    return m_stream->GetLocalAddress();
}

const AlpnMode& TLSServerSocketImpl::getUsedAlpnMode() const
{
    return ALPN_OFF;
}

IANAProtocol TLSServerSocketImpl::getUsedProtocol() const
{
    return NONE;
}