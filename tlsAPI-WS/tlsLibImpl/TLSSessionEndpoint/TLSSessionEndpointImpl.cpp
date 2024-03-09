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

#include "TLSSessionEndpointImpl.hpp"
#include "TLSReturnCodes.h"
#include "TLSSession.h"

using vwg::tls::TLSReturnCodes;
using vwg::tls::TLSDropStatus;
using vwg::tls::TLSDropStatusListener;
using vwg::tls::TLSSessionStatusListener;

using vwg::tls::impl::ITLSEngine;
using vwg::tls::impl::TLSSessionEndpointImpl;
using namespace vwg::tls;


TLSSessionEndpointImpl::TLSSessionEndpointImpl(std::shared_ptr<IOStreamIf> stream, std::shared_ptr<ITLSEngine> engine, bool isFdManagedLocal, bool droppable)
                    : m_stream(stream)
                    , m_engine(engine)
                    , m_isFdManagedLocal(isFdManagedLocal)
#ifdef TLSAPI_WITH_DROP_SUPPORT
                    , m_droppable(droppable)
                    , m_dropInitiated(false)
                    , m_dropSendCompleted(false)
                    , m_dropReceived(false)
#endif
{
}

TLSSessionEndpointImpl::~TLSSessionEndpointImpl()
{
    close();
}

Int32 TLSSessionEndpointImpl::send(const Byte b[], const Int32 len)
{
    return send(b, 0, len);
}

Int32 TLSSessionEndpointImpl::send(const Byte b[], const UInt32 offset, const Int32 len)
{
#ifdef TLSAPI_WITH_DROP_SUPPORT
    if (m_droppable && m_dropInitiated)
    {
        addPendingError(RC_TLS_IO_ERROR);
        return -1;
    }
#endif

    Int32 actualLength;
    TLSEngineError res = m_engine->Send(b + offset, len, actualLength);
    TLSReturnCodes err = EngineToTLSReturnCode(res);

    if (err == RC_TLS_SUCCESSFUL)
        return actualLength;

    addPendingError(err);
    return -1;
}

Int32 TLSSessionEndpointImpl::flush()
{
    return 0;
}

Int32 TLSSessionEndpointImpl::available()
{
    return 0;
}

Int32 TLSSessionEndpointImpl::receive(Byte b[], const Int32 len)
{
    return receive(b, 0, len);
}

Int32 TLSSessionEndpointImpl::receive(Byte b[], const UInt32 offset, const Int32 len)
{
    Int32 actualLength;
    TLSEngineError res;
    TLSReturnCodes err;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    if (m_droppable && m_dropReceived)
    {
        res = RC_TLS_ENGINE_SUCCESSFUL;
        actualLength = 0;
    }
    else
#endif
    {
        do
        {
            res = m_engine->Receive(b + offset, len, actualLength);
        }
        while (false
#ifdef TLSAPI_WITH_DROP_SUPPORT
               || (m_droppable && m_dropInitiated && res == RC_TLS_ENGINE_SUCCESSFUL && actualLength > 0)
#endif
               );
    }

#ifdef TLSAPI_WITH_DROP_SUPPORT
    if (m_droppable && res == RC_TLS_ENGINE_SUCCESSFUL && actualLength == 0)
    {
        /* TLS drop received */
        m_dropReceived = true;
        if (!m_dropSendCompleted)
        {
            m_dropInitiated = true;
            res = m_engine->DropTLS();
            if (res == RC_TLS_ENGINE_SUCCESSFUL)
                m_dropSendCompleted = true;
        }
    }
#endif

    err = EngineToTLSReturnCode(res);

    if (err == RC_TLS_SUCCESSFUL)
        return actualLength;

    addPendingError(err);
    return -1;
}

TLSReturnCodes TLSSessionEndpointImpl::setBlocking(bool blocking)
{
    if (RC_TLS_ENGINE_SUCCESSFUL == m_engine->SetBlocking(blocking))
        return RC_TLS_SUCCESSFUL;
    return RC_TLS_IO_ERROR;
}

int TLSSessionEndpointImpl::getSocketFD()
{
    return m_stream->GetFD();
}

TLSReturnCodes TLSSessionEndpointImpl::shutdown()
{
    TLSEngineError res = m_engine->Shutdown();
    TLSReturnCodes tlsReturnCodes = EngineToTLSReturnCode(res);
    if (RC_TLS_SUCCESSFUL == tlsReturnCodes)
    {
        close();
    }
    return tlsReturnCodes;
}

Boolean TLSSessionEndpointImpl::isClosed()
{
    return !isOpen();
}

Boolean TLSSessionEndpointImpl::isOpen()
{
    return m_stream->isOpen();
}


///////// functions regarding drop-tls /////////

#ifdef TLSAPI_WITH_DROP_SUPPORT
Boolean TLSSessionEndpointImpl::isDroppable()
{
    return m_droppable;
}

TLSReturnCodes TLSSessionEndpointImpl::dropTLS()
{
    Byte buf[100];
    Int32 actualLength;
    TLSReturnCodes ret = RC_TLS_SUCCESSFUL;

    if (!m_droppable)
        return RC_TLS_DROPPING_NOTSUPPORTED;

    /* send drop request */
    m_dropInitiated = true;
    if (!m_dropSendCompleted)
    {
        TLSEngineError sendRes = m_engine->DropTLS();
        if (sendRes == RC_TLS_ENGINE_SUCCESSFUL)
            m_dropSendCompleted = true;
        else if (sendRes == RC_TLS_ENGINE_WOULD_BLOCK_READ)
            ret = RC_TLS_WOULD_BLOCK_READ;
        else if (sendRes == RC_TLS_ENGINE_WOULD_BLOCK_WRITE)
            ret = RC_TLS_WOULD_BLOCK_WRITE;
        else
            return EngineToTLSReturnCode(sendRes);
    }

    /* clear until drop response is received */
    actualLength = receive(buf, sizeof(buf));

    if (actualLength < 0)
    {
        TLSReturnCodes recvRet = (TLSReturnCodes) getPendingErrors();
        if (ret == RC_TLS_SUCCESSFUL)
            ret = recvRet;
    }

   if (ret == RC_TLS_SUCCESSFUL)
       m_engine->Close();

    return ret;
}
#endif

TLSDropStatus TLSSessionEndpointImpl::getDropState()
{
    return TLSDROP_DROPPED;
}
void TLSSessionEndpointImpl::setSessionStatusListener(TLSSessionStatusListener listener)
{
    (void)listener;
}

void TLSSessionEndpointImpl::setDropStatusListener(TLSDropStatusListener listener)
{
    (void)listener;
}

Boolean TLSSessionEndpointImpl::isConnectionSocket()
{
    return m_stream->GetConnectionType();
}

void TLSSessionEndpointImpl::close()
{
    m_engine->Close();
    if(m_isFdManagedLocal && isOpen())
    {
        m_stream->close();
    }
}

UInt16 TLSSessionEndpointImpl::getLocalPort()
{
    return m_stream->GetLocalPort();
}

SPIInetAddress TLSSessionEndpointImpl::getLocalInetAddress()
{
    return m_stream->GetLocalAddress();
}

std::string TLSSessionEndpointImpl::getRemoteDomainName()
{
    return m_engine->GetRemoteHintName();
}

std::string TLSSessionEndpointImpl::getLocalDomainName()
{
    return m_engine->GetHintName();
}

UInt16 TLSSessionEndpointImpl::getRemotePort()
{
    return  m_stream->GetRemotePort();
}

SPIInetAddress TLSSessionEndpointImpl::getRemoteInetAddress()
{
    return m_stream->GetRemoteAddress();
}

const AlpnMode& TLSSessionEndpointImpl::getUsedAlpnMode() const
{
    return m_engine->getUsedAlpnMode();
}

IANAProtocol TLSSessionEndpointImpl::getUsedProtocol() const
{
    return m_engine->getUsedProtocol();
}
