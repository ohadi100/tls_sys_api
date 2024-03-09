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

#ifndef _TLS_SESSION_ENDPOINT_IMPL_HPP_
#define _TLS_SESSION_ENDPOINT_IMPL_HPP_

#include <cstdint>
#include <memory>

#include "InetAddress.h"
#include "TLSSession.h"
#include "IOStreamIf.hpp"
#include "ITLSEngine.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{

class TLSSessionEndpointImpl : public ITLSSessionEndpoint
{
public:
    TLSSessionEndpointImpl(std::shared_ptr<IOStreamIf> stream, std::shared_ptr<ITLSEngine> engine, bool isFdManagedLocal, bool droppable=false);

    virtual ~TLSSessionEndpointImpl();

    /* ------------ write functions--------------------- */
    virtual	Int32 send(const Byte b[], const Int32 len);
    virtual Int32 send(const Byte b[], const UInt32 offset, const Int32 len);
    virtual Int32 flush();

    /* ------------ read functions--------------------- */

    virtual Int32 available();
    virtual Int32 receive(Byte b[], const Int32 len);
    virtual Int32 receive(Byte b[], const UInt32 offset, const Int32 len);

    virtual TLSReturnCodes setBlocking(bool blocking) override;
    virtual int getSocketFD() override;
    virtual TLSReturnCodes shutdown() override;

    ///////// functions from ITLSSocketBase /////////

    virtual Boolean isClosed() override;

    virtual Boolean isOpen()  override;

    ///////// functions regarding drop-tls /////////

#ifdef TLSAPI_WITH_DROP_SUPPORT
    virtual Boolean isDroppable() override;
    virtual TLSReturnCodes dropTLS() override;
#endif
    virtual TLSDropStatus getDropState();
    virtual void setSessionStatusListener(TLSSessionStatusListener listener);
    virtual void setDropStatusListener(TLSDropStatusListener listener);

    virtual Boolean isConnectionSocket() override;

    virtual void close() override;

    virtual UInt16 getLocalPort() override;

    virtual SPIInetAddress getLocalInetAddress() override;

    virtual std::string getRemoteDomainName()  override;

    virtual std::string getLocalDomainName()  override;

    virtual UInt16 getRemotePort() override;

    virtual SPIInetAddress getRemoteInetAddress() override;

    virtual const AlpnMode& getUsedAlpnMode() const  override;

    virtual IANAProtocol getUsedProtocol() const  override;

#ifndef UNIT_TEST
private:
#endif //UNIT_TEST

    std::shared_ptr<IOStreamIf> m_stream;
    std::shared_ptr<ITLSEngine> m_engine;
    bool m_isFdManagedLocal;
#ifdef TLSAPI_WITH_DROP_SUPPORT
    bool m_droppable;
    bool m_dropInitiated;
    bool m_dropSendCompleted;
    bool m_dropReceived;
#endif //TLSAPI_WITH_DROP_SUPPORT
};

using TLSSessionEndpointResult = TLSResult<SPITLSSessionEndpoint>;

} // namespace impl
} // namespace tls
} // namespace vwg

#endif /* _TLS_SESSION_ENDPOINT_IMPL_HPP_ */
