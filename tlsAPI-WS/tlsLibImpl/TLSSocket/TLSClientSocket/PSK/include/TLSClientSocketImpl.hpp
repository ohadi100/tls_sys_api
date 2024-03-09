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

#ifndef _TLS_CLIENT_SOCKET_IMPL_HPP_
#define _TLS_CLIENT_SOCKET_IMPL_HPP_

#include <functional>
#include <memory>

#include "TLSSockets.h"
#include "TLSSessionEndpointImpl.hpp"
#include "TLSEngine.hpp"
#include "IOStreamIf.hpp"

using vwg::tls::SPIInetAddress;


namespace vwg
{
namespace tls
{
namespace impl
{

class TLSClientSocketImpl : public ITLSClientSocket
{
public:
    TLSClientSocketImpl(std::shared_ptr<IOStreamIf> stream, const std::string & hint, SecurityLevel confidentiality,
            bool isFdManagedLocal = true, bool droppable = false);

    // The std::shared_ptr<IOStream> member is destroyed and its memory deallocated when the counter is 0.
    // option 1: the TLSServerSocketImpl owns the object. In TLSClientSocketImpl destruction - the counter reaches 0 and the IOstream is destroyed.
    // option 2: the user owns the object. In TLSClientSocketImpl destruction - The counter does not reaches 0 and the IOstream is not destroyed.
    ~TLSClientSocketImpl();

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> connect() override;

    void setSoTimeout(Int32 timeout) override;

    int getSocketFD() override;

    Boolean isConnectionSocket() override;

    void close() override;

    Boolean isClosed() override;

    Boolean isOpen() override;

    UInt16 getLocalPort() override;

    SPIInetAddress getLocalInetAddress() override;

    const AlpnMode& getUsedAlpnMode() const  override;

    IANAProtocol getUsedProtocol() const  override;
#ifndef UNIT_TEST
private:
#endif
    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> createSession();

    std::shared_ptr<IOStreamIf> m_stream;
    std::shared_ptr<ITLSEngine>     m_engine;
    std::string                     m_hint;
    SecurityLevel                   m_confidentiality;
    bool                            m_isFdManagedLocal;
#ifdef TLSAPI_WITH_DROP_SUPPORT
    bool                            m_droppable;
#endif
};

} // namespace impl
} // namespace tls
} // namespace vwg

#endif /* _TLS_CLIENT_SOCKET_IMPL_HPP_ */