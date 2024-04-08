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

#include <cstdint>
#include "TLSResult.h"
#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "InetAddress.h"


#include "Logger.hpp"

using vwg::tls::TLSResult;
using vwg::tls::InetAddressFactory;
using vwg::tls::IInetAddressResult;
using vwg::tls::SPIInetAddress;
using vwg::tls::ITLSSocketFactory;
using vwg::tls::TLSServerSocketResult;
using vwg::tls::ITLSSessionEndpoint;

using vwg::tls::initTLSLib;
using vwg::tls::cleanupTLSLib;

int main()
{
    TLSResult<std::shared_ptr<ITLSSocketFactory>> socketFactory_rc = initTLSLib();
    if (socketFactory_rc.failed())
    {
        FND_LOG_ERROR << "error initializing socket factory: " << socketFactory_rc.getErrorCode();
        return socketFactory_rc.getErrorCode();
    }

    IInetAddressResult inet_rc = InetAddressFactory::makeIPAddress("127.0.0.1");
    if (inet_rc.failed())
    {
        FND_LOG_ERROR << "error initializing ip address: " << inet_rc.getErrorCode();
        return inet_rc.getErrorCode();
    }
    SPIInetAddress address = inet_rc.getPayload();

    TLSServerSocketResult serverSocket_rc = socketFactory_rc.getPayload()->createServerSocket(address, 1337,
                                                                                           "1001",
                                                                                           vwg::tls::CONFIDENTIAL_WITHPSK);
    if (serverSocket_rc.failed())
    {
        FND_LOG_ERROR << "error creating client socket: " << serverSocket_rc.getErrorCode();
        return serverSocket_rc.getErrorCode();
    }



    FND_LOG_INFO << "waiting for client to connect";
    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> session_ep_rc = serverSocket_rc.getPayload()->accept();
    if (session_ep_rc.failed())
    {
        FND_LOG_ERROR << "error accepting connection: " << session_ep_rc.getErrorCode();
        return session_ep_rc.getErrorCode();
    }
    FND_LOG_INFO << "received new connection from client";

    std::shared_ptr<ITLSSessionEndpoint> sessionEP = session_ep_rc.getPayload();

    FND_LOG_INFO << "Sending: \"Hello << Client!\"";
    Int32 bytesSent = sessionEP->send(reinterpret_cast<const Byte*>("Hello, Client!"), 15);
    if (0 > bytesSent)
    {
        FND_LOG_ERROR << "error sending data to tls session";
        return bytesSent;
    }

    FND_LOG_INFO << "Trying to read: \"Hello << Server!\"" ;
    uint8_t buffer[1024] = {0};
    Int32 receivedLen = sessionEP->receive(buffer, sizeof(buffer));
    if (receivedLen < 0)
    {
        FND_LOG_ERROR << "Error receiving data from session";
        return receivedLen;
    }
    if (receivedLen != 15)
    {
        FND_LOG_ERROR << "received size mismatched";
        return 1;
    }
    //FND_LOG_DEBUG << "buffer read: " << buffer;

    sessionEP->shutdown();
    cleanupTLSLib();

    FND_LOG_INFO << "Done!";

    return 0;
}
