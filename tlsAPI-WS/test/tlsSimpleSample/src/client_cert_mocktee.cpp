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
#include <memory>

#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "TLSResult.h"
#include "InetAddress.h"
#include "TLSSockets.h"
#include "InternIOStream.hpp"


#include "Logger.hpp"

using vwg::tls::TLSResult;
using vwg::tls::ITLSSocketFactory;
using vwg::tls::InetAddressFactory;
using vwg::tls::IInetAddressResult;
using vwg::tls::SPIInetAddress;
using vwg::tls::TLSClientSocketResult;
using vwg::tls::ITLSSessionEndpoint;

using namespace vwg::tls;

using vwg::tls::initTLSLib;
using vwg::tls::cleanupTLSLib;

using std::string;

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


    std::shared_ptr<vwg::tls::impl::InternIOStream> ptr = std::make_shared<vwg::tls::impl::InternIOStream>(inet_rc.getPayload(), 1337);
    const CipherSuiteIds cipherSuiteIds = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    const TimeCheckTime checkTime = CHECK_TIME_OFF;
    std::vector<HashSha256> httpPublicKeyPinningHashs;


    TLSClientSocketResult clientSocket_rc =
        socketFactory_rc.getPayload()->createTlsClient(
            ptr,
            "server",
            "VKMS",
            "BASE",
            cipherSuiteIds,
            checkTime,
            httpPublicKeyPinningHashs);

    if (clientSocket_rc.failed())
    {
        FND_LOG_ERROR << "error creating client socket: " << clientSocket_rc.getErrorCode();
        return clientSocket_rc.getErrorCode();
    }

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> session_ep_rc = clientSocket_rc.getPayload()->connect();
    if (session_ep_rc.failed())
    {
        FND_LOG_ERROR << "Error connecting to server: " << session_ep_rc.getErrorCode();
        return session_ep_rc.getErrorCode();
    }
    std::shared_ptr<ITLSSessionEndpoint> sessionEP = session_ep_rc.getPayload();
    FND_LOG_INFO << "connected to server";
    const Byte sendbuf[] = "GET / HTTP/1.1\n"
                           "Host: server\n\n";


    FND_LOG_DEBUG << "Sending: \"Hello << Server!\"";
    sessionEP->send(sendbuf, sizeof(sendbuf));

    FND_LOG_DEBUG << "Trying to read: \"Hello << Client!\"";
    uint8_t buffer[1024];
    Int32 actualLength = sessionEP->receive(buffer, sizeof(buffer));
    if (actualLength < 0)
    {
        FND_LOG_ERROR << "Error receiving data from session";
        return actualLength;
    }

    FND_LOG_DEBUG << "buffer read: " << buffer;

    sessionEP->shutdown();
    cleanupTLSLib();

    FND_LOG_INFO << "Done!";
    return 0;
}
