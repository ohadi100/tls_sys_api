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
#include <iostream>
#include <thread>
#include <string>

#include "TLSResult.h"
#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "InetAddress.h"

#include "WaitableQueue.h"

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
using namespace std;

WaitableQueue g_queue;
bool g_stopThread = true;

void MessagesThread()
{
    string input;
    while(g_stopThread)
    {
        cin >> input;
        g_queue.Push(input);
    }
}

int main()
{
    vwg::tls::SecurityLevel securityLevel;
    string security;

    while(true) {
        cout << "PSK Server\n\n" << endl;

        cout << ":A     Authentic SecurityLevel\n"
                ":C     Confidential SecurityLevel" << endl;
        cin >> security;

        if(security == ":A"){
            securityLevel = vwg::tls::AUTHENTIC_WITHPSK;
            break;
        }
        else if (security == ":C"){
            securityLevel = vwg::tls::CONFIDENTIAL_WITHPSK;
            break;
        } else{
            cout << "invalid command" << endl;
        }
    }

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

    TLSServerSocketResult serverSocket_rc = socketFactory_rc.getPayload()->createServerSocket(address, 1338,
                                                                                           "1001",
                                                                                              securityLevel);
    if (serverSocket_rc.failed())
    {
        FND_LOG_ERROR << "error creating client socket: " << serverSocket_rc.getErrorCode();
        return serverSocket_rc.getErrorCode();
    }

    cout << "Waiting for connection" << endl;

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> session_ep_rc = serverSocket_rc.getPayload()->accept();
    if (session_ep_rc.failed())
    {
        FND_LOG_ERROR << "error accepting connection: " << session_ep_rc.getErrorCode();
        return session_ep_rc.getErrorCode();
    }
    //FND_LOG_INFO << "received new connection from client";

    cout << "\n"
            " __   ___  __   ___         ___  __           ___          __   __             ___  __  ___    __       \n"
            "|__) |__  /  ` |__  | \\  / |__  |  \\    |\\ | |__  |  |    /  ` /  \\ |\\ | |\\ | |__  /  `  |  | /  \\ |\\ | \n"
            "|  \\ |___ \\__, |___ |  \\/  |___ |__/    | \\| |___ |/\\|    \\__, \\__/ | \\| | \\| |___ \\__,  |  | \\__/ | \\| \n"
            "                                                                                                        " << endl;

    std::shared_ptr<ITLSSessionEndpoint> sessionEP = session_ep_rc.getPayload();

    string serverHello = "Hello im Server";
    sessionEP->send((vwg::types::Byte*)serverHello.c_str(), serverHello.size());

    uint8_t buffer[1024] = {0};
    Int32 actualLength = sessionEP->receive(buffer, sizeof(buffer));
    if (actualLength < 0)
    {
        FND_LOG_ERROR << "Error receiving data from session";
        return actualLength;
    }
    cout << buffer <<endl;

    sessionEP->setBlocking(false);
    thread messagesThread(MessagesThread);
    messagesThread.detach();

    string input;
    while(true)
    {
        memset(buffer,0,1024);
        Int32 receivedLen = sessionEP->receive(buffer, sizeof(buffer));
        if (receivedLen > 0)
        {
            string msg((char*)buffer);
            if (msg == ":quit")
            {
                FND_LOG_ERROR << "Got Shutdown message from client";
                break;
            }
            cout << buffer << endl;
        }

        g_queue.Pop(input);
        if (!input.empty())
        {
            sessionEP->send((vwg::types::Byte*)input.c_str(), input.size());
            input.clear();
        }
    }

    cleanupTLSLib();

    //FND_LOG_INFO << "Done!";
    cout << "\n"
            " __   __        ___    \n"
            "|  \\ /  \\ |\\ | |__     \n"
            "|__/ \\__/ | \\| |___ ...\n"
            "                       " << endl;

    return 0;
}
