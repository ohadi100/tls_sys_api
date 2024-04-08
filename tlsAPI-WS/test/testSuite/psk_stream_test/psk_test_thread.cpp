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
#include <iostream>
#include <thread>
#include <zconf.h>

#include "TLSLibApi.h"


#include "Logger.hpp"

#define NUM_OF_ARGS 5
#define NUM_OF_COLLECTIVE_ARGS 2
#define NUM_OF_THREAD 128
#define MAX_MESSAGE_LEN 1024

void taskSndRcv(std::shared_ptr<vwg::tls::ITLSSessionEndpoint> sessionEP, uint loop, const std::string &msgSend)
{
    // initializes every element in the array to zero.
    uint8_t buffer[MAX_MESSAGE_LEN] = {0};

    while (loop)
    {
        // *** send ***
        FND_LOG_INFO << "------------------ start send --------------" ;
        Int32 bytesSent = sessionEP->send((const Byte*)(msgSend.c_str()), msgSend.length());
        FND_LOG_INFO << "------------------ end send --------------" ;

        if (bytesSent < 0)
        {
            FND_LOG_ERROR << "CLIENT error sending data to session";
            break;
        }
        FND_LOG_INFO << "CLIENT send successfully: " << msgSend.c_str() ;


        // *** receive ***
        FND_LOG_INFO << "------------------ start receive --------------" ;
        Int32 receivedLen = sessionEP->receive(buffer, sizeof(buffer));
        FND_LOG_INFO << "------------------ end receive --------------" ;

        if (receivedLen < 0)
        {
            auto err = sessionEP->getPendingErrors();
            FND_LOG_ERROR << "CLIENT error receiving data from session: " << err;
            break;
        }
        FND_LOG_INFO << "CLIENT read successfully: "  <<buffer ;

        --loop;
    }
}

void taskClose(std::shared_ptr<vwg::tls::ITLSSessionEndpoint> sessionEP)
{
    srand (time(NULL));
    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 10));

    FND_LOG_INFO << "------------------ start shutdown --------------" ;
    sessionEP->shutdown();
    FND_LOG_INFO << "------------------ end shutdown --------------" ;
}


void thread_client(vwg::tls::TLSResult<std::shared_ptr<vwg::tls::ITLSSocketFactory>> socketFactory_rc, const vwg::tls::SPIInetAddress &ipAddress,
                   const uint16_t &port, const std::string &localDomainName, const vwg::tls::SecurityLevel &confidentiality,
                   const std::string &msgSend, const uint16_t loop)
{
    // createClientSocket
    vwg::tls::TLSClientSocketResult Socket_rc = socketFactory_rc.getPayload()->createClientSocket(ipAddress, port,
                                                                                                  localDomainName,
                                                                                                  confidentiality);
    if (Socket_rc.failed()) {
        FND_LOG_ERROR << "error creating client socket: " << Socket_rc.getErrorCode();
        return;
    }

    // connect
    auto begin = std::chrono::steady_clock::now();
    vwg::tls::TLSResult<std::shared_ptr<vwg::tls::ITLSSessionEndpoint>> session_ep_rc = Socket_rc.getPayload()->connect();
    auto end = std::chrono::steady_clock::now();
    FND_LOG_INFO << "Elapsed: " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << " [µs]";

    if (session_ep_rc.failed()) {
        FND_LOG_ERROR << "Error connecting to server: " << session_ep_rc.getErrorCode();
        return;
    }
    std::shared_ptr<vwg::tls::ITLSSessionEndpoint> sessionEP = session_ep_rc.getPayload();
    FND_LOG_INFO << "successfully connected to server";

    // create multi-threaded operation
    std::thread t1(taskSndRcv, sessionEP, loop, msgSend);
    std::thread t2(taskClose, sessionEP);

    if(t2.joinable())
    {
        FND_LOG_INFO << "start 2.join();" ;
        t2.join();
        FND_LOG_INFO << "end 2.join();" ;
    }
    if(t1.joinable())
    {
        FND_LOG_INFO << "start 1.join();" ;
        t1.join();
        FND_LOG_INFO << "end 1.join();" ;
    }
}


void send_rcv_server(std::shared_ptr<vwg::tls::ITLSSessionEndpoint> sessionEP, const std::string &msgSend)
{
    while(true)
    {
        // initializes every element in the array to zero.
        uint8_t buffer[MAX_MESSAGE_LEN] = {0};

        // *** receive ***
        Int32 receivedLen = sessionEP->receive(buffer, sizeof(buffer));
        if (0 >= receivedLen)
        {
            FND_LOG_ERROR << "SERVER error receiving data from session";
            break;
        }
        FND_LOG_INFO << "SERVER read successfully: " << buffer ;

        // *** send ***
        Int32 bytesSent = sessionEP->send((const Byte*)(msgSend.c_str()), msgSend.length());
        if (0 >= bytesSent)
        {
            FND_LOG_ERROR << "error sending data to tls session";
			sessionEP->shutdown();
            break;
        }
        FND_LOG_INFO << "SERVER send successfully: " << msgSend.c_str() ;
    }

    sessionEP->shutdown();
}

void thread_server(vwg::tls::TLSResult<std::shared_ptr<vwg::tls::ITLSSocketFactory>> socketFactory_rc, const vwg::tls::SPIInetAddress &ipAddress,
                   const uint16_t &port, const std::string &localDomainName, const vwg::tls::SecurityLevel &confidentiality, const std::string &msgSend, uint loop)
{
    (void)loop;
    
    // createServerSocket
    vwg::tls::TLSServerSocketResult Socket_rc = socketFactory_rc.getPayload()->createServerSocket(ipAddress, port, localDomainName, confidentiality);
    if (Socket_rc.failed())
    {
        return;
    }

    std::thread threads[NUM_OF_THREAD];
    uint idx = 0;

    while(true)
    {
        // accept
        vwg::tls::TLSResult<std::shared_ptr<vwg::tls::ITLSSessionEndpoint>> session_ep_rc = Socket_rc.getPayload()->accept();
        if (session_ep_rc.failed())
		{
            break;
        }
        std::shared_ptr<vwg::tls::ITLSSessionEndpoint> sessionEP = session_ep_rc.getPayload();

        //thread send_rcv_server
        threads[idx] = std::thread(send_rcv_server, sessionEP, msgSend);
        ++idx;
    }
}

int main(int argc, char *argv[])
{
    std::string ipAddress = argv[1], localDomainName = argv[2], msg;
    uint16_t port, loop;

    vwg::tls::TLSResult<std::shared_ptr<vwg::tls::ITLSSocketFactory>> socketFactory_rc = vwg::tls::initTLSLib();
    if (socketFactory_rc.failed())
    {
        FND_LOG_ERROR << "error initializing socket factory: " << socketFactory_rc.getErrorCode();
        return socketFactory_rc.getErrorCode();
    }

    vwg::tls::IInetAddressResult inet_rc = vwg::tls::InetAddressFactory::makeIPAddress(ipAddress);
    if (inet_rc.failed())
    {
        FND_LOG_ERROR << "error initializing ip address: "  << inet_rc.getErrorCode();
        return inet_rc.getErrorCode();
    }
    vwg::tls::SPIInetAddress address = inet_rc.getPayload();

    std::thread threads[NUM_OF_THREAD];

    for(auto idx = 0; idx < ((argc - NUM_OF_COLLECTIVE_ARGS) / NUM_OF_ARGS) ; ++idx)
    {
        bool isServer = strcmp(argv[(idx*NUM_OF_ARGS) + 3], "s") == 0;
        vwg::tls::SecurityLevel securityLevel = "1" == std::string(argv[idx*NUM_OF_ARGS + 4]) ? vwg::tls::CONFIDENTIAL_WITHPSK : vwg::tls::AUTHENTIC_WITHPSK;
        try
        {
            port = std::stoi(argv[(idx*NUM_OF_ARGS) + 5]);
            msg = argv[idx*NUM_OF_ARGS + 6];
            loop = std::stoi(argv[(idx*NUM_OF_ARGS) + 7]);
        }
        catch (...)
        {
            FND_LOG_ERROR << "error stoi";
            break;
        }

        if(isServer)
        {
            threads[idx] = std::thread(thread_server, socketFactory_rc, address, port, localDomainName, securityLevel, msg, loop);
        }
        else
        {
            threads[idx] = std::thread(thread_client, socketFactory_rc, address, port, localDomainName, securityLevel, msg, loop);
        }
    }

    for(auto& t : threads)
    {
        if(t.joinable())
        {
            t.join();
        }
    }

    vwg::tls::cleanupTLSLib();

    FND_LOG_DEBUG << "Done!";
    return 0;
}
