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
#include <string>
#include <chrono>
#include <thread>
#include <fstream>

#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "TLSResult.h"
#include "InetAddress.h"
#include "TLSSockets.h"
#include "IOStreamIf.hpp"
#include "InternIOStream.hpp"

#include "WaitableQueue.h"

#include "Logger.hpp"

using vwg::tls::TLSResult;
using vwg::tls::ITLSSocketFactory;
using vwg::tls::InetAddressFactory;
using vwg::tls::IInetAddressResult;
using vwg::tls::SPIInetAddress;
using vwg::tls::TLSClientSocketResult;
using vwg::tls::ITLSSessionEndpoint;
using vwg::tls::initTLSLib;
using vwg::tls::cleanupTLSLib;

using namespace std;
using namespace vwg::tls;

static WaitableQueue g_queue;

void InitParams(string& ip, string& port, string& service, vwg::tls::SecurityLevel& securityLevel)
{
    string security;

    cout << "PSK & Certificate client Demo" << endl;

    cout << "Enter IP address: " << flush;
    cin >> ip;

    cout << "Enter port: " << flush;
    cin >> port;

    while(true) {
        cout << ":P     PSK client\n"
                ":C     Certificate client" << endl;
        cin >> service;

        if(service == ":P") {
            while (true) {
                cout << ":A     Authentic SecurityLevel\n"
                        ":C     Confidential SecurityLevel" << endl;
                cin >> security;

                if (security == ":A") {
                    securityLevel = vwg::tls::AUTHENTIC_WITHPSK;
                    break;
                } else if (security == ":C") {
                    securityLevel = vwg::tls::CONFIDENTIAL_WITHPSK;
                    break;
                } else {
                    cout << "invalid command" << endl;
                }
            }
            break;
        }
        else if(service == ":C")
        {
            break;
        }
        else{
            cout << "invalid command" << endl;
        }
    }
}

void UserThread()
{
    string input;
    while(true)
    {
        cin >> input;
        g_queue.Push(input);
        if(input == ":quit")
        {
            return;
        }
    }
}

void CertSendRcv(std::shared_ptr<ITLSSessionEndpoint> sessionEP)
{
    const Byte sendbuf[] = "GET / HTTP/1.1\n"
                           "Host: server\n\n";

    FND_LOG_DEBUG << "Sending: \"Hello << Server!\"";
    auto startSend = chrono::steady_clock::now();
    sessionEP->send(sendbuf, sizeof(sendbuf));
    auto endSend = chrono::steady_clock::now();

    FND_LOG_DEBUG << "Trying to read: \"Hello << Client!\"";
    uint8_t buffer[1024] = {0};
    auto startRcv = chrono::steady_clock::now();
    sessionEP->receive(buffer, sizeof(buffer));
    auto endRcv = chrono::steady_clock::now();

    cout << buffer << endl;
    cout << "Delta timing in send: " << chrono::duration_cast<chrono::microseconds>(endSend - startSend).count() << " ms" << endl;
    cout <<  "Delta timing in receive: " << chrono::duration_cast<chrono::microseconds>(endRcv - startRcv).count() << " ms\n" << endl;
}


void PSKSendRcv(std::shared_ptr<ITLSSessionEndpoint> sessionEP)
{
    uint8_t buffer[1024] = {0};
    thread userThread(UserThread);

    string clientHello = "Hello im Client";
    sessionEP->send((vwg::types::Byte*)clientHello.c_str(), clientHello.size());

    sessionEP->setBlocking(false);
    while(true)
    {
        string input;
        g_queue.Pop(input);

        if (!input.empty())
        {
            if (input == ":quit")
            {
                sessionEP->send((vwg::types::Byte*)input.c_str(), input.size());
                break;
            }

            auto startSend = chrono::steady_clock::now();
            sessionEP->send((vwg::types::Byte*)input.c_str(), input.size());
            auto endSend = chrono::steady_clock::now();
            cout << "Delta timing in send: " << chrono::duration_cast<chrono::microseconds>(endSend - startSend).count() << " ms" << endl;
        }

        memset(buffer,0,1024);

        auto startRcv = chrono::steady_clock::now();
        Int32 actualLength = sessionEP->receive(buffer, sizeof(buffer));
        auto endRcv = chrono::steady_clock::now();
        if (actualLength > 0)
        {
            cout << buffer <<endl;
            cout <<  "Delta timing in receive: " << chrono::duration_cast<chrono::microseconds>(endRcv - startRcv).count() << " ms" << endl;
            input.clear();
        }
    }

    userThread.join();
}


void setup_vkms_truststore_and_client_cert(string certStoreId, string clientCertificateSetID, string serverCA_filename)
{
    char buff[255];

    system("mkdir -p /tmp/MockTeeStorage/TrustStore/");
    system("mkdir -p /tmp/MockTeeStorage/ClientCertStore");

    sprintf(buff, "cp ../auxiliary_files/user.crt /tmp/MockTeeStorage/ClientCertStore/%s_CERT.pem", clientCertificateSetID.c_str());
    system(buff);
    sprintf(buff, "cp ../auxiliary_files/%s /tmp/MockTeeStorage/TrustStore/%s_TS.pem", serverCA_filename.c_str(), certStoreId.c_str());
    system(buff);
    sprintf(buff, "cp ../auxiliary_files/user_key_to_use.pem  /tmp/MockTeeStorage/ClientCertStore/%s_KEY.pem", clientCertificateSetID.c_str());
    system(buff);
}

int main()
{
    TLSResult<std::shared_ptr<ITLSSocketFactory>> socketFactory_rc = initTLSLib();
    if (socketFactory_rc.failed())
    {
        FND_LOG_ERROR << "error initializing socket factory: " << socketFactory_rc.getErrorCode();
        return socketFactory_rc.getErrorCode();
    }

    string ip, port, service;
    vwg::tls::SecurityLevel securityLevel;
    InitParams(ip, port, service, securityLevel);

    IInetAddressResult inet_rc = InetAddressFactory::makeIPAddress(ip);
    if (inet_rc.failed())
    {
        FND_LOG_ERROR << "error initializing ip address: " << inet_rc.getErrorCode();
        return inet_rc.getErrorCode();
    }
    SPIInetAddress address = inet_rc.getPayload();

    TLSClientSocketResult clientSocket_rc;
    if (service == ":P")
    {
        cout << " __  __  __     __         __  __ __       __    \n"
                "|__)|__)|_  __ (_ |__| /\\ |__)|_ |  \\  |_/|_ \\_/ \n"
                "|   | \\ |__    __)|  |/--\\| \\ |__|__/  | \\|__ |  \n"
                "                                                " << endl;

        clientSocket_rc = socketFactory_rc.getPayload()->createClientSocket(inet_rc.getPayload(), stoi(port), "0001",
                                                                                securityLevel);

    }
    else if (service == ":C")
    {
        std::shared_ptr<vwg::tls::impl::IOStreamIf> ptr = make_shared<vwg::tls::impl::InternIOStream>(inet_rc.getPayload(), 1337);
        const CipherSuiteIds cipherSuiteIds = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        const TimeCheckTime checkTime = CHECK_TIME_OFF;
        const std::vector<HashSha256> httpPublicKeyPinningHashs;

        string certStoreId = "TRUSTSTORE_SERVERT_ROOT";
        string clientCertificateSetID = "MOS";
        string serverCA_filename = "apache2_serverCA.crt";

        setup_vkms_truststore_and_client_cert(certStoreId, clientCertificateSetID, serverCA_filename);

        clientSocket_rc = socketFactory_rc.getPayload()->createTlsClient(ptr, "server", certStoreId, clientCertificateSetID, cipherSuiteIds, checkTime, httpPublicKeyPinningHashs);
    }
    if (clientSocket_rc.failed())
    {
        FND_LOG_ERROR << "error creating client socket: " << clientSocket_rc.getErrorCode();
        return clientSocket_rc.getErrorCode();
    }

    std::shared_ptr<ITLSSessionEndpoint> sessionEP;
    std::string input;
    while(true)
    {
        cout << ":connect   connect to server\n"
                ":quit      quit" << endl;
        cin >> input;
        if (!input.empty())
        {
            if (input == ":connect")
            {
                cout << "\n"
                        "___  __              __     ___  __      __   __             ___  __  ___ \n"
                        " |  |__) \\ / | |\\ | / _`     |  /  \\    /  ` /  \\ |\\ | |\\ | |__  /  `  |  \n"
                        " |  |  \\  |  | | \\| \\__>     |  \\__/    \\__, \\__/ | \\| | \\| |___ \\__,  |" << endl;



                TLSResult<std::shared_ptr<ITLSSessionEndpoint>> session_ep_rc = clientSocket_rc.getPayload()->connect();
                if (session_ep_rc.failed())
                {
                    FND_LOG_ERROR << "Error connecting to server: " << session_ep_rc.getErrorCode();
                    return session_ep_rc.getErrorCode();
                }
                sessionEP = session_ep_rc.getPayload();
                //FND_LOG_INFO << "connected to server";
                cout << "             __  __            __   __ __      __     _____ __ \n"
                        "|__| /\\ |\\ ||  \\(_ |__| /\\ |_/|_   /  /  \\|\\/||__)|  |_  | |_  \n"
                        "|  |/--\\| \\||__/__)|  |/--\\| \\|__  \\__\\__/|  ||   |__|__ | |__ \n"
                        "                                                              " << endl;
                break;
            }
            else if (input == ":quit")
            {
                return 0;
            }
            else{
                cout << "invalid command" << endl;
            }
        }
    }

    if (service == ":C")
    {
        CertSendRcv(sessionEP);
    }
    else
    {
        PSKSendRcv(sessionEP);
    }

    sessionEP->shutdown();
    cleanupTLSLib();

    //FND_LOG_INFO << "Done!";
    cout << "\n"
            "           ___            ___  __   ___  __   __   ___       ___      \n"
            " /\\  |  | |__     |  | | |__  |  \\ |__  |__) /__` |__  |__| |__  |\\ | \n"
            "/~~\\ \\__/ |       |/\\| | |___ |__/ |___ |  \\ .__/ |___ |  | |___ | \\| \n"
            "                                                                      " << endl;
    return 0;
}

string readFile(string path)
{
    std::ifstream ifs(path);
    std::string content((std::istreambuf_iterator<char>(ifs)),
                        (std::istreambuf_iterator<char>()));
    return content;
}
