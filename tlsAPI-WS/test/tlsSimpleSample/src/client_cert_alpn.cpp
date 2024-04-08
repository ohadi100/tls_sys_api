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
#include <fstream>
#include <iostream>
#include <dirent.h>
#include <zconf.h>

#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "TLSResult.h"
#include "InetAddress.h"
#include "TLSSockets.h"
#include "InternIOStream.hpp"


#include "Logger.hpp"

using namespace vwg::tls;

static const std::string MOCK_TEE_STORAGE = "/tmp/MockTeeStorage";
static const std::string AUX_FILES = "../../auxiliary_files";

#define NUM_OF_PARAMS 6

/* This function is for ECC key/cert */
void ECC_setup_vkms_truststore_and_client_cert(std::string certStoreId, std::string clientCertificateSetID, std::string serverCA_filaname)
{
    char buff[255];

    sprintf(buff, "mkdir -p %s/TrustStore/", MOCK_TEE_STORAGE.c_str());
    system(buff);
    sprintf(buff, "mkdir -p %s/ClientCertStore/", MOCK_TEE_STORAGE.c_str());
    system(buff);

    sprintf(buff, "cp %s/ECC_CLIENT.pem %s/ClientCertStore/%s_CERT.pem", AUX_FILES.c_str(), MOCK_TEE_STORAGE.c_str(), clientCertificateSetID.c_str());
    system(buff);
    sprintf(buff, "cp %s/WebRadioRootCA/%s %s/TrustStore/%s_TS.pem", AUX_FILES.c_str(), serverCA_filaname.c_str(), MOCK_TEE_STORAGE.c_str(), certStoreId.c_str());
    system(buff);
    sprintf(buff, "cp %s/ECC_CLIENT.key  %s/ClientCertStore/%s_KEY.pem", AUX_FILES.c_str(), MOCK_TEE_STORAGE.c_str(), clientCertificateSetID.c_str());
    system(buff);
}

int main (int argc, char *argv[])
{
    if(argc < NUM_OF_PARAMS) {
        FND_LOG_ERROR << "argc error";
        return 0;
    }

    std::string ipAddress = argv[1];
    std::string port = argv[2];
    std::string hostName = argv[3];
    std::string serverCA_filename = argv[4];
    std::vector<std::string> protocolsVec;

    for(int i = 5; i < argc; ++i)
    {
        protocolsVec.emplace_back(argv[i]);
    }
    AlpnMode alpnMode{protocolsVec};

    TLSConnectionSettings connectionSettings(alpnMode);

    TLSResult<std::shared_ptr<ITLSSocketFactory>> socketFactory_rc = initTLSLib();
    if (socketFactory_rc.failed())
    {
        FND_LOG_ERROR << "error initializing socket factory: " << socketFactory_rc.getErrorCode();
        return socketFactory_rc.getErrorCode();
    }

    IInetAddressResult inet_rc = InetAddressFactory::makeIPAddress(ipAddress);
    if (inet_rc.failed())
    {
        FND_LOG_ERROR << "error initializing ip address: " << inet_rc.getErrorCode();
        return inet_rc.getErrorCode();
    }
    SPIInetAddress address = inet_rc.getPayload();

    std::shared_ptr<impl::InternIOStream> ptr = std::make_shared<impl::InternIOStream>(inet_rc.getPayload(), stoi(port));
    if (!ptr->Connect())
    {
        FND_LOG_ERROR << "Stream connected failed";
        return -1;
    }

    const CipherSuiteIds cipherSuiteIds = "";
    const TimeCheckTime checkTime = CHECK_TIME_OFF;
    const std::vector<HashSha256> httpPublicKeyPinningHashs;

    std::string certStoreId = "TRUSTSTORE_SERVERT_ROOT";
    std::string clientCertificateSetID = "MOS";

    ECC_setup_vkms_truststore_and_client_cert(certStoreId, clientCertificateSetID, serverCA_filename);

    TLSClientSocketResult clientSocket_rc =
            socketFactory_rc.getPayload()->createTlsClient(connectionSettings, ptr, hostName,
                                                           certStoreId, clientCertificateSetID, checkTime, httpPublicKeyPinningHashs, true);
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

    IANAProtocol usedServerProtocol = sessionEP->getUsedProtocol();
    std::cout << "getUsedProtocol is " << usedServerProtocol << std::endl;

    sessionEP->shutdown();
    cleanupTLSLib();

    FND_LOG_INFO << "********** Done! **********";
    return 0;
}