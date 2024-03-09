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
#include "TLSLibApiWrapper.hpp"

#include "TLSLibApi.h"
#include "TestIOStreamImpl.hpp"
#include "TestTLSOcspHandler.hpp"

using namespace vwg::tls;

std::shared_ptr<ITLSSocketFactory> g_socketFactory;

bool
TLSLibApiWrapper::InitTLSLib()
{
    TLSResult<std::shared_ptr<ITLSSocketFactory>> socketFactory_rc = initTLSLib();
    ASSERT_OBJ_NO_FAILED(socketFactory_rc);

    g_socketFactory = socketFactory_rc.getPayload();

    return true;
}

bool
TLSLibApiWrapper::CreateTLSClient(int         cipherSuitesUseCase,
                                  std::shared_ptr<vwg::tls::ITLSOcspHandler> const& handler,
                                  std::string ip,
                                  uint16_t    port,
                                  std::string hostName,
                                  std::string certStoreId,
                                  std::string clientCertificateSetID,
                                  std::vector<HashSha256> httpPublicKeyPinningHashes)
{
    AlpnMode                         alpnMode        = ALPN_OFF;

    std::shared_ptr<TLSConnectionSettings> connectionSettings =
        std::make_shared<TLSConnectionSettings>(alpnMode,
                                                handler,
                                                DEFAULT_OCSP_ONLINE_TIMEOUT_MS,
                                                (TLSCipherSuiteUseCasesSettings)(cipherSuitesUseCase));

    TimeCheckTime                            checkTime                  = CHECK_TIME_OFF;

    ASSERT_TRUE(createStreamConnection(ip, port))

    TLSClientSocketResult clientSocket_rc = g_socketFactory->createTlsClient(*connectionSettings,
                                                                             m_ioStream,
                                                                             hostName,
                                                                             certStoreId,
                                                                             clientCertificateSetID,
                                                                             checkTime,
                                                                             httpPublicKeyPinningHashes,
                                                                             true);
    ASSERT_OBJ_NO_FAILED(clientSocket_rc);

    m_clientSocket = clientSocket_rc.getPayload();

    return true;
}

bool
TLSLibApiWrapper::CreateTLSClient(std::string alpn_protocol,
                                  int         cipherSuitesUseCase,
                                  std::shared_ptr<vwg::tls::ITLSOcspHandler> const& handler,
                                  std::string ip,
                                  uint16_t    port,
                                  std::string hostName,
                                  std::string certStoreId,
                                  std::string clientCertificateSetID,
                                  std::vector<HashSha256> httpPublicKeyPinningHashes)
{
    TimeCheckTime                            checkTime                  = CHECK_TIME_OFF;

    ASSERT_TRUE(createStreamConnection(ip, port))

    AlpnMode                         alpnMode{std::vector<std::string>{alpn_protocol}};

    std::shared_ptr<TLSConnectionSettings> connectionSettings =
        std::make_shared<TLSConnectionSettings>(alpnMode,
                                                handler,
                                                DEFAULT_OCSP_ONLINE_TIMEOUT_MS,
                                                (TLSCipherSuiteUseCasesSettings)(cipherSuitesUseCase));

    TLSClientSocketResult clientSocket_rc = g_socketFactory->createTlsClient(*connectionSettings,
                                                                             m_ioStream,
                                                                             hostName,
                                                                             certStoreId,
                                                                             clientCertificateSetID,
                                                                             checkTime,
                                                                             httpPublicKeyPinningHashes,
                                                                             true);
    ASSERT_OBJ_NO_FAILED(clientSocket_rc);

    m_clientSocket = clientSocket_rc.getPayload();

    return true;
}

bool
TLSLibApiWrapper::Connect()
{
    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> session_ep_rc = m_clientSocket->connect();
    ASSERT_OBJ_NO_FAILED(session_ep_rc);

    m_sessionep = session_ep_rc.getPayload();

    return true;
}

bool
TLSLibApiWrapper::Send(uint8_t* data, uint32_t size)
{
    ASSERT_NOT_NULLPTR(data);

    return (m_sessionep->send((const Byte*)data, size) >= 0);
}

int
TLSLibApiWrapper::GetUsedProtocol()
{
    return (int)(m_sessionep->getUsedProtocol());
}

bool
TLSLibApiWrapper::Shutdown()
{
    // TODO: why in cert_based_client_alpn source the shutdown return code didnt check??
    // BUG: it seems like to take time to shutdown the socket. is it a known issue? for now, we dont check return code.

    m_sessionep->shutdown();

    return true;
}

void
TLSLibApiWrapper::CleanupTLSLib()
{
    cleanupTLSLib();
}

bool
TLSLibApiWrapper::createStreamConnection(std::string ip, uint16_t port)
{
    IInetAddressResult inet_rc = InetAddressFactory::makeIPAddress(ip);
    ASSERT_OBJ_NO_FAILED(inet_rc);

    m_ioStream = std::make_shared<impl::TestIOStreamImpl>(inet_rc.getPayload(), port);
    ASSERT_TRUE(m_ioStream->Connect());

    return true;
}