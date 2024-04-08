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

#include <gtest/gtest.h>

#include "IPInetAddressImpl.hpp"
#include "MockCertEngine.hpp"
#include "MockIOStreamIf.hpp"
#include "TLSClientCertImpl.hpp"
#include "TLSSocketFactory.h"
#include "MockTLSOcspHandler.hpp"

using namespace vwg::tls;
using namespace vwg::tls::impl;
using ::testing::Return;
using ::testing::ReturnRef;

MockCertEngine* CertEngineUT::mMockCertEngine;

class TLSClientCertImplTest : public ::testing::Test
{
public:
    std::shared_ptr<MockIOStreamIf> m_stream;
    std::string                     m_hostName;
    std::string                     m_certStoreId;
    std::string                     m_clientCertificateSetID;
    std::vector<HashSha256>         m_httpPublicKeyPinningHashs;
    bool                            m_revocationCheckEnabled;
    CipherSuiteIds                  m_cipherSuiteIds;
    TimeCheckTime                   m_checkTime;
    TLSClientCertImpl*              m_clientSocket;
    bool                            m_isFdManagedLocal;
    int                             m_timeDelta;
    std::shared_ptr<ITLSOcspHandler> m_ocspHandler;
    uint32_t                        m_ocspTimeoutMs;

    virtual void
    SetUp()
    {
        m_stream = std::make_shared<MockIOStreamIf>();
        m_ocspHandler = std::make_shared<MockTLSOcspHandlerUT>();
        MockTLSOcspHandlerUT::mMockTLSOcspHandler = new MockTLSOcspHandler();
        m_ocspTimeoutMs = 0;

        std::string             m_hostName;
        std::string             m_certStoreId;
        std::string             m_clientCertificateSetID;
        std::vector<HashSha256> m_httpPublicKeyPinningHashs;
        bool                    m_revocationCheckEnabled = false;
        CipherSuiteIds          m_cipherSuiteIds;

        m_timeDelta                   = 0;
        CertEngineUT::mMockCertEngine = new MockCertEngine(m_stream,
                                                           m_hostName,
                                                           m_certStoreId,
                                                           m_clientCertificateSetID,
                                                           m_httpPublicKeyPinningHashs,
                                                           m_timeDelta,
                                                           m_revocationCheckEnabled,
                                                           m_cipherSuiteIds,
                                                           CSUSDefault,
                                                           ALPN_DEFAULT,
                                                           m_ocspHandler,
                                                           m_ocspTimeoutMs);


        m_isFdManagedLocal = false;
        m_clientSocket     = new TLSClientCertImpl(m_stream,
                                               m_hostName,
                                               m_certStoreId,
                                               m_clientCertificateSetID,
                                               m_cipherSuiteIds,
                                               CSUSDefault,
                                               m_checkTime,
                                               m_httpPublicKeyPinningHashs,
                                               m_revocationCheckEnabled,
                                               m_ocspHandler,
                                               m_ocspTimeoutMs,
                                               m_isFdManagedLocal);
    }
    void
    expect_eq_AlpnMode(AlpnMode alpn1, AlpnMode alpn2)
    {
        EXPECT_EQ(alpn1.userDefinedALPNisUsed(), alpn2.userDefinedALPNisUsed());
        EXPECT_EQ(alpn1.getSupportedProtocols(), alpn2.getSupportedProtocols());
        EXPECT_EQ(alpn1.getUserDefinedAlpnSetting(), alpn2.getUserDefinedAlpnSetting());
    }

    void
    ExpectCheckAuthenticTimeCheckSuccess()
    {
        EXPECT_CALL(*CertEngineUT::mMockCertEngine, CheckAuthenticTimeCheck())
            .Times(1)
            .WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));
    }

    void
    TestDtorTLSSessionEndPointImpl()  // Checks the TLSSessionEndPointImpl
                                      // destructor
    {
        EXPECT_CALL(*CertEngineUT::mMockCertEngine, Close()).Times(1);
        if (m_isFdManagedLocal)
            EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(false));
    }

    virtual void
    TearDown()
    {
        delete CertEngineUT::mMockCertEngine;
        delete m_clientSocket;
    }
};

/**
 * @ingroup TLSClientCert_connect
 * @fn TEST_F(TLSClientCertImplTest, connectClientSuccess)
 * @brief connect client successfully
 */
TEST_F(TLSClientCertImplTest, connectClientSuccess)
{
    ExpectCheckAuthenticTimeCheckSuccess();
    EXPECT_CALL(*CertEngineUT::mMockCertEngine, DoSSLHandshake()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->connect();

    ASSERT_TRUE(res.succeeded());
    TestDtorTLSSessionEndPointImpl();
}

/**
 * @ingroup TLSClientCert_connect
 * @fn TEST_F(TLSClientCertImplTest, connectClientFailure)
 * @brief get failure when connecting client (getting RC_TLS_CERTSTORE_NOT_FOUND
 * error)
 */
TEST_F(TLSClientCertImplTest, connectClientFailure)
{
    m_clientSocket->m_isFdManagedLocal = true;

    ExpectCheckAuthenticTimeCheckSuccess();
    EXPECT_CALL(*CertEngineUT::mMockCertEngine, DoSSLHandshake())
        .Times(1)
        .WillOnce(Return(RC_TLS_ENGINE_CERTSTORE_NOT_FOUND));
    EXPECT_CALL(*m_stream, isOpen())
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));  // 1. m_clientSocket->connect() ->close ->isOpen()
    // 2.TLSClientCertImplDtor->isOpen() ,because m_isFdManagedLocal = true

    EXPECT_CALL(*m_stream, close()).Times(1);  // m_isFdManagedLocal = true;

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->connect();

    ASSERT_TRUE(res.failed());
    EXPECT_EQ(res.getErrorCode(), RC_TLS_CERTSTORE_NOT_FOUND);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, createSessionSuccess)
 * @brief create session successfully
 */
TEST_F(TLSClientCertImplTest, createSessionSuccess)
{
    ExpectCheckAuthenticTimeCheckSuccess();

    EXPECT_CALL(*CertEngineUT::mMockCertEngine, DoSSLHandshake()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->createSession();

    ASSERT_TRUE(res.succeeded());

    TestDtorTLSSessionEndPointImpl();
}

/**
 * @fn TEST_F(TLSClientCertImplTest, createSessionSuccess)
 * @brief get a failure when creating a session
 */
TEST_F(TLSClientCertImplTest, createSessionFailed)
{
    ExpectCheckAuthenticTimeCheckSuccess();
    EXPECT_CALL(*CertEngineUT::mMockCertEngine, DoSSLHandshake())
        .Times(1)
        .WillOnce(Return(RC_TLS_ENGINE_HANDSHAKE_FAILURE));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->createSession();

    EXPECT_EQ(res.getErrorCode(), RC_TLS_HANDSHAKE_FAILURE);

    ExpectCheckAuthenticTimeCheckSuccess();
    EXPECT_CALL(*CertEngineUT::mMockCertEngine, DoSSLHandshake())
        .Times(1)
        .WillOnce(Return(RC_TLS_ENGINE_BAD_CERTIFICATE));

    res = m_clientSocket->createSession();

    EXPECT_EQ(res.getErrorCode(), RC_TLS_BAD_CERTIFICATE);
}


/**
 * @fn TEST_F(TLSClientCertImplTest, createSessionSuccess)
 * @brief get a failure when creating a session and CheckAuthenticTimeCheck returns
 * RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED
 */
TEST_F(TLSClientCertImplTest, createSessionCheckTimeFailed)
{
    ExpectCheckAuthenticTimeCheckSuccess();
    EXPECT_CALL(*CertEngineUT::mMockCertEngine, DoSSLHandshake())
        .Times(1)
        .WillOnce(Return(RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->createSession();

    EXPECT_EQ(res.getErrorCode(), RC_TLS_AUTHENTIC_TIMECHECK_FAILED);
}
/**
 * @fn TEST_F(TLSClientCertImplTest, isConnectionSocket)
 * @brief check isConnectionSocket function
 */
TEST_F(TLSClientCertImplTest, isConnectionSocket)
{
    Boolean isConnection = true;

    EXPECT_CALL(*m_stream, isConnectionSocket()).Times(1).WillOnce(Return(isConnection));

    Boolean res = m_clientSocket->isConnectionSocket();

    EXPECT_EQ(res, isConnection);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, close)
 * @brief check close function
 */
TEST_F(TLSClientCertImplTest, close)
{
    TLSClientCertImpl clientSocket(m_stream,
                                   m_hostName,
                                   m_certStoreId,
                                   m_clientCertificateSetID,
                                   m_cipherSuiteIds,
                                   CSUSDefault,
                                   m_checkTime,
                                   m_httpPublicKeyPinningHashs,
                                   m_revocationCheckEnabled,
                                   m_ocspHandler,
                                   m_ocspTimeoutMs,
                                   true,
                                   ALPN_DEFAULT);

    EXPECT_CALL(*m_stream, isOpen()).Times(2).WillOnce(Return(true)).WillOnce(Return(false));
    EXPECT_CALL(*m_stream, close()).Times(1);

    clientSocket.close();
}

/**
 * @fn TEST_F(TLSClientCertImplTest, isClosed)
 * @brief check isClosed function
 */
TEST_F(TLSClientCertImplTest, isClosed)
{
    Boolean isOpen = true;
    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(isOpen));

    Boolean res = m_clientSocket->isClosed();
    EXPECT_EQ(res, !isOpen);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, isOpen)
 * @brief check isOpen function
 */
TEST_F(TLSClientCertImplTest, isOpen)
{
    Boolean isOpen = true;
    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(isOpen));

    Boolean res = m_clientSocket->isOpen();
    EXPECT_EQ(res, isOpen);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, getLocalPort)
 * @brief check getLocalPort function
 */
TEST_F(TLSClientCertImplTest, getLocalPort)
{
    UInt16 port = 8080;
    EXPECT_CALL(*m_stream, GetLocalPort()).Times(1).WillOnce(Return(port));

    UInt16 res = m_clientSocket->getLocalPort();
    EXPECT_EQ(res, port);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, getLocalInetAddress)
 * @brief check getLocalInetAddress function
 */
TEST_F(TLSClientCertImplTest, getLocalInetAddress)
{
    std::string              stringAddress = "1:2:3:4:5:6:7:8";
    vwg::tls::SPIInetAddress address       = std::make_shared<IPInetAddressImpl>(stringAddress);

    EXPECT_CALL(*m_stream, GetLocalAddress()).Times(1).WillOnce(Return(address));

    SPIInetAddress resAddress = m_clientSocket->getLocalInetAddress();
    EXPECT_EQ(resAddress->toString(), stringAddress);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, setSoTimeout)
 * @brief check setSoTimeout function
 */
TEST_F(TLSClientCertImplTest, setSoTimeout)
{
    Int32 timeout = 1000;

    EXPECT_CALL(*m_stream, setSoTimeout(timeout)).Times(1);

    m_clientSocket->setSoTimeout(timeout);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, getSocketFD)
 * @brief check getSocketFD function
 */
TEST_F(TLSClientCertImplTest, getSocketFD)
{
    EXPECT_CALL(*m_stream, GetFD()).Times(1);

    m_clientSocket->getSocketFD();
}


/**
 * @fn TEST_F(TLSClientCertImplTest, getUsedAlpnMode)
 * @brief check getUsedAlpnMode function
 */
TEST_F(TLSClientCertImplTest, getUsedAlpnMode)
{
    m_clientSocket->m_engine = std::make_shared<CertEngineUT>(m_stream);

    EXPECT_CALL(*CertEngineUT::mMockCertEngine, getUsedAlpnMode()).Times(1).WillOnce(ReturnRef(ALPN_HTTP2));
    expect_eq_AlpnMode(m_clientSocket->getUsedAlpnMode(), ALPN_HTTP2);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, getUsedProtocol)
 * @brief check getUsedProtocol function
 */
TEST_F(TLSClientCertImplTest, getUsedProtocol)
{
    m_clientSocket->m_engine = std::make_shared<CertEngineUT>(m_stream);

    IANAProtocol protocol = HTTP2;
    EXPECT_CALL(*CertEngineUT::mMockCertEngine, getUsedProtocol()).Times(1).WillOnce(Return(protocol));

    EXPECT_EQ(m_clientSocket->getUsedProtocol(), protocol);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, getWhenStreamIsNull)
 * @brief check getters functions when m_stream is nullptr
 */
TEST_F(TLSClientCertImplTest, getWhenStreamIsNull)
{
    m_clientSocket->m_stream = nullptr;

    EXPECT_EQ(m_clientSocket->getLocalInetAddress(), nullptr);
    EXPECT_EQ(m_clientSocket->getSocketFD(), 0);
    EXPECT_EQ(m_clientSocket->getLocalPort(), 0);

    EXPECT_EQ(m_clientSocket->isOpen(), false);
    EXPECT_EQ(m_clientSocket->isConnectionSocket(), false);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, getWhenEngineIsNull)
 * @brief check getters getUsedProtocol & getUsedAlpnMode functions when m_engine is nullptr
 */
TEST_F(TLSClientCertImplTest, getWhenEngineIsNull)
{
    EXPECT_EQ(m_clientSocket->getUsedProtocol(), NONE);
    expect_eq_AlpnMode(m_clientSocket->getUsedAlpnMode(), ALPN_OFF);
}
