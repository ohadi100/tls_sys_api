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
#include "MockIOStreamIf.hpp"
#include "MockPSKEngine.hpp"
#include "TLSClientSocketImpl.hpp"
#include "TLSSocketFactory.h"

using namespace vwg::tls;
using namespace vwg::tls::impl;

using ::testing::Return;
using ::testing::ReturnRef;

MockPSKEngine* PSKEngineUT::mMockPSKEngine;

class TLSClientSocketImplTest : public ::testing::Test
{
public:
    std::shared_ptr<MockIOStreamIf>      m_stream;
    std::shared_ptr<TLSClientSocketImpl> m_clientSocket;
    std::string                          m_hint;
    SecurityLevel                        m_confidentiality;
    // SocketType                      m_socketType;
    bool m_isFdManagedLocal;

    virtual void
    SetUp()
    {
        m_stream           = std::make_shared<MockIOStreamIf>();
        m_hint             = "1001";
        m_confidentiality  = AUTHENTIC_WITHPSK;
        m_isFdManagedLocal = false;

        m_clientSocket = std::make_shared<TLSClientSocketImpl>(m_stream, m_hint, m_confidentiality, m_isFdManagedLocal);

        PSKEngineUT::mMockPSKEngine = new MockPSKEngine(m_stream, m_isFdManagedLocal, m_hint, m_confidentiality);
    }

    void
    expect_eq_AlpnMode(AlpnMode alpn1, AlpnMode alpn2)
    {
        EXPECT_EQ(alpn1.userDefinedALPNisUsed(), alpn2.userDefinedALPNisUsed());
        EXPECT_EQ(alpn1.getSupportedProtocols(), alpn2.getSupportedProtocols());
        EXPECT_EQ(alpn1.getUserDefinedAlpnSetting(), alpn2.getUserDefinedAlpnSetting());
    }

    void
    DtorTLSSessionEndPointImpl()  // Checks the TLSSessionEndPointImpl destructor
    {
        EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Close()).Times(1);
    }

    virtual void
    TearDown()
    {
        delete PSKEngineUT::mMockPSKEngine;
    }
};

/**
 * @ingroup TLSClientSocket_connect
 * @fn TEST_F(TLSClientSocketImplTest, connectClientSuccess)
 * @brief connect client successfully
 */
TEST_F(TLSClientSocketImplTest, connectClientSuccess)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->connect();

    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);

    DtorTLSSessionEndPointImpl();
}

/**
 * @ingroup TLSClientSocket_connect
 * @fn TEST_F(TLSClientSocketImplTest, connectClientFailure)
 * @brief get failure when connecting client (getting RC_TLS_CERTSTORE_NOT_FOUND
 * error)
 */
TEST_F(TLSClientSocketImplTest, connectClientFailure)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake())
        .Times(1)
        .WillOnce(Return(RC_TLS_ENGINE_CERTSTORE_NOT_FOUND));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->connect();

    ASSERT_TRUE(res.failed());
    EXPECT_EQ(res.getErrorCode(), RC_TLS_CERTSTORE_NOT_FOUND);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, createSessionSuccess)
 * @brief create a session successfully
 */
TEST_F(TLSClientSocketImplTest, createSessionSuccess)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->createSession();

    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);
    DtorTLSSessionEndPointImpl();
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, createSessionFailure)
 * @brief get failure when create a session (getting RC_TLS_CERTSTORE_NOT_FOUND
 * error)
 */
TEST_F(TLSClientSocketImplTest, createSessionFailure)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake())
        .Times(1)
        .WillOnce(Return(RC_TLS_ENGINE_CERTSTORE_NOT_FOUND));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_clientSocket->createSession();

    ASSERT_TRUE(res.failed());
    EXPECT_EQ(res.getErrorCode(), RC_TLS_CERTSTORE_NOT_FOUND);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, setSoTimeout)
 * @brief check setSoTimeout function
 */
TEST_F(TLSClientSocketImplTest, setSoTimeout)
{
    Int32 timeout = 1000;

    EXPECT_CALL(*m_stream, setSoTimeout(timeout)).Times(1);
    m_clientSocket->setSoTimeout(timeout);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, getSocketFD)
 * @brief check getSocketFD function
 */
TEST_F(TLSClientSocketImplTest, getSocketFD)
{
    int fd = 2;

    EXPECT_CALL(*m_stream, GetFD()).Times(1).WillOnce(Return(fd));
    int resFd = m_clientSocket->getSocketFD();
    EXPECT_EQ(resFd, fd);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, isConnectionSocket)
 * @brief check isConnectionSocket function
 */
TEST_F(TLSClientSocketImplTest, isConnectionSocket)
{
    Boolean isConnectionSocket;

    EXPECT_CALL(*m_stream, GetConnectionType()).Times(1).WillOnce(Return(SocketType::SOCKETTYPE_STREAM));
    isConnectionSocket = m_clientSocket->isConnectionSocket();
    EXPECT_TRUE(isConnectionSocket);

    EXPECT_CALL(*m_stream, GetConnectionType()).Times(1).WillOnce(Return(SocketType::SOCKETTYPE_DATAGRAM));
    isConnectionSocket = m_clientSocket->isConnectionSocket();
    EXPECT_FALSE(isConnectionSocket);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, close)
 * @brief check close function
 */
TEST_F(TLSClientSocketImplTest, close)
{
    m_clientSocket->m_isFdManagedLocal = true;

    EXPECT_CALL(*m_stream, isOpen()).Times(2).WillOnce(Return(true)).WillOnce(Return(false));  // 1.for close(), 2.dtor
    EXPECT_CALL(*m_stream, close()).Times(1);
    m_clientSocket->close();
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, isClosed)
 * @brief check isClosed function
 */
TEST_F(TLSClientSocketImplTest, isClosed)
{
    Boolean isOpen = true;
    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(isOpen));

    Boolean isClosedRes = m_clientSocket->isClosed();
    EXPECT_NE(isClosedRes, isOpen);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, isOpen)
 * @brief check isOpen function
 */
TEST_F(TLSClientSocketImplTest, isOpen)
{
    Boolean isOpen = true;
    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(isOpen));

    Boolean isOpenRes = m_clientSocket->isOpen();
    EXPECT_EQ(isOpenRes, isOpen);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, getLocalPort)
 * @brief check getLocalPort function
 */
TEST_F(TLSClientSocketImplTest, getLocalPort)
{
    UInt16 port = 8080;
    EXPECT_CALL(*m_stream, GetLocalPort()).Times(1).WillOnce(Return(port));

    UInt16 portRes = m_clientSocket->getLocalPort();
    EXPECT_EQ(portRes, port);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, getLocalInetAddress)
 * @brief check getLocalInetAddress function
 */
TEST_F(TLSClientSocketImplTest, getLocalInetAddress)
{
    std::string              stringAddress = "1:2:3:4:5:6:7:8";
    vwg::tls::SPIInetAddress address       = std::make_shared<IPInetAddressImpl>(stringAddress);

    EXPECT_CALL(*m_stream, GetLocalAddress()).Times(1).WillOnce(Return(address));
    ;
    SPIInetAddress resAddress = m_clientSocket->getLocalInetAddress();
    EXPECT_EQ(resAddress->toString(), stringAddress);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, getUsedAlpnMode)
 * @brief check getUsedAlpnMode function
 */
TEST_F(TLSClientSocketImplTest, getUsedAlpnMode)
{
    m_clientSocket->m_engine = std::make_shared<PSKEngineUT>(m_stream, false /*client*/, m_hint, m_confidentiality);

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, getUsedAlpnMode()).Times(1).WillOnce(ReturnRef(ALPN_HTTP2));
    expect_eq_AlpnMode(m_clientSocket->getUsedAlpnMode(), ALPN_HTTP2);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, getUsedProtocol)
 * @brief check getUsedProtocol function
 */
TEST_F(TLSClientSocketImplTest, getUsedProtocol)
{
    m_clientSocket->m_engine = std::make_shared<PSKEngineUT>(m_stream, false /*client*/, m_hint, m_confidentiality);

    IANAProtocol protocol = HTTP2;
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, getUsedProtocol()).Times(1).WillOnce(Return(protocol));

    EXPECT_EQ(m_clientSocket->getUsedProtocol(), protocol);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, getWhenStreamIsNull)
 * @brief check getters functions when m_stream is nullptr
 */
TEST_F(TLSClientSocketImplTest, getWhenStreamIsNull)
{
    m_clientSocket->m_stream = nullptr;

    EXPECT_EQ(m_clientSocket->getLocalInetAddress(), nullptr);
    EXPECT_EQ(m_clientSocket->getSocketFD(), 0);
    EXPECT_EQ(m_clientSocket->getLocalPort(), 0);

    EXPECT_EQ(m_clientSocket->isOpen(), false);
    EXPECT_EQ(m_clientSocket->isConnectionSocket(), false);
}

/**
 * @fn TEST_F(TLSClientSocketImplTest, getWhenEngineIsNull)
 * @brief check getters getUsedProtocol & getUsedAlpnMode functions when m_engine is nullptr
 */
TEST_F(TLSClientSocketImplTest, getWhenEngineIsNull)
{
    EXPECT_EQ(m_clientSocket->getUsedProtocol(), NONE);
    expect_eq_AlpnMode(m_clientSocket->getUsedAlpnMode(), ALPN_OFF);
}
