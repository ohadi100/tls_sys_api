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
#include "TLSServerSocketImpl.hpp"
#include "TLSSocketFactory.h"

#include "MockInternIOStream.hpp"
#include "MockPSKEngine.hpp"

using namespace vwg::tls;
using namespace vwg::tls::impl;

using ::testing::Return;

class TLSServerSocketImplTest : public ::testing::Test {
public:
  std::shared_ptr<MockInternIOStream> m_serverStream;
  std::shared_ptr<InternIOStream> m_clientStream;
  std::shared_ptr<TLSServerSocketImpl> m_serverSocket;
  int m_serverFd;
  int m_clientFd;

  virtual void
  SetUp()
  {
      m_serverFd     = 2;
      m_serverStream = std::make_shared<MockInternIOStream>(m_serverFd);

      m_clientFd     = 3;
      m_clientStream = std::make_shared<InternIOStream>(m_clientFd);

      std::string someHint             = "1001";
      SecurityLevel confidentiality  = AUTHENTIC_WITHPSK;
      bool isFdManagedLocal = false;

      m_serverSocket = std::make_shared<TLSServerSocketImpl>(m_serverStream, someHint, confidentiality, isFdManagedLocal);

      PSKEngineUT::mMockPSKEngine = new MockPSKEngine(m_serverStream, isFdManagedLocal, someHint, confidentiality);
  }

  void
  TestDtorTLSSessionEndPointImpl()  // Checks the TLSSessionEndPointImpl destructor
  {
      EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Close()).Times(1);
      if (m_serverSocket->m_isFdManagedLocal)
          EXPECT_CALL(*m_serverStream, isOpen()).Times(1).WillOnce(Return(false));
  }

  virtual void
  TearDown()
  {
      delete PSKEngineUT::mMockPSKEngine;
  }
};

/**
 * @ingroup TLSServerSocket_accept
 * @fn TEST_F(TLSServerSocketImplTest, acceptServerSuccess)
 * @brief accepting on server successfully
 */
TEST_F(TLSServerSocketImplTest, acceptServerSuccess) {

  EXPECT_CALL(*m_serverStream.get(), Accept())
      .Times(1)
      .WillOnce(Return(m_clientStream));

  EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake())
      .Times(1)
      .WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

  TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_serverSocket->accept();

  ASSERT_TRUE(res.succeeded());
  ASSERT_EQ(res.getPayload()->getSocketFD(), m_clientFd);

  TestDtorTLSSessionEndPointImpl();// res DTOR
}

/**
 * @ingroup TLSServerSocket_accept
 * @fn TEST_F(TLSServerSocketImplTest, acceptServerFailureNullWorkingStream)
 * @brief get failure when accepting on server (getting
 * RC_TLS_ACCEPT_FAILED error) since WorkingStream is nullptr
 */
TEST_F(TLSServerSocketImplTest, acceptServerFailureNullWorkingStream) {

    EXPECT_CALL(*m_serverStream.get(), Accept())
        .Times(1)
        .WillOnce(Return(nullptr));

    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_serverSocket->accept();

    EXPECT_EQ(res.getErrorCode(), RC_TLS_ACCEPT_FAILED);
}

/**
 * @ingroup TLSServerSocket_accept
 * @fn TEST_F(TLSServerSocketImplTest, acceptServerFailure)
 * @brief get failure when accepting on server (getting
 * RC_TLS_CERTSTORE_NOT_FOUND error)
 */
TEST_F(TLSServerSocketImplTest, acceptServerFailure) {

  EXPECT_CALL(*m_serverStream.get(), Accept())
      .Times(1)
      .WillOnce(Return(m_clientStream));
  EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake())
      .Times(1)
      .WillOnce(Return(RC_TLS_ENGINE_CERTSTORE_NOT_FOUND));

  TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res = m_serverSocket->accept();

  ASSERT_TRUE(res.failed());
  EXPECT_EQ(res.getErrorCode(), RC_TLS_CERTSTORE_NOT_FOUND);
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, createSessionSuccess)
 * @brief create a session successfully
 */
TEST_F(TLSServerSocketImplTest, createSessionSuccess) {

  EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake())
      .Times(1)
      .WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

  TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res =
      m_serverSocket->createSession(m_clientStream);

  ASSERT_TRUE(res.succeeded());
  ASSERT_EQ(res.getPayload()->getSocketFD(), m_clientFd);

  TestDtorTLSSessionEndPointImpl();// res DTOR
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, createSessionFailure)
 * @brief get a failure when creating a session (getting
 * RC_TLS_CERTSTORE_NOT_FOUND error)
 */
TEST_F(TLSServerSocketImplTest, createSessionFailure) {

  //case 2: RC_TLS_CERTSTORE_NOT_FOUND
  EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake())
      .Times(1)
      .WillOnce(Return(RC_TLS_ENGINE_CERTSTORE_NOT_FOUND));

  TLSResult<std::shared_ptr<ITLSSessionEndpoint>> res =
      m_serverSocket->createSession(m_clientStream);
  EXPECT_EQ(res.getErrorCode(), RC_TLS_CERTSTORE_NOT_FOUND);

  //case 2: RC_TLS_HANDSHAKE_FAILURE
  EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DoSSLHandshake())
      .Times(1)
      .WillOnce(Return((vwg::tls::impl::TLSEngineError)10000));//in order for EngineToTLSReturnCode(10000) would return RC_TLS_IO_ERROR

      res = m_serverSocket->createSession(m_clientStream);
  EXPECT_EQ(res.getErrorCode(),RC_TLS_HANDSHAKE_FAILURE);
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, getSocketFD)
 * @brief check getSocketFD function
 */
TEST_F(TLSServerSocketImplTest, getSocketFD) {
  EXPECT_CALL(*m_serverStream, GetFD()).Times(1).WillOnce(Return(m_serverFd));
  int resFd = m_serverSocket->getSocketFD();
  EXPECT_EQ(resFd, m_serverFd);
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, isConnectionSocket)
 * @brief check isConnectionSocket function
 */
TEST_F(TLSServerSocketImplTest, isConnectionSocket) {
  Boolean isConnectionSocket;

  EXPECT_CALL(*m_serverStream, GetConnectionType())
      .Times(1)
      .WillOnce(Return(SocketType::SOCKETTYPE_STREAM));
  isConnectionSocket = m_serverSocket->isConnectionSocket();
  EXPECT_TRUE(isConnectionSocket);

  EXPECT_CALL(*m_serverStream, GetConnectionType())
      .Times(1)
      .WillOnce(Return(SocketType::SOCKETTYPE_DATAGRAM));
  isConnectionSocket = m_serverSocket->isConnectionSocket();
  EXPECT_FALSE(isConnectionSocket);
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, close_localFD)
 * @brief check close function
 */
TEST_F(TLSServerSocketImplTest, close_localFD) {
    m_serverSocket-> m_isFdManagedLocal = true;

    EXPECT_CALL(*m_serverStream, isOpen()).Times(2).WillOnce(Return(true)).WillOnce(Return(false));
    EXPECT_CALL(*m_serverStream, close()).Times(1);
    m_serverSocket->close();
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, close_userFD)
 * @brief check close function
 */
TEST_F(TLSServerSocketImplTest, close_userFD) {
    m_serverSocket-> m_isConnectionFd = true;

    EXPECT_CALL(*m_serverStream, close()).Times(0);
    m_serverSocket->close();
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, isClosed)
 * @brief check isClosed function
 */
TEST_F(TLSServerSocketImplTest, isClosed) {
  Boolean isOpen = true;
  EXPECT_CALL(*m_serverStream, isOpen()).Times(1).WillOnce(Return(isOpen));
  Boolean isClosedRes = m_serverSocket->isClosed();
  EXPECT_NE(isClosedRes, isOpen);
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, isOpen)
 * @brief check isOpen function
 */
TEST_F(TLSServerSocketImplTest, isOpen) {
  Boolean isOpen = true;
  EXPECT_CALL(*m_serverStream, isOpen()).Times(1).WillOnce(Return(isOpen));
  EXPECT_EQ(m_serverSocket->isOpen(), isOpen);
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, getLocalPort)
 * @brief check getLocalPort function
 */
TEST_F(TLSServerSocketImplTest, getLocalPort) {
  UInt16 port = 8080;
  EXPECT_CALL(*m_serverStream, GetLocalPort()).Times(1).WillOnce(Return(port));
  UInt16 portRes = m_serverSocket->getLocalPort();
  EXPECT_EQ(portRes, port);
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, getLocalInetAddress)
 * @brief check getLocalInetAddress function
 */
TEST_F(TLSServerSocketImplTest, getLocalInetAddress) {

  std::string stringAddress = "1:2:3:4:5:6:7:8";
  vwg::tls::SPIInetAddress address =
      std::make_shared<IPInetAddressImpl>(stringAddress);

  EXPECT_CALL(*m_serverStream, GetLocalAddress()).Times(1).WillOnce(Return(address));
  SPIInetAddress resAddress = m_serverSocket->getLocalInetAddress();
  EXPECT_EQ(resAddress->toString(), stringAddress);
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, getUsedAlpnMode)
 * @brief check getUsedAlpnMode function
 */
TEST_F(TLSServerSocketImplTest, getUsedAlpnMode) {
    AlpnMode res = m_serverSocket->getUsedAlpnMode();

    EXPECT_EQ(res.userDefinedALPNisUsed(), ALPN_OFF.userDefinedALPNisUsed());
    EXPECT_EQ(res.getSupportedProtocols(), ALPN_OFF.getSupportedProtocols());
    EXPECT_EQ(res.getUserDefinedAlpnSetting(), ALPN_OFF.getUserDefinedAlpnSetting());
}

/**
 * @fn TEST_F(TLSServerSocketImplTest, getUsedProtocol)
 * @brief check getUsedProtocol function
 */
TEST_F(TLSServerSocketImplTest, getUsedProtocol) {
    EXPECT_EQ(m_serverSocket->getUsedProtocol(), NONE);
}
