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

#include "MockIOStreamIf.hpp"
#include "UserIOStream.hpp"

using namespace vwg::tls;
using namespace vwg::tls::impl;
using ::testing::Return;

class UserIOStreamTest : public ::testing::Test {
public:
  std::shared_ptr<MockIOStreamIf> m_stream;

  virtual void SetUp() { m_stream = std::make_shared<MockIOStreamIf>(); }

  virtual void TearDown() {}
};

/**
 * @fn TEST_F(TLSClientCertImplTest, receive)
 * @brief check receive function
 */
TEST_F(UserIOStreamTest, receive) {
  UserIOStream userIoStream(m_stream);
  Byte buf[10];
  uint32_t len = 10;
  int32_t receiveRes = 5;
  EXPECT_CALL(*m_stream, receive(buf, len))
      .Times(1)
      .WillOnce(Return(receiveRes));

  int32_t res = userIoStream.receive(buf, len);
  EXPECT_EQ(res, receiveRes);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, send)
 * @brief send receive function
 */
TEST_F(UserIOStreamTest, send) {
  UserIOStream userIoStream(m_stream);
  Byte buf[10];
  uint32_t len = 10;
  int32_t sendRes = 5;
  EXPECT_CALL(*m_stream, send(buf, len)).Times(1).WillOnce(Return(sendRes));

  int32_t res = userIoStream.send(buf, len);
  EXPECT_EQ(res, sendRes);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, close)
 * @brief check close function
 */
TEST_F(UserIOStreamTest, close) {
  UserIOStream userIoStream(m_stream);

  EXPECT_CALL(*m_stream, close()).Times(1);

  userIoStream.close();
}

/**
 * @fn TEST_F(TLSClientCertImplTest, isOpen)
 * @brief send isOpen function
 */
TEST_F(UserIOStreamTest, isOpen) {
  UserIOStream userIoStream(m_stream);
  bool isOpenReturn = true;
  EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(isOpenReturn));
  bool res = userIoStream.isOpen();
  EXPECT_EQ(res, isOpenReturn);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, isClosed)
 * @brief send isClosed function
 */
TEST_F(UserIOStreamTest, isClosed) {
  UserIOStream userIoStream(m_stream);
  bool isClosedReturn = true;
  EXPECT_CALL(*m_stream, isClosed()).Times(1).WillOnce(Return(isClosedReturn));
  bool res = userIoStream.isClosed();
  EXPECT_EQ(res, isClosedReturn);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, IsBlocking)
 * @brief send IsBlocking function
 */
TEST_F(UserIOStreamTest, IsBlocking) {
  UserIOStream userIoStream(m_stream);

  bool res = userIoStream.IsBlocking();
  EXPECT_EQ(res, false);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, GetFD)
 * @brief send GetFD function
 */
TEST_F(UserIOStreamTest, GetFD) {
  UserIOStream userIoStream(m_stream);

  int res = userIoStream.GetFD();
  EXPECT_EQ(res, -1);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, GetConnectionType)
 * @brief send GetConnectionType function
 */
TEST_F(UserIOStreamTest, GetConnectionType) {
  UserIOStream userIoStream(m_stream);

  vwg::tls::SocketType res = userIoStream.GetConnectionType();
  EXPECT_EQ(res, SOCKETTYPE_STREAM);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, GetLocalPort)
 * @brief send GetLocalPort function
 */
TEST_F(UserIOStreamTest, GetLocalPort) {
  UserIOStream userIoStream(m_stream);

  uint16_t res = userIoStream.GetLocalPort();
  EXPECT_EQ(res, 0);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, GetRemotePort)
 * @brief send GetRemotePort function
 */
TEST_F(UserIOStreamTest, GetRemotePort) {
  UserIOStream userIoStream(m_stream);

  uint16_t res = userIoStream.GetRemotePort();
  EXPECT_EQ(res, 0);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, GetLocalAddress)
 * @brief send GetLocalAddress function
 */
TEST_F(UserIOStreamTest, GetLocalAddress) {
  UserIOStream userIoStream(m_stream);

  vwg::tls::SPIInetAddress res = userIoStream.GetLocalAddress();
  EXPECT_EQ(res, SPIInetAddress());
}

/**
 * @fn TEST_F(TLSClientCertImplTest, GetRemoteAddress)
 * @brief send GetRemoteAddress function
 */
TEST_F(UserIOStreamTest, GetRemoteAddress) {
  UserIOStream userIoStream(m_stream);

  vwg::tls::SPIInetAddress res = userIoStream.GetRemoteAddress();
  EXPECT_EQ(res, SPIInetAddress());
}

/**
 * @fn TEST_F(TLSClientCertImplTest, SetBlocking)
 * @brief send SetBlocking function
 */
TEST_F(UserIOStreamTest, SetBlocking) {
  UserIOStream userIoStream(m_stream);

  bool blocking = true;
  bool res = userIoStream.SetBlocking(blocking);
  EXPECT_EQ(res, false);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, setSoTimeout)
 * @brief send setSoTimeout function
 */
TEST_F(UserIOStreamTest, setSoTimeout) {
  UserIOStream userIoStream(m_stream);

  Int32 timeout = 1;
  userIoStream.setSoTimeout(timeout);
}

/**
 * @fn TEST_F(TLSClientCertImplTest, isConnectionSocket)
 * @brief send isConnectionSocket function
 */
TEST_F(UserIOStreamTest, isConnectionSocket) {
  UserIOStream userIoStream(m_stream);

  Boolean res = userIoStream.isConnectionSocket();
  EXPECT_EQ(res, true);
}
