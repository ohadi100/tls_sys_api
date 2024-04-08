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
#include "TLSEngineHelpTest.hpp"
#include "InternIOStream.hpp"

using namespace vwg::tls;
using ::testing::_;
using ::testing::Return;

class TLSEngineTest : public ::testing::Test {
public:
  std::shared_ptr<MockIOStreamIf> m_stream;

  virtual void SetUp() { m_stream = std::make_shared<MockIOStreamIf>(); }

  virtual void TearDown() {}
};

/**
 * @fn TEST_F(TLSCertEngineTest, SetBlockingSuccess)
 * @brief SetBlocking function successfully
 */
TEST_F(TLSEngineTest, SetBlockingSuccess) {
  TLSEngineHelpTest certEngine(m_stream);

  bool blocking = true;
  EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(true));

  vwg::tls::impl::TLSEngineError res = certEngine.SetBlocking(blocking);

  EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(TLSEngineTest, SetBlockingFailure)
 * @brief SetBlocking function in failure case
 */
TEST_F(TLSEngineTest, SetBlockingFailure) {
  TLSEngineHelpTest certEngine(m_stream);

  bool blocking = true;
  EXPECT_CALL(*m_stream, SetBlocking(blocking))
      .Times(1)
      .WillOnce(Return(false));

  vwg::tls::impl::TLSEngineError res = certEngine.SetBlocking(blocking);

  EXPECT_EQ(res, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(TLSEngineTest, GetIOStream)
 * @brief check GetIOStream function
 */
TEST_F(TLSEngineTest, GetIOStream) {
  TLSEngineHelpTest certEngine(m_stream);

  std::shared_ptr<IOStream> streamRes = certEngine.GetIOStream();

  EXPECT_EQ(streamRes, m_stream);
}

/**
 * @fn TEST_F(TLSEngineTest, SetStream)
 * @brief check SetStream function
 */
TEST_F(TLSEngineTest, SetStream) {
  TLSEngineHelpTest certEngine(m_stream);

  std::shared_ptr<IOStreamIf> stream = std::make_shared<InternIOStream>(3);
  certEngine.SetStream(stream);
  EXPECT_EQ(certEngine.m_stream, stream);
}

/**
 * @fn TEST_F(TLSEngineTest, Close)
 * @brief check Close function
 */
TEST_F(TLSEngineTest, Close) {

  TLSEngineHelpTest certEngine(m_stream);
  certEngine.Close();
  EXPECT_EQ(certEngine.m_context, nullptr);
}