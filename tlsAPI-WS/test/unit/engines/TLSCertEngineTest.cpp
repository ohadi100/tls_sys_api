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


#include <TLSSocketFactory.h>
#include <gtest/gtest.h>

#include "MockIOStreamIf.hpp"
#include "TLSCertEngineHelpTest.hpp"

using ::testing::_;
using ::testing::Return;

class TLSCertEngineTest : public ::testing::Test {
public:
  std::shared_ptr<MockIOStreamIf> m_stream;
  void checkTimeTestHelper(std::time_t expectedTime, int permittedDeviation , TLSEngineError expectRes)
  {
    TimeCheckTime checkTime = {expectedTime, permittedDeviation};
    TLSCertEngineHelpTest certEngine(m_stream, checkTime);
    TLSEngineError res = certEngine.CheckAuthenticTimeCheck();
    EXPECT_EQ(res, expectRes);
  }

  void checkTimeTest(std::time_t deltaFromCurrTime, int permittedDeviation , TLSEngineError expectRes)
  {
    //check the relation (<, >, =) between |expectedTime  - system_time.now()| to |permittedDeviation|, so it checks the 4 cases
    //check the case with  minus permittedDeviation in order to check permittedDeviation<0 and also permittedDeviation>0
    //because we expect the same result since checkAuthenticTimeCheck checks |permittedDeviation|
    //Also check when the expectedTime is current_time-deltaFromCurrTime or it is current_time+deltaFromCurrTime.
    std::time_t current_time = std::time(nullptr);
    std::time_t expectedTimeAfterCurrentTime = current_time+deltaFromCurrTime;
    std::time_t expectedTimeBeforeCurrentTime = current_time-deltaFromCurrTime;
    checkTimeTestHelper(expectedTimeBeforeCurrentTime, permittedDeviation, expectRes);
    if( 0!=permittedDeviation) {
      checkTimeTestHelper(expectedTimeBeforeCurrentTime, -permittedDeviation, expectRes);
    }
    if(0!=deltaFromCurrTime)
    {
      checkTimeTestHelper(expectedTimeAfterCurrentTime, permittedDeviation, expectRes);
    }
    if(0!=deltaFromCurrTime && 0!=permittedDeviation)
    {
      checkTimeTestHelper(expectedTimeAfterCurrentTime, -permittedDeviation, expectRes);
    }
  }

  virtual void SetUp() { m_stream = std::make_shared<MockIOStreamIf>(); }

  virtual void TearDown() {}
};

/**
 * @fn TEST_F(TLSCertEngineTest, SetBlockingSuccess)
 * @brief SetBlocking function successfully
 */
TEST_F(TLSCertEngineTest, SetBlockingSuccess) {
  TLSCertEngineHelpTest certEngine(m_stream, CHECK_TIME_OFF);

  bool blocking = true;
  EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(true));

  vwg::tls::impl::TLSEngineError res = certEngine.SetBlocking(blocking);

  EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(TLSCertEngineTest, SetBlockingFailure)
 * @brief SetBlocking function in failure case
 */
TEST_F(TLSCertEngineTest, SetBlockingFailure) {
  TLSCertEngineHelpTest certEngine(m_stream, CHECK_TIME_OFF);

  bool blocking = true;
  EXPECT_CALL(*m_stream, SetBlocking(blocking))
      .Times(1)
      .WillOnce(Return(false));

  vwg::tls::impl::TLSEngineError res = certEngine.SetBlocking(blocking);

  EXPECT_EQ(res, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(TLSCertEngineTest, GetIOStream)
 * @brief check GetIOStream function
 */
TEST_F(TLSCertEngineTest, GetIOStream) {
  TLSCertEngineHelpTest certEngine(m_stream, CHECK_TIME_OFF);

  std::shared_ptr<IOStream> streamRes = certEngine.GetIOStream();

  EXPECT_EQ(streamRes, m_stream);
}


/**
 * @fn TEST_F(TLSCertEngineTest, checkAuthenticTimeCheckSuccess)
 * @brief check checkAuthenticTimeCheck function - happy flow
 */
TEST_F(TLSCertEngineTest, checkAuthenticTimeCheckSuccess) {

  int delta =10000;
  //Check when 0 = |(currentTime-expectedTime)| < |permittedDeviation|, and  currentTime = expectedTime
  checkTimeTest(0, 1,RC_TLS_ENGINE_SUCCESSFUL );

  //Check when |(currentTime-expectedTime)| < |permittedDeviation|
  checkTimeTest(delta, delta+1,RC_TLS_ENGINE_SUCCESSFUL );

  //Check when |(currentTime-expectedTime)| = |permittedDeviation|
  checkTimeTest(delta, delta,RC_TLS_ENGINE_SUCCESSFUL );

  //Check when expectedTime = 0, then check time is not in use
  checkTimeTest(0, 0,RC_TLS_ENGINE_SUCCESSFUL );
}

/**
 * @fn TEST_F(TLSCertEngineTest, checkAuthenticTimeNOExpectedTime)
 * @brief check checkAuthenticTimeCheck function - when no time check required
 */
TEST_F(TLSCertEngineTest, checkAuthenticTimeNoExpectedTimeSuccess) {

    TLSCertEngineHelpTest certEngine(m_stream, CHECK_TIME_OFF);
    EXPECT_EQ(certEngine.CheckAuthenticTimeCheck(),RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(TLSCertEngineTest, checkAuthenticTimeCheckFailure)
 * @brief check checkAuthenticTimeCheck function - get an error RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED
 */
TEST_F(TLSCertEngineTest, checkAuthenticTimeCheckFailure) {


  //Check when expectedTime is current-2 and permittedDeviation is 1 second ,
  // so |(currentTime-expectedTime)| > |permittedDeviation|=1
  checkTimeTest(2, 1, RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED);

  //Check when expected time is current_time-delta and |permittedDeviation| is delta-1, so |(currentTime-expectedTime)| > |permittedDeviation|
  int delta =10000;
  checkTimeTest(delta, delta-1, RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED);

  //Check when expected time is current_time+2 years+delta and permittedDeviation is delta-1, so |(currentTime-expectedTime)| > |permittedDeviation|
  int secInYear =365*24*60*60;
  checkTimeTest(secInYear*2+delta , delta-1, RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED);
}


/**
 * @fn TEST_F(TLSCertEngineTest, checkAuthenticTimeCheckMaxPermitted)
 * @brief check checkAuthenticTimeCheck function - get an error - RC_TLS_ENGINE_MAX_PERMITTED_DEVIATION
 */
TEST_F(TLSCertEngineTest, checkAuthenticTimeCheckMaxPermitted) {

  //Check when |permittedDeviation| = |MAX_PERMITTED_DEVIATION|
  checkTimeTest(0, MAX_PERMITTED_DEVIATION, RC_TLS_ENGINE_MAX_PERMITTED_DEVIATION);

  //Check when |permittedDeviation| > |MAX_PERMITTED_DEVIATION|
  int addition =1;
  checkTimeTest(0, MAX_PERMITTED_DEVIATION+addition, RC_TLS_ENGINE_MAX_PERMITTED_DEVIATION);
}

/**
 * @fn TEST_F(TLSCertEngineTest, GetCipherSuiteUseCase)
 * @brief check GetCipherSuiteUseCase function
 */
TEST_F(TLSCertEngineTest, GetCipherSuiteUseCase) {

    TLSCertEngineHelpTest certEngine(m_stream, CHECK_TIME_OFF);
    EXPECT_EQ(certEngine.GetCipherSuiteUseCase(), certEngine.m_cipherSuiteUseCase);
}

#ifdef TLSAPI_WITH_DROP_SUPPORT
/**
 * @fn TEST_F(TLSCertEngineTest, DropTLS)
 * @brief check DropTLS function
 */
TEST_F(TLSCertEngineTest, DropTLS) {

    TLSCertEngineHelpTest certEngine(m_stream, CHECK_TIME_OFF);
    EXPECT_EQ(certEngine.DropTLS(),RC_TLS_ENGINE_NOT_SUPPORTED);
}
#endif //TLSAPI_WITH_DROP_SUPPORT

/**
 * @fn TEST_F(TLSCertEngineTest, IsHardFailFallbackMechanismActive)
 * @brief check IsHardFailFallbackMechanismActive function
 */
TEST_F(TLSCertEngineTest, IsHardFailFallbackMechanismActive) {
    // Revocation check disabled + any use case -> hard fail not active
    TLSCertEngineHelpTest certEngine(m_stream, CHECK_TIME_OFF);
    certEngine.m_revocationCheckEnabled = false;
    certEngine.m_cipherSuiteUseCase = CSUSDefault;
    EXPECT_FALSE(certEngine.IsHardFailFallbackMechanismActive());
    certEngine.m_cipherSuiteUseCase = CSUSLegacy;
    EXPECT_FALSE(certEngine.IsHardFailFallbackMechanismActive());
    certEngine.m_cipherSuiteUseCase = CSUSDefaultWithSoftFail;
    EXPECT_FALSE(certEngine.IsHardFailFallbackMechanismActive());
    certEngine.m_cipherSuiteUseCase = CSUSIanaRecommended;
    EXPECT_FALSE(certEngine.IsHardFailFallbackMechanismActive());
    certEngine.m_cipherSuiteUseCase = CSUSLongtermSecure;
    EXPECT_FALSE(certEngine.IsHardFailFallbackMechanismActive());

    // Revocation check enabled + CSUSDefault/CSUSIanaRecommended/CSUSLongtermSecure use case -> hard fail active
    certEngine.m_revocationCheckEnabled = true;
    certEngine.m_cipherSuiteUseCase = CSUSDefault;
    EXPECT_TRUE(certEngine.IsHardFailFallbackMechanismActive());
    certEngine.m_cipherSuiteUseCase = CSUSIanaRecommended;
    EXPECT_TRUE(certEngine.IsHardFailFallbackMechanismActive());
    certEngine.m_cipherSuiteUseCase = CSUSLongtermSecure;
    EXPECT_TRUE(certEngine.IsHardFailFallbackMechanismActive());

    // Revocation check enabled + CSUSLegacy/CSUSDefaultWithSoftFail use case -> hard fail not active
    certEngine.m_revocationCheckEnabled = true;
    certEngine.m_cipherSuiteUseCase = CSUSLegacy;
    EXPECT_FALSE(certEngine.IsHardFailFallbackMechanismActive());
    certEngine.m_cipherSuiteUseCase = CSUSDefaultWithSoftFail;
    EXPECT_FALSE(certEngine.IsHardFailFallbackMechanismActive());
}
