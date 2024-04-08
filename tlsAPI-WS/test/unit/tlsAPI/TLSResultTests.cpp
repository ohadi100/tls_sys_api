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

#include "TLSResult.h"

using namespace vwg::tls;

TEST(TLSResult, Empty_TLSResult) {
  TLSResult<int> result;
  EXPECT_TRUE(result.getErrorCode() == RC_TLS_PROGRAMMING_ERROR_RESULT);
  EXPECT_TRUE(result.failed());
  EXPECT_FALSE(result.succeeded());
}

TEST(TLSResult, Error_TLSResult) {
  TLSResult<int> result(RC_TLS_INIT_FAILED);
  EXPECT_TRUE(result.getErrorCode() == RC_TLS_INIT_FAILED);
  EXPECT_TRUE(result.failed());
  EXPECT_FALSE(result.succeeded());
}

TEST(TLSResult, OK_TLSResult) {
  TLSResult<int> result(5);

  EXPECT_TRUE(result.getErrorCode() == RC_TLS_SUCCESSFUL);
  EXPECT_FALSE(result.failed());
  EXPECT_TRUE(result.succeeded());
  EXPECT_TRUE(result.getPayload() == 5);
}

TEST(TLSResult, TLSResult_copy) {
  TLSResult<int> result;
  TLSResult<int> other(5);

  result = other;
  EXPECT_TRUE(result.getErrorCode() == RC_TLS_SUCCESSFUL);
  EXPECT_FALSE(result.failed());
  EXPECT_TRUE(result.succeeded());
  EXPECT_TRUE(result.getPayload() == 5);
}
