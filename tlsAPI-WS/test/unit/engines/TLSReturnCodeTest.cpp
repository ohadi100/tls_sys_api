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

#include "TLSEngine.hpp"

using namespace vwg::tls::impl;
using namespace vwg::tls;

/**
 * @fn TEST(TLSReturnCode, EngineToTLSReturnCode)
 * @brief check EngineToTLSReturnCode function
 */
TEST(TLSReturnCode, EngineToTLSReturnCode) {
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_SUCCESSFUL), RC_TLS_SUCCESSFUL);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_WOULD_BLOCK_READ), RC_TLS_WOULD_BLOCK_READ);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_WOULD_BLOCK_WRITE), RC_TLS_WOULD_BLOCK_WRITE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_PEER_CLOSED), RC_TLS_PEER_CLOSED);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED), RC_TLS_AUTHENTIC_TIMECHECK_FAILED);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_MAX_PERMITTED_DEVIATION), RC_TLS_MAX_PERMITTED_DEVIATION);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN), RC_TLS_SEND_AFTER_SHUTDOWN);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_NOT_SUPPORTED), RC_TLS_DROPPING_NOTSUPPORTED);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_UNEXPECTED_MESSAGE), RC_TLS_UNEXPECTED_MESSAGE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_BAD_RECORD_MAC), RC_TLS_BAD_RECORD_MAC);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_RECORD_OVERFLOW), RC_TLS_RECORD_OVERFLOW);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_DECOMPRESSION_FAILURE), RC_TLS_DECOMPRESSION_FAILURE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_HANDSHAKE_FAILURE), RC_TLS_HANDSHAKE_FAILURE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_BAD_CERTIFICATE), RC_TLS_BAD_CERTIFICATE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE), RC_TLS_UNSUPPORTED_CERTIFICATE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_CERTIFICATE_REVOKED), RC_TLS_CERTIFICATE_REVOKED);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_CERTIFICATE_EXPIRED), RC_TLS_CERTIFICATE_EXPIRED);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_CERTIFICATE_UNKNOWN), RC_TLS_CERTIFICATE_UNKNOWN);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_ILLEGAL_PARAMETER), RC_TLS_ILLEGAL_PARAMETER);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_UNKNOWN_CA), RC_TLS_UNKOWN_CA);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_ACCESS_DENIED), RC_TLS_ACCESS_DENIED);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_DECODE_ERROR), RC_TLS_DECODE_ERROR);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_DECRYPT_ERROR), RC_TLS_DECRYPT_ERROR);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_PROTOCOL_VERSION), RC_TLS_PROTOCOL_VERSION);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_INSUFFICIENT_SECURITY), RC_TLS_INSUFFICIENT_SECURITY);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_NO_RENEGOTIATION), RC_TLS_NO_RENEGOTIATION);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_UNSUPPORTED_EXTENSION), RC_TLS_UNSUPPORTED_EXTENSION);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_CERTIFICATE_UNOBTAINABLE), RC_TLS_CERTIFICATE_UNOBTAINABLE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_UNRECOGNIZED_NAME), RC_TLS_UNRECOGNIZED_NAME);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE), RC_TLS_BAD_CERTIFICATE_STATUS_RESPONSE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_BAD_CERTIFICATE_HASH_VALUE), RC_TLS_BAD_CERTIFICATE_HASH_VALUE);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_TEE_ACCESS_ERROR), RC_TLS_TEE_ACCESS_ERROR);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_CERTSTORE_NOT_FOUND), RC_TLS_CERTSTORE_NOT_FOUND);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID), RC_TLS_UNKNOWN_CLIENT_CERTIFICATE_SET_ID);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_CLIENT_CERTIFICATE_SET_IDERROR), RC_TLS_CLIENT_CERTIFICATE_SET_IDERROR);
      EXPECT_EQ(EngineToTLSReturnCode(RC_TLS_ENGINE_NO_APPLICATION_PROTOCOL), RC_TLS_NO_APPLICATION_PROTOCOL);
      EXPECT_EQ(EngineToTLSReturnCode(TLSEngineError(4000)), RC_TLS_IO_ERROR);

}
