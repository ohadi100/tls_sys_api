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

#include <wolfssl/options.h>

#include <wolfssl/error-ssl.h>

#include "MockIOStreamIf.hpp"
#include "MockWolfSSL.hpp"
#include "WolfSSLPSKEngine.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::DoAll;

using namespace vwg::tls::impl;
using namespace vwg::tls;

struct WOLFSSL {
    int dummy;
};

class WolfSSLPSKEngineTest : public ::testing::Test {
public:
    std::shared_ptr<MockIOStreamIf> m_stream;
    std::shared_ptr<WolfSSLPSKEngine> m_engine;
    SecurityLevel m_confidentiality;
    std::string m_hint;

    // To be returned
    WOLFSSL *m_newSSLRetVal = (WOLFSSL *) 0xdeadbeef;
    WOLFSSL_CTX *m_newCtxRetVal = (WOLFSSL_CTX *) 0x1337cafe;
    WOLFSSL_ALERT_HISTORY m_historyRetVal;

    // some WolfSSL error and its appropriate EngineError
    std::pair<int, TLSEngineError> someWolfSSLAndEngineErrorPair = {SOCKET_PEER_CLOSED_E, RC_TLS_ENGINE_PEER_CLOSED};


    virtual void
    SetUp() {
        bool isServer = true;
        m_hint = "hint";
        m_confidentiality = AUTHENTIC_WITHPSK;

        m_stream = std::make_shared<MockIOStreamIf>();
        m_engine = std::make_shared<WolfSSLPSKEngine>(m_stream, isServer, m_hint, m_confidentiality);
        MockWolfSSLUT::mMockWolfSSL = new MockWolfSSL();
    }

    void
    WolfSSLToEngineErrorTest(int getErrorRet) {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_error(_, 0)).WillOnce(Return(getErrorRet));
    }

    void
    WolfSSLToEngineErrorTestHistory(int historyErrorRet, int expectedResult, bool isRx = true) {
        int getErrorRet = HANDSHAKE_SIZE_ERROR;  // for calling mock wolfSSL_get_error, in order to go default case
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_error(_, 0)).WillOnce(Return(getErrorRet));

        if (isRx)  // in order to (history.last_rx.level == alert_fatal)=true in WolfSSLToEngineError()
        {
            m_historyRetVal.last_rx.level = alert_fatal;
            m_historyRetVal.last_rx.code = historyErrorRet;
        } else {
            m_historyRetVal.last_rx.level = alert_warning;
            m_historyRetVal.last_tx.level = alert_fatal;
            m_historyRetVal.last_tx.code = historyErrorRet;
        }

        int getAlertHistoryRval = WOLFSSL_SUCCESS;
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_alert_history(_, _))
                .WillOnce(
                        DoAll(SetArgPointee<1>(
                                      m_historyRetVal),  // out parameter returning from wolfSSL_get_alert_history mock
                              Return(getAlertHistoryRval)));

        EXPECT_EQ(m_engine->WolfSSLToEngineError(), expectedResult);
    }

    void
    successShutdownCheck() {
        m_engine->m_ssl = std::make_shared<WOLFSSL>();

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(0));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_shutdown(_))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SHUTDOWN_NOT_DONE))
                .WillOnce(Return(0));  // success shutdown
    }

    void
    successShutdownIsDrop() {
        m_engine->m_ssl = std::make_shared<WOLFSSL>();

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(0));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_shutdown(_))
                .Times(1)
                .WillOnce(Return(0));  // success shutdown
    }

    void
    sslInitScenarioForSuccess() {
        WOLFSSL *newRetVal = m_newSSLRetVal;  // for calling mock wolfSSL_new
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_new(_)).Times(1).WillOnce(Return(newRetVal));
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(m_newSSLRetVal))
                .Times(1);  // ssl dtor- ssl is created with wolfSSL_free function that should be called from m_ssl dtor
    }

    void
    DoSSLHandshakeHelperTest() {
        // ctxInit
        ctxInitScenarioForSuccess();

        // sslInit
        sslInitScenarioForSuccess();

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_use_psk_identity_hint(_, _))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_set_cipher_list(_, _))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOReadCtx(_, _))  // wolfSSL_SetIOReadCtx
                .Times(1);
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOWriteCtx(_, _))  // wolfSSL_SetIOWriteCtx
                .Times(1);

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_set_ex_data(_, _, _))  // wolfSSL_set_ex_data X 2
                .Times(2)
                .WillRepeatedly(Return(WOLFSSL_SUCCESS));
    }

    void
    ctxInitScenarioFailureCTX_new()  // function ctxInit fails because wolfSSL_CTX_new fails
    {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfTLSv1_2_method()).Times(1);

        // wolfSSL_CTX_new returns nullptr
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(nullptr));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(nullptr)).Times(1);  // ctx dtor
    }

    void
    CTX_newSuccess() {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfTLSv1_2_method()).Times(1);

        WOLFSSL_CTX *newRetVal = m_newCtxRetVal;  // for calling mock wolfSSL_CTX_new
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(newRetVal));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(m_newCtxRetVal))
                .Times(
                        1);  // ctx dtor -ctx is created with wolfSSL_CTX_free function, that should be called from m_ctx dtor

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_set_psk_server_callback(_, _)).Times(1);
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_set_psk_client_callback(_, _)).Times(1);
    }

    void
    ctxInitScenarioForSuccess() {
        CTX_newSuccess();
        int setMinVersionRetval = 1;  // for calling mock wolfSSL_CTX_SetMinVersion
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_SetMinVersion(_, WOLFSSL_TLSV1_2))
                .Times(1)
                .WillOnce(Return(setMinVersionRetval));

        // wolfSSL_SetIORecv(m_newCtxRetVal.get(), recvIO);
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIORecv(_, _)).Times(1);

        // wolfSSL_SetIOSend(m_newCtxRetVal.get(), sendIO);
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOSend(_, _)).Times(1);
    }

    void
    engineDestructor() {
        m_engine->m_ssl
                .reset();  // in order to get in : if (!m_ssl || ...) in close() function (that's called from engine's dtor)
    }

    virtual void
    TearDown() {
        engineDestructor();
        m_engine.reset();

        delete MockWolfSSLUT::mMockWolfSSL;
    }
};

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, WolfSSLToEngineError)
 * @brief called function WolfSSLToEngineError
 */
TEST_F(WolfSSLPSKEngineTest, WolfSSLToEngineError) {
    WolfSSLToEngineErrorTest(WOLFSSL_ERROR_WANT_READ);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_WOULD_BLOCK_READ);

    WolfSSLToEngineErrorTest(WOLFSSL_ERROR_WANT_WRITE);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_WOULD_BLOCK_WRITE);

    WolfSSLToEngineErrorTest(WOLFSSL_ERROR_ZERO_RETURN);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_SUCCESSFUL);

    WolfSSLToEngineErrorTest(SOCKET_PEER_CLOSED_E);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_PEER_CLOSED);

    WolfSSLToEngineErrorTestHistory(unexpected_message, RC_TLS_ENGINE_UNEXPECTED_MESSAGE);
    WolfSSLToEngineErrorTestHistory(bad_record_mac, RC_TLS_ENGINE_BAD_RECORD_MAC);
    WolfSSLToEngineErrorTestHistory(record_overflow, RC_TLS_ENGINE_RECORD_OVERFLOW);
    WolfSSLToEngineErrorTestHistory(decompression_failure, RC_TLS_ENGINE_DECOMPRESSION_FAILURE);
    WolfSSLToEngineErrorTestHistory(handshake_failure, RC_TLS_ENGINE_HANDSHAKE_FAILURE);
    WolfSSLToEngineErrorTestHistory(bad_certificate, RC_TLS_ENGINE_BAD_CERTIFICATE);
    WolfSSLToEngineErrorTestHistory(unsupported_certificate, RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE);
    WolfSSLToEngineErrorTestHistory(certificate_revoked, RC_TLS_ENGINE_CERTIFICATE_REVOKED);
    WolfSSLToEngineErrorTestHistory(certificate_expired, RC_TLS_ENGINE_CERTIFICATE_EXPIRED);
    WolfSSLToEngineErrorTestHistory(certificate_unknown, RC_TLS_ENGINE_CERTIFICATE_UNKNOWN);
    WolfSSLToEngineErrorTestHistory(illegal_parameter, RC_TLS_ENGINE_ILLEGAL_PARAMETER);
    WolfSSLToEngineErrorTestHistory(decode_error, RC_TLS_ENGINE_DECODE_ERROR);
    WolfSSLToEngineErrorTestHistory(decrypt_error, RC_TLS_ENGINE_DECRYPT_ERROR);
    WolfSSLToEngineErrorTestHistory(protocol_version, RC_TLS_ENGINE_PROTOCOL_VERSION);
    WolfSSLToEngineErrorTestHistory(no_renegotiation, RC_TLS_ENGINE_NO_RENEGOTIATION);
    WolfSSLToEngineErrorTestHistory(unsupported_extension, RC_TLS_ENGINE_UNSUPPORTED_EXTENSION);
    WolfSSLToEngineErrorTestHistory(unrecognized_name, RC_TLS_ENGINE_UNRECOGNIZED_NAME);
    WolfSSLToEngineErrorTestHistory(bad_certificate_status_response, RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE);
    WolfSSLToEngineErrorTestHistory(48, RC_TLS_ENGINE_UNKNOWN_CA);
    WolfSSLToEngineErrorTestHistory(49, RC_TLS_ENGINE_ACCESS_DENIED);
    WolfSSLToEngineErrorTestHistory(71, RC_TLS_ENGINE_INSUFFICIENT_SECURITY);

    WolfSSLToEngineErrorTestHistory(1000 /*unknown error*/, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, getUsedProtocol)
 * @brief called function getUsedProtocol
 */
TEST_F(WolfSSLPSKEngineTest, getUsedProtocol) {
    EXPECT_EQ(m_engine->getUsedProtocol(), NONE);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, getUsedAlpnMode)
 * @brief called function getUsedAlpnMode
 */
TEST_F(WolfSSLPSKEngineTest, getUsedAlpnMode) {
    AlpnMode alpn = m_engine->getUsedAlpnMode();
    EXPECT_EQ(alpn.userDefinedALPNisUsed(), ALPN_OFF.userDefinedALPNisUsed());
    EXPECT_EQ(alpn.getSupportedProtocols(), ALPN_OFF.getSupportedProtocols());
    EXPECT_EQ(alpn.getUserDefinedAlpnSetting(), ALPN_OFF.getUserDefinedAlpnSetting());
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, SendSuccess)
 * @brief function Send called successfully
 */
TEST_F(WolfSSLPSKEngineTest, SendSuccess) {
    m_engine->m_ssl = std::make_shared<WOLFSSL>();

    int getShutdownRetVal = 0;  // for wolfSSL_get_shutdown calling
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(getShutdownRetVal));

    const int32_t bufLength = 2;
    uint8_t buffer[bufLength];
    int32_t actualLength = 0;

    int sendRetVal = bufLength;  // for wolfSSL_send calling
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_send(_, buffer, bufLength, 0))
            .Times(1)
            .WillOnce(Return(sendRetVal));

    TLSEngineError res = m_engine->Send(buffer, bufLength, actualLength);
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
    EXPECT_EQ(actualLength, sendRetVal);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, SendFailure)
 * @brief checking Send function - when it gets a failure
 */
TEST_F(WolfSSLPSKEngineTest, SendFailure) {
    int32_t bufLength = 10;
    uint8_t buf[bufLength];
    int32_t actualLength = 0;

    // when buffer is nullptr
    EXPECT_EQ(m_engine->Send(nullptr, bufLength, actualLength), RC_TLS_ENGINE_FATAL_ERROR);
    EXPECT_EQ(actualLength, 0);

    // when m_ssl is nullptr
    m_engine->m_ssl = nullptr;

    // Test
    EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength), RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN);
    EXPECT_EQ(actualLength, 0);

    // expected calls when wolfSSL_get_shutdown returns WOLFSSL_SENT_SHUTDOWN
    m_engine->m_ssl = std::make_shared<WOLFSSL>();
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(WOLFSSL_SENT_SHUTDOWN));

    // Test
    EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength), RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN);
    EXPECT_EQ(actualLength, 0);

    // expected calls when wolfSSL_send returns an error
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(0));

    int sendRetVal = -1;  // for wolfSSL_send calling
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_send(_, buf, bufLength, 0))
            .Times(1)
            .WillOnce(Return(sendRetVal));

    WolfSSLToEngineErrorTest(someWolfSSLAndEngineErrorPair.first);

    // Test
    TLSEngineError res = m_engine->Send(buf, bufLength, actualLength);
    EXPECT_EQ(res, someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(actualLength, sendRetVal);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, ReceiveSuccess)
 * @brief function Receive called successfully
 */
TEST_F(WolfSSLPSKEngineTest, ReceiveSuccess) {
    m_engine->m_ssl = std::make_shared<WOLFSSL>();

    int getShutdownRetVal = 0;  // for wolfSSL_get_shutdown calling
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(getShutdownRetVal));

    const int32_t bufLength = 2;
    uint8_t buffer[bufLength];
    int32_t actualLength = 0;

    int recvRetVal = bufLength;  // for wolfSSL_recv calling
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_recv(_, buffer, bufLength, 0))
            .Times(1)
            .WillOnce(Return(recvRetVal));

    TLSEngineError res = m_engine->Receive(buffer, bufLength, actualLength);
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
    EXPECT_EQ(actualLength, recvRetVal);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, ReceiveFailure)
 * @brief function Receive when it fails
 */
TEST_F(WolfSSLPSKEngineTest, ReceiveFailure) {
    int32_t bufLength = 10;
    uint8_t buf[bufLength];
    int32_t actualLength = 0;

    // when buffer is nullptr
    EXPECT_EQ(m_engine->Receive(nullptr, bufLength, actualLength), RC_TLS_ENGINE_FATAL_ERROR);
    EXPECT_EQ(actualLength, 0);

    // when m_ssl is nullptr
    m_engine->m_ssl = nullptr;

    // Test
    EXPECT_EQ(m_engine->Receive(buf, bufLength, actualLength), RC_TLS_ENGINE_SPECIFIC_ERROR);
    EXPECT_EQ(actualLength, 0);

    // expected calls when wolfSSL_get_shutdown returns WOLFSSL_SENT_SHUTDOWN
    m_engine->m_ssl = std::make_shared<WOLFSSL>();
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(WOLFSSL_SENT_SHUTDOWN));

    // Test
    EXPECT_EQ(m_engine->Receive(buf, bufLength, actualLength), RC_TLS_ENGINE_SPECIFIC_ERROR);
    EXPECT_EQ(actualLength, 0);

    // expected calls when wolfSSL_recv returns an error
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(0));

    int sendRetVal = -1;  // for wolfSSL_recv calling
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_recv(_, buf, bufLength, 0))
            .Times(1)
            .WillOnce(Return(sendRetVal));

    WolfSSLToEngineErrorTest(someWolfSSLAndEngineErrorPair.first);

    // Test
    TLSEngineError res = m_engine->Receive(buf, bufLength, actualLength);
    EXPECT_EQ(res, someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(actualLength, sendRetVal);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, SetBlockingSuccess)
 * @brief function SetBlocking called successfully
 */
TEST_F(WolfSSLPSKEngineTest, SetBlockingSuccess) {
    bool blocking = true;
    EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(true));  // TLSEngine::SetBlocking

    m_engine->m_ssl = std::make_shared<WOLFSSL>();  // in order to get in the if(m_ssl) in SetBlocking function
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_set_using_nonblock(_, !blocking)).Times(1);

    TLSEngineError res = m_engine->SetBlocking(blocking);
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, SetBlockingFailure)
 * @brief function SetBlocking fails
 */
TEST_F(WolfSSLPSKEngineTest, SetBlockingFailure) {
    bool blocking = true;
    // expected calls
    EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(false));  // TLSEngine::SetBlocking

    //TEST : when TLSEngine::SetBlocking fails
    EXPECT_EQ(m_engine->SetBlocking(blocking), RC_TLS_ENGINE_FATAL_ERROR);

    // expected calls
    m_engine->m_ssl = nullptr;
    EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(true));  // TLSEngine::SetBlocking

    //TEST : when engine's ssl is nullptr
    EXPECT_EQ(m_engine->SetBlocking(blocking), RC_TLS_ENGINE_SPECIFIC_ERROR);

}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, ShutdownSuccess)
 * @brief function Shutdown called successfully
 */
TEST_F(WolfSSLPSKEngineTest, ShutdownSuccess) {
    successShutdownCheck();
    TLSEngineError res = m_engine->Shutdown();
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, CloseSuccess)
 * @brief function Close called successfully
 */
TEST_F(WolfSSLPSKEngineTest, CloseSuccess) {
    successShutdownCheck();
    m_engine->Close();
    EXPECT_EQ(m_engine->m_ssl, nullptr);
    EXPECT_EQ(m_engine->m_context, nullptr);  // TLSEngine::Close();
    EXPECT_EQ(m_engine->m_ctx, nullptr);
    EXPECT_EQ(m_engine->m_keys.remoteHint, "");
    EXPECT_EQ(m_engine->m_keys.hint, "");
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, ctxInitSuccess)
 * @brief calls function ctxInit successfully
 */
TEST_F(WolfSSLPSKEngineTest, ctxInitSuccess) {
    ctxInitScenarioForSuccess();

    TLSEngineError res = m_engine->ctxInit();

    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, ctxInitFailureCTX_new)
 * @brief function ctxInit fails because wolfSSL_CTX_new fails
 */
TEST_F(WolfSSLPSKEngineTest, ctxInitFailureCTX_new) {
    ctxInitScenarioFailureCTX_new();
    EXPECT_EQ(m_engine->ctxInit(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, ctxInitFailureSetMinVersion)
 * @brief function ctxInit fails because wolfSSL_CTX_SetMinVersion fails
 */
TEST_F(WolfSSLPSKEngineTest, ctxInitFailureSetMinVersion) {
    CTX_newSuccess();  // wolfSSL_CTX_new succeeds

    int setMinVersionRetval = 0;  // failure val
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_SetMinVersion(_, WOLFSSL_TLSV1_2))
            .Times(1)
            .WillOnce(Return(setMinVersionRetval));

    EXPECT_EQ(m_engine->ctxInit(), RC_TLS_ENGINE_FATAL_ERROR);
    EXPECT_EQ(m_engine->m_ctx, nullptr);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeServerSuccess)
 * @brief called function DoSSLHandshake successfully, when m_engine->m_isServer == true
 */
TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeServerSuccess) {
    m_engine->m_isServer = true;

    DoSSLHandshakeHelperTest();

    // wolfSSL_accept
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_accept(_)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));

    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeClientSuccess)
 * @brief called function DoSSLHandshake successfully, when m_engine->m_isServer == false
 */
TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeClientSuccess) {
    m_engine->m_isServer = false;

    DoSSLHandshakeHelperTest();

    // wolfSSL_connect
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_connect(_)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));

    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeFailureCtxInitfail)
 * @brief function DoSSLHandshake fails when ctxInit fails
 */
TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeFailureCtxInitfail) {
    ctxInitScenarioFailureCTX_new();  // ctxInit fails

    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeFailureSslInitfail)
 * @brief function DoSSLHandshake fails when ssl initialization fails
 */
TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeFailureSslInitfail) {
    ctxInitScenarioForSuccess();  // ctxInit() succeeds

    // ssl init Fails
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_new(_)).Times(1).WillOnce(Return(nullptr));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(nullptr))
            .Times(1);  // ssl dtor- ssl is created with wolfSSL_free function that should be called from m_ssl dtor

    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeServerFailureAccept)
 * @brief function DoSSLHandshake fails when the engine is server and it wolfSSL_accept fails
 */
TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeServerFailureAccept) {
    m_engine->m_isServer = true;

    DoSSLHandshakeHelperTest();

    // wolfSSL_accept fails - does not return WOLFSSL_SUCCESS
    int acceptError = WOLFSSL_FAILURE;
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_accept(_)).Times(1).WillOnce(Return(acceptError));

    int someError = SOCKET_PEER_CLOSED_E;
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_error(_, acceptError))
            .Times(1)
            .WillRepeatedly(Return(someError));  // 1. DoSSLHandshake() 2. WolfSSLToEngineError()
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_ERR_error_string(someError, _))
            .Times(1);

    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_PEER_CLOSED);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeClientFailureConnect)
 * @brief function DoSSLHandshake fails when the engine is client and it wolfSSL_connect fails
 */
TEST_F(WolfSSLPSKEngineTest, DoSSLHandshakeClientFailureConnect) {
    m_engine->m_isServer = false;

    DoSSLHandshakeHelperTest();

    // wolfSSL_connect fails - does not return WOLFSSL_SUCCESS
    int acceptError = WOLFSSL_FAILURE;
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_connect(_)).Times(1).WillOnce(Return(acceptError));

    int someError = SOCKET_PEER_CLOSED_E;
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_error(_, acceptError))
            .Times(1)
            .WillRepeatedly(Return(someError));  // 1. DoSSLHandshake() 2. WolfSSLToEngineError()
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_ERR_error_string(someError, _))
            .Times(1);

    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_PEER_CLOSED);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, GetHintName)
 * @brief called function GetHintName successfully
 */
TEST_F(WolfSSLPSKEngineTest, GetHintName) {
    EXPECT_EQ(m_engine->GetHintName(), m_hint);
}

/**
 * @fn TEST_F(WolfSSLPSKEngineTest, GetRemoteHintName)
 * @brief called function GetRemoteHintName successfully
 */
TEST_F(WolfSSLPSKEngineTest, GetRemoteHintName) {
    m_engine->m_keys.remoteHint = "some hint";
    EXPECT_EQ(m_engine->GetRemoteHintName(), m_engine->m_keys.remoteHint);
}

#ifdef TLSAPI_WITH_DROP_SUPPORT
/**
 * @fn TEST_F(WolfSSLPSKEngineTest, DropTLSSuccess)
 * @brief called function DropTLS when it calls successfully
 */
TEST_F(WolfSSLPSKEngineTest, DropTLSSuccess) {
    successShutdownIsDrop();
    EXPECT_EQ(m_engine->DropTLS(), RC_TLS_ENGINE_SUCCESSFUL);
    EXPECT_TRUE(m_engine->m_isDropped);
}

#endif //TLSAPI_WITH_DROP_SUPPORT