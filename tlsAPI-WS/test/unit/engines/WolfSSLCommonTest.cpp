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

#include <wolfssl/options.h>

#include <wolfssl/error-ssl.h>

#include "ITLSEngine.hpp"
#include "MockIOStreamIf.hpp"
#include "MockTLSOcspHandler.hpp"
#include "MockTLSTEEAPI.hpp"
#include "MockWolfSSL.hpp"
#include "WolfSSLCertEngine.hpp"
#include "WolfSSLCommon.hpp"
#include "TLSLibApi.h"

using ::testing::_;
using ::testing::ByMove;
using ::testing::Return;
using ::testing::ReturnRef;

using namespace vwg::tls;
using namespace vwg::tls::impl;

class WolfSSLCommonTest : public ::testing::Test {
public:
    // To be returned
    WOLFSSL *m_newSSLRetVal = (WOLFSSL *) 0xdeadbeef;
    WOLFSSL_CTX *m_newCtxRetVal = (WOLFSSL_CTX *) 0x1337cafe;
    pskData m_data{"1001", "0001"};
    char m_identity[4] = {'0', '0', '0', '1'};
    char m_hint[4] = {'1', '0', '0', '1'};
    unsigned char m_key[PSK_MAX_PSK_LEN] = {'d', 'd', ':', 'b', 'f', ':', '4', '2', ':', '0', '3', ':',
                                            'd', 'd', ':', '4', 'd', ':', '0', 'a', ':', '4', '6', ':',
                                            '5', '8', ':', 'e', 'd', ':', 'a', '2', ':', '0', '6', ':',
                                            'f', 'c', ':', 'b', '3', ':', 'f', '5', ':', 'd', 'f'};

    char m_buffer[1024];
    unsigned char m_buffer_uc[1024];

    const std::string m_dummyUrl = "dummyUrl";
    std::vector<uint8_t> m_dummyOcspReq = {0xff, 0xff, 0xff, 0xff};
    std::vector<uint8_t> m_dummyOcspRes = {0x12, 0x34};
    byte *m_ocspResp = nullptr;
    std::shared_ptr<TLSOcspRequest> m_dummyTlsOcspReq;
    std::shared_ptr<TLSOcspRequestResponse> m_dummyTlsOcspRes;

    std::shared_ptr<MockIOStreamIf> m_stream;
    std::string m_hostName = "host";
    std::string m_certStoreId = "cert store";
    std::string m_clientCertificateSetID = "client cert id";
    CipherSuiteIds m_cipherSuiteIds = "";
    std::vector<HashSha256> m_httpPublicKeyPinningHashs;
    bool m_revocationCheckEnabled = true;
    AlpnMode m_alpnMode = ALPN_OFF;
    TimeCheckTime m_checkTime = CHECK_TIME_OFF;
    std::shared_ptr<ITLSOcspHandler> m_ocspHandler;
    uint32_t m_ocspTimeoutMs;

    std::shared_ptr<WolfSSLCertEngine> m_engine;

    char m_ctx[1024];


    virtual void
    SetUp() {
        m_stream = std::make_shared<MockIOStreamIf>();

        m_ocspTimeoutMs = 0;
        MockTLSOcspHandlerUT::mMockTLSOcspHandler = new MockTLSOcspHandler();
        m_ocspHandler = std::make_shared<MockTLSOcspHandlerUT>();

        m_engine = std::make_shared<WolfSSLCertEngine>(m_stream,
                                                       m_hostName,
                                                       m_certStoreId,
                                                       m_clientCertificateSetID,
                                                       m_httpPublicKeyPinningHashs,
                                                       m_revocationCheckEnabled,
                                                       m_cipherSuiteIds,
                                                       CSUSDefault,
                                                       m_alpnMode,
                                                       m_checkTime,
                                                       m_ocspHandler,
                                                       m_ocspTimeoutMs);

        MockWolfSSLUT::mMockWolfSSL = new MockWolfSSL();
        vwg::tee::TLSTEEUT::mMockTLSTEEAPI = std::make_shared<vwg::tee::MockTLSTEEAPI>();

        m_dummyTlsOcspReq = std::make_shared<TLSOcspRequest>(m_dummyUrl, m_dummyOcspReq);
        m_dummyTlsOcspRes =
                std::make_shared<TLSOcspRequestResponse>(m_dummyOcspRes, false, m_dummyTlsOcspReq->getUniqueId());
    }

    virtual void
    TearDown() {
        vwg::tee::TLSTEEUT::mMockTLSTEEAPI.reset();
        delete MockTLSOcspHandlerUT::mMockTLSOcspHandler;
        delete MockWolfSSLUT::mMockWolfSSL;
    }

    std::shared_ptr<WOLFSSL_CTX>
    success_wolfSSL_CTX_new() {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfTLSv1_2_method()).Times(1);

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(m_newCtxRetVal));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(m_newCtxRetVal)).Times(1);

        return std::shared_ptr<WOLFSSL_CTX>(wolfSSL_CTX_new(wolfTLSv1_2_method()), wolfSSL_CTX_free);
    }

    std::shared_ptr<WOLFSSL>
    success_wolfSSL_new() {
        // init ctx
        std::shared_ptr<WOLFSSL_CTX> ctx = success_wolfSSL_CTX_new();

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_new(_)).Times(1).WillOnce(Return(m_newSSLRetVal));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(m_newSSLRetVal)).Times(1);

        return std::shared_ptr<WOLFSSL>(wolfSSL_new(ctx.get()), wolfSSL_free);
    }

    void
    success_ocspOnlineCallback(const std::vector<uint8_t> &req, const std::vector<uint8_t> &res,
                               const std::string url) {
        std::promise<std::vector<TLSOcspRequestResponse>> dummyPromise;

        TLSOcspRequest dummyTlsOcspRequest(url.c_str(), req);
        TLSOcspRequestResponse dummyTlsOcspResponse(res, false, dummyTlsOcspRequest.getUniqueId());
        std::vector<TLSOcspRequestResponse> dummyTlsOcspResponses = {dummyTlsOcspResponse};

        dummyPromise.set_value(dummyTlsOcspResponses);

        EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, processRequests(_))
                .Times(1)
                .WillOnce(Return(ByMove(dummyPromise.get_future())));
    }
};

TEST_F(WolfSSLCommonTest, ServerPSKCallback) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected call in test
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _)).Times(1).WillOnce(Return(&m_data));
    EXPECT_CALL(*vwg::tee::TLSTEEUT::mMockTLSTEEAPI, get_psk(_, _, _)).Times(1).WillOnce(Return(true));

    // run test
    ServerPSKCallback(m_ssl.get(), m_identity, m_key, PSK_MAX_PSK_LEN);
}

TEST_F(WolfSSLCommonTest, ServerPSKCallback_get_psk_failed) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected call in test
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _)).Times(1).WillOnce(Return(&m_data));
    EXPECT_CALL(*vwg::tee::TLSTEEUT::mMockTLSTEEAPI, get_psk(_, _, _)).Times(1).WillOnce(Return(false));

    // run test
    ServerPSKCallback(m_ssl.get(), m_identity, m_key, PSK_MAX_PSK_LEN);
}

TEST_F(WolfSSLCommonTest, ServerPSKCallback_wolfSSL_get_ex_data_nullptr) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected call in test
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _)).Times(1).WillOnce(Return(nullptr));

    // run test
    ServerPSKCallback(m_ssl.get(), m_identity, m_key, PSK_MAX_PSK_LEN);
}

TEST_F(WolfSSLCommonTest, ServerPSKCallback_nullptr_check) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected not call in test
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _)).Times(0);

    // run test

    // ssl nullptr
    ServerPSKCallback(nullptr, m_identity, m_key, PSK_MAX_PSK_LEN);

    // identity nullptr
    ServerPSKCallback(m_ssl.get(), nullptr, m_key, PSK_MAX_PSK_LEN);

    // key nullptr
    ServerPSKCallback(m_ssl.get(), m_identity, nullptr, PSK_MAX_PSK_LEN);

    // max key size 0
    ServerPSKCallback(m_ssl.get(), m_identity, m_key, 0);
}

TEST_F(WolfSSLCommonTest, ClientPSKCallback) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected call in test
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _)).Times(1).WillOnce(Return(&m_data));
    EXPECT_CALL(*vwg::tee::TLSTEEUT::mMockTLSTEEAPI, get_psk(_, _, _)).Times(1).WillOnce(Return(true));

    // run test
    ClientPSKCallback(m_ssl.get(), m_hint, m_identity, PSK_MAX_IDENTITY_LEN, m_key, PSK_MAX_PSK_LEN);
}

TEST_F(WolfSSLCommonTest, ClientPSKCallback_get_psk_failed) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected call in test
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _)).Times(1).WillOnce(Return(&m_data));
    EXPECT_CALL(*vwg::tee::TLSTEEUT::mMockTLSTEEAPI, get_psk(_, _, _)).Times(1).WillOnce(Return(false));

    // run test
    ClientPSKCallback(m_ssl.get(), m_hint, m_identity, PSK_MAX_IDENTITY_LEN, m_key, PSK_MAX_PSK_LEN);
}

TEST_F(WolfSSLCommonTest, ClientPSKCallback_wolfSSL_get_ex_data_nullptr) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected call in test
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _)).Times(1).WillOnce(Return(nullptr));

    // run test
    ClientPSKCallback(m_ssl.get(), m_hint, m_identity, PSK_MAX_IDENTITY_LEN, m_key, PSK_MAX_PSK_LEN);
}

TEST_F(WolfSSLCommonTest, ClientPSKCallback_nullptr_check) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected not call in test
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _)).Times(0);

    // run test

    // ssl nullptr
    ClientPSKCallback(nullptr, m_hint, m_identity, PSK_MAX_IDENTITY_LEN, m_key, PSK_MAX_PSK_LEN);

    // hint nullptr
    ClientPSKCallback(m_ssl.get(), nullptr, m_identity, PSK_MAX_IDENTITY_LEN, m_key, PSK_MAX_PSK_LEN);

    // identity nullptr
    ClientPSKCallback(m_ssl.get(), m_hint, nullptr, PSK_MAX_IDENTITY_LEN, m_key, PSK_MAX_PSK_LEN);

    // max identity size 0
    ClientPSKCallback(m_ssl.get(), m_hint, m_identity, 0, m_key, PSK_MAX_PSK_LEN);

    // key nullptr
    ClientPSKCallback(m_ssl.get(), m_hint, m_identity, PSK_MAX_IDENTITY_LEN, nullptr, PSK_MAX_PSK_LEN);

    // max key size 0
    ClientPSKCallback(m_ssl.get(), m_hint, m_identity, PSK_MAX_IDENTITY_LEN, m_key, 0);
}

TEST_F(WolfSSLCommonTest, Init_Once) {
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_Init()).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_Cleanup()).Times(1);

    TLSResult<std::shared_ptr<ITLSSocketFactory>> socketFactory_rc = initTLSLib();
    EXPECT_TRUE(socketFactory_rc.succeeded());

    cleanupTLSLib();
}

TEST_F(WolfSSLCommonTest, Init_Twice)
{
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_Init()).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_Cleanup()).Times(1);

    TLSResult<std::shared_ptr<ITLSSocketFactory>> socketFactory_rc = initTLSLib();
    EXPECT_TRUE(socketFactory_rc.succeeded());
    socketFactory_rc = initTLSLib();
    EXPECT_TRUE(socketFactory_rc.succeeded());

    cleanupTLSLib();
}

TEST_F(WolfSSLCommonTest, Init_withThreads) {
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_Init()).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_Cleanup()).Times(1);

    std::vector<std::future<TLSResult<std::shared_ptr<ITLSSocketFactory>>>> vec(100); 

    for (int i = 0; i < vec.size(); i++)
    {
        vec.at(i) = std::async(std::launch::async, initTLSLib);
    }

    for (int i = 0; i < vec.size(); i++)
    {
        vec.at(i).wait();
        EXPECT_TRUE(vec.at(i).valid());
        EXPECT_TRUE(vec.at(i).get().succeeded()); 
    }

        cleanupTLSLib();
}

TEST_F(WolfSSLCommonTest, recvIO) {
    int rcvSize = 16;

    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected call in test
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(rcvSize));

    // run test
    EXPECT_EQ(recvIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), rcvSize);
}

TEST_F(WolfSSLCommonTest, nullptr_recvIO) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected not call in test
    EXPECT_CALL(*m_stream, receive(_, _)).Times(0);

    // ssl nullptr
    EXPECT_EQ(recvIO(nullptr, m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // buffer nullptr
    EXPECT_EQ(recvIO(m_ssl.get(), nullptr, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // buffer len zero
    EXPECT_EQ(recvIO(m_ssl.get(), m_buffer, 0, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // buffer less than zero
    EXPECT_EQ(recvIO(m_ssl.get(), m_buffer, -1, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // stream nullptr
    EXPECT_EQ(recvIO(m_ssl.get(), m_buffer, 1024, nullptr), WOLFSSL_CBIO_ERR_GENERAL);
}

TEST_F(WolfSSLCommonTest, fail_recvIO) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // test 1: receive return zero
    int rcvSize = 0;

    // expected call in test
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(rcvSize));

    // run test
    EXPECT_EQ(recvIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_CONN_CLOSE);

    // test 2: receive return RC_STREAM_WOULD_BLOCK
    rcvSize = vwg::tls::RC_STREAM_WOULD_BLOCK;

    // expected call in test
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(rcvSize));

    // run test
    EXPECT_EQ(recvIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_WANT_READ);

    // test 3: receive return RC_STREAM_IO_ERROR
    rcvSize = vwg::tls::RC_STREAM_IO_ERROR;

    // expected call in test
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(rcvSize));

    // run test
    EXPECT_EQ(recvIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // test 4: receive return everything else
    rcvSize = -20;

    // expected call in test
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(rcvSize));

    // run test
    EXPECT_EQ(recvIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);
}

TEST_F(WolfSSLCommonTest, sendIO) {
    int sendSize = 16;

    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected call in test
    EXPECT_CALL(*m_stream, send(_, _)).Times(1).WillOnce(Return(sendSize));

    // run test
    EXPECT_EQ(sendIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), sendSize);
}

TEST_F(WolfSSLCommonTest, nullptr_sendIO) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // expected not call in test
    EXPECT_CALL(*m_stream, send(_, _)).Times(0);

    // ssl nullptr
    EXPECT_EQ(sendIO(nullptr, m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // buffer nullptr
    EXPECT_EQ(sendIO(m_ssl.get(), nullptr, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // buffer len zero
    EXPECT_EQ(sendIO(m_ssl.get(), m_buffer, 0, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // buffer less than zero
    EXPECT_EQ(sendIO(m_ssl.get(), m_buffer, -1, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // stream nullptr
    EXPECT_EQ(sendIO(m_ssl.get(), m_buffer, 1024, nullptr), WOLFSSL_CBIO_ERR_GENERAL);
}

TEST_F(WolfSSLCommonTest, fail_sendIO) {
    // init ssl
    std::shared_ptr<WOLFSSL> m_ssl = success_wolfSSL_new();

    // test 1: send return -10
    int sendSize = -10;

    // expected call in test
    EXPECT_CALL(*m_stream, send(_, _)).Times(1).WillOnce(Return(sendSize));

    // run test
    EXPECT_EQ(sendIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // test 2: send return RC_STREAM_IO_ERROR
    sendSize = vwg::tls::RC_STREAM_IO_ERROR;

    // expected call in test
    EXPECT_CALL(*m_stream, send(_, _)).Times(1).WillOnce(Return(sendSize));

    // run test
    EXPECT_EQ(sendIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_GENERAL);

    // test 3: send return RC_STREAM_WOULD_BLOCK
    sendSize = vwg::tls::RC_STREAM_WOULD_BLOCK;

    // expected call in test
    EXPECT_CALL(*m_stream, send(_, _)).Times(1).WillOnce(Return(sendSize));

    // run test
    EXPECT_EQ(sendIO(m_ssl.get(), m_buffer, 1024, (void *) m_stream.get()), WOLFSSL_CBIO_ERR_WANT_WRITE);
}

TEST_F(WolfSSLCommonTest, ocspOnlineCallback) {
    success_ocspOnlineCallback(m_dummyOcspReq, m_dummyOcspRes, m_dummyUrl);

    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              m_dummyOcspRes.size());
}

TEST_F(WolfSSLCommonTest, fail_bad_arguments_ocspOnlineCallback) {
    const int FAIL = -1;

    // Context is nullptr
    EXPECT_EQ(ocspOnlineCallback(nullptr,
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // url is nullptr
    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 nullptr,
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // url size 0
    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 0,
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // url size mismatch
    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size() - 1,
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // url size negative
    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 (int) -m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // request is nullptr
    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 nullptr,
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // request size 0
    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 0,
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // request size negative
    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 (int) -m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // response is nullptr
    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 nullptr),
              FAIL);
}

TEST_F(WolfSSLCommonTest, fail_ocspOnlineCallback) {
    const int FAIL = -1;

    std::shared_ptr<vwg::tls::ITLSOcspHandler> nullptrHandler = nullptr;

    // GetOcspHandler returns nullptr
    std::shared_ptr<WolfSSLCertEngine> nullOcspHandlerEngine =
            std::make_shared<WolfSSLCertEngine>(m_stream,
                                                m_hostName,
                                                m_certStoreId,
                                                m_clientCertificateSetID,
                                                m_httpPublicKeyPinningHashs,
                                                m_revocationCheckEnabled,
                                                m_cipherSuiteIds,
                                                CSUSDefault,
                                                m_alpnMode,
                                                m_checkTime,
                                                nullptrHandler,
                                                m_ocspTimeoutMs);

    EXPECT_EQ(ocspOnlineCallback(nullOcspHandlerEngine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // Invalid future
    std::promise<std::vector<TLSOcspRequestResponse>> notSetPromise;
    EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, processRequests(_))
            .Times(1)
            .WillOnce(Return(ByMove(notSetPromise.get_future())));

    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // Responses vector that return from processRequests is empty
    std::promise<std::vector<TLSOcspRequestResponse>> emptyVectorPromise;
    emptyVectorPromise.set_value(std::vector<TLSOcspRequestResponse>());
    EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, processRequests(_))
            .Times(1)
            .WillOnce(Return(ByMove(emptyVectorPromise.get_future())));

    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // Responses vector size > 1
    std::promise<std::vector<TLSOcspRequestResponse>> responsesVectorBiggerPromise;
    responsesVectorBiggerPromise.set_value(
            std::vector<TLSOcspRequestResponse>({*m_dummyTlsOcspRes, *m_dummyTlsOcspRes}));
    EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, processRequests(_))
            .Times(1)
            .WillOnce(Return(ByMove(responsesVectorBiggerPromise.get_future())));

    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // Responses unique id mismatch with request
    std::promise<std::vector<TLSOcspRequestResponse>> respUniqueIdMismatchPromise;
    respUniqueIdMismatchPromise.set_value(std::vector<TLSOcspRequestResponse>{
            TLSOcspRequestResponse(m_dummyOcspRes, false, ~m_dummyTlsOcspReq->getUniqueId())});
    EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, processRequests(_))
            .Times(1)
            .WillOnce(Return(ByMove(respUniqueIdMismatchPromise.get_future())));

    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);

    // Response was marked as corrupted
    std::promise<std::vector<TLSOcspRequestResponse>> respCorruptedPromise;
    respCorruptedPromise.set_value(
            std::vector<TLSOcspRequestResponse>{TLSOcspRequestResponse(m_dummyTlsOcspReq->getUniqueId())});
    EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, processRequests(_))
            .Times(1)
            .WillOnce(Return(ByMove(respCorruptedPromise.get_future())));

    EXPECT_EQ(ocspOnlineCallback(m_engine.get(),
                                 m_dummyUrl.c_str(),
                                 m_dummyUrl.size(),
                                 m_dummyOcspReq.data(),
                                 m_dummyOcspReq.size(),
                                 (unsigned char **) &m_ocspResp),
              FAIL);
}