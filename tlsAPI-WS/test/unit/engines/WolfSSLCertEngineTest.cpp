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

#include <gtest/gtest.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>

#include <fstream>
#include <unordered_set>

#include "MockEngineCommon.hpp"
#include "MockIOStreamIf.hpp"
#include "MockTLSOcspHandler.hpp"
#include "MockTLSTEEAPI.hpp"
#include "MockWolfSSL.hpp"
#include "WolfSSLCertEngine.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::DoAll;

using namespace vwg::tls;
using namespace vwg::tls::impl;
using namespace vwg::tee;

MockWolfSSL *MockWolfSSLUT::mMockWolfSSL;
MockEngineCommon *MockEngineCommonUT::mMockEngineCommon;
MockTLSOcspHandler *MockTLSOcspHandlerUT::mMockTLSOcspHandler;
std::shared_ptr<MockTLSTEEAPI> TLSTEEUT::mMockTLSTEEAPI;

// Required definitions due to creation of shard pointer for this type.
// This is dummy definitions. we did it instead of copy wolfssl's "internal.h" file into our test files.
struct WOLFSSL {
    int dummy;
};

class WolfSSLCertEngineTest : public ::testing::Test {
public:
    std::shared_ptr<MockIOStreamIf> m_stream;
    std::shared_ptr<ITLSOcspHandler> m_ocspHandler;
    uint32_t m_ocspTimeoutMs;

    std::string m_hostName = "host";
    std::string m_certStoreId = "cert store";
    std::string m_clientCertificateSetID = "client cert id";
    CipherSuiteIds m_cipherSuiteIds = "";
    bool m_revocationCheckEnabled = true;
    AlpnMode m_alpnMode = ALPN_OFF;
    TimeCheckTime m_checkTime = CHECK_TIME_OFF;
    std::vector<HashSha256> m_httpPublicKeyPinningHashs;
    std::shared_ptr<WolfSSLCertEngine> m_engine;
    std::shared_ptr<WOLFSSL_X509_STORE_CTX> m_x509Ctx;
    std::shared_ptr<OcspResponse> m_wolfSslOcspResponse;
    std::shared_ptr<TLSOcspRequestResponse> m_validOcspRequestResponse;

    std::string defaultCipherSuites = "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:"
                                      "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
                                      "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:"
                                      "DHE-RSA-AES256-GCM-SHA384:TLS13-AES128-GCM-SHA256:"
                                      "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256";

    // To be returned
    WOLFSSL *m_newSSLRetVal = (WOLFSSL *) 0xdeadbeef;
    WOLFSSL_CTX *m_newCtxRetVal = (WOLFSSL_CTX *) 0x1337cafe;
    WOLFSSL_ALERT_HISTORY m_historyRetVal;

    std::string m_rsaCertificateFileName = "rsa_1.der";
    std::string m_certificatesDirName = "certificates";

    const int ELIPTIC_CURVE_OID = 518;

    // some WolfSSL error and its appropriate EngineError
    std::pair<int, TLSEngineError> m_someWolfSSLAndEngineErrorPair = {SOCKET_PEER_CLOSED_E, RC_TLS_ENGINE_PEER_CLOSED};

    virtual void
    SetUp() {
        std::vector<char> dummyHash = {'a', 'b', 'c'};
        m_httpPublicKeyPinningHashs.push_back(dummyHash);

        m_stream = std::make_shared<MockIOStreamIf>();
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
        m_validOcspRequestResponse =
                std::make_shared<TLSOcspRequestResponse>(std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}, false, 0);
        TLSTEEUT::mMockTLSTEEAPI = std::make_shared<MockTLSTEEAPI>();
        MockWolfSSLUT::mMockWolfSSL = new MockWolfSSL();
        MockEngineCommonUT::mMockEngineCommon = new MockEngineCommon();
        MockTLSOcspHandlerUT::mMockTLSOcspHandler = new MockTLSOcspHandler();
        m_x509Ctx = std::make_shared<WOLFSSL_X509_STORE_CTX>();
        m_x509Ctx->current_cert = (WOLFSSL_X509 *) 0xdeadbeef;
        m_wolfSslOcspResponse = std::make_shared<OcspResponse>();
        m_wolfSslOcspResponse->single = new OcspEntry;
        m_wolfSslOcspResponse->single->status = new CertStatus;
    }

    std::vector<uint8_t>
    loadFile(std::string const &path) {
        std::ifstream file(path);
        std::vector<uint8_t> data;

        if (file.is_open()) {
            // load certificate data from file, return file contents without processing
            data = std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
        }

        return data;
    }

    void
    checkEqual(std::unordered_set<std::string> expected, std::string str) {
        uint count = 0;
        for (auto iter = expected.begin(); iter != expected.end(); ++iter, count++) {
            EXPECT_NE((str).find(*iter), std::string::npos);
        }
        EXPECT_EQ(count, expected.size());
    }

    void
    successShutdownCheck() {
        m_engine->m_ssl = std::make_shared<WOLFSSL>();

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(0));

        m_engine->m_sslInit.store(true);

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_shutdown(_))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SHUTDOWN_NOT_DONE))
                .WillOnce(Return(WOLFSSL_SUCCESS));
    }

    void
    getAlpnProtocolTest(AlpnMode alpnMode, bool expectedRes, std::string expectedAlpnRes) {
        m_engine = std::make_shared<WolfSSLCertEngine>(m_stream,
                                                       m_hostName,
                                                       m_certStoreId,
                                                       m_clientCertificateSetID,
                                                       m_httpPublicKeyPinningHashs,
                                                       m_revocationCheckEnabled,
                                                       m_cipherSuiteIds,
                                                       CSUSDefault,
                                                       alpnMode,
                                                       m_checkTime,
                                                       m_ocspHandler,
                                                       m_ocspTimeoutMs);

        std::string alpn = "";
        bool res = m_engine->getAlpnProtocol(alpn);
        EXPECT_EQ(res, expectedRes);
        EXPECT_EQ(alpn, expectedAlpnRes);
    }

    void
    WolfSSLToEngineErrorTest(int getErrorRet) {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_error(_, 0)).WillOnce(Return(getErrorRet));
    }

    void
    WolfSSLToEngineErrorTestHistory(int historyErrorRet, bool isRx = true) {
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

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_alert_history(_, _))
                .WillOnce(
                        DoAll(SetArgPointee<1>(
                                      m_historyRetVal),  // out parameter returning from wolfSSL_get_alert_history mock
                              Return(WOLFSSL_SUCCESS)));
    }

    void
    getUsedProtocolTest(char *protocol, int getProtocolRet, IANAProtocol expectedProtocol) {
        // wolfSSL_ALPN_GetProtocol
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_ALPN_GetProtocol(_, _, _))
                .WillOnce(
                        DoAll(SetArgPointee<1>(protocol),  // out parameter returning from wolfSSL_ALPN_GetProtocol mock
                              Return(getProtocolRet)));

        EXPECT_EQ(m_engine->getUsedProtocol(), expectedProtocol);
    }

    void
    calculate_public_key_pin_hash_test() {
        // checked calculate_public_key_pin_hash_test internal function have called

        // wc_Sha256Hash
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wc_Sha256Hash(_, _, _)).Times(1).WillOnce(Return(0));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, Base64_Encode_NoNl(_, _, _, _)).Times(1).WillOnce(Return(0));
    }

    void
    ctxInitScenarioForSuccess() {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSLv23_client_method()).Times(1);

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(m_newCtxRetVal));

        int setMinVersionRetval = 1;  // for calling mock wolfSSL_CTX_SetMinVersion
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_SetMinVersion(_, WOLFSSL_TLSV1_2))
                .Times(1)
                .WillOnce(Return(setMinVersionRetval));

        // wolfSSL_SetIORecv(m_ctx.get(), recvIO);
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIORecv(_, _)).Times(1);

        // wolfSSL_SetIOSend(m_ctx.get(), sendIO);
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOSend(_, _)).Times(1);

        std::string toBeRet = "root cert";
        EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(m_certStoreId)).Times(1).WillOnce(Return(toBeRet));

        // for calling mock wolfSSL_CTX_load_verify_buffer
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_load_verify_buffer(_, _, _, _))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));
    }


    void
    sslInitHelper() {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_new(_)).Times(1).WillOnce(Return(m_newSSLRetVal));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOReadCtx(_, _))  // wolfSSL_SetIOReadCtx
                .Times(1);
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOWriteCtx(_, _))  // wolfSSL_SetIOWriteCtx
                .Times(1);

        for (int ec = WOLFSSL_ECC_SECP256R1; ec <= WOLFSSL_ECC_SECP521R1; ec++) {
            EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseSupportedCurve(_, ec))
                    .Times(1)
                    .WillOnce(Return(WOLFSSL_SUCCESS));
        }
    }

    void
    sslInitScenarioForSuccess() {
        sslInitHelper();

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseSNI(_, 0, _, (word16) m_hostName.size()))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));


        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_set_cipher_list(_, m_engine->m_validCiphers.c_str()))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));

        int setSetEngineObjectExData = WOLFSSL_SUCCESS;  // for calling mock wolfSSL_set_ex_data
        EXPECT_CALL(
                *MockWolfSSLUT::mMockWolfSSL,
                wolfSSL_set_ex_data(_, WolfSSLCertEngine::EX_DATA_IDX_WOLFSSL_CERT_ENGINE_OBJ, (void *) m_engine.get()))
                .Times(1)
                .WillOnce(Return(setSetEngineObjectExData));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                    wolfSSL_set_verify(_, SSL_VERIFY_PEER, WolfSSLCertEngine::verifyCallback))
                .Times(1);
    }

    void
    teeInitScenarioForSuccess() {
        std::string cerToBeRet = "client_cert";
        EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(m_clientCertificateSetID))
                .Times(1)
                .WillOnce(Return(cerToBeRet));

        std::string keyToBeRet = "private key";
        EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert_private_key(m_clientCertificateSetID))
                .Times(1)
                .WillOnce(Return(keyToBeRet));

        // for wolfSSL_use_certificate_buffer calling mock
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                    wolfSSL_use_certificate_buffer(_, _, cerToBeRet.size(), WOLFSSL_FILETYPE_PEM))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));

        // for wolfSSL_use_PrivateKey_buffer calling mock
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                    wolfSSL_use_PrivateKey_buffer(_, _, keyToBeRet.size(), WOLFSSL_FILETYPE_PEM))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));
    }

    void
    ocspInitScenarioForSuccess() {
        m_engine->m_revocationCheckEnabled = true;

#ifndef TLSAPI_ICAS3_TEST_STAPLING_HARDFAIL_NO_OCSP_FALLBACK
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSP(_, _))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetOCSP_Cb(_, _, _, _))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));
#else
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_EnableOCSPMustStaple(_))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));
#endif

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSPStapling(_))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseOCSPStapling(_, _, _))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));
    }

    void
    wolfsslConnectScenarioForSuccess() {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_connect(_)).Times(1).WillOnce(Return(SSL_SUCCESS));
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_check_domain_name(_, _)).Times(1).WillOnce(Return(SSL_SUCCESS));
    }

    void
    wolfsslConnectScenarioForFailure() {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_connect(_)).Times(0);
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_check_domain_name(_, _)).Times(1).WillOnce(Return(SSL_FAILURE));
    }

    void
    validateHashPinningGetPeerChainAndGetX509() {
        const size_t CHAIN_SIZE = 1;

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_peer_chain(_))
                .Times(1)
                .WillOnce(Return((WOLFSSL_X509_CHAIN *) 0xdeadbeef));
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_chain_count(_)).Times(1).WillOnce(Return(CHAIN_SIZE));
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_chain_X509(_, _))
                .Times(1)
                .WillOnce(Return((WOLFSSL_X509 *) 0xdeadbeef));
    }

    void
    validateHashPinningScenarioHelper() {
        validateHashPinningGetPeerChainAndGetX509();
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_get_pubkey_buffer(_, _, _))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));

        calculate_public_key_pin_hash_test();  // check calculate_public_key_pin_hash function has called
    }

    void
    validateHashPinningScenarioForSuccess() {
        validateHashPinningScenarioHelper();

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_free(_)).Times(1);

        EXPECT_CALL(*MockEngineCommonUT::mMockEngineCommon, atLeastOneCommonMember(_, _)).Times(1).WillOnce(Return(1));
    }

    void
    postVerificationHandlerScenarioForSuccess() {
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_ext_isSet_by_NID(_, _))
                .Times(1)
                .WillOnce(Return(WOLFSSL_SUCCESS));

        m_engine->m_ocspRequestsResponses.push_back(*m_validOcspRequestResponse);

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_d2i_OCSP_RESPONSE(_, _, _))
                .Times(1)
                .WillOnce(Return(m_wolfSslOcspResponse.get()));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_OCSP_RESPONSE_free(_)).Times(1);

        EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, cacheResponses(_)).Times(1);
    }

    void
    verifyCallbackScenarioForSuccess() {
        m_engine->m_ssl = std::shared_ptr<WOLFSSL>(m_newSSLRetVal, wolfSSL_free);

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data_X509_STORE_CTX_idx())
                .Times(1)
                .WillOnce(Return(0));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_STORE_CTX_get_ex_data(_, _))
                .Times(1)
                .WillOnce(Return((WOLFSSL *) m_engine->m_ssl.get()));

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data(_, _))
                .Times(1)
                .WillOnce(Return((WolfSSLCertEngine *) m_engine.get()));
                
        const size_t CHAIN_SIZE = 1;

        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_peer_chain(_))
                .Times(1)
                .WillOnce(Return((WOLFSSL_X509_CHAIN *) 0xdeadbeef));
        EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_chain_count(_)).Times(1).WillOnce(Return(CHAIN_SIZE));
    }

    void
    ctxDtor() {
        if (m_engine->m_ctx != nullptr) {
            EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);
        }
    }

    void
    sslDtor() {
        if (m_engine->m_ssl != nullptr) {
            EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(m_engine->m_ssl.get())).Times(1);
        }
    }

    void
    engineDestructor() {
        m_engine->m_sslInit.store(false);  // in order not to get in : if (m_sslInit) in close() function (that's
        // called from engine's dtor)

        ctxDtor();
        sslDtor();
    }

    virtual void
    TearDown() {
        TLSTEEUT::mMockTLSTEEAPI.reset();

        engineDestructor();
        m_engine.reset();

        delete MockWolfSSLUT::mMockWolfSSL;
        delete MockEngineCommonUT::mMockEngineCommon;
        delete MockTLSOcspHandlerUT::mMockTLSOcspHandler;
        delete m_wolfSslOcspResponse->single;
        delete m_wolfSslOcspResponse->single->status;
    }
};

/**
 * @fn TEST_F(WolfSSLCertEngineTest, filteredCiphers)
 * @brief checking filteredCiphers - function
 */
TEST_F(WolfSSLCertEngineTest, filteredCiphers) {
    std::unordered_set<std::string> expected = {"ECDHE-ECDSA-CHACHA20-POLY1305:",
                                                "ECDHE-ECDSA-AES128-GCM-SHA256:",
                                                "ECDHE-ECDSA-AES256-GCM-SHA384:",
                                                "ECDHE-RSA-AES128-GCM-SHA256:",
                                                "ECDHE-RSA-AES256-GCM-SHA384:",
                                                "DHE-RSA-AES128-GCM-SHA256:",
                                                "DHE-RSA-AES256-GCM-SHA384:",
                                                "TLS13-AES128-GCM-SHA256:",
                                                "TLS13-AES256-GCM-SHA384:",
                                                "TLS13-CHACHA20-POLY1305-SHA256"};

    // Checked filteredCiphers When cipher suite id is invalid
    m_engine->m_validCiphers = "";
    m_engine->filteredCiphers("some invalid data");
    checkEqual(expected, m_engine->m_validCiphers);

    // Checked filteredCiphers when cipher suite id is all
    m_engine->m_validCiphers = "";
    m_engine->filteredCiphers("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
                              "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
                              "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:"
                              "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");

    checkEqual(expected, m_engine->m_validCiphers);

    // Checked filteredCiphers When cipher suite id is empty
    m_engine->m_validCiphers = "";
    m_engine->filteredCiphers("");
    checkEqual(expected, m_engine->m_validCiphers);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, setCipherSuitesListUseCase)
 * @brief checks setCipherSuitesListUseCase function
 */
TEST_F(WolfSSLCertEngineTest, setCipherSuitesListUseCase) {
    std::string ianaRecommendedCiphers = defaultCipherSuites + ":DHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                                                               "TLS13-AES128-CCM-SHA256";

    // CSUSDefault case
    m_engine->m_validCiphers = "";
    m_engine->setCipherSuitesListUseCase(CSUSDefault);
    EXPECT_EQ(defaultCipherSuites, m_engine->m_validCiphers);
    EXPECT_EQ(CSUSDefault, m_engine->m_cipherSuiteUseCase);

    // CSUSDefaultWithSoftFail case
    m_engine->m_validCiphers.clear();
    m_engine->setCipherSuitesListUseCase(CSUSDefaultWithSoftFail);
    // Should be the same as CSUSDefault case
    EXPECT_EQ(defaultCipherSuites, m_engine->m_validCiphers);
    EXPECT_EQ(CSUSDefaultWithSoftFail, m_engine->m_cipherSuiteUseCase);

    // CSUSLegacy case
    std::string legacyCiphers = ianaRecommendedCiphers + ":ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:"
                                                         "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:"
                                                         "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
                                                         "DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:"
                                                         "AES128-GCM-SHA256:AES256-GCM-SHA384:"
                                                         "AES128-SHA256:AES256-SHA256:"
                                                         "AES128-SHA:AES256-SHA:"
                                                         "DES-CBC3-SHA:TLS13-AES128-CCM-SHA256";
    m_engine->m_validCiphers = "";
    m_engine->setCipherSuitesListUseCase(CSUSLegacy);
    EXPECT_EQ(legacyCiphers, m_engine->m_validCiphers);
    EXPECT_EQ(CSUSLegacy, m_engine->m_cipherSuiteUseCase);

    // CSUSLongtermSecure case
    std::string longTermSecureCiphers = "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:"
                                        "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:"
                                        "DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384:"
                                        "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256";
    m_engine->m_validCiphers = "";
    m_engine->setCipherSuitesListUseCase(CSUSLongtermSecure);
    EXPECT_EQ(longTermSecureCiphers, m_engine->m_validCiphers);
    EXPECT_EQ(CSUSLongtermSecure, m_engine->m_cipherSuiteUseCase);


    // CSUSIanaRecommended case
    m_engine->m_validCiphers = "";
    m_engine->setCipherSuitesListUseCase(CSUSIanaRecommended);
    EXPECT_EQ(ianaRecommendedCiphers, m_engine->m_validCiphers);
    EXPECT_EQ(CSUSIanaRecommended, m_engine->m_cipherSuiteUseCase);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, getUsedAlpnMode)
 * @brief checking getUsedAlpnMode - function
 */
TEST_F(WolfSSLCertEngineTest, getUsedAlpnMode) {
    AlpnMode res = m_engine->getUsedAlpnMode();
    EXPECT_EQ(res.userDefinedALPNisUsed(), m_alpnMode.userDefinedALPNisUsed());
    EXPECT_EQ(res.getSupportedProtocols(), m_alpnMode.getSupportedProtocols());
    EXPECT_EQ(res.getUserDefinedAlpnSetting(), m_alpnMode.getUserDefinedAlpnSetting());
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, wolfsslConnectSuccess)
 * @brief wolfsslConnect - function called successfully
 */
TEST_F(WolfSSLCertEngineTest, wolfsslConnectSuccess) {
    wolfsslConnectScenarioForSuccess();
    EXPECT_EQ(m_engine->wolfsslConnect(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, wolfsslConnectFailure)
 * @brief wolfsslConnect - function call failed
 */
TEST_F(WolfSSLCertEngineTest, wolfsslConnectFailure) {
    wolfsslConnectScenarioForFailure();
    EXPECT_EQ(m_engine->wolfsslConnect(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, SendSuccess)
 * @brief function Send called successfully
 */
TEST_F(WolfSSLCertEngineTest, SendSuccess) {
    m_engine->m_ssl = std::shared_ptr<WOLFSSL>(m_newSSLRetVal, wolfSSL_free);

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
 * @fn TEST_F(WolfSSLCertEngineTest, SendFailure)
 * @brief checking Send function - when it gets a failure
 */
TEST_F(WolfSSLCertEngineTest, SendFailure) {
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
    m_engine->m_ssl = std::shared_ptr<WOLFSSL>(m_newSSLRetVal, wolfSSL_free);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(WOLFSSL_SENT_SHUTDOWN));

    // Test
    EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength), RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN);
    EXPECT_EQ(actualLength, 0);

    // expected calls when wolfSSL_send returns an error
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(0));

    int sendRetVal = -1;  // for wolfSSL_send calling
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_send(_, buf, bufLength, 0)).Times(1).WillOnce(Return(sendRetVal));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    // Test
    TLSEngineError res = m_engine->Send(buf, bufLength, actualLength);
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(actualLength, sendRetVal);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ReceiveSuccess)
 * @brief function Receive called successfully
 */
TEST_F(WolfSSLCertEngineTest, ReceiveSuccess) {
    m_engine->m_ssl = std::shared_ptr<WOLFSSL>(m_newSSLRetVal, wolfSSL_free);

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
 * @fn TEST_F(WolfSSLCertEngineTest, ReceiveFailure)
 * @brief function Receive when it fails
 */
TEST_F(WolfSSLCertEngineTest, ReceiveFailure) {
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
    m_engine->m_ssl = std::shared_ptr<WOLFSSL>(m_newSSLRetVal, wolfSSL_free);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(WOLFSSL_SENT_SHUTDOWN));

    // Test
    EXPECT_EQ(m_engine->Receive(buf, bufLength, actualLength), RC_TLS_ENGINE_SPECIFIC_ERROR);
    EXPECT_EQ(actualLength, 0);

    // expected calls when wolfSSL_recv returns an error
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(0));

    int sendRetVal = -1;  // for wolfSSL_recv calling
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_recv(_, buf, bufLength, 0)).Times(1).WillOnce(Return(sendRetVal));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    // Test
    TLSEngineError res = m_engine->Receive(buf, bufLength, actualLength);
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(actualLength, sendRetVal);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, SetBlockingSuccess)
 * @brief function SetBlocking called successfully
 */
TEST_F(WolfSSLCertEngineTest, SetBlockingSuccess) {
    bool blocking = true;
    EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(true));  // TLSCertEngine::SetBlocking
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_dtls_set_using_nonblock(_, !blocking)).Times(1);

    TLSEngineError res = m_engine->SetBlocking(blocking);
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, SetBlockingFailure)
 * @brief function SetBlocking fails
 */
TEST_F(WolfSSLCertEngineTest, SetBlockingFailure) {
    bool blocking = true;
    EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(false));  // TLSCertEngine::SetBlocking

    TLSEngineError res = m_engine->SetBlocking(blocking);
    EXPECT_EQ(res, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ShutdownSuccess_wolfSSL_shutdown_twice)
 * @brief function Shutdown called successfully when it calls wolfSSL_shutdown twice
 */
TEST_F(WolfSSLCertEngineTest, ShutdownSuccess_wolfSSL_shutdown_twice) {
    // expected calls
    successShutdownCheck();

    // Test 2
    TLSEngineError res = m_engine->Shutdown();
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ShutdownSuccess_WOLFSSL_SENT_SHUTDOWN)
 * @brief function Shutdown called successfully when wolfSSL_get_shutdown returns WOLFSSL_SENT_SHUTDOWN
 */
TEST_F(WolfSSLCertEngineTest, ShutdownSuccess_WOLFSSL_SENT_SHUTDOWN) {
    // Test 1: when m_ssl is nullptr
    EXPECT_EQ(m_engine->Shutdown(), RC_TLS_ENGINE_SUCCESSFUL);

    // Expected calls
    m_engine->m_ssl = std::shared_ptr<WOLFSSL>(m_newSSLRetVal, wolfSSL_free);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(WOLFSSL_SENT_SHUTDOWN));

    // Test: when m_ssl is not nullptr and wolfSSL_get_shutdown returns WOLFSSL_SENT_SHUTDOWN
    EXPECT_EQ(m_engine->Shutdown(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ShutdownSuccess_noInitSsl)
 * @brief function Shutdown called successfully when m_sslInit is false
 */
TEST_F(WolfSSLCertEngineTest, ShutdownSuccess_noInitSsl) {
    // Expected calls
    m_engine->m_ssl = std::shared_ptr<WOLFSSL>(m_newSSLRetVal, wolfSSL_free);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_))
            .Times(1)
            .WillOnce(Return(WOLFSSL_RECEIVED_SHUTDOWN));  // does not return WOLFSSL_SENT_SHUTDOWN

    // Test: when m_sslInit is false
    EXPECT_EQ(m_engine->Shutdown(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ShutdownFailure)
 * @brief function Shutdown called when wolfSSL_shutdown does not return WOLFSSL_SHUTDOWN_NOT_DONE in the first call
 */
TEST_F(WolfSSLCertEngineTest, ShutdownFailure) {
    // Expected calls
    m_engine->m_ssl = std::shared_ptr<WOLFSSL>(m_newSSLRetVal, wolfSSL_free);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(1).WillOnce(Return(0));

    m_engine->m_sslInit.store(true);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_shutdown(_))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));  // does not return WOLFSSL_SHUTDOWN_NOT_DONE

    EXPECT_EQ(m_engine->Shutdown(), 0);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, CloseSuccess)
 * @brief function Close called successfully
 */
TEST_F(WolfSSLCertEngineTest, CloseSuccess) {
    // expected calls
    successShutdownCheck();

    // test
    m_engine->Close();
    EXPECT_EQ(m_engine->m_ssl, nullptr);
    EXPECT_EQ(m_engine->m_sslInit, false);
    EXPECT_EQ(m_engine->m_ctx, nullptr);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ocspInitSuccess)
 * @brief function ocspInit called successfully
 */
TEST_F(WolfSSLCertEngineTest, ocspInitSuccess) {
    // Cipher suites use case is default
    m_engine->m_cipherSuiteUseCase = CSUSDefault;
    ocspInitScenarioForSuccess();
    m_engine->m_revocationCheckEnabled = true;
    TLSEngineError res = m_engine->ocspInit();  // call ocspInit when m_revocationCheckEnabled==true
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);

    // Cipher suites use case is legacy
    m_engine->m_cipherSuiteUseCase = CSUSLegacy;
    ocspInitScenarioForSuccess();
    m_engine->m_revocationCheckEnabled = true;
    res = m_engine->ocspInit();  // call ocspInit when m_revocationCheckEnabled==true
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);

    m_engine->m_revocationCheckEnabled = false;
    res = m_engine->ocspInit();  // call ocspInit when m_revocationCheckEnabled==false
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

#ifndef TLSAPI_ICAS3_TEST_STAPLING_HARDFAIL_NO_OCSP_FALLBACK
/**
 * @fn TEST_F(WolfSSLCertEngineTest, ocspInitSuccessDefaultWithSoftFail)
 * @brief function ocspInit called successfully
 */
TEST_F(WolfSSLCertEngineTest, ocspInitSuccessDefaultWithSoftFail) {

    // Cipher suites use case is default with soft-fail
    m_engine->m_cipherSuiteUseCase = CSUSDefaultWithSoftFail;
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSPStapling(_))
        .Times(1)
        .WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseOCSPStapling(_, _, _))
        .Times(1)
        .WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSP(_, _)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetOCSP_Cb(_, _, _, _)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));
    m_engine->m_revocationCheckEnabled = true;
    TLSEngineError res = m_engine->ocspInit();  // call ocspInit when m_revocationCheckEnabled==true
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ocspInitFailure_wolfSSL_SetOCSP_Cb)
 * @brief function ocspInit called when wolfSSL_SetOCSP_Cb fails
 */
TEST_F(WolfSSLCertEngineTest, ocspInitFailure_wolfSSL_SetOCSP_Cb) {
    // Cipher suites use case is default
    m_engine->m_cipherSuiteUseCase = CSUSDefault;

    m_engine->m_revocationCheckEnabled = true;

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSPStapling(_)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseOCSPStapling(_, _, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSP(_, _)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetOCSP_Cb(_, _, _, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    TLSEngineError res = m_engine->ocspInit();  // call ocspInit when m_revocationCheckEnabled==true
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
}

#endif

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ocspInitFailure_wolfSSL_EnableOCSPStapling)
 * @brief function ocspInit called when wolfSSL_EnableOCSPStapling fails
 */
TEST_F(WolfSSLCertEngineTest, ocspInitFailure_wolfSSL_EnableOCSPStapling) {
    // Cipher suites use case is default
    m_engine->m_cipherSuiteUseCase = CSUSDefault;

    m_engine->m_revocationCheckEnabled = true;

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSPStapling(_)).Times(1).WillOnce(Return(WOLFSSL_FAILURE));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    TLSEngineError res = m_engine->ocspInit();  // call ocspInit when m_revocationCheckEnabled==true
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ocspInitFailure_wolfSSL_UseOCSPStapling)
 * @brief function ocspInit called when wolfSSL_UseOCSPStapling fails
 */
TEST_F(WolfSSLCertEngineTest, ocspInitFailure_wolfSSL_UseOCSPStapling) {
    // Cipher suites use case is default
    m_engine->m_cipherSuiteUseCase = CSUSDefault;

    m_engine->m_revocationCheckEnabled = true;

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSPStapling(_)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseOCSPStapling(_, _, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    TLSEngineError res = m_engine->ocspInit();  // call ocspInit when m_revocationCheckEnabled==true
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, teeInitSuccess)
 * @brief function teeInit called successfully
 */
TEST_F(WolfSSLCertEngineTest, teeInitSuccess) {
    teeInitScenarioForSuccess();

    TLSEngineError res = m_engine->teeInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, teeInitFailure_get_client_cert)
 * @brief function teeInit fails because get_client_cert returns an empty private key
 */
TEST_F(WolfSSLCertEngineTest, teeInitFailure_get_client_cert) {
    std::string cerToBeRet = "";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(m_clientCertificateSetID))
            .Times(1)
            .WillOnce(Return(cerToBeRet));

    TLSEngineError res = m_engine->teeInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, teeInitFailure_get_client_cert_private_key)
 * @brief function teeInit fails because get_client_cert_private_key returns an empty private key
 */
TEST_F(WolfSSLCertEngineTest, teeInitFailure_get_client_cert_private_key) {
    std::string cerToBeRet = "client_cert";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(m_clientCertificateSetID))
            .Times(1)
            .WillOnce(Return(cerToBeRet));

    std::string keyToBeRet = "";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert_private_key(m_clientCertificateSetID))
            .Times(1)
            .WillOnce(Return(keyToBeRet));

    TLSEngineError res = m_engine->teeInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, teeInitFailure_wolfSSL_use_certificate_buffer)
 * @brief function teeInit fails due to wolfSSL_use_certificate_buffer failure
 */
TEST_F(WolfSSLCertEngineTest, teeInitFailure_wolfSSL_use_certificate_buffer) {
    std::string cerToBeRet = "client_cert";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(m_clientCertificateSetID))
            .Times(1)
            .WillOnce(Return(cerToBeRet));

    std::string keyToBeRet = "private key";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert_private_key(m_clientCertificateSetID))
            .Times(1)
            .WillOnce(Return(keyToBeRet));

    // for wolfSSL_use_certificate_buffer calling mock
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                wolfSSL_use_certificate_buffer(_, _, cerToBeRet.size(), WOLFSSL_FILETYPE_PEM))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    // for calling WolfSSLToEngineError
    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    TLSEngineError res = m_engine->teeInit();
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, teeInitFailure_get_client_cert_private_key)
 * @brief function teeInit fails due to wolfSSL_use_PrivateKey_buffer failure
 */
TEST_F(WolfSSLCertEngineTest, teeInitFailure_wolfSSL_use_PrivateKey_buffer) {
    std::string cerToBeRet = "client_cert";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(m_clientCertificateSetID))
            .Times(1)
            .WillOnce(Return(cerToBeRet));

    std::string keyToBeRet = "private key";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert_private_key(m_clientCertificateSetID))
            .Times(1)
            .WillOnce(Return(keyToBeRet));

    // for wolfSSL_use_certificate_buffer calling mock
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                wolfSSL_use_certificate_buffer(_, _, cerToBeRet.size(), WOLFSSL_FILETYPE_PEM))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));

    // for wolfSSL_use_PrivateKey_buffer calling mock
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                wolfSSL_use_PrivateKey_buffer(_, _, keyToBeRet.size(), WOLFSSL_FILETYPE_PEM))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    // for calling WolfSSLToEngineError
    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    TLSEngineError res = m_engine->teeInit();
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, getAlpnProtocolUserDefined)
 * @brief called function getAlpnProtocol successfully when m_alpnMode.userDefinedALPNisUsed()
 */
TEST_F(WolfSSLCertEngineTest, getAlpnProtocolUserDefined) {
    m_alpnMode = AlpnMode(std::vector<std::string>{"alpn1", "alpn2"});
    getAlpnProtocolTest(m_alpnMode, true, "alpn1,alpn2,");
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, getAlpnProtocolSupportedProtocols)
 * @brief called function getAlpnProtocol successfully when !m_alpnMode.userDefinedALPNisUsed()
 */
TEST_F(WolfSSLCertEngineTest, getAlpnProtocolSupportedProtocols) {
    getAlpnProtocolTest(ALPN_ANY, true, "h2,http/1.1,");
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, getAlpnProtocolFailure)
 * @brief function getAlpnProtocol returns a failure
 */
TEST_F(WolfSSLCertEngineTest, getAlpnProtocolFailure) {
    m_alpnMode = ALPN_OFF;
    getAlpnProtocolTest(m_alpnMode, false, "");
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_UseSupportedCurve)
 * @brief called function sslInit when wolfSSL_UseSupportedCurve fails
 */
TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_UseSupportedCurve) {
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_new(_)).Times(1).WillOnce(Return(m_newSSLRetVal));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOReadCtx(_, _))  // wolfSSL_SetIOReadCtx
            .Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOWriteCtx(_, _))  // wolfSSL_SetIOWriteCtx
            .Times(1);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseSupportedCurve(_, WOLFSSL_ECC_SECP256R1))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    TLSEngineError res = m_engine->sslInit();
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(m_engine->m_sslInit.load(), false);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_UseALPN)
 * @brief called function sslInit when ALPN is used and wolfSSL_UseALPN fails
 */
TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_UseALPN) {
    m_engine = std::make_shared<WolfSSLCertEngine>(m_stream,
                                                   m_hostName,
                                                   m_certStoreId,
                                                   m_clientCertificateSetID,
                                                   m_httpPublicKeyPinningHashs,
                                                   m_revocationCheckEnabled,
                                                   m_cipherSuiteIds,
                                                   CSUSDefault,
                                                   ALPN_ANY,
                                                   m_checkTime,
                                                   m_ocspHandler,
                                                   m_ocspTimeoutMs);

    sslInitHelper();

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseALPN(_, _, _, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    TLSEngineError res = m_engine->sslInit();
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(m_engine->m_sslInit.load(), false);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_UseSNI)
 * @brief called function sslInit when ALPN is used and wolfSSL_UseSNI fails
 */
TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_UseSNI) {
    // Expected calls
    sslInitHelper();

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseSNI(_, 0, _, (word16) m_hostName.size()))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    // WolfSSLToEngineError
    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    // TEST
    TLSEngineError res = m_engine->sslInit();
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(m_engine->m_sslInit.load(), false);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_set_cipher_list)
 * @brief called function sslInit when ALPN is used and wolfSSL_set_cipher_list fails
 */
TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_set_cipher_list) {
    // Expected calls
    sslInitHelper();

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseSNI(_, 0, _, (word16) m_hostName.size()))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_set_cipher_list(_, m_engine->m_validCiphers.c_str()))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    // WolfSSLToEngineError
    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    // TEST
    TLSEngineError res = m_engine->sslInit();
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(m_engine->m_sslInit.load(), false);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_set_ex_data)
 * @brief called function sslInit when ALPN is used and wolfSSL_set_ex_data fails
 */
TEST_F(WolfSSLCertEngineTest, sslInitFailure_wolfSSL_set_ex_data) {
    // Expected calls
    sslInitHelper();

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseSNI(_, 0, _, (word16) m_hostName.size()))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_set_cipher_list(_, m_engine->m_validCiphers.c_str()))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                wolfSSL_set_ex_data(_, WolfSSLCertEngine::EX_DATA_IDX_WOLFSSL_CERT_ENGINE_OBJ, (void *) m_engine.get()))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    // WolfSSLToEngineError()
    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    // TEST
    TLSEngineError res = m_engine->sslInit();
    EXPECT_EQ(res, m_someWolfSSLAndEngineErrorPair.second);
    EXPECT_EQ(m_engine->m_sslInit.load(), false);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, sslInitSuccess_ALPNisUsed)
 * @brief called function sslInit successfully, ALPN is used
 */
TEST_F(WolfSSLCertEngineTest, sslInitSuccess_ALPN_used) {
    m_engine = std::make_shared<WolfSSLCertEngine>(m_stream,
                                                   m_hostName,
                                                   m_certStoreId,
                                                   m_clientCertificateSetID,
                                                   m_httpPublicKeyPinningHashs,
                                                   m_revocationCheckEnabled,
                                                   m_cipherSuiteIds,
                                                   CSUSDefault,
                                                   ALPN_ANY,
                                                   m_checkTime,
                                                   m_ocspHandler,
                                                   m_ocspTimeoutMs);

    // Expected calls
    sslInitHelper();

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseALPN(_, _, _, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseSNI(_, 0, _, (word16) m_hostName.size()))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));


    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_set_cipher_list(_, m_engine->m_validCiphers.c_str()))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));

    int setSetEngineObjectExData = WOLFSSL_SUCCESS;  // for calling mock wolfSSL_set_ex_data
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                wolfSSL_set_ex_data(_, WolfSSLCertEngine::EX_DATA_IDX_WOLFSSL_CERT_ENGINE_OBJ, (void *) m_engine.get()))
            .Times(1)
            .WillOnce(Return(setSetEngineObjectExData));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_set_verify(_, SSL_VERIFY_PEER, WolfSSLCertEngine::verifyCallback))
            .Times(1);

    // TEST
    TLSEngineError res = m_engine->sslInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
    EXPECT_EQ(m_engine->m_sslInit.load(), true);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, sslInitSuccess)
 * @brief called function sslInit successfully, ALPN is unused
 */
TEST_F(WolfSSLCertEngineTest, sslInitSuccess_ALPN_unused) {
    sslInitScenarioForSuccess();

    TLSEngineError res = m_engine->sslInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
    EXPECT_EQ(m_engine->m_sslInit.load(), true);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ctxInitSuccess)
 * @brief called function ctxInit successfully
 */
TEST_F(WolfSSLCertEngineTest, ctxInitSuccess) {
    // expected calls
    ctxInitScenarioForSuccess();

    // test
    TLSEngineError res = m_engine->ctxInit();

    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ctxInitFail_wolfSSL_CTX_new)
 * @brief called function ctxInit wolfSSL_CTX_new failure
 */
TEST_F(WolfSSLCertEngineTest, ctxInitFail_wolfSSL_CTX_new) {
    // expected calls
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSLv23_client_method()).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(nullptr));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);

    WolfSSLToEngineErrorTestHistory(1024);  // unknown error - default return value: RC_TLS_ENGINE_FATAL_ERROR

    // test
    TLSEngineError res = m_engine->ctxInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ctxInitFail_wolfSSLv23_client_method)
 * @brief called function ctxInit wolfSSLv23_client_method failure
 */
TEST_F(WolfSSLCertEngineTest, ctxInitFail_wolfSSLv23_client_method) {
    // expected calls
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSLv23_client_method()).Times(1).WillOnce(Return(nullptr));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(nullptr));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);

    WolfSSLToEngineErrorTestHistory(1024);  // unknown error - default return value: RC_TLS_ENGINE_FATAL_ERROR

    // test
    TLSEngineError res = m_engine->ctxInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ctxInitFail_wolfSSL_CTX_SetMinVersion)
 * @brief called function ctxInit wolfSSLv23_wolfSSL_CTX_SetMinVersion failure
 */
TEST_F(WolfSSLCertEngineTest, ctxInitFail_wolfSSL_CTX_SetMinVersion) {
    // expected calls
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSLv23_client_method()).Times(1);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(m_newCtxRetVal));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_SetMinVersion(_, WOLFSSL_TLSV1_2))
            .Times(1)
            .WillOnce(Return(0));

    WolfSSLToEngineErrorTestHistory(1024);  // unknown error - default return value: RC_TLS_ENGINE_FATAL_ERROR

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);

    // test
    TLSEngineError res = m_engine->ctxInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ctxInitFail_get_root_cert_bundle)
 * @brief called function ctxInit get_root_cert_bundle failure
 */
TEST_F(WolfSSLCertEngineTest, ctxInitFail_get_root_cert_bundle) {
    // expected calls
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSLv23_client_method()).Times(1);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(m_newCtxRetVal));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_SetMinVersion(_, WOLFSSL_TLSV1_2))
            .Times(1)
            .WillOnce(Return(1));

    // wolfSSL_SetIORecv(m_ctx.get(), recvIO);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIORecv(_, _)).Times(1);

    // wolfSSL_SetIOSend(m_ctx.get(), sendIO);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOSend(_, _)).Times(1);

    std::string toBeRet{};
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(m_certStoreId)).Times(1).WillOnce(Return(toBeRet));

    // test
    TLSEngineError res = m_engine->ctxInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_CERTSTORE_NOT_FOUND);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, ctxInitFail_wolfSSL_CTX_load_verify_buffer)
 * @brief called function ctxInit wolfSSL_CTX_load_verify_buffer failure
 */
TEST_F(WolfSSLCertEngineTest, ctxInitFail_wolfSSL_CTX_load_verify_buffer) {
    // expected calls
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSLv23_client_method()).Times(1);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(m_newCtxRetVal));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_SetMinVersion(_, WOLFSSL_TLSV1_2))
            .Times(1)
            .WillOnce(Return(1));

    // wolfSSL_SetIORecv(m_ctx.get(), recvIO);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIORecv(_, _)).Times(1);

    // wolfSSL_SetIOSend(m_ctx.get(), sendIO);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_SetIOSend(_, _)).Times(1);

    std::string toBeRet = "root cert";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(m_certStoreId)).Times(1).WillOnce(Return(toBeRet));

    // for calling mock wolfSSL_CTX_load_verify_buffer
    int err = unknown_ca;
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_load_verify_buffer(_, _, _, _))
            .Times(1)
            .WillOnce(Return(err));

    WolfSSLToEngineErrorTestHistory(unknown_ca);

    // test
    TLSEngineError res = m_engine->ctxInit();
    EXPECT_EQ(res, RC_TLS_ENGINE_UNKNOWN_CA);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, WolfSSLToEngineError)
 * @brief called function WolfSSLToEngineError
 */
TEST_F(WolfSSLCertEngineTest, WolfSSLToEngineError) {
    WolfSSLToEngineErrorTest(WOLFSSL_ERROR_WANT_READ);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_WOULD_BLOCK_READ);

    WolfSSLToEngineErrorTest(WOLFSSL_ERROR_WANT_WRITE);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_WOULD_BLOCK_WRITE);

    WolfSSLToEngineErrorTest(WOLFSSL_ERROR_ZERO_RETURN);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_SUCCESSFUL);

    WolfSSLToEngineErrorTest(SOCKET_PEER_CLOSED_E);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_PEER_CLOSED);

    WolfSSLToEngineErrorTest(ASN_NO_SIGNER_E);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_UNKNOWN_CA);

    WolfSSLToEngineErrorTestHistory(unknown_ca);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_UNKNOWN_CA);

    WolfSSLToEngineErrorTestHistory(unexpected_message);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_UNEXPECTED_MESSAGE);

    WolfSSLToEngineErrorTestHistory(bad_record_mac);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_BAD_RECORD_MAC);

    WolfSSLToEngineErrorTestHistory(record_overflow);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_RECORD_OVERFLOW);

    WolfSSLToEngineErrorTestHistory(decompression_failure);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_DECOMPRESSION_FAILURE);

    WolfSSLToEngineErrorTestHistory(handshake_failure);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_HANDSHAKE_FAILURE);

    WolfSSLToEngineErrorTestHistory(bad_certificate);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_BAD_CERTIFICATE);

    WolfSSLToEngineErrorTestHistory(unsupported_certificate);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE);

    WolfSSLToEngineErrorTestHistory(certificate_revoked);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_CERTIFICATE_REVOKED);

    WolfSSLToEngineErrorTestHistory(certificate_expired);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_CERTIFICATE_EXPIRED);

    WolfSSLToEngineErrorTestHistory(certificate_unknown);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_CERTIFICATE_UNKNOWN);

    WolfSSLToEngineErrorTestHistory(illegal_parameter);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_ILLEGAL_PARAMETER);

    WolfSSLToEngineErrorTestHistory(decode_error);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_DECODE_ERROR);

    WolfSSLToEngineErrorTestHistory(decrypt_error);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_DECRYPT_ERROR);

    WolfSSLToEngineErrorTestHistory(protocol_version);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_PROTOCOL_VERSION);

    WolfSSLToEngineErrorTestHistory(no_renegotiation);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_NO_RENEGOTIATION);

    WolfSSLToEngineErrorTestHistory(unsupported_extension);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_UNSUPPORTED_EXTENSION);

    WolfSSLToEngineErrorTestHistory(unrecognized_name);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_UNRECOGNIZED_NAME);

    WolfSSLToEngineErrorTestHistory(bad_certificate_status_response);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE);

    WolfSSLToEngineErrorTestHistory(no_application_protocol, false);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_NO_APPLICATION_PROTOCOL);

    WolfSSLToEngineErrorTestHistory(1000 /*unknown error*/);
    EXPECT_EQ(m_engine->WolfSSLToEngineError(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, getUsedProtocolSuccess)
 * @brief called function getUsedProtocol successfully
 */
TEST_F(WolfSSLCertEngineTest, getUsedProtocolSuccess) {
    char *http1 = strdup("http/1.1");
    char *h2 = strdup("h2");
    char *none = strdup("none");

    getUsedProtocolTest(http1, WOLFSSL_SUCCESS, HTTP);
    getUsedProtocolTest(h2, WOLFSSL_SUCCESS, HTTP2);
    getUsedProtocolTest(none, WOLFSSL_SUCCESS, NONE);

    free(http1);
    free(h2);
    free(none);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, getUsedProtocolFailure)
 * @brief called function getUsedProtocol and gets a failure
 */
TEST_F(WolfSSLCertEngineTest, getUsedProtocolFailure) {
    char *none = strdup("none");

    getUsedProtocolTest(none, WOLFSSL_FAILURE, NONE);

    free(none);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, validateHashPinningSuccessEmptyVec)
 * @brief called function validateHashPinning successfully when no hash pinning is required
 */
TEST_F(WolfSSLCertEngineTest, validateHashPinningSuccessEmptyVec) {
    std::vector<HashSha256> m_httpPublicKeyPinningHashs = {};
    std::shared_ptr<WolfSSLCertEngine> engine = std::make_shared<WolfSSLCertEngine>(m_stream,
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

    EXPECT_EQ(engine->validateHashPinning(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, validateHashPinningSuccess)
 * @brief called function validateHashPinning successfully with ECC certificate
 */
TEST_F(WolfSSLCertEngineTest, validateHashPinningSuccess) {
    validateHashPinningScenarioForSuccess();

    EXPECT_EQ(m_engine->validateHashPinning(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_atLeastOneCommonMember)
 * @brief called function validateHashPinning when it gets a failure from atLeastOneCommonMember
 */
TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_atLeastOneCommonMember) {
    validateHashPinningScenarioHelper();

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_free(_)).Times(1);

    EXPECT_CALL(*MockEngineCommonUT::mMockEngineCommon, atLeastOneCommonMember(_, _)).Times(1).WillOnce(Return(false));

    EXPECT_EQ(m_engine->validateHashPinning(), TLSEngineError::RC_TLS_PUBLIC_KEY_PINNING_FAILED);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_wolfSSL_get_peer_chain)
 * @brief called function validateHashPinning when it gets a failure from wolfSSL_get_peer_chain
 */
TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_wolfSSL_get_peer_chain) {
    // for calling wolfSSL_get_peer_chain
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_peer_chain(_)).Times(1).WillOnce(Return(nullptr));

    // for calling WolfSSLToEngineError
    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    EXPECT_EQ(m_engine->validateHashPinning(), m_someWolfSSLAndEngineErrorPair.second);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_wolfSSL_get_chain_X509)
 * @brief called function validateHashPinning when it gets a failure from wolfSSL_get_chain_X509
 */
TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_wolfSSL_get_chain_X509) {
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_peer_chain(_))
            .Times(1)
            .WillOnce(Return((WOLFSSL_X509_CHAIN *) 0xdeadbeef));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_chain_count(_)).Times(1).WillOnce(Return(1));

    // for calling mock wolfSSL_get_chain_X509
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_chain_X509(_, _)).Times(1).WillOnce(Return(nullptr));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_free(_)).Times(1);

    // for calling WolfSSLToEngineError
    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    EXPECT_EQ(m_engine->validateHashPinning(), m_someWolfSSLAndEngineErrorPair.second);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_wolfSSL_X509_get_pubkey)
 * @brief called function validateHashPinning when it gets a failure from wolfSSL_X509_get_pubkey
 */
TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_wolfSSL_X509_get_pubkey) {
    validateHashPinningGetPeerChainAndGetX509();

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_get_pubkey_buffer(_, _, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    // for calling WolfSSLToEngineError
    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_free(_)).Times(1);

    EXPECT_EQ(m_engine->validateHashPinning(), m_someWolfSSLAndEngineErrorPair.second);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_wolfSSL_X509_get_pubkey_invalid_len)
 * @brief called function validateHashPinning when it gets a failure from wolfSSL_X509_get_pubkey
 */
TEST_F(WolfSSLCertEngineTest, validateHashPinningFailed_wolfSSL_X509_get_pubkey_invalid_len) {
    validateHashPinningGetPeerChainAndGetX509();

    int bufLenRet = 0;
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_get_pubkey_buffer(_, _, _))
            .Times(1)
            .WillOnce(DoAll(SetArgPointee<2>(bufLenRet), Return(WOLFSSL_SUCCESS)));

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_free(_)).Times(1);

    EXPECT_EQ(m_engine->validateHashPinning(), TLSEngineError::RC_TLS_PUBLIC_KEY_PINNING_FAILED);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, DoSSLHandshakeSuccess)
 * @brief called function DoSSLHandshake successfully
 */
TEST_F(WolfSSLCertEngineTest, DoSSLHandshakeSuccess) {
    // ctxInit
    ctxInitScenarioForSuccess();

    // sslInit
    sslInitScenarioForSuccess();

    // teeInit
    teeInitScenarioForSuccess();

    // ocspInit
    ocspInitScenarioForSuccess();

    // wolfsslConnect scenario
    wolfsslConnectScenarioForSuccess();

    // validateHashPinning
    validateHashPinningScenarioForSuccess();

    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_ctxInit_failed)
 * @brief called function DoSSLHandshake failure (init WOLFSSL context)
 */
TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_ctxInit_failed) {
    // ctxInit
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSLv23_client_method()).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_new(_)).Times(1).WillOnce(Return(nullptr));

    WolfSSLToEngineErrorTestHistory(WOLFSSL_FAILURE);

    // free nullpointer
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);

    // test
    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_sslInit_failed)
 * @brief called function DoSSLHandshake failure (init wolfssl)
 */
TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_sslInit_failed) {
    // ctxInit
    ctxInitScenarioForSuccess();

    // sslInit
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_new(_)).Times(1).WillOnce(Return(nullptr));

    WolfSSLToEngineErrorTestHistory(WOLFSSL_FAILURE);

    // shutdown session
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_shutdown(_)).Times(0);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_shutdown(_)).Times(0);

    // free nullpointer
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(_)).Times(1);

    // test
    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_teeInit_failed)
 * @brief called function DoSSLHandshake failure (init tee)
 */
TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_teeInit_failed) {
    // ctxInit
    ctxInitScenarioForSuccess();

    // sslInit
    sslInitScenarioForSuccess();

    // teeInit
    std::string cerToBeRet = "";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(m_clientCertificateSetID))
            .Times(1)
            .WillOnce(Return(cerToBeRet));

    // shutdown session
    successShutdownCheck();

    // free WOLFSSL objects
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(_)).Times(1);

    // test
    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_ocspInit_failed)
 * @brief called function DoSSLHandshake failure (init ocsp) when using default cipher suite use case.
 */
TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_ocspInit_nonlegacy_case_failed) {
    // ctxInit
    ctxInitScenarioForSuccess();

    // sslInit
    sslInitScenarioForSuccess();

    // teeInit
    teeInitScenarioForSuccess();

    // ocspInit
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSPStapling(_)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_UseOCSPStapling(_, _, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));

#ifndef TLSAPI_ICAS3_TEST_STAPLING_HARDFAIL_NO_OCSP_FALLBACK
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSP(_, _)).Times(1).WillOnce(Return(WOLFSSL_FAILURE));
#else
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_EnableOCSPMustStaple(_))
        .Times(1)
        .WillOnce(Return(WOLFSSL_FAILURE));
#endif
    WolfSSLToEngineErrorTestHistory(WOLFSSL_FAILURE);

    // shutdown session
    successShutdownCheck();

    // free WOLFSSL objects
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(_)).Times(1);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);

    // test
    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_ocspInit_failed)
 * @brief called function DoSSLHandshake failure (init ocsp) when using legacy cipher suite use case.
 */
TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_ocspInit_legacy_case_failed) {
    m_engine->m_cipherSuiteUseCase = CSUSLegacy;

    // ctxInit
    ctxInitScenarioForSuccess();

    // sslInit
    sslInitScenarioForSuccess();

    // teeInit
    teeInitScenarioForSuccess();

    // ocspInit
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_EnableOCSPStapling(_)).Times(1).WillOnce(Return(WOLFSSL_FAILURE));


    WolfSSLToEngineErrorTestHistory(WOLFSSL_FAILURE);

    // shutdown session
    successShutdownCheck();

    // free WOLFSSL objects
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(_)).Times(1);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);

    // test
    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_check_domain_name_failed)
 * @brief called function DoSSLHandshake failure (wolfssl check_domain_name)
 */
TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_check_domain_name_failed) {
    // ctxInit
    ctxInitScenarioForSuccess();

    // sslInit
    sslInitScenarioForSuccess();

    // teeInit
    teeInitScenarioForSuccess();

    // ocspInit
    ocspInitScenarioForSuccess();

    // wolfsslConnect scenario
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_connect(_)).Times(0);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_check_domain_name(_,_)).Times(1).WillOnce(Return(WOLFSSL_FAILURE));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    // shutdown session
    successShutdownCheck();

    // free WOLFSSL objects
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(_)).Times(1);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);

    // test
    EXPECT_EQ(m_engine->DoSSLHandshake(), m_someWolfSSLAndEngineErrorPair.second);
}

/**
 * @fn TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_connect_failed)
 * @brief called function DoSSLHandshake failure (wolfssl connect)
 */
TEST_F(WolfSSLCertEngineTest, DoSSLHandshake_connect_failed) {
    // ctxInit
    ctxInitScenarioForSuccess();

    // sslInit
    sslInitScenarioForSuccess();

    // teeInit
    teeInitScenarioForSuccess();

    // ocspInit
    ocspInitScenarioForSuccess();

    // wolfsslConnect scenario
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_connect(_)).Times(1).WillOnce(Return(WOLFSSL_FAILURE));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_check_domain_name(_,_)).Times(1).WillOnce(Return(WOLFSSL_SUCCESS));

    WolfSSLToEngineErrorTest(m_someWolfSSLAndEngineErrorPair.first);

    // shutdown session
    successShutdownCheck();

    // free WOLFSSL objects
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_free(_)).Times(1);

    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_CTX_free(_)).Times(1);

    // test
    EXPECT_EQ(m_engine->DoSSLHandshake(), m_someWolfSSLAndEngineErrorPair.second);
}

TEST_F(WolfSSLCertEngineTest, normal_verifyCallback) {
    verifyCallbackScenarioForSuccess();

    postVerificationHandlerScenarioForSuccess();

    EXPECT_EQ(WolfSSLCertEngine::verifyCallback(WOLFSSL_SUCCESS, m_x509Ctx.get()), WOLFSSL_SUCCESS);
}

TEST_F(WolfSSLCertEngineTest, invalid_verifyCallback) {
    // Bad preverify
    EXPECT_EQ(WolfSSLCertEngine::verifyCallback(WOLFSSL_FAILURE, m_x509Ctx.get()), WOLFSSL_FAILURE);

    // WOLFSSL_X509_STORE_CTX is nullptr
    EXPECT_EQ(WolfSSLCertEngine::verifyCallback(WOLFSSL_SUCCESS, nullptr), WOLFSSL_FAILURE);

    // wolfSSL_X509_STORE_CTX_get_ex_data result is nullptr
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data_X509_STORE_CTX_idx()).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_STORE_CTX_get_ex_data(m_x509Ctx.get(), _))
            .Times(1)
            .WillOnce(Return(nullptr));
    EXPECT_EQ(WolfSSLCertEngine::verifyCallback(WOLFSSL_SUCCESS, m_x509Ctx.get()), WOLFSSL_FAILURE);

    // wolfSSL_X509_STORE_CTX_get_ex_data result is nullptr
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_get_ex_data_X509_STORE_CTX_idx()).Times(1);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_STORE_CTX_get_ex_data(m_x509Ctx.get(), _))
            .Times(1)
            .WillOnce(Return(m_newSSLRetVal));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL,
                wolfSSL_get_ex_data(_, WolfSSLCertEngine::EX_DATA_IDX_WOLFSSL_CERT_ENGINE_OBJ))
            .Times(1)
            .WillOnce(Return(nullptr));
    EXPECT_EQ(WolfSSLCertEngine::verifyCallback(WOLFSSL_SUCCESS, m_x509Ctx.get()), WOLFSSL_FAILURE);
}

TEST_F(WolfSSLCertEngineTest, normal_postVerificationHandler) {
    // Hard fail case with ocsp response which is not in cache
    postVerificationHandlerScenarioForSuccess();
    EXPECT_TRUE(m_engine->postVerificationHandler(m_x509Ctx.get()));

    // Hard fail case with ocsp response which is already exist in cache
    m_engine->m_ocspRequestsResponses.clear();
    m_engine->m_ocspRequestsResponses.push_back({{0xca, 0xfe}, true, 1});
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_ext_isSet_by_NID(_, _))
            .Times(0)
            .WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, cacheResponses(_)).Times(0);
    //EXPECT_TRUE(m_engine->postVerificationHandler(m_x509Ctx.get()));

    // Hard fail case with empty ocsp response vector - it means we've validate successfully stapled ocsp
    m_engine->m_ocspRequestsResponses.clear();
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_ext_isSet_by_NID(_, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_d2i_OCSP_RESPONSE(_, _, _)).Times(0);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_OCSP_RESPONSE_free(_)).Times(0);
    EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, cacheResponses(_)).Times(0);
    EXPECT_TRUE(m_engine->postVerificationHandler(m_x509Ctx.get()));

    // Soft fail case
    m_engine->m_revocationCheckEnabled = false;
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_d2i_OCSP_RESPONSE(_, _, _)).Times(0);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_OCSP_RESPONSE_free(_)).Times(0);
    EXPECT_CALL(*MockTLSOcspHandlerUT::mMockTLSOcspHandler, cacheResponses(_)).Times(0);
    EXPECT_TRUE(m_engine->postVerificationHandler(m_x509Ctx.get()));
}

TEST_F(WolfSSLCertEngineTest, invalid_postVerificationHandler) {
    // parameter is nullptr
    EXPECT_FALSE(m_engine->postVerificationHandler(nullptr));

    // wolfSSL_d2i_OCSP_RESPONSE failure
    m_engine->m_ocspRequestsResponses.push_back(*m_validOcspRequestResponse);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_ext_isSet_by_NID(_, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_d2i_OCSP_RESPONSE(_, _, _)).Times(1).WillOnce(Return(nullptr));
    EXPECT_FALSE(m_engine->postVerificationHandler(m_x509Ctx.get()));

    // cert status in OcspResponse is null
    delete m_wolfSslOcspResponse->single->status;
    m_wolfSslOcspResponse->single->status = nullptr;
    m_engine->m_ocspRequestsResponses.push_back(*m_validOcspRequestResponse);
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_ext_isSet_by_NID(_, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_SUCCESS));
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_d2i_OCSP_RESPONSE(_, _, _))
            .Times(1)
            .WillOnce(Return(m_wolfSslOcspResponse.get()));
    EXPECT_FALSE(m_engine->postVerificationHandler(m_x509Ctx.get()));
}

TEST_F(WolfSSLCertEngineTest, invalid_authInfo_postVerificationHandler) {
    EXPECT_CALL(*MockWolfSSLUT::mMockWolfSSL, wolfSSL_X509_ext_isSet_by_NID(_, _))
            .Times(1)
            .WillOnce(Return(WOLFSSL_FAILURE));

    EXPECT_FALSE(m_engine->postVerificationHandler(m_x509Ctx.get()));
}

TEST_F(WolfSSLCertEngineTest, invalid_certificate_postVerificationHandler) {
    m_x509Ctx->current_cert = nullptr;
    EXPECT_FALSE(m_engine->postVerificationHandler(m_x509Ctx.get()));
}