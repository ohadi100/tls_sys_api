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


#include <botan/auto_rng.h>
#include <botan/tls_exceptn.h>

#include "BotanCertEngine.hpp"
#include "MockBotanCertEngine.hpp"
#include "MockBotanChannel.hpp"
#include "MockIOStreamIf.hpp"
#include "MockTLSTEEAPI.hpp"
#include "MockTLSOcspHandler.hpp"

using namespace vwg::tee;
using Botan::TLS::Alert;

using ::testing::_;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::Throw;

MockBotanChannel*              BotanClientUT::m_mockBotanChannel;
std::shared_ptr<MockTLSTEEAPI> TLSTEEUT::mMockTLSTEEAPI;

class BotanCertEngineTestIf : public ::testing::Test
{
public:
    std::string             m_certStoreId               = "certStoreId";
    std::string             m_clientCertificateSetID    = "certStoreId";
    std::vector<HashSha256> m_httpPublicKeyPinningHashs = {{'h'}};
    bool                    m_revocationCheckEnabled    = true;
    CipherSuiteIds          m_cipherSuiteIds            = "cipherSuiteIds";
    std::string             m_hostName                  = "host name";
};

class ClientCredsManagerTest : public BotanCertEngineTestIf
{
public:
    std::shared_ptr<MockIOStreamIf> m_streamEngine;
    BotanCertEngine*                m_botanCertEngine;

    std::shared_ptr<MockIOStreamIf> m_streamEmpty;
    BotanCertEngine*                m_botanCertEngineEmptyCertId;

    Botan::X509_Certificate  m_cert{};
    std::string              m_type{};
    std::string              m_context{};
    std::vector<std::string> m_vec{};
    std::shared_ptr<ITLSOcspHandler> m_ocspHandler;
    uint32_t                         m_ocspTimeoutMs;

    ClientCredsManagerTest()
    {
        m_streamEngine    = std::make_shared<MockIOStreamIf>();
        m_botanCertEngine = new BotanCertEngine(m_streamEngine,
                                                m_hostName,
                                                m_certStoreId,
                                                m_clientCertificateSetID,
                                                m_httpPublicKeyPinningHashs,
                                                m_revocationCheckEnabled,
                                                m_cipherSuiteIds,
                                                CSUSDefault,
                                                ALPN_DEFAULT,
                                                CHECK_TIME_OFF,
                                                m_ocspHandler,
                                                m_ocspTimeoutMs);

        m_streamEmpty = std::make_shared<MockIOStreamIf>();

        m_botanCertEngineEmptyCertId = new BotanCertEngine(m_streamEmpty,
                                                           m_hostName,
                                                           m_certStoreId,
                                                           "",
                                                           m_httpPublicKeyPinningHashs,
                                                           m_revocationCheckEnabled,
                                                           m_cipherSuiteIds,
                                                           CSUSDefault,
                                                           ALPN_DEFAULT,
                                                           CHECK_TIME_OFF,
                                                           m_ocspHandler,
                                                           m_ocspTimeoutMs);

        TLSTEEUT::mMockTLSTEEAPI = std::make_shared<MockTLSTEEAPI>();
    }


    ~ClientCredsManagerTest()
    {
        delete m_botanCertEngine;
        m_botanCertEngine = nullptr;

        delete m_botanCertEngineEmptyCertId;
        m_botanCertEngineEmptyCertId = nullptr;

        TLSTEEUT::mMockTLSTEEAPI.reset();
    }
};

class BotanCertEngineTest : public BotanCertEngineTestIf
{
public:
    CallbacksCert*                m_callbacks;
    Botan::TLS::Session_Manager*  m_session_manager;
    Botan::RandomNumberGenerator* m_rng;

    std::string m_http         = "http/1.1";
    std::string m_http2        = "h2";
    std::string m_someProtocol = "some";

    std::shared_ptr<MockIOStreamIf>  m_stream = std::make_shared<MockIOStreamIf>();
    std::shared_ptr<BotanCertEngine> m_engine;
    std::shared_ptr<ITLSOcspHandler> m_ocspHandler;
    uint32_t                         m_ocspTimeoutMs;

    std::vector<uint16_t> defaultCipherSuites = {TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                                 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                                 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                                 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                                 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                                 TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                                                 TLS_DHE_RSA_WITH_AES_256_GCM_SHA384};

    virtual void
    SetUp()
    {
        MockTLSOcspHandlerUT::mMockTLSOcspHandler = new MockTLSOcspHandler();
        m_ocspHandler = std::make_shared<MockTLSOcspHandlerUT>();
        m_engine = std::make_shared<BotanCertEngine>(m_stream,
                                                     m_hostName,
                                                     m_certStoreId,
                                                     m_clientCertificateSetID,
                                                     m_httpPublicKeyPinningHashs,
                                                     m_revocationCheckEnabled,
                                                     m_cipherSuiteIds,
                                                     CSUSDefault,
                                                     ALPN_DEFAULT,
                                                     CHECK_TIME_OFF,
                                                     m_ocspHandler,
                                                     m_ocspTimeoutMs);

        m_callbacks       = new CallbacksCert(m_engine.get());
        m_session_manager = new Botan::TLS::Session_Manager_Noop();
        m_rng             = new Botan::AutoSeeded_RNG();
        Botan::TLS::Policy policy;

        BotanClientUT::m_mockBotanChannel = new MockBotanChannel(*m_callbacks, *m_session_manager, *m_rng, policy);

        TLSTEEUT::mMockTLSTEEAPI = std::make_shared<MockTLSTEEAPI>();
    }

    void
    getAlpnProtocolTest(AlpnMode alpnMode, bool expectedRes, std::vector<std::string> expectedAlpnRes)
    {
        //reset engine in order recreate it with alpnMode
        TestDestructor();
        m_engine = std::make_shared<BotanCertEngine>(m_stream,
                                                     m_hostName,
                                                     m_certStoreId,
                                                     m_clientCertificateSetID,
                                                     m_httpPublicKeyPinningHashs,
                                                     m_revocationCheckEnabled,
                                                     m_cipherSuiteIds,
                                                     CSUSDefault,
                                                     alpnMode,
                                                     CHECK_TIME_OFF,
                                                     m_ocspHandler,
                                                     m_ocspTimeoutMs);

        std::vector<std::string> alpn = {};
        bool        res  = m_engine->getAlpnProtocol(alpn);
        EXPECT_EQ(res, expectedRes);
        EXPECT_EQ(alpn, expectedAlpnRes);
    }

    void
    expect_eq_AlpnMode(AlpnMode alpn1, AlpnMode alpn2)
    {
        EXPECT_EQ(alpn1.userDefinedALPNisUsed(), alpn2.userDefinedALPNisUsed());
        EXPECT_EQ(alpn1.getSupportedProtocols(), alpn2.getSupportedProtocols());
        EXPECT_EQ(alpn1.getUserDefinedAlpnSetting(), alpn2.getUserDefinedAlpnSetting());
    }

    void
    testFeedFailureThrow(Botan::TLS::Alert::Type expectedRes) const
    {
        // What to throw is out of this function because the exception parameter type needs to be different depends on
        // the case
        EXPECT_CALL(*BotanClientUT::m_mockBotanChannel,
                    is_closed)  // 1-while condition 2-while content 3-while condition
            .Times(3)
            .WillRepeatedly(Return(false));

        int32_t toBeReturned = sizeof(m_engine->m_buffer);
        EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(toBeReturned));

        EXPECT_EQ(m_engine->feed(), m_engine->AlertToEngineError(expectedRes));
    }

    void
    checkTeeAndItsDataSuccess()
    {
        EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(_)).Times(1).WillOnce(Return("root cert"));

        EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(_)).Times(1).WillOnce(Return("client cert"));

        EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert_private_key(_))
            .Times(1)
            .WillOnce(Return("client cert pk"));
    }

    void
    TestShutdownSuccess()
    {
        EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, close()).Times(1);
    }

    void
    TestDestructor()
    {
        TestShutdownSuccess();
        m_engine.reset();
    }

    virtual void
    TearDown()
    {
        TestDestructor();

        delete BotanClientUT::m_mockBotanChannel;
        BotanClientUT::m_mockBotanChannel = nullptr;

        TLSTEEUT::mMockTLSTEEAPI.reset();

        delete m_callbacks;
        delete m_rng;
        delete m_session_manager;
    }
};

class CallbacksCertTest : public ::testing::Test
{
public:
    void
    SetUp()
    {
        m_engine    = std::make_shared<MockBotanCertEngine>(m_stream);
        m_callbacks = std::make_shared<CallbacksCert>(m_engine.get());
    }

    void
    TearDown()
    {
    }

    std::shared_ptr<MockIOStreamIf>      m_stream = std::make_shared<MockIOStreamIf>();
    std::shared_ptr<MockBotanCertEngine> m_engine;
    std::shared_ptr<CallbacksCert>       m_callbacks;

    std::string mData         = "hjdguguhkahdkuahsdasddas";
    std::string mBase64sha256 = "46pWuSGjdyCWi/BsmtK2CUfWqbNrwVM0/jnqD4K5QN4=";
};

class strict_policy_with_ocsp_config_test : public ::testing::Test
{
public:
    strict_policy_with_ocsp_config m_policy;
};

/**
 * @fn TEST_F(CallbacksCertTest, tls_emit_data)
 * @brief check tls_emit_data function
 */
TEST_F(CallbacksCertTest, tls_emit_data)
{
    // GetIOStream
    size_t  bufLength = 10;
    uint8_t buf[bufLength];
    EXPECT_CALL(*m_engine, GetIOStream()).Times(1).WillOnce(Return(m_stream));
    EXPECT_CALL(*m_stream, send(buf, bufLength)).Times(1);

    m_callbacks->tls_emit_data(buf, bufLength);
}

/**
 * @fn TEST_F(CallbacksCertTest, tls_session_established)
 * @brief check tls_session_established function
 */
TEST_F(CallbacksCertTest, tls_session_established)
{
    EXPECT_FALSE(m_callbacks->tls_session_established(Botan::TLS::Session()));
}

/**
 * @fn TEST_F(CallbacksCertTest, tls_alert)
 * @brief check tls_alert function
 */
TEST_F(CallbacksCertTest, tls_alert)
{
    Alert::Type       alertType = Alert::Type::UNEXPECTED_MESSAGE;
    Botan::TLS::Alert alert(alertType, true);

    //sSetReceivedAlert()
    EXPECT_CALL(*m_engine, SetReceivedAlert(alertType)).Times(1);

    m_callbacks->tls_alert(alert);
}

/**
 * @fn TEST_F(CallbacksCertTest, calculate_public_key_hash)
 * @brief check calculate_public_key_hash function
 */
TEST_F(CallbacksCertTest, calculate_public_key_hash)
{
    std::vector<uint8_t> dataVec(mData.begin(), mData.end());
    std::vector<char> base64shaRes = m_callbacks->calculate_public_key_hash(dataVec);
    auto expected = std::vector<char>(mBase64sha256.begin(), mBase64sha256.end());
    EXPECT_EQ(base64shaRes, expected);
}

/**
 * @fn TEST_F(BotanCertEngineTest, AlertToEngineError)
 * @brief check AlertToEngineError function
 */
TEST_F(BotanCertEngineTest, AlertToEngineError)
{
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNEXPECTED_MESSAGE), RC_TLS_ENGINE_UNEXPECTED_MESSAGE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::BAD_RECORD_MAC), RC_TLS_ENGINE_BAD_RECORD_MAC);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::RECORD_OVERFLOW), RC_TLS_ENGINE_RECORD_OVERFLOW);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::DECOMPRESSION_FAILURE),
              RC_TLS_ENGINE_DECOMPRESSION_FAILURE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::HANDSHAKE_FAILURE), RC_TLS_ENGINE_HANDSHAKE_FAILURE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::BAD_CERTIFICATE), RC_TLS_ENGINE_BAD_CERTIFICATE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNSUPPORTED_CERTIFICATE),
              RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::CERTIFICATE_REVOKED), RC_TLS_ENGINE_CERTIFICATE_REVOKED);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::CERTIFICATE_EXPIRED), RC_TLS_ENGINE_CERTIFICATE_EXPIRED);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::CERTIFICATE_UNKNOWN), RC_TLS_ENGINE_CERTIFICATE_UNKNOWN);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::ILLEGAL_PARAMETER), RC_TLS_ENGINE_ILLEGAL_PARAMETER);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::ILLEGAL_PARAMETER), RC_TLS_ENGINE_ILLEGAL_PARAMETER);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNKNOWN_CA), RC_TLS_ENGINE_UNKNOWN_CA);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::ACCESS_DENIED), RC_TLS_ENGINE_ACCESS_DENIED);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::DECODE_ERROR), RC_TLS_ENGINE_DECODE_ERROR);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::DECRYPT_ERROR), RC_TLS_ENGINE_DECRYPT_ERROR);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::PROTOCOL_VERSION), RC_TLS_ENGINE_PROTOCOL_VERSION);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::INSUFFICIENT_SECURITY),
              RC_TLS_ENGINE_INSUFFICIENT_SECURITY);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::NO_RENEGOTIATION), RC_TLS_ENGINE_NO_RENEGOTIATION);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNSUPPORTED_EXTENSION),
              RC_TLS_ENGINE_UNSUPPORTED_EXTENSION);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::NULL_ALERT), RC_TLS_ENGINE_UNKNOWN_ERROR);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::CERTIFICATE_UNOBTAINABLE), RC_TLS_ENGINE_CERTIFICATE_UNOBTAINABLE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNRECOGNIZED_NAME), RC_TLS_ENGINE_UNRECOGNIZED_NAME);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::BAD_CERTIFICATE_STATUS_RESPONSE), RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::BAD_CERTIFICATE_HASH_VALUE), RC_TLS_ENGINE_BAD_CERTIFICATE_HASH_VALUE);
}

/**
 * @fn TEST_F(BotanCertEngineTest, checkTeeAndItsDataSuccess)
 * @brief checking checkTeeAndItsData - happy flow
 */
TEST_F(BotanCertEngineTest, checkTeeAndItsDataSuccess)
{
    checkTeeAndItsDataSuccess();
    EXPECT_EQ(m_engine->checkTeeAndItsData(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanCertEngineTest, checkTeeAndItsDataFailureTeeNull)
 * @brief checking checkTeeAndItsData function - get a failure RC_TLS_ENGINE_TEE_ACCESS_ERROR when tee is nullptr
 */
TEST_F(BotanCertEngineTest, checkTeeAndItsDataFailureTeeNull)
{
    TLSTEEUT::mMockTLSTEEAPI.reset();  // in order for m_tlsTeeApi would be nullptr

    EXPECT_EQ(m_engine->checkTeeAndItsData(), RC_TLS_ENGINE_TEE_ACCESS_ERROR);
}

/**
 * @fn TEST_F(BotanCertEngineTest, checkTeeAndItsDataFailure)
 * @brief checking checkTeeAndItsData function - get a failure when some certificate data is empty
 */
TEST_F(BotanCertEngineTest, checkTeeAndItsDataFailure)
{
    std::string someRootCert = "root cert";
    std::string clientCert   = "client cert";
    // case 1 -get_root_cert_bundle returns empty string
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(_)).Times(1).WillOnce(Return(""));
    EXPECT_EQ(m_engine->checkTeeAndItsData(), RC_TLS_ENGINE_CERTSTORE_NOT_FOUND);

    // case 2 - get_client_cert returns empty string
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(_)).Times(1).WillOnce(Return(someRootCert));
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(_)).Times(1).WillOnce(Return(""));
    EXPECT_EQ(m_engine->checkTeeAndItsData(), RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID);

    // case 3 - get_client_cert_private_key returns empty string
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(_)).Times(1).WillOnce(Return(someRootCert));
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(_)).Times(1).WillOnce(Return(clientCert));
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert_private_key(_)).Times(1).WillOnce(Return(""));
    EXPECT_EQ(m_engine->checkTeeAndItsData(), RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID);
}

/**
 * @fn TEST_F(BotanCertEngineTest, DoSSLHandshakeServerSuccess)
 * @brief checking doSSLHandshake - happy flow
 */
TEST_F(BotanCertEngineTest, DoSSLHandshakeSuccess)
{
    checkTeeAndItsDataSuccess();  // for checkTeeAndItsData() call in
                                  // DoSSLHandshake

    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_active())
        .Times(2)
        .WillOnce(Return(false))
        .WillOnce(Return(true));
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
        .Times(3)  // 1 for DoSSLHandshakeServer, 2 and 3 for feed()
        .WillRepeatedly(Return(false));

    // feed()
    int32_t toBeReturned = sizeof(m_engine->m_buffer);
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(toBeReturned));
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _)).Times(1).WillOnce(Return(0));

    EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanCertEngineTest, SendSuccess)
 * @brief checking Send function - happy flow
 */
TEST_F(BotanCertEngineTest, SendSuccess)
{
    int32_t bufLength = 10;
    uint8_t buf[bufLength];
    int32_t actualLength = 0;

    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, send(buf, bufLength)).Times(1);

    EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength), RC_TLS_ENGINE_SUCCESSFUL);
    EXPECT_EQ(actualLength, bufLength);
}

/**
 * @fn TEST_F(BotanCertEngineTest, SendFailure)
 * @brief checking Send function - get a failure
 */
TEST_F(BotanCertEngineTest, SendFailure)
{
    int32_t bufLength = 10;
    uint8_t buf[bufLength];
    int32_t actualLength = 5;

    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed()).Times(1).WillOnce(Return(true));
    EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength), RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN);

    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, send(buf, bufLength)).Times(1).WillOnce(Throw("exception"));
    EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength), RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(BotanCertEngineTest, ReceiveSuccess)
 * @brief called Receive function successfully
 */
TEST_F(BotanCertEngineTest, ReceiveSuccess)
{
    const int32_t bufLength      = 3;
    uint8_t       buf[bufLength] = {1, 2, 3};
    int32_t       actualLength   = 0;

    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
        .Times(4)  // the 3th and 4th times are for feed() calling
        .WillRepeatedly(Return(false));

    // feed();
    // EXPECT_CALL mockBotanChannel->is_closed() twice and return false
    int32_t toBeReturned = bufLength;
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(toBeReturned));
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _)).Times(1).WillOnce(Return(0));

    EXPECT_EQ(m_engine->Receive(buf, bufLength, actualLength), RC_TLS_ENGINE_SUCCESSFUL);
    EXPECT_EQ(actualLength, bufLength);

    for (int i = 0; i < bufLength; i++) {
        EXPECT_EQ(m_engine->m_plaintext[i], buf[i]);
    }
}

/**
 * @fn TEST_F(BotanCertEngineTest, ReceiveSuccess2)
 * @brief called Receive function with buffer size that is bigger than engine's buffer size
 */
TEST_F(BotanCertEngineTest, ReceiveSuccess2)
{
    const int32_t        bufBigLength = sizeof(m_engine->m_buffer) + 1;
    std::vector<uint8_t> buf(bufBigLength, 'a');
    int32_t              actualLength = 0;


    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
        .Times(6) // the 3th - 6th times are for feed() calls
        .WillRepeatedly(Return(false));

    EXPECT_CALL(*m_stream, receive(_, sizeof(m_engine->m_buffer)))
        .Times(1)
        .WillOnce(Return(sizeof(m_engine->m_buffer)));
    EXPECT_CALL(*m_stream, receive(_, 1))
        .Times(1)
        .WillOnce(Return(1));
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
        .Times(2)
        .WillOnce(Return(1)).WillOnce(Return(0));

    EXPECT_EQ(m_engine->Receive(buf.data(), bufBigLength, actualLength),
              RC_TLS_ENGINE_SUCCESSFUL);
    EXPECT_EQ(actualLength, bufBigLength);

    for (int i = 0; i < bufBigLength; i++) {
        EXPECT_EQ(m_engine->m_plaintext[i], buf[i]);
    }
}

/**
 * @fn TEST_F(BotanCertEngineTest, feedSuccess)
 * @brief called feed function successfully
 */
TEST_F(BotanCertEngineTest, feedSuccess)
{
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed()).Times(2).WillRepeatedly(Return(false));
    int32_t toBeReturned = sizeof(m_engine->m_buffer);
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(toBeReturned));

    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _)).Times(1).WillOnce(Return(0));

    EXPECT_EQ(m_engine->feed(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, feedFailureThrow)
 * @brief called feed when received_data throw an exception
 */
TEST_F(BotanCertEngineTest, feedFailureThrow)
{
    // 1
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
        .Times(1)
        .WillOnce(Throw(Botan::TLS::TLS_Exception(Botan::TLS::Alert::UNEXPECTED_MESSAGE, "")));
    testFeedFailureThrow(Botan::TLS::Alert::UNEXPECTED_MESSAGE);

    // 2
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
        .Times(1)
        .WillOnce(Throw(Botan::Integrity_Failure("")));
    testFeedFailureThrow(Botan::TLS::Alert::BAD_RECORD_MAC);

    // 3
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
        .Times(1)
        .WillOnce(Throw(Botan::Decoding_Error("")));
    testFeedFailureThrow(Botan::TLS::Alert::DECODE_ERROR);

    // 4
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _)).Times(1).WillOnce(Throw(exception()));
    testFeedFailureThrow(Botan::TLS::Alert::INTERNAL_ERROR);
}


/**
 * @fn TEST_F(BotanCertEngineTest, feedFailure)
 * @brief get a failure when called feed function
 */
TEST_F(BotanCertEngineTest, feedFailure)
{
    // toBeReturned (receive result) = RC_STREAM_WOULD_BLOCK < 0
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed()).Times(2).WillRepeatedly(Return(false));
    int32_t toBeReturned = RC_STREAM_WOULD_BLOCK;
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(toBeReturned));
    EXPECT_EQ(m_engine->feed(), RC_TLS_ENGINE_WOULD_BLOCK_READ);

    // toBeReturned (receive result) = RC_STREAM_IO_ERROR < 0
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed()).Times(2).WillRepeatedly(Return(false));
    toBeReturned = RC_STREAM_IO_ERROR;
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(toBeReturned));
    EXPECT_EQ(m_engine->feed(), RC_TLS_ENGINE_SPECIFIC_ERROR);

    // toBeReturned (receive result) == 0
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed()).Times(2).WillRepeatedly(Return(false));
    toBeReturned = 0;
    EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(toBeReturned));
    EXPECT_EQ(m_engine->feed(), RC_TLS_ENGINE_PEER_CLOSED);
}

//------------------------------------------------------------------

/**
 * @fn TEST_F(BotanCertEngineTest, ShutdownSuccess)
 * @brief called Shutdown function successfully
 */
TEST_F(BotanCertEngineTest, ShutdownSuccess)
{
    TestShutdownSuccess();
    EXPECT_EQ(m_engine->Shutdown(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanCertEngineTest, ShutdownFailure)
 * @brief get a failure when called Shutdown function
 */
TEST_F(BotanCertEngineTest, ShutdownFailure)
{
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, close()).Times(1).WillOnce(Throw("exception"));
    EXPECT_EQ(m_engine->Shutdown(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanCertEngineTest, Close)
 * @brief check Close function
 */
TEST_F(BotanCertEngineTest, Close)
{
    TestShutdownSuccess();
    m_engine->Close();
    EXPECT_TRUE(m_engine->m_plaintext.empty());
}

/**
 * @fn TEST_F(BotanCertEngineTest, SetBlockingSucces)
 * @brief called SetBlocking function successfully
 */
TEST_F(BotanCertEngineTest, SetBlocking)
{
    bool blocking = true;
    EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(true));

    vwg::tls::impl::TLSEngineError res = m_engine->SetBlocking(blocking);

    EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(TLSCertEngineTest, SetBlockingFailure)
 * @brief SetBlocking function in failure case
 */
TEST_F(BotanCertEngineTest, SetBlockingFailure)
{
    bool blocking = true;
    EXPECT_CALL(*m_stream, SetBlocking(blocking)).Times(1).WillOnce(Return(false));

    vwg::tls::impl::TLSEngineError res = m_engine->SetBlocking(blocking);

    EXPECT_EQ(res, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(BotanCertEngineTest, GetIOStream)
 * @brief check GetIOStream function
 */
TEST_F(BotanCertEngineTest, GetIOStream)
{
    std::shared_ptr<IOStream> streamRes = m_engine->GetIOStream();
    EXPECT_EQ(streamRes, m_stream);
}

/**
 * @fn TEST_F(BotanCertEngineTest, SetReceivedAlert)
 * @brief check SetReceivedAlert function
 */
TEST_F(BotanCertEngineTest, SetReceivedAlert)
{
    Alert::Type alertType = Alert::Type::UNEXPECTED_MESSAGE;
    Alert       alert(alertType, true);

    m_callbacks->tls_alert(alert);

    EXPECT_EQ(m_engine->m_receivedAlert, alertType);
}

/**
 * @fn TEST_F(BotanCertEngineTest, getUsedAlpnMode)
 * @brief check getUsedAlpnMode function
 */
TEST_F(BotanCertEngineTest, getUsedAlpnMode)
{
    expect_eq_AlpnMode(ALPN_DEFAULT, m_engine->getUsedAlpnMode());
}

/**
 * @fn TEST_F(BotanCertEngineTest, getUsedProtocol)
 * @brief check getUsedProtocol function
 */
TEST_F(BotanCertEngineTest, getUsedProtocol)
{
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, application_protocol())
        .Times(3)
        .WillOnce(ReturnRef(m_http))           // 1
        .WillOnce(ReturnRef(m_http2))          // 2
        .WillOnce(ReturnRef(m_someProtocol));  // 3

    EXPECT_EQ(m_engine->getUsedProtocol(), HTTP);   // 1
    EXPECT_EQ(m_engine->getUsedProtocol(), HTTP2);  // 2
    EXPECT_EQ(m_engine->getUsedProtocol(), NONE);   // 3
}

/**
 * @fn TEST_F(BotanCertEngineTest, setCipherSuitesListUseCase)
 * @brief checking setCipherSuitesListUseCase function
 */
TEST_F(BotanCertEngineTest, setCipherSuitesListUseCase)
{
    std::vector<uint16_t> ianaRecommendedCiphers(defaultCipherSuites);
    ianaRecommendedCiphers.insert(
        ianaRecommendedCiphers.end(),
        {TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256});

    // CSUSDefault case
    m_engine->m_ciphersuiteCodes.clear();
    m_engine->setCipherSuitesListUseCase(CSUSDefault);
    EXPECT_EQ(defaultCipherSuites, m_engine->m_ciphersuiteCodes);
    EXPECT_EQ(CSUSDefault, m_engine->m_cipherSuiteUseCase);

    // CSUSDefaultWithSoftFail case
    m_engine->m_ciphersuiteCodes.clear();
    m_engine->setCipherSuitesListUseCase(CSUSDefaultWithSoftFail);
    // Should be the same as CSUSDefault case
    EXPECT_EQ(defaultCipherSuites, m_engine->m_ciphersuiteCodes);
    EXPECT_EQ(CSUSDefaultWithSoftFail, m_engine->m_cipherSuiteUseCase);

    // CSUSLegacy case
    std::vector<uint16_t> legacyCiphers(ianaRecommendedCiphers);
    legacyCiphers.insert(legacyCiphers.end(),
                         {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                          TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                          TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                          TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                          TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                          TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                          TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                          TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                          TLS_RSA_WITH_AES_128_GCM_SHA256,
                          TLS_RSA_WITH_AES_256_GCM_SHA384,
                          TLS_RSA_WITH_AES_128_CBC_SHA256,
                          TLS_RSA_WITH_AES_256_CBC_SHA256,
                          TLS_RSA_WITH_AES_128_CBC_SHA,
                          TLS_RSA_WITH_AES_256_CBC_SHA,
                          TLS_RSA_WITH_3DES_EDE_CBC_SHA});

    m_engine->m_ciphersuiteCodes.clear();
    m_engine->setCipherSuitesListUseCase(CSUSLegacy);
    EXPECT_EQ(legacyCiphers, m_engine->m_ciphersuiteCodes);
    EXPECT_EQ(CSUSLegacy, m_engine->m_cipherSuiteUseCase);

    // CSUSLongtermSecure case
    std::vector<uint16_t> longTermSecureCiphers = {TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                                   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                                   TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                                   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                                   TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                                   TLS_DHE_RSA_WITH_AES_256_GCM_SHA384};
    m_engine->m_ciphersuiteCodes.clear();
    m_engine->setCipherSuitesListUseCase(CSUSLongtermSecure);
    EXPECT_EQ(longTermSecureCiphers, m_engine->m_ciphersuiteCodes);
    EXPECT_EQ(CSUSLongtermSecure, m_engine->m_cipherSuiteUseCase);

    // CSUSIanaRecommended case
    m_engine->m_ciphersuiteCodes.clear();
    m_engine->setCipherSuitesListUseCase(CSUSIanaRecommended);
    EXPECT_EQ(ianaRecommendedCiphers, m_engine->m_ciphersuiteCodes);
    EXPECT_EQ(CSUSIanaRecommended, m_engine->m_cipherSuiteUseCase);
}

/**
 * @fn TEST_F(BotanCertEngineTest, filteredCiphers)
 * @brief checking filteredCiphers - function
 */
TEST_F(BotanCertEngineTest, filteredCiphers)
{
    std::string defaultCipherSuitesIds =
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:"
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:";

    // Checked filteredCiphers when cipher suite ids is the all default ids
    m_engine->m_ciphersuiteCodes.clear();
    m_engine->filteredCiphers(defaultCipherSuitesIds);
    EXPECT_EQ(defaultCipherSuites, m_engine->m_ciphersuiteCodes);

    // Checked filteredCiphers When cipher suite id is invalid
    m_engine->m_ciphersuiteCodes.clear();
    m_engine->filteredCiphers("some invalid data");
    EXPECT_EQ(defaultCipherSuites, m_engine->m_ciphersuiteCodes);
}

/**
 * @fn TEST_F(BotanCertEngineTest, GetRevocationCheckEnable)
 * @brief checking GetRevocationCheckEnable - function
 */
TEST_F(BotanCertEngineTest, GetRevocationCheckEnable)
{
    EXPECT_EQ(m_engine->m_revocationCheckEnabled, m_engine->GetRevocationCheckEnable());
}

/**
 * @fn TEST_F(BotanCertEngineTest, getAlpnProtocolUserDefined)
 * @brief called function getAlpnProtocol successfully when m_alpnMode.userDefinedALPNisUsed()
 */
TEST_F(BotanCertEngineTest, getAlpnProtocolUserDefined)
{
    auto alpnMode = AlpnMode(std::vector<std::string>{"alpn1", "alpn2"});
    getAlpnProtocolTest(alpnMode, true, {"alpn1", "alpn2"});
}

/**
 * @fn TEST_F(BotanCertEngineTest, getAlpnProtocolSupportedProtocols)
 * @brief called function getAlpnProtocol successfully when !m_alpnMode.userDefinedALPNisUsed()
 */
TEST_F(BotanCertEngineTest, getAlpnProtocolSupportedProtocols)
{
    getAlpnProtocolTest(ALPN_ANY, true, {"h2", "http/1.1"});
}

/**
 * @fn TEST_F(BotanCertEngineTest, getAlpnProtocolFailure)
 * @brief function getAlpnProtocol returns a failure
 */
TEST_F(BotanCertEngineTest, getAlpnProtocolFailure)
{
    auto alpnMode = ALPN_OFF;
    getAlpnProtocolTest(alpnMode, false, {});
}

/**
 * @fn TEST_F(ClientCredsManagerTest, trusted_certificate_authorities_fail_empty_cert_bundle)
 * @brief check trusted_certificate_authorities function fail while empty cert bundle
 */
TEST_F(ClientCredsManagerTest, trusted_certificate_authorities_fail_empty_cert_bundle)
{
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(_)).Times(1).WillOnce(Return(""));

    ClientCredsManager                     clientCredsManager(m_botanCertEngine);
    std::vector<Botan::Certificate_Store*> ret = clientCredsManager.trusted_certificate_authorities(m_type, m_context);
    EXPECT_TRUE(ret.empty());
}

/**
 * @fn TEST_F(BotanCertEngineTest, trusted_certificate_authorities_fail_invalid_cert_format)
 * @brief check trusted_certificate_authorities function fail while invalid cert format
 */
TEST_F(ClientCredsManagerTest, trusted_certificate_authorities_fail_invalid_cert_format)
{
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_root_cert_bundle(_)).Times(1).WillOnce(Return("root cert"));

    ClientCredsManager clientCredsManager(m_botanCertEngine);

    // throw an exception and catch it into the function
    clientCredsManager.trusted_certificate_authorities(m_type, m_context);
    EXPECT_EQ(clientCredsManager.m_engine->m_privateStore.get(), nullptr);
}

/**
 * @fn TEST_F(BotanCertEngineTest, cert_chain_fail_invalid_client_cert)
 * @brief check cert_chain function fail while invalid client cert
 */
TEST_F(ClientCredsManagerTest, cert_chain_fail_invalid_client_cert)
{
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert(_)).Times(1).WillOnce(Return("invalid client cert format"));

    ClientCredsManager                   clientCredsManager(m_botanCertEngine);
    std::vector<Botan::X509_Certificate> ret = clientCredsManager.cert_chain(m_vec, m_type, m_context);
    EXPECT_TRUE(ret.empty());
}


/**
 * @fn TEST_F(BotanCertEngineTest, private_key_for_invalid_key)
 * @brief check private_key_for function while invalid key format
 */
TEST_F(ClientCredsManagerTest, private_key_for_invalid_key)
{
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_client_cert_private_key(_))
        .Times(1)
        .WillOnce(Return("invalid client cert pk format"));

    ClientCredsManager clientCredsManager(m_botanCertEngine);

    // throw an exception and catch it into the function
    clientCredsManager.private_key_for(m_cert, m_type, m_context);

    EXPECT_EQ(clientCredsManager.m_engine->m_privateKey.get(), nullptr);
}

/**
 * @fn TEST_F(BotanCertEngineTest, emptyCertId)
 * @brief check ClientCredsManager functions while CertID is empty
 */
TEST_F(ClientCredsManagerTest, emptyCertId)
{
    ClientCredsManager clientCredsManager(m_botanCertEngineEmptyCertId);

    Botan::Private_Key* retPrivateKey = clientCredsManager.private_key_for(m_cert, m_type, m_context);
    EXPECT_EQ(retPrivateKey, nullptr);

    std::vector<Botan::X509_Certificate> retCertificate = clientCredsManager.cert_chain(m_vec, m_type, m_context);
    EXPECT_TRUE(retCertificate.empty());
}

/**
 * @fn TEST_F(strict_policy_with_ocsp_config_test, set_ciphersuite_list)
 * @brief check set_ciphersuite_list function
 */
TEST_F(strict_policy_with_ocsp_config_test, set_ciphersuite_list)
{
    std::vector<uint16_t> someIds = {TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                     TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};

    m_policy.set_ciphersuite_list(someIds);
    EXPECT_EQ(m_policy.ciphersuite_codes, someIds);
}

/**
 * @fn TEST_F(strict_policy_with_ocsp_config_test, support_cert_status_message)
 * @brief checks support_cert_status_message and set_cert_status functions
 */
TEST_F(strict_policy_with_ocsp_config_test, cert_status_message)
{
    // Checks when cipher suite id is all
    bool someStatus = true;

    m_policy.set_cert_status(someStatus);
    EXPECT_EQ(m_policy.support_cert_status_message(), someStatus);
    EXPECT_EQ(m_policy.m_cert_status_policy, someStatus);
}

/**
 * @fn TEST_P(strict_policy_with_ocsp_config_test, strict_policy_with_ocsp_config)
 * @brief checks strict_policy_with_ocsp_config function
 */
TEST_F(strict_policy_with_ocsp_config_test, ciphersuite_list)
{
    std::vector<uint16_t> ciperSuites = {TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256};
    m_policy.ciphersuite_codes        = ciperSuites;
    EXPECT_EQ(m_policy.ciphersuite_list(Botan::TLS::Protocol_Version(), true), ciperSuites);
}