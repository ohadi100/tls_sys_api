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


#include <botan/tls_exceptn.h>
#include <botan/auto_rng.h>

#include "BotanPSKEngine.hpp"

#include "MockBotanChannel.hpp"
#include "MockIOStreamIf.hpp"
#include "MockTLSTEEAPI.hpp"
#include "gtest/gtest.h"

using Botan::TLS::Alert;
using ::testing::_;
using ::testing::Return;
using ::testing::Throw;
using ::testing::SetArgPointee;

using namespace vwg::tee;


class PolicyPSKTest : public ::testing::Test {
public:
  PolicyPSK m_policy;
};

class BotanPSKEngineTest : public ::testing::Test {
public:
  // server
  std::shared_ptr<MockIOStreamIf> m_stream;
  std::shared_ptr<BotanPSKEngine> m_engine;
  std::shared_ptr<CallbacksPSK> m_callbacks;

  virtual void SetUp() {
      m_stream = std::make_shared<MockIOStreamIf>();
      m_engine = std::make_shared<BotanPSKEngine>(m_stream, true /* is server */, "", CONFIDENTIAL_WITHPSK);

      m_callbacks = std::make_shared<CallbacksPSK>(m_engine.get());
      std::shared_ptr<Botan::TLS::Session_Manager> session_manager =
          std::make_shared<Botan::TLS::Session_Manager_Noop>();
      std::shared_ptr<Botan::RandomNumberGenerator> rng = std::make_shared<Botan::AutoSeeded_RNG>();
      Botan::TLS::Policy                            policy;

      BotanClientUT::m_mockBotanChannel = new MockBotanChannel(*m_callbacks, *session_manager, *rng, policy);

      TLSTEEUT::mMockTLSTEEAPI = std::make_shared<MockTLSTEEAPI>();
  }

  void
  testFeedFailureThrow(Botan::TLS::Alert::Type expectedRes) const
  {
      // What to throw is out of this function because the exception parameter type needs to be different depends on
      // the case
      EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed)  // 1-while condition 2-while content 3-while condition
          .Times(3)
          .WillRepeatedly(Return(false));

      int32_t toBeReturned = sizeof(m_engine->m_buffer);
      EXPECT_CALL(*m_stream, receive(_, _)).Times(1).WillOnce(Return(toBeReturned));

      EXPECT_EQ(m_engine->feed(), m_engine->AlertToEngineError(expectedRes));
  }

  void TestShutdownSuccess() {
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, close()).Times(1);
  }

  void TestDestructor() {
    TestShutdownSuccess();
    m_engine.reset();
  }

  virtual void TearDown() {
    TestDestructor();

    delete BotanClientUT::m_mockBotanChannel;
    BotanClientUT::m_mockBotanChannel = nullptr;

    TLSTEEUT::mMockTLSTEEAPI.reset();
  }
};

class CallbacksPSKTest : public BotanPSKEngineTest
{
};

class ServerCredsPSKTest : public BotanPSKEngineTest
{
public:

    virtual void SetUp(){
        BotanPSKEngineTest::SetUp();

        m_serverCredsPsk = std::make_shared<ServerCredsPSK>(m_engine.get());

    }
    std::shared_ptr<ServerCredsPSK> m_serverCredsPsk;

};

class ClientCredsPSKTest : public BotanPSKEngineTest
{
public:

    virtual void SetUp(){
        BotanPSKEngineTest::SetUp();

        m_clientCredsPsk = std::make_shared<ClientCredsPSK>(m_engine.get());

    }
    std::shared_ptr<ClientCredsPSK> m_clientCredsPsk;

};

/**
 * @fn TEST_F(ClientCredsPSKTest, psk_identity_hint)
 * @brief checks psk_identity_hint function
 */
TEST_F(ClientCredsPSKTest, psk_identity_hint) {
    m_engine->m_keys.hint = "some hint";
    EXPECT_EQ(m_clientCredsPsk->psk_identity_hint("",""),  m_engine->m_keys.hint);
}

/**
 * @fn TEST_F(ClientCredsPSKTest, psk_identity)
 * @brief checks psk_identity function
 */
TEST_F(ClientCredsPSKTest, psk_identity) {
    m_engine->m_keys.hint = "some hint";
    std::string identity_hint = "some identity remote hint";

    EXPECT_EQ(m_clientCredsPsk->psk_identity("some type", "some context",identity_hint),  m_engine->m_keys.hint);
    EXPECT_EQ(m_engine->m_keys.remoteHint,  identity_hint);
}


/**
 * @fn TEST_F(ClientCredsPSKTest, pskSuccess)
 * @brief check psk function when it's called successfully
 */
TEST_F(ClientCredsPSKTest, pskSuccess) {
    vwg::tee::SessionKey keyDataOutParam = {2, {0x23, 0x56}};  // out parameter returning from get_psk mock function
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_psk(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(keyDataOutParam), Return(true)));

    Botan::SymmetricKey res = m_clientCredsPsk->psk("some type", "some context", "some identity");

    EXPECT_EQ(res, Botan::SymmetricKey(keyDataOutParam.value, keyDataOutParam.length));
}

/**
 * @fn TEST_F(ClientCredsPSKTest, pskFailure)
 * @brief check psk function when it throws exception
 */
TEST_F(ClientCredsPSKTest, pskFailure) {
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_psk(_, _, _)).Times(1).WillOnce(Return(false));// get_psk fails
    EXPECT_THROW(m_clientCredsPsk->psk("some type", "some context", "some identity"), BotanEngineError);
}

/**
 * @fn TEST_F(ServerCredsPSKTest, psk_identity_hint)
 * @brief check psk_identity_hint function
 */
TEST_F(ServerCredsPSKTest, psk_identity_hint) {
    m_engine->m_keys.hint = "some hint";
    EXPECT_EQ(m_serverCredsPsk->psk_identity_hint("some type", "some context"),  m_engine->m_keys.hint);
}

/**
 * @fn TEST_F(ServerCredsPSKTest, pskSuccess)
 * @brief check psk function when it's called successfully
 */
TEST_F(ServerCredsPSKTest, pskSuccess) {
    std::string identity = "some identity";
    vwg::tee::SessionKey keyDataOutParam = {2, {0x23, 0x56}};  // out parameter returning from get_psk mock function

    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_psk(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(keyDataOutParam), Return(true)));

    Botan::SymmetricKey res = m_serverCredsPsk->psk("some type", "some context", identity);

    EXPECT_EQ(res, Botan::SymmetricKey(keyDataOutParam.value, keyDataOutParam.length));
    EXPECT_EQ(m_engine->m_keys.remoteHint, identity);
}

/**
 * @fn TEST_F(ServerCredsPSKTest, pskFailure)
 * @brief check psk function when it throws exceptions
 */
TEST_F(ServerCredsPSKTest, pskFailure) {
    //first psk() thrown case
    EXPECT_THROW(m_serverCredsPsk->psk("tls-server", "session-ticket", ""), BotanEngineError);

    //second psk() thrown case
    std::string identity = "some identity";
    EXPECT_CALL(*TLSTEEUT::mMockTLSTEEAPI, get_psk(_, _, _)).Times(1).WillOnce(Return(false));// get_psk fails
    EXPECT_THROW(m_serverCredsPsk->psk("", "", identity), BotanEngineError);
    EXPECT_EQ( m_engine->m_keys.remoteHint, identity);
}

/**
 * @fn TEST_F(PolicyPSKTest, allowed_ciphers)
 * @brief check allowed_ciphers function
 */
TEST_F(PolicyPSKTest, allowed_ciphers) {
  std::vector<std::string> expectedRes = {"AES-128/GCM"};
  EXPECT_EQ(m_policy.allowed_ciphers(), expectedRes);
}

/**
 * @fn TEST_F(PolicyPSKTest, allowed_key_exchange_methods)
 * @brief check allowed_key_exchange_methods function
 */
TEST_F(PolicyPSKTest, allowed_key_exchange_methods) {
  std::vector<std::string> expectedRes = {"PSK"};
  EXPECT_EQ(m_policy.allowed_key_exchange_methods(), expectedRes);
}

/**
 * @fn TEST_F(PolicyPSKTest, allowed_key_exchange_methods)
 * @brief check allowed_key_exchange_methods function
 */
TEST_F(PolicyPSKTest, allowed_signature_hashes) {
  std::vector<std::string> expectedRes = {"SHA-256"};
  EXPECT_EQ(m_policy.allowed_signature_hashes(), expectedRes);
}

/**
 * @fn TEST_F(PolicyPSKTest, allow_tls10)
 * @brief check allow_tls10 function
 */
TEST_F(PolicyPSKTest, allow_tls10) { EXPECT_EQ(m_policy.allow_tls10(), false); }

/**
 * @fn TEST_F(PolicyPSKTest, allow_tls11)
 * @brief check allow_tls11 function
 */
TEST_F(PolicyPSKTest, allow_tls11) { EXPECT_EQ(m_policy.allow_tls11(), false); }

/**
 * @fn TEST_F(PolicyPSKTest, allow_tls12)
 * @brief check allow_tls12 function
 */
TEST_F(PolicyPSKTest, allow_tls12) { EXPECT_EQ(m_policy.allow_tls12(), true); }

/**
 * @fn TEST_F(CallbacksPSKTest, tls_emit_data)
 * @brief check tls_emit_data function
 */
TEST_F(CallbacksPSKTest, tls_emit_data) {
  const uint8_t buf_len = 2;
  uint8_t buf[buf_len];

  EXPECT_CALL(*m_stream, send(buf, buf_len)).Times(1);

  m_callbacks->tls_emit_data(buf, buf_len);
}

/**
 * @fn TEST_F(CallbacksPSKTest, tls_alert)
 * @brief check tls_alert function
 */
TEST_F(CallbacksPSKTest, tls_alert) {

  Alert::Type alertType = Alert::Type::UNEXPECTED_MESSAGE;
  Alert alert(alertType, true);

  m_callbacks->tls_alert(alert);

  EXPECT_EQ(m_engine->m_receivedAlert, alertType);
}

/**
 * @fn TEST_F(CallbacksPSKTest, tls_record_received)
 * @brief check tls_record_received function
 */
TEST_F(CallbacksPSKTest, tls_record_received) {

  std::vector<uint8_t> plaintext;

  const size_t len = 3;
  uint8_t buf[len] = {1, 2, 3};

  m_callbacks->tls_record_received(0, buf, len);
  size_t plainTextSize = m_engine->m_plaintext.size();

  EXPECT_EQ(plainTextSize, len);

  for (size_t i = 0; i < len && i < plainTextSize; i++) {
    EXPECT_EQ(m_engine->m_plaintext[i], buf[i]);
  }
}

/**
 * @fn TEST_F(CallbacksPSKTest, tls_session_established)
 * @brief check tls_session_established function
 */
TEST_F(CallbacksPSKTest, tls_session_established) {

  Botan::TLS::Session session;
  EXPECT_EQ(m_callbacks->tls_session_established(session), false);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, checkTeeAndItsData)
 * @brief check checkTeeAndItsData function
 */
TEST_F(BotanPSKEngineTest, checkTeeAndItsData) {
  EXPECT_EQ(m_engine->checkTeeAndItsData(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, DoSSLHandshakeServerSuccess)
 * @brief checking doSSLHandshake for server - happy flow
 */
TEST_F(BotanPSKEngineTest, DoSSLHandshakeServerSuccess) {

  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_active())
      .Times(2)
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(3) // 1 for DoSSLHandshakeServer, 2 and 3 for feed()
      .WillRepeatedly(Return(false));

  // feed()
  int32_t toBeReturned = sizeof(m_engine->m_buffer);
  EXPECT_CALL(*m_stream, receive(_, _))
      .Times(1)
      .WillOnce(Return(toBeReturned));
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
      .Times(1)
      .WillOnce(Return(0));

  EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, DoSSLHandshakeServerFailure_closeChannel)
 * @brief checking doSSLHandshake for server, when it gets a failure because the channel is close
 */
TEST_F(BotanPSKEngineTest, DoSSLHandshakeServerFailure_closeChannel) {
    m_engine->m_isServer = true;

    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_active())
        .Times(1)
        .WillOnce(Return(false));
    //channel is close
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_EQ(m_engine->DoSSLHandshake(), m_engine->AlertToEngineError(Botan::TLS::Alert::NULL_ALERT));
}

/**
 * @fn TEST_F(BotanPSKEngineTest, DoSSLHandshakeClientSuccess)
 * @brief checking doSSLHandshake for client - happy flow
 */
TEST_F(BotanPSKEngineTest, DoSSLHandshakeClientSuccess) {
    m_engine->m_isServer = false;

  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_active())
      .Times(2)
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(3)
      .WillRepeatedly(Return(false));

  // feed()
  int32_t toBeReturned = sizeof(m_engine->m_buffer);
  EXPECT_CALL(*m_stream, receive(_, _))
      .Times(1)
      .WillOnce(Return(toBeReturned));
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
      .Times(1)
      .WillOnce(Return(0));

  EXPECT_EQ(m_engine->DoSSLHandshake(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, DoSSLHandshakeClientFailure_closeChannel)
 * @brief checking doSSLHandshake for client, when it gets a failure because the channel is close
 */
TEST_F(BotanPSKEngineTest, DoSSLHandshakeClientFailure_closeChannel) {
    m_engine->m_isServer = false;

    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_active())
        .Times(1)
        .WillOnce(Return(false));
    //channel is close
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_EQ(m_engine->DoSSLHandshake(), m_engine->AlertToEngineError(Botan::TLS::Alert::NULL_ALERT));
}

/**
 * @fn TEST_F(BotanPSKEngineTest, SendSuccess)
 * @brief checking Send function - happy flow
 */
TEST_F(BotanPSKEngineTest, SendSuccess) {
  int32_t bufLength = 10;
  uint8_t buf[bufLength];
  int32_t actualLength = 0;

  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(1)
      .WillOnce(Return(false));
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, send(buf, bufLength))
      .Times(1);

  EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength),
            RC_TLS_ENGINE_SUCCESSFUL);
  EXPECT_EQ(actualLength, bufLength);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, SendFailure)
 * @brief checking Send function - get a failure
 */
TEST_F(BotanPSKEngineTest, SendFailure) {
  int32_t bufLength = 10;
  uint8_t buf[bufLength];
  int32_t actualLength = 5;

  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength),
            RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN);

  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(1)
      .WillOnce(Return(false));
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, send(buf, bufLength))
      .Times(1)
      .WillOnce(Throw("exception"));
  EXPECT_EQ(m_engine->Send(buf, bufLength, actualLength),
            RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, ReceiveSuccess)
 * @brief called Receive function successfully
 */
TEST_F(BotanPSKEngineTest, ReceiveSuccess) {
  const int32_t bufLength = 3;
  uint8_t buf[bufLength] = {1, 2, 3};
  int32_t actualLength = 0;

  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(4) // the 3th and 4th times are for feed() calling
      .WillRepeatedly(Return(false));

  // feed();
  // EXPECT_CALL mockBotanChannel->is_closed() twice and return false
  int32_t toBeReturned = bufLength;
  EXPECT_CALL(*m_stream, receive(_, _))
      .Times(1)
      .WillOnce(Return(toBeReturned));
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
      .Times(1)
      .WillOnce(Return(0));

  EXPECT_EQ(m_engine->Receive(buf, bufLength, actualLength),
            RC_TLS_ENGINE_SUCCESSFUL);
  EXPECT_EQ(actualLength, bufLength);

  for (int i = 0; i < bufLength; i++) {
    EXPECT_EQ(m_engine->m_plaintext[i], buf[i]);
  }
}

/**
 * @fn TEST_F(BotanPSKEngineTest, ReceiveSuccess2)
 * @brief called Receive function with buffer size that is bigger than engine's buffer size
 */
TEST_F(BotanPSKEngineTest, ReceiveSuccess2)
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
 * @fn TEST_F(BotanPSKEngineTest, feedSuccess)
 * @brief called feed function successfully
 */
TEST_F(BotanPSKEngineTest, feedSuccess) {

  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(2)
      .WillRepeatedly(Return(false));

  int32_t toBeReturned = sizeof(m_engine->m_buffer);
  EXPECT_CALL(*m_stream, receive(_, _))
      .Times(1)
      .WillOnce(Return(toBeReturned));

  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
      .Times(1)
      .WillOnce(Return(0));

  EXPECT_EQ(m_engine->feed(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, feedFailureThrow)
 * @brief called feed when received_data throw an exception
 */
TEST_F(BotanPSKEngineTest, feedFailureThrow) {

    //1
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
        .Times(1)
        .WillOnce(Throw(Botan::TLS::TLS_Exception(Botan::TLS::Alert::UNEXPECTED_MESSAGE, "")));
    testFeedFailureThrow(Botan::TLS::Alert::UNEXPECTED_MESSAGE);

    //2
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
        .Times(1)
        .WillOnce(Throw(Botan::Integrity_Failure("")));
    testFeedFailureThrow(Botan::TLS::Alert::BAD_RECORD_MAC);

    //3
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
        .Times(1)
        .WillOnce(Throw(Botan::Decoding_Error("")));
    testFeedFailureThrow(Botan::TLS::Alert::DECODE_ERROR);

    //4
    m_engine->m_isServer = false;// just for get in "else" for LOG in feed function
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, received_data(_, _))
        .Times(1)
        .WillOnce(Throw(exception()));
    testFeedFailureThrow(Botan::TLS::Alert::INTERNAL_ERROR);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, feedFailure)
 * @brief get a failure when called feed function
 */
TEST_F(BotanPSKEngineTest, feedFailure) {
  // toBeReturned (receive result) = RC_STREAM_WOULD_BLOCK < 0
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(2)
      .WillRepeatedly(Return(false));
  int32_t toBeReturned = RC_STREAM_WOULD_BLOCK;
  EXPECT_CALL(*m_stream, receive(_, _))
      .Times(1)
      .WillOnce(Return(toBeReturned));
  EXPECT_EQ(m_engine->feed(), RC_TLS_ENGINE_WOULD_BLOCK_READ);

  // toBeReturned (receive result) = RC_STREAM_IO_ERROR < 0
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(2)
      .WillRepeatedly(Return(false));
  toBeReturned = RC_STREAM_IO_ERROR;
  EXPECT_CALL(*m_stream, receive(_, _))
      .Times(1)
      .WillOnce(Return(toBeReturned));
  EXPECT_EQ(m_engine->feed(), RC_TLS_ENGINE_SPECIFIC_ERROR);

  // toBeReturned (receive result) == 0
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, is_closed())
      .Times(2)
      .WillRepeatedly(Return(false));
  toBeReturned = 0;
  EXPECT_CALL(*m_stream, receive(_, _))
      .Times(1)
      .WillOnce(Return(toBeReturned));
  EXPECT_EQ(m_engine->feed(), RC_TLS_ENGINE_PEER_CLOSED);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, ShutdownSuccess)
 * @brief called Shutdown function successfully
 */
TEST_F(BotanPSKEngineTest, ShutdownSuccess) {
  TestShutdownSuccess();
  EXPECT_EQ(m_engine->Shutdown(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, ShutdownFailure)
 * @brief get a failure when called Shutdown function
 */
TEST_F(BotanPSKEngineTest, ShutdownFailure) {
  EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, close())
      .Times(1)
      .WillOnce(Throw("exception"));
  EXPECT_EQ(m_engine->Shutdown(), RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, Close)
 * @brief check Close function
 */
TEST_F(BotanPSKEngineTest, Close) {
  TestShutdownSuccess();
  m_engine->Close();
  EXPECT_TRUE(m_engine->m_plaintext.empty());
  EXPECT_TRUE(m_engine->m_keys.remoteHint.empty());
  EXPECT_TRUE(m_engine->m_keys.hint.empty());
}

/**
 * @fn TEST_F(BotanPSKEngineTest, AlertToEngineError)
 * @brief check AlertToEngineError function
 */
TEST_F(BotanPSKEngineTest, AlertToEngineError) {

  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNEXPECTED_MESSAGE),
      RC_TLS_ENGINE_UNEXPECTED_MESSAGE);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::BAD_RECORD_MAC),
      RC_TLS_ENGINE_BAD_RECORD_MAC);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNEXPECTED_MESSAGE),
      RC_TLS_ENGINE_UNEXPECTED_MESSAGE);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNEXPECTED_MESSAGE),
      RC_TLS_ENGINE_UNEXPECTED_MESSAGE);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::RECORD_OVERFLOW),
      RC_TLS_ENGINE_RECORD_OVERFLOW);
  EXPECT_EQ(m_engine->AlertToEngineError(
                Botan::TLS::Alert::DECOMPRESSION_FAILURE),
            RC_TLS_ENGINE_DECOMPRESSION_FAILURE);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::HANDSHAKE_FAILURE),
      RC_TLS_ENGINE_HANDSHAKE_FAILURE);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::BAD_CERTIFICATE),
      RC_TLS_ENGINE_BAD_CERTIFICATE);
  EXPECT_EQ(m_engine->AlertToEngineError(
                Botan::TLS::Alert::UNSUPPORTED_CERTIFICATE),
            RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE);
  EXPECT_EQ(m_engine->AlertToEngineError(
                Botan::TLS::Alert::CERTIFICATE_REVOKED),
            RC_TLS_ENGINE_CERTIFICATE_REVOKED);
  EXPECT_EQ(m_engine->AlertToEngineError(
                Botan::TLS::Alert::CERTIFICATE_EXPIRED),
            RC_TLS_ENGINE_CERTIFICATE_EXPIRED);
  EXPECT_EQ(m_engine->AlertToEngineError(
                Botan::TLS::Alert::CERTIFICATE_UNKNOWN),
            RC_TLS_ENGINE_CERTIFICATE_UNKNOWN);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::ILLEGAL_PARAMETER),
      RC_TLS_ENGINE_ILLEGAL_PARAMETER);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNKNOWN_CA),
            RC_TLS_ENGINE_UNKNOWN_CA);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::ACCESS_DENIED),
      RC_TLS_ENGINE_ACCESS_DENIED);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::DECODE_ERROR),
            RC_TLS_ENGINE_DECODE_ERROR);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::DECRYPT_ERROR),
      RC_TLS_ENGINE_DECRYPT_ERROR);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::PROTOCOL_VERSION),
      RC_TLS_ENGINE_PROTOCOL_VERSION);
  EXPECT_EQ(m_engine->AlertToEngineError(
                Botan::TLS::Alert::INSUFFICIENT_SECURITY),
            RC_TLS_ENGINE_INSUFFICIENT_SECURITY);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::NO_RENEGOTIATION),
      RC_TLS_ENGINE_NO_RENEGOTIATION);
  EXPECT_EQ(m_engine->AlertToEngineError(
                Botan::TLS::Alert::UNSUPPORTED_EXTENSION),
            RC_TLS_ENGINE_UNSUPPORTED_EXTENSION);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::NULL_ALERT),
            RC_TLS_ENGINE_UNKNOWN_ERROR);
  EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::USER_CANCELED),
      RC_TLS_ENGINE_SPECIFIC_ERROR);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::CERTIFICATE_UNOBTAINABLE), RC_TLS_ENGINE_CERTIFICATE_UNOBTAINABLE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::UNRECOGNIZED_NAME), RC_TLS_ENGINE_UNRECOGNIZED_NAME);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::BAD_CERTIFICATE_STATUS_RESPONSE), RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE);
    EXPECT_EQ(m_engine->AlertToEngineError(Botan::TLS::Alert::BAD_CERTIFICATE_HASH_VALUE), RC_TLS_ENGINE_BAD_CERTIFICATE_HASH_VALUE);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, SetBlockingSucces)
 * @brief called SetBlocking function successfully
 */
TEST_F(BotanPSKEngineTest, SetBlocking) {

  bool blocking = true;
  EXPECT_CALL(*m_stream, SetBlocking(blocking))
      .Times(1)
      .WillOnce(Return(true));

  vwg::tls::impl::TLSEngineError res = m_engine->SetBlocking(blocking);

  EXPECT_EQ(res, RC_TLS_ENGINE_SUCCESSFUL);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, SetBlockingFailure)
 * @brief SetBlocking function in failure case
 */
TEST_F(BotanPSKEngineTest, SetBlockingFailure) {

  bool blocking = true;
  EXPECT_CALL(*m_stream, SetBlocking(blocking))
      .Times(1)
      .WillOnce(Return(false));

  vwg::tls::impl::TLSEngineError res = m_engine->SetBlocking(blocking);

  EXPECT_EQ(res, RC_TLS_ENGINE_FATAL_ERROR);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, GetIOStream)
 * @brief check GetIOStream function
 */
TEST_F(BotanPSKEngineTest, GetIOStream) {

  std::shared_ptr<IOStream> streamRes = m_engine->GetIOStream();
  EXPECT_EQ(streamRes, m_stream);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, GetRemoteHintName)
 * @brief check GetRemoteHintName function
 */
TEST_F(BotanPSKEngineTest, GetRemoteHintName) {

  std::string remoteHint = m_engine->GetRemoteHintName();
  EXPECT_EQ(remoteHint, m_engine->m_keys.remoteHint);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, GetHintName)
 * @brief check GetHintName function
 */
TEST_F(BotanPSKEngineTest, GetHintName) {

  std::string hint = m_engine->GetHintName();
  EXPECT_EQ(hint, m_engine->m_keys.hint);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, SetReceivedAlert)
 * @brief check SetReceivedAlert function
 */
TEST_F(BotanPSKEngineTest, SetReceivedAlert) {

  Alert::Type alertType = Alert::Type::UNEXPECTED_MESSAGE;
  m_engine->SetReceivedAlert(alertType);
  EXPECT_EQ(alertType, m_engine->m_receivedAlert);
}


/**
 * @fn TEST_F(BotanPSKEngineTest, getUsedAlpnMode)
 * @brief checks getUsedAlpnMode function
 */
TEST_F(BotanPSKEngineTest, getUsedAlpnMode) {
    AlpnMode res = m_engine->getUsedAlpnMode();
    EXPECT_EQ(res.userDefinedALPNisUsed(), ALPN_OFF.userDefinedALPNisUsed());
    EXPECT_EQ(res.getSupportedProtocols(), ALPN_OFF.getSupportedProtocols());
    EXPECT_EQ(res.getUserDefinedAlpnSetting(), ALPN_OFF.getUserDefinedAlpnSetting());
}

/**
 * @fn TEST_F(BotanPSKEngineTest, getUsedProtocol)
 * @brief checks getUsedProtocol function
 */
TEST_F(BotanPSKEngineTest, getUsedProtocol) {
    EXPECT_EQ( m_engine->getUsedProtocol(), NONE);
}

/**
 * @fn TEST_F(BotanPSKEngineTest, ctorFailure)
 * @brief checks constructor function
 */
TEST_F(BotanPSKEngineTest, ctorFailure)
{
    EXPECT_THROW(m_engine = std::make_shared<BotanPSKEngine>(m_stream, true /* is server */, "", AUTHENTIC_WITHPSK),
                 runtime_error);
}

#ifdef TLSAPI_WITH_DROP_SUPPORT
/**
 * @fn TEST_F(BotanPSKEngineTest, DropTLSSuccess)
 * @brief checks DropTLSSuccess function when it's called successfully
 */
TEST_F(BotanPSKEngineTest, DropTLSSuccess) {
    EXPECT_CALL(*BotanClientUT::m_mockBotanChannel, closeNoReset()).Times(1);

    EXPECT_EQ(m_engine->DropTLS(), RC_TLS_ENGINE_SUCCESSFUL);
}

#endif //TLSAPI_WITH_DROP_SUPPORT