/**
 * 
 * @file MockBotanChannel.hpp
 * 
 * @brief contains the mock Botan::TLS::Channel class
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


#ifndef MOCK_BOTAN_CHANNEL_HPP
#define MOCK_BOTAN_CHANNEL_HPP

#include <botan/tls_callbacks.h>
#include <botan/tls_channel.h>
#include <gmock/gmock.h>

class Botan::TLS::Handshake_State
{
};

using ::testing::_;

using namespace vwg::tls;
using namespace vwg::tls::impl;

// MockBotanChannel needs to derive from Botan::TLS::Client, but it is a final class,
// therefore clientBotanHelper derives from Botan::TLS::Channel and implements the required Botan::TLS::Client
// functions.
class clientBotanHelper : public Botan::TLS::Channel
{
public:
    clientBotanHelper(Botan::TLS::Callbacks&        callbacks,
                      Botan::TLS::Session_Manager&  session_manager,
                      Botan::RandomNumberGenerator& rng,
                      const Botan::TLS::Policy&     policy,
                      bool                          is_datagram = false)
      : Botan::TLS::Channel((Botan::TLS::Callbacks&)callbacks, session_manager, rng, policy, is_datagram)
    {
    }

    const std::string&
    application_protocol() const
    {
        return mStr;
    }

private:
    std::string mStr{};
};

class MockBotanChannel : public clientBotanHelper
{
public:
    MockBotanChannel(Botan::TLS::Callbacks&        callbacks,
                     Botan::TLS::Session_Manager&  session_manager,
                     Botan::RandomNumberGenerator& rng,
                     const Botan::TLS::Policy&     policy,
                     bool                          is_datagram = false)
      : clientBotanHelper((Botan::TLS::Callbacks&)callbacks, session_manager, rng, policy, is_datagram)
      , m_callbacks(&callbacks)
    {
    }

    MOCK_CONST_METHOD0(is_active, bool(void));
    MOCK_CONST_METHOD0(is_closed, bool(void));
    MOCK_METHOD2(send, void(const uint8_t buf[], size_t buf_size));
    MOCK_METHOD1(send, void(const std::string& val));
    MOCK_METHOD2(received_data, size_t(const uint8_t buf[], size_t buf_size));
    MOCK_METHOD1(received_data, size_t(const std::vector<uint8_t>& buf));
    MOCK_METHOD0(close, void(void));
    MOCK_METHOD4(process_handshake_msg,
                 void(const Botan::TLS::Handshake_State* active_state,
                      Botan::TLS::Handshake_State&       pending_state,
                      Botan::TLS::Handshake_Type         type,
                      const std::vector<uint8_t>&        contents));
    MOCK_METHOD2(initiate_handshake, void(Botan::TLS::Handshake_State& state, bool force_full_renegotiation));
    MOCK_CONST_METHOD1(get_peer_cert_chain,
                       std::vector<Botan::X509_Certificate>(const Botan::TLS::Handshake_State& state));
    MOCK_METHOD1(new_handshake_state, Botan::TLS::Handshake_State*(class Botan::TLS::Handshake_IO* io));
    MOCK_CONST_METHOD0(application_protocol, std::string&(void));
    MOCK_METHOD0(closeNoReset, void(void));

    Botan::TLS::Callbacks* m_callbacks;
};

class BotanClientUT : public clientBotanHelper
{
public:
    BotanClientUT(Botan::TLS::Callbacks&        callbacks,
                  Botan::TLS::Session_Manager&  session_manager,
                  Botan::RandomNumberGenerator& rng,
                  const Botan::TLS::Policy&     policy,
                  bool                          is_datagram = false)
      : clientBotanHelper((callbacks), session_manager, rng, policy, is_datagram)
    {
    }

    const std::string&
    application_protocol() const
    {
        return m_mockBotanChannel->application_protocol();
    }

    bool
    is_active() const
    {
        return m_mockBotanChannel->is_active();
    }

    bool
    is_closed() const
    {
        return m_mockBotanChannel->is_closed();
    }

    void
    send(const uint8_t buf[], size_t buf_size)
    {
        m_mockBotanChannel->send(buf, buf_size);
    }

    void
    send(const std::string& val)
    {
        m_mockBotanChannel->send(val);
    }

    void
    close()
    {
        if (m_mockBotanChannel) {
            m_mockBotanChannel->close();
        }
    }

    size_t
    received_data(const uint8_t buf[], size_t buf_size)
    {
        (m_mockBotanChannel->m_callbacks)->tls_record_received(0, buf, buf_size);

        return m_mockBotanChannel->received_data(buf, buf_size);
    }

    size_t
    received_data(const std::vector<uint8_t>& buf)
    {
        return m_mockBotanChannel->received_data(buf);
    }

    void
    process_handshake_msg(const Botan::TLS::Handshake_State* active_state,
                          Botan::TLS::Handshake_State&       pending_state,
                          Botan::TLS::Handshake_Type         type,
                          const std::vector<uint8_t>&        contents)
    {
        return m_mockBotanChannel->process_handshake_msg(active_state, pending_state, type, contents);
    }

    void
    initiate_handshake(Botan::TLS::Handshake_State& state, bool force_full_renegotiation)
    {
        m_mockBotanChannel->initiate_handshake(state, force_full_renegotiation);
    }

    std::vector<Botan::X509_Certificate>
    get_peer_cert_chain(const Botan::TLS::Handshake_State& state) const
    {
        return m_mockBotanChannel->get_peer_cert_chain(state);
    }

    Botan::TLS::Handshake_State*
    new_handshake_state(class Botan::TLS::Handshake_IO* io)
    {
        return m_mockBotanChannel->new_handshake_state(io);
    }

    void
    closeNoReset()
    {
        m_mockBotanChannel->closeNoReset();
    }

    static MockBotanChannel* m_mockBotanChannel;
};

class MockCallbacksPSK : public Botan::TLS::Callbacks
{
public:
    MOCK_METHOD2(tls_emit_data, void(uint8_t const buf[], size_t length));
    MOCK_METHOD3(tls_record_received, void(uint64_t rec, uint8_t const data[], size_t len));
    MOCK_METHOD1(tls_alert, void(Botan::TLS::Alert alert));
    MOCK_METHOD1(tls_session_established, bool(const Botan::TLS::Session&));
};
#endif  // MOCK_BOTAN_CHANNEL_HPP