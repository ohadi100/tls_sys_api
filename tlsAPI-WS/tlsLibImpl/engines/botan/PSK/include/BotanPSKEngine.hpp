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

#ifndef SACCESSLIB_BOTANPSKENGINE_HPP
#define SACCESSLIB_BOTANPSKENGINE_HPP

#include <functional>
#include <string>
#include <vector>
#include <botan/tls_client.h>

#include "TLSEngine.hpp"

#include "ITLSEngine.hpp"
#include "TLSTEEAPI.h"
#if defined(UNIT_TEST)
#include "MockBotanChannel.hpp"
#endif

using namespace std;

namespace vwg
{
namespace tls
{
namespace impl
{
/**
* \class BotanEngine
*
* \brief The BotanEngine is the Botan implementation of TLSEngine.
*/
class BotanPSKEngine : public TLSEngine
    {
    public:
        /**
         * \brief   Constructor.
         *
         * \param[in] stream the underlying IOStreamIf used by the engine to perform actual input/output.
         * \param[in] context the shared context for the engine.
         * \param[in] hint hint
         * \param[in] confidentiality the SSOA confidentiality (see Secure service communication LHA).
         * This call will accept only the security levels AUTHENTIC_WITHPSK, CONFIDENTIAL_WITHPSK.
         */
        BotanPSKEngine(std::shared_ptr<IOStreamIf> stream, bool isServer,const std::string &hint,SecurityLevel confidentiality);

        /**
         * \brief Destructor. Calls BotanEngine::Close().
         */
        virtual ~BotanPSKEngine();

        /**
         * \brief Performs the TLS handshake, according to the arguments provided in the constructor. Also
         * initializes some Botan memory constructs.
         *
         * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
         */
        virtual TLSEngineError DoSSLHandshake() override;

        /**
         * \brief Sends a buffer to the other side.
         *
         * \param[in] buffer an unencrypted buffer of size 'length', which will be encrypted and sent through the
         * underlying (inheriting) TLS engine. This argument must be pre-allocated (either statically or
         * dynamically) by the callee.
         * \param[in] bufLength length of unencrypted buffer.
         * \param[out] actualLength length of unencrypted buffer actually sent.
         *
         * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
         */
        virtual TLSEngineError Send(const uint8_t *data, int32_t bufLength, int32_t &actualLength) override;

        /**
         * \brief Receives a buffer from the other side.
         *
         * \param[in] buffer a buffer of size 'bufLength' to receive the data. 'buffer' should be pre-allocated (either
         * statically or dynamically) by the callee.
         * \param[in] bufLength length of buffer.
         * \param[out] actualLength length of unencrypted buffer actually read.
         *
         * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
         */
        virtual TLSEngineError Receive(uint8_t *buffer, int32_t bufLength, int32_t &actualLength) override;

        virtual TLSEngineError Shutdown() override;

#ifdef TLSAPI_WITH_DROP_SUPPORT
        virtual TLSEngineError DropTLS() override;
#endif

        /**
         * \brief Closes the underlying TLS connection and release any resources that are used by Botan.
         */
        virtual void Close() override;

        const string GetRemoteHintName() const override
        {
            return m_keys.remoteHint;
        }

        const string GetHintName() const override
        {
            return m_keys.hint;
        }

        void SetReceivedAlert(Botan::TLS::Alert::Type type)
        {
            m_receivedAlert = type;
        }

        virtual const AlpnMode& getUsedAlpnMode() const  override;

        virtual IANAProtocol getUsedProtocol() const  override;

#ifdef TLSAPI_WITH_DROP_SUPPORT
        bool GetDropSendStarted() const
        {
            return m_dropSendStarted;
        }
#endif

        std::vector<uint8_t> m_plaintext;
        pskData m_keys;
#ifndef UNIT_TEST
    protected:
#endif
        /**
         * \brief Error status according to the provided alert type.
         *
         * \param[in] type The TLS alerts that want to Alert.
         *
         * \return error status according to the provided alert type
         */
        static TLSEngineError AlertToEngineError(Botan::TLS::Alert::Type type);

        /**
         * \brief Receives data from the stream up to specific length
         *
         * \param[in] len up to the max length of the expected received stream.
         *
         * \return RC_TLS_ENGINE_SUCCESSFUL on successful, error status of feed otherwise
         */
        TLSEngineError feed(size_t len);

        /**
         * \brief Receives data from the stream up to specific length
         *
         * \return RC_TLS_ENGINE_SUCCESSFUL on successful, error status of feed otherwise
         */
        TLSEngineError feed();

        TLSEngineError doSSLHandshakeClient();

        TLSEngineError doSSLHandshakeServer();

        /**
         * \brief Checks the client and server certificates data
         *
         * \return RC_TLS_ENGINE_SUCCESSFUL on successful, error status of unknown certifications otherwise
         */
        TLSEngineError checkTeeAndItsData();
#ifdef UNIT_TEST
        std::unique_ptr<BotanClientUT> m_channel;
#else
        std::unique_ptr<Botan::TLS::Channel> m_channel;
#endif

        uint8_t m_buffer[0x1000];
        bool m_isServer;
        Botan::TLS::Alert::Type m_receivedAlert;
#ifdef TLSAPI_WITH_DROP_SUPPORT
        bool m_dropSendStarted;
#endif
        std::unique_ptr<Botan::Credentials_Manager> m_creds_mgr;
        std::unique_ptr<Botan::RandomNumberGenerator> m_rng;
        std::unique_ptr<Botan::TLS::Callbacks> m_callbacks;
        std::unique_ptr<Botan::TLS::Session_Manager> m_session_mgr;
    };

/**
* \class BotanEngineError
*
* \brief Represents an error for BotanPSKEngine class.
*/
class BotanEngineError : public std::runtime_error {
public:
    explicit BotanEngineError(const std::string &s) : std::runtime_error(s) {}
};

/**
* \class ClientCredsPSK
*
* \brief This class manages the clients credentials for BotanPSKEngine class.
*/
class ClientCredsPSK : public Botan::Credentials_Manager {
public:
  ClientCredsPSK(BotanPSKEngine *engine);

  ~ClientCredsPSK();

  std::string psk_identity_hint(const std::string &type,
                                const std::string &context) override;

  std::string psk_identity(const std::string &type, const std::string &context,
                           const std::string &identity_hint) override;

  Botan::SymmetricKey psk(const std::string &type, const std::string &context,
                          const std::string &identity) override;

private:
  BotanPSKEngine *m_engine;
  std::shared_ptr<vwg::tee::TLSTEEAPI> m_tlsTeeApi;
};

/**
* \class ServerCredsPSK
*
* \brief This class manages the server credentials for BotanPSKEngine class.
*/
class ServerCredsPSK : public Botan::Credentials_Manager {
public:

    ServerCredsPSK(BotanPSKEngine *engine);

    std::string psk_identity_hint(const std::string &type,
                                  const std::string &context) override;

    Botan::SymmetricKey psk(const std::string &type, const std::string &context,
                            const std::string &identity) override;

private:
    BotanPSKEngine *m_engine;
    std::shared_ptr<vwg::tee::TLSTEEAPI> m_tlsTeeApi;
};

/**
* \class PolicyPSK
*
* \brief This class manages the policy for BotanPSKEngine class.
*/
class PolicyPSK : public Botan::TLS::Policy {
public:
    std::vector<std::string> allowed_ciphers() const override;

    std::vector<std::string> allowed_key_exchange_methods() const override;

    std::vector<std::string> allowed_signature_hashes() const override;

    bool allow_tls10() const override;

    bool allow_tls11() const override;

    bool allow_tls12() const override;

};

/**
* \class CallbacksPSK
*
* \brief This class manages the callbacks for BotanPSKEngine class.
*/
class CallbacksPSK : public Botan::TLS::Callbacks {
public:
    CallbacksPSK(BotanPSKEngine *engine) : Botan::TLS::Callbacks(), m_engine(engine) {}
    virtual ~CallbacksPSK() = default;

    virtual void tls_emit_data(const uint8_t buf[], size_t length) override;

    virtual void tls_record_received(uint64_t rec, const uint8_t data[], size_t len) override;

    virtual void tls_alert(Botan::TLS::Alert alert) override;

    virtual bool tls_session_established(const Botan::TLS::Session &) override;

private:
    BotanPSKEngine *m_engine;
};

} // namespace impl
} // namespace tls
} // namespace vwg



#endif //SACCESSLIB_BOTANPSKENGINE_HPP
