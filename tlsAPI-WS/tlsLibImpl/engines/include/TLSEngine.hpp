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

#ifndef _TLS_ENGINE_HPP_
#define _TLS_ENGINE_HPP_

#include <functional>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <vwgtypes.h>
#include <cmath>

#include "IOStreamIf.hpp"
#include "ITLSEngine.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{

typedef uint32_t (server_psk_cb)(const char * localIdentity, const char * clientIdentity, unsigned char * key, uint32_t keyMaxLength);
typedef uint32_t (client_psk_cb)(const char * serverIdentity, const char * localIdentity, uint32_t idMaxLength, unsigned char * key, uint32_t keyMaxLength);

class TLSEngine;

/**
 * \class TLSEngineContext
 *
 * \brief A TLSEngineContext instance can be shared by multiple engines (for
 * example, all sessions of the same server), to reduce overhead
 * inside each of the engines.
 */
class TLSEngineContext : public std::enable_shared_from_this<TLSEngineContext> {
public:
    /**
     * \brief Constructor.
     *
     * \param isDTLS is the connection DTLS-based or not?
     * \param hint the server hint.
     */
    TLSEngineContext(bool isDTLS, const std::string & hint);

    /**
     * \brief Default destructor.
     */
    virtual ~TLSEngineContext() = default;

    /**
     * \brief Creates an engine for the given stream.
     * \param stream the underlying IOStream used by the engine to perform actual input/output.
     * \return the created engine.
     */
    virtual std::unique_ptr<TLSEngine> createEngine(std::shared_ptr<IOStream> stream) const = 0;

    /**
     * \brief Indicates whether this is a server or a client context.
     *
     * \return true if this is a server.
     */
    virtual bool IsServer() const = 0;

    const std::string & GetHint() const;

    virtual void SetRemoteHint(std::string hint) = 0;
    virtual std::string GetRemoteHint() const = 0;
    virtual const std::function<server_psk_cb> & GetServerCallback() const;
    virtual const std::function<client_psk_cb> & GetClientCallback() const;

protected:
    const bool m_isDTLS;
    const std::string m_hint;
    std::string m_remoteHint;
};

/**
 * \class TLSEngine
 *
 * \brief The TLSEngine is the base class for all possible SSL engines (WolfSSL, Botan, etc). The class provides
 * a basic API that all sub-classes must implement, to provide basic and common functionality, such
 * as: sending and receiving data, performing the SSL handshake, providing authentication parameters...
 */
class TLSEngine : public ITLSEngine
{
public:
    /**
     * \brief Constructor.
     *
     * \param[in] stream the underlying IOStream used by the engine to perform actual input/output.
     * \param[in] context the shared context for the engine.
     */
    TLSEngine(std::shared_ptr<IOStreamIf> stream, std::shared_ptr<const TLSEngineContext> context);

    /**
     * \brief Constructor.
     *
     * \param[in] stream the underlying IOStream used by the engine to perform actual input/output.
     */
    TLSEngine(std::shared_ptr<IOStreamIf> stream);

    /**
     * \brief Destructor. Calls TLSEngine::Close().
     */
    virtual ~TLSEngine();

    /**
     * \brief Performs the TLS handshake, according to the arguments provided in the constructor.
     */
    virtual TLSEngineError DoSSLHandshake() = 0;

    /**
     * \brief Sends a buffer to the other side.
     *
     * \param[in] buffer an unencrypted buffer of size 'length', which will be encrypted and sent through the
     * underlying (inheriting) TLS engine. This argument must be pre-allocated (either statically or
     * dynamically) by the callee.
     * \param[in] bufLength length of unencrypted buffer.
     * \param[out] actualLength - length of unencrypted buffer actually sent.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Send(const uint8_t * buffer, int32_t bufLength, int32_t & actualLength) = 0;

    /**
     * \brief Receives a buffer from the other side.
     *
     * \param[in] buffer - a buffer of size 'length' to receive the data. 'buffer' should be pre-allocated (either
     * \param[in] bufLength - length of unencrypted buffer to read.
     * \param[out] actualLength - length of unencrypted buffer actually read.
     * statically or dynamically) by the callee.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Receive(uint8_t * buffer, int32_t bufLength, int32_t & actualLength) = 0;

    /**
     * \brief Sets blocking/non-blocking mode for the stream. Blocking by default.
     *
     * \param[in] blocking the new mode.
     */
    virtual TLSEngineError SetBlocking(bool blocking);

    /**
     * \brief Sends a "close notify" alert to the peer.
     */
    virtual TLSEngineError Shutdown() = 0;

    /**
     * \brief Closes the underlying TLS connection and release any resources that are used. Also closes the
     * accompanying IOStream.
     */
    virtual void Close() override;

    /**
     * \brief Gets the accompanying IOStream.
     *
     * \return the accompanying IOStream.
     */
    const std::shared_ptr<IOStream> GetIOStream() const;
    virtual void SetStream(std::shared_ptr<IOStreamIf> stream);

    virtual const std::string GetRemoteHintName() const = 0;
    virtual const std::string GetHintName() const = 0;
#ifndef UNIT_TEST
protected:
#endif
    std::shared_ptr<IOStreamIf> m_stream;
    std::shared_ptr<const TLSEngineContext> m_context;
    std::string m_connectionLoggingName;
};

} // namespace impl
} // namespace tls
} // namespace vwg

#endif // _TLS_ENGINE_HPP_
