/**
 * @file TLSEngine.hpp
 * @brief Defines the TLSEngine and TLSEngineContext classes for managing TLS connections.
 *
 * This header file provides the declarations of the TLSEngine and TLSEngineContext classes.
 * These classes are designed to abstract the handling of TLS connections, allowing for
 * the use of different underlying TLS libraries. The TLSEngineContext class provides shared
 * configuration and state that can be used by multiple TLSEngine instances.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 *
 * All information and materials contained herein, including the
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

namespace vwg {
namespace tls {
namespace impl {

/**
 * @typedef server_psk_cb
 * @brief Callback type for server pre-shared key retrieval.
 * 
 * @param localIdentity The local identity.
 * @param clientIdentity The client identity.
 * @param key Buffer to store the key.
 * @param keyMaxLength Maximum length of the key buffer.
 * @return The length of the key.
 */
typedef uint32_t (server_psk_cb)(const char * localIdentity, const char * clientIdentity, unsigned char * key, uint32_t keyMaxLength);

/**
 * @typedef client_psk_cb
 * @brief Callback type for client pre-shared key retrieval.
 * 
 * @param serverIdentity The server identity.
 * @param localIdentity The local identity.
 * @param idMaxLength Maximum length of the identity buffer.
 * @param key Buffer to store the key.
 * @param keyMaxLength Maximum length of the key buffer.
 * @return The length of the key.
 */
typedef uint32_t (client_psk_cb)(const char * serverIdentity, const char * localIdentity, uint32_t idMaxLength, unsigned char * key, uint32_t keyMaxLength);

class TLSEngine;

/**
 * @class TLSEngineContext
 * @brief Manages shared TLS engine context.
 * 
 * A TLSEngineContext instance can be shared by multiple engines (for example, all sessions of the same server), 
 * to reduce overhead inside each of the engines.
 */
class TLSEngineContext : public std::enable_shared_from_this<TLSEngineContext> {
public:
    /**
     * @brief Constructor for TLSEngineContext.
     * 
     * @param isDTLS Indicates whether the connection is DTLS-based or not.
     * @param hint The server hint.
     */
    TLSEngineContext(bool isDTLS, const std::string& hint);

    /**
     * @brief Default destructor.
     */
    virtual ~TLSEngineContext() = default;

    /**
     * @brief Creates a TLSEngine for the given stream.
     * 
     * @param stream The underlying IOStream used by the engine for input/output.
     * @return A unique_ptr to the created TLSEngine.
     */
    virtual std::unique_ptr<TLSEngine> createEngine(std::shared_ptr<IOStream> stream) const = 0;

    /**
     * @brief Checks if this is a server or client context.
     * 
     * @return True if this is a server context.
     */
    virtual bool IsServer() const = 0;

    /**
     * @brief Retrieves the hint associated with this context.
     * 
     * @return The hint as a string.
     */
    const std::string& GetHint() const;

    virtual void SetRemoteHint(std::string hint) = 0;
    virtual std::string GetRemoteHint() const = 0;
    virtual const std::function<server_psk_cb>& GetServerCallback() const;
    virtual const std::function<client_psk_cb>& GetClientCallback() const;

protected:
    const bool m_isDTLS;
    const std::string m_hint;
    std::string m_remoteHint;
};

/**
 * @class TLSEngine
 * @brief Base class for SSL/TLS engines.
 * 
 * The TLSEngine class is the base for all SSL/TLS engines (e.g., WolfSSL, Botan, etc.).
 * It defines a basic API for common functionality such as sending and receiving data,
 * performing SSL handshakes, and providing authentication parameters.
 */
class TLSEngine : public ITLSEngine {
public:
    /**
     * @brief Constructs a TLSEngine with a stream and context.
     * 
     * @param stream The underlying IOStream for input/output.
     * @param context The shared TLSEngineContext.
     */
    TLSEngine(std::shared_ptr<IOStreamIf> stream, std::shared_ptr<const TLSEngineContext> context);

    /**
     * @brief Constructs a TLSEngine with only a stream.
     * 
     * @param stream The underlying IOStream for input/output.
     */
    TLSEngine(std::shared_ptr<IOStreamIf> stream);

    /**
     * @brief Destructor that also calls TLSEngine::Close().
     */
    virtual ~TLSEngine();

    /**
     * @brief Performs the TLS handshake.
     */
    virtual TLSEngineError DoSSLHandshake() = 0;

    /**
     * @brief Sends data over the TLS connection.
     * 
     * @param buffer Buffer containing data to send.
     * @param bufLength Length of the buffer.
     * @param actualLength Actual length of data sent.
     * @return A TLSEngineError indicating success or the type of error.
     */
    virtual TLSEngineError Send(const uint8_t* buffer, int32_t bufLength, int32_t& actualLength) = 0;

    /**
     * @brief Receives data from the TLS connection.
     * 
     * @param buffer Buffer to store received data.
     * @param bufLength Length of the buffer.
     * @param actualLength Actual length of data received.
     * @return A TLSEngineError indicating success or the type of error.
     */
    virtual TLSEngineError Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) = 0;

    /**
     * @brief Sets the blocking mode of the stream.
     * 
     * @param blocking True for blocking mode, false for non-blocking.
     */
    virtual TLSEngineError SetBlocking(bool blocking);

    /**
     * @brief Sends a "close notify" alert to the peer.
     */
    virtual TLSEngineError Shutdown() = 0;

    /**
     * @brief Closes the TLS connection and releases resources.
     */
    virtual void Close() override;

    /**
     * @brief Gets the accompanying IOStream.
     * 
     * @return The IOStream used by this TLSEngine.
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
