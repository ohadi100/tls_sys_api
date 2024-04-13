/**
 * @file TLSSockets.h
 * @brief Interface definitions for TLS-aware sockets.
 *
 * This file provides the interface definitions for TLS server and client sockets.
 * These interfaces are used to establish and manage secure TLS or TLS-PSK connections over the network.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All information and materials contained herein, including intellectual and technical concepts,
 * are the property of CARIAD SE and may be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * Reproduction, dissemination, modification, distribution, public performance, public display,
 * or any other use of this source code and/or any other information and/or material contained herein
 * without the prior written consent of CARIAD SE is strictly prohibited and in violation of applicable laws.
 */

#ifndef SRC_TLSSOCKETS_H_
#define SRC_TLSSOCKETS_H_

#include <memory>
#include "vwgtypes.h"
#include "TLSApiTypes.h"
#include "TLSResult.h"
#include "TLSSession.h"

using namespace vwg::types;

namespace vwg {
namespace tls {

/**
 * @class ITLSServerSocket
 * @brief Interface for TLS-PSK aware server sockets.
 *
 * This interface defines the necessary methods for managing server-side TLS sockets, including
 * accepting incoming connections and performing necessary TLS handshakes.
 */
class ITLSServerSocket : public ITLSSocketBase {
public:
    ITLSServerSocket() = default;
    virtual ~ITLSServerSocket() = default;

    /**
     * @brief Accepts an incoming connection and performs a TLS handshake.
     *
     * This is a blocking call that waits for a client to establish a connection.
     * It performs the necessary network operations and TLS or TLS-PSK handshake as defined in RFC 4279.
     *
     * @return A TLSSessionEndpointResult containing either a successful session endpoint or an error code.
     */
    virtual TLSSessionEndpointResult accept() = 0;

    /**
     * @brief Sets the socket timeout for operations on this socket.
     *
     * @param timeout The timeout value in milliseconds.
     */
    virtual void setSoTimeout(Int32 timeout) = 0;

    /**
     * @brief Retrieves the network socket file descriptor.
     *
     * @return The socket file descriptor.
     */
    virtual int getSocketFD() = 0;
};

/**
 * @class ITLSClientSocket
 * @brief Interface for TLS-PSK aware client sockets.
 *
 * This interface defines the necessary methods for managing client-side TLS sockets, including
 * connecting to a server and performing necessary TLS handshakes.
 */
class ITLSClientSocket : public ITLSSocketBase {
public:
    ITLSClientSocket() = default;
    virtual ~ITLSClientSocket() = default;

    /**
     * @brief Connects to a server and performs a TLS handshake.
     *
     * This method handles the underlying operations required to establish a secure connection,
     * including performing a TLS or TLS-PSK handshake as per RFC 4279.
     *
     * @return A TLSResult containing either a successful session endpoint or an error code.
     */
    virtual TLSResult<std::shared_ptr<ITLSSessionEndpoint>> connect() = 0;

    /**
     * @brief Sets the socket timeout for receiving and sending operations.
     *
     * @param timeout The timeout value in milliseconds.
     */
    virtual void setSoTimeout(Int32 timeout) = 0;

    /**
     * @brief Retrieves the network socket file descriptor.
     *
     * @return The socket file descriptor.
     */
    virtual int getSocketFD() = 0;
};

using SPTLSClientSocket = std::shared_ptr<ITLSClientSocket>;
using SPTLSServerSocket = std::shared_ptr<ITLSServerSocket>;
using TLSClientSocketResult = TLSResult<SPTLSClientSocket>;
using TLSServerSocketResult = TLSResult<SPTLSServerSocket>;

} // namespace tls
} // namespace vwg

#endif /* SRC_TLSSOCKETS_H_ */
