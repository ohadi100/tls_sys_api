/**
 * @file TLSServerSocketImpl.hpp
 * @brief Implementation of the ITLSServerSocket interface for TLS server sockets.
 *
 * This file provides the implementation details of TLSServerSocketImpl which encapsulates
 * the functionality necessary for establishing and managing a TLS-secured server socket connection.
 * It integrates functionalities like accepting connections, setting socket options, and retrieving connection details.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All information and materials contained herein, including intellectual and technical concepts,
 * are the property of CARIAD SE and may be covered by patents, patents in process, and are protected
 * by trade secret and/or copyright law.
 *
 * The reproduction, dissemination, modification, distribution, public performance, public display,
 * or any other use of this source code without the prior written consent of CARIAD SE is strictly prohibited
 * and in violation of applicable laws. The receipt or possession of this source code does not convey
 * or imply any rights to reproduce, disclose or distribute its contents, or to manufacture, use,
 * or sell anything that it may describe, in whole or in part.
 */

#ifndef _TLS_SERVER_SOCKET_IMPL_HPP_
#define _TLS_SERVER_SOCKET_IMPL_HPP_

#include <functional>
#include <memory>
#include "TLSSockets.h"
#include "TLSSessionEndpointImpl.hpp"
#include "TLSEngine.hpp"

#ifdef UNIT_TEST
#include "MockInternIOStream.hpp"
#else
#include "InternIOStream.hpp"
#endif

namespace vwg
{
namespace tls
{
namespace impl
{

/**
 * @class TLSServerSocketImpl
 * @brief Implementation of a TLS-secured server socket interface.
 *
 * This class provides a specific implementation for a TLS server socket, managing its lifecycle,
 * including connection acceptance, data transmission, and connection teardown, while ensuring secure
 * communication through TLS protocols.
 */
class TLSServerSocketImpl : public ITLSServerSocket
{
public:
    /**
     * @brief Constructor for TLSServerSocketImpl.
     *
     * @param stream A shared pointer to an InternIOStream object for underlying I/O operations.
     * @param hint A string representing a hint to identify the remote entity.
     * @param confidentiality The desired security level for the connection.
     * @param isFdManagedLocal Flag to indicate whether the file descriptor is managed locally.
     * @param droppable Flag indicating if the connection supports being dropped (optional, requires drop support enabled).
     * @param isConnectionFd Flag indicating if the file descriptor represents a connection (default is false).
     */
    TLSServerSocketImpl(std::shared_ptr<InternIOStream> stream,
                        const std::string &hint,
                        SecurityLevel confidentiality,
                        bool isFdManagedLocal = true,
                        bool droppable = false,
                        bool isConnectionFd = false);

    /**
     * @brief Destructor for TLSServerSocketImpl.
     */
    virtual ~TLSServerSocketImpl();

    /**
     * @brief Sets the socket timeout for both receive and send operations.
     *
     * @param timeout The timeout value in milliseconds.
     */
    virtual void setSoTimeout(Int32 timeout) override;

    /**
     * @brief Retrieves the socket file descriptor associated with this connection.
     *
     * @return The socket file descriptor.
     */
    virtual int getSocketFD() override;

    /**
     * @brief Accepts a new client connection and initializes a TLSSession.
     *
     * @return A TLSSessionEndpointResult containing a shared pointer to an ITLSSessionEndpoint if successful.
     */
    virtual TLSSessionEndpointResult accept() override;

    /**
     * @brief Checks if the socket is designated for connection purposes.
     *
     * @return True if this is a connection socket, false otherwise.
     */
    virtual Boolean isConnectionSocket() override;

    /**
     * @brief Closes the socket, effectively ending the connection.
     */
    virtual void close() override;

    /**
     * @brief Checks if the socket has been closed.
     *
     * @return True if the socket is closed, false otherwise.
     */
    virtual Boolean isClosed() override;

    /**
     * @brief Checks if the socket is currently open and able to send/receive data.
     *
     * @return True if the socket is open, false otherwise.
     */
    virtual Boolean isOpen() override;

    /**
     * @brief Retrieves the local port number to which the socket is bound.
     *
     * @return The local port number.
     */
    virtual UInt16 getLocalPort() override;

    /**
     * @brief Retrieves the local internet address of the server socket.
     *
     * @return A shared pointer to an SPIInetAddress representing the local internet address.
     */
    virtual SPIInetAddress getLocalInetAddress() override;

    /**
     * @brief Retrieves the ALPN mode used by the socket.
     *
     * @return The ALPN mode as an enum value.
     */
    virtual const AlpnMode& getUsedAlpnMode() const override;

    /**
     * @brief Retrieves the IANA protocol used by the socket.
     *
     * @return The protocol used, as defined by IANA standards.
     */
    virtual IANAProtocol getUsedProtocol() const override;

#ifndef UNIT_TEST
protected:
#endif
    /**
     * @brief Internal helper function to create and initialize a new TLS session.
     *
     * @param stream A shared pointer to an InternIOStream specific for the session.
     * @return A TLSSessionEndpointResult containing a shared pointer to an ITLSSessionEndpoint.
     */
    TLSSessionEndpointResult createSession(std::shared_ptr<InternIOStream> stream);

    std::shared_ptr<InternIOStream> m_stream; ///< Shared pointer to the internal I/O stream.
    std::string m_hint; ///< Hint to identify the remote server.
    SecurityLevel m_confidentiality; ///< Security level of the connection.
    bool m_isFdManagedLocal; ///< Indicates whether the file descriptor is managed locally.
#ifdef TLSAPI_WITH_DROP_SUPPORT
    bool m_droppable; ///< Indicates if the socket can be dropped.
#endif
    bool m_isConnectionFd; ///< Indicates if the file descriptor is used for a connection.
};

} // namespace impl
} // namespace tls
} // namespace vwg

#endif /* _TLS_SERVER_SOCKET_IMPL_HPP_ */
