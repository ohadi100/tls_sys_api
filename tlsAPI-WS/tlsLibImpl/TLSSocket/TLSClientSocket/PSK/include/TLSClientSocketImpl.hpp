/**
 * @file TLSClientSocketImpl.hpp
 * @brief Implementation of the ITLSClientSocket interface for TLS client sockets.
 *
 * This file provides the implementation details of TLSClientSocketImpl which encapsulates
 * the functionality necessary for establishing and managing a TLS-secured client socket connection.
 * It integrates functionalities like connecting, setting socket options, and retrieving connection details.
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

#ifndef _TLS_CLIENT_SOCKET_IMPL_HPP_
#define _TLS_CLIENT_SOCKET_IMPL_HPP_

#include <functional>
#include <memory>
#include "TLSSockets.h"
#include "TLSSessionEndpointImpl.hpp"
#include "TLSEngine.hpp"
#include "IOStreamIf.hpp"

using vwg::tls::SPIInetAddress;

namespace vwg
{
namespace tls
{
namespace impl
{

/**
 * @class TLSClientSocketImpl
 * @brief Implementation of a TLS-secured client socket interface.
 *
 * This class provides a specific implementation for a TLS client socket, managing its lifecycle,
 * including connection setup, data transmission, and connection teardown, while ensuring secure
 * communication through TLS protocols.
 */
class TLSClientSocketImpl : public ITLSClientSocket
{
public:
    /**
     * @brief Constructor for TLSClientSocketImpl.
     *
     * @param stream A shared pointer to an IOStreamIf object for underlying I/O operations.
     * @param hint A string representing a hint to identify the remote entity.
     * @param confidentiality The desired security level for the connection.
     * @param isFdManagedLocal Flag to indicate whether the file descriptor is managed locally.
     * @param droppable Flag indicating if the connection supports being dropped (optional, requires drop support enabled).
     */
    TLSClientSocketImpl(std::shared_ptr<IOStreamIf> stream, const std::string & hint, SecurityLevel confidentiality,
                        bool isFdManagedLocal = true, bool droppable = false);

    /**
     * @brief Destructor for TLSClientSocketImpl.
     */
    virtual ~TLSClientSocketImpl();

    /**
     * @brief Attempts to connect to a TLS server socket and establish a session.
     *
     * @return A TLSResult containing a shared pointer to an ITLSSessionEndpoint if successful.
     */
    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> connect() override;

    /**
     * @brief Sets the socket timeout for both receive and send operations.
     *
     * @param timeout The timeout value in milliseconds.
     */
    void setSoTimeout(Int32 timeout) override;

    /**
     * @brief Retrieves the socket file descriptor associated with this connection.
     *
     * @return The socket file descriptor.
     */
    int getSocketFD() override;

    /**
     * @brief Checks if the socket is designated for connection purposes.
     *
     * @return True if this is a connection socket, false otherwise.
     */
    Boolean isConnectionSocket() override;

    /**
     * @brief Closes the socket, effectively ending the connection.
     */
    void close() override;

    /**
     * @brief Checks if the socket has been closed.
     *
     * @return True if the socket is closed, false otherwise.
     */
    Boolean isClosed() override;

    /**
     * @brief Checks if the socket is currently open and able to send/receive data.
     *
     * @return True if the socket is open, false otherwise.
     */
    Boolean isOpen() override;

    /**
     * @brief Retrieves the local port number to which the socket is bound.
     *
     * @return The local port number.
     */
    UInt16 getLocalPort() override;

    /**
     * @brief Retrieves the local address to which the socket is bound.
     *
     * @return A shared pointer to an SPIInetAddress representing the local address.
     */
    SPIInetAddress getLocalInetAddress() override;

    /**
     * @brief Retrieves the ALPN mode used by the socket.
     *
     * @return The ALPN mode as an enum value.
     */
    const AlpnMode& getUsedAlpnMode() const override;

    /**
     * @brief Retrieves the IANA protocol used by the socket.
     *
     * @return The protocol used, as defined by IANA standards.
     */
    IANAProtocol getUsedProtocol() const override;

#ifndef UNIT_TEST
private:
#endif
    /**
     * @brief Internal helper function to create and initialize a new TLS session.
     *
     * @return A TLSResult containing a shared pointer to an ITLSSessionEndpoint.
     */
    TLSResult<std::shared_ptr<ITLSSessionEndpoint>> createSession();

    std::shared_ptr<IOStreamIf> m_stream; ///< Shared pointer to the I/O stream interface.
    std::shared_ptr<ITLSEngine> m_engine; ///< Shared pointer to the TLS engine.
    std::string m_hint; ///< Hint to identify the remote server.
    SecurityLevel m_confidentiality; ///< Security level of the connection.
    bool m_isFdManagedLocal; ///< Indicates whether the file descriptor is managed locally.
#ifdef TLSAPI_WITH_DROP_SUPPORT
    bool m_droppable; ///< Indicates if the socket can be dropped.
#endif
};

} // namespace impl
} // namespace tls
} // namespace vwg

#endif /* _TLS_CLIENT_SOCKET_IMPL_HPP_ */
