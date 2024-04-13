/**
 * @file TLSSession.h
 * @brief Defines the interfaces for managing TLS (Transport Layer Security) sessions.
 *
 * This file contains the interfaces and types necessary for managing the lifecycle of
 * TLS sessions between a client and server, including sending, receiving data, and
 * managing session status.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All information and materials herein, including intellectual and technical concepts,
 * are proprietary to CARIAD SE, may be covered by patents, and protected by trade secret
 * and copyright law.
 *
 * Unauthorized reproduction, dissemination, modification, distribution, performance,
 * display, or other use of this source code without prior written consent from CARIAD SE
 * is strictly prohibited and may violate applicable laws.
 *
 * Possession or receipt of this source code does not convey any rights to reproduce,
 * disclose, or distribute its contents, or to manufacture, use, or sell anything it may
 * describe, in whole or in part.
 */

#ifndef SRC_TLSSESSION_H_
#define SRC_TLSSESSION_H_

#include <functional>
#include <string>
#include <memory>
#include "TLSApiTypes.h"
#include "vwgtypes.h"
#include "TLSReturnCodes.h"

namespace vwg {
namespace tls {

/**
 * @enum TLSDropStatus
 * @brief Enumerates the possible states for dropping a TLS session.
 */
enum TLSDropStatus : UInt32 {
    TLSDROP_SECURED,       ///< Connection is secured.
    TLSDROP_DROPPED,       ///< TLS has been dropped, connection unsecured.
    TLSDROP_REQUESTED,     ///< TLS drop has been requested.
    TLSDROP_SEND_LOCKED,   ///< Sending is locked.
    TLSDROP_PERFORMED      ///< TLS drop has been performed.
};

/**
 * @enum TLSSessionStatus
 * @brief Enumerates the states of a TLS session.
 */
enum TLSSessionStatus : UInt32 {
    TLSSESSION_SECURED,    ///< Session is secured and active.
    TLSSESSION_UNSECURED,  ///< Session is unsecured, TLS can be dropped.
    TLSSESSION_BROKEN,     ///< Session is broken due to errors.
    TLSSESSION_CLOSED      ///< Session is closed.
};

/**
 * @brief Represents EOF value for closed connections.
 */
constexpr int TLS_EOF = 0;

class ITLSSessionEndpoint;

/**
 * @typedef SPITLSSessionEndpoint
 * @brief Shared pointer to an ITLSSessionEndpoint interface.
 */
using SPITLSSessionEndpoint = std::shared_ptr<ITLSSessionEndpoint>;

/**
 * @typedef TLSSessionStatusListener
 * @brief Function type for listening to session status changes.
 * @param endpoint The session endpoint.
 * @param status The new session status.
 */
using TLSSessionStatusListener = std::function<void(SPITLSSessionEndpoint endpoint, TLSSessionStatus status)>;

/**
 * @typedef TLSDropStatusListener
 * @brief Function type for listening to drop status changes.
 * @param endpoint The session endpoint.
 * @param status The new drop status.
 */
using TLSDropStatusListener = std::function<void(SPITLSSessionEndpoint endpoint, TLSDropStatus status)>;

/**
 * @class ITLSSessionEndpoint
 * @brief Interface for managing TLS session endpoints.
 *
 * This interface is responsible for managing communication sessions that are secured by TLS.
 * It provides methods to send and receive data securely, as well as to manage the state and configuration
 * of the TLS session.
 */
class ITLSSessionEndpoint : public ITLSSocketBase {
public:
    ITLSSessionEndpoint() = default;
    virtual ~ITLSSessionEndpoint() = default;

    /**
     * @brief Sends data over the TLS session.
     * @param b Pointer to the data buffer.
     * @param len Number of bytes to send.
     * @return Number of bytes sent, 0 if the connection is closed, or a negative error code.
     */
    virtual Int32 send(const Byte b[], const Int32 len) = 0;

    /**
     * @brief Sends data over the TLS session from a specified offset.
     * @param b Pointer to the data buffer.
     * @param offset Offset in the buffer from which to start sending data.
     * @param len Number of bytes to send from the offset.
     * @return Number of bytes sent, 0 if the connection is closed, or a negative error code.
     */
    virtual Int32 send(const Byte b[], const UInt32 offset, const Int32 len) = 0;

    /**
     * @brief Forces any buffered data to be sent over the TLS session.
     * @return 0 if successful, or a negative error code if an error occurred.
     */
    virtual Int32 flush() = 0;

    /**
     * @brief Checks how many bytes are available for reading.
     * @return Number of bytes available to be read.
     */
    virtual Int32 available() = 0;

    /**
     * @brief Receives data from the TLS session.
     * @param b Buffer to store the received data.
     * @param len Maximum number of bytes to read.
     * @return Number of bytes received, 0 if the connection is closed, or a negative error code.
     */
    virtual Int32 receive(Byte b[], const Int32 len) = 0;

    /**
     * @brief Receives data from the TLS session starting at a specific offset in the buffer.
     * @param b Buffer to store the received data.
     * @param offset Offset in the buffer at which to start storing data.
     * @param len Maximum number of bytes to read.
     * @return Number of bytes received, 0 if the connection is closed, or a negative error code.
     */
    virtual Int32 receive(Byte b[], const UInt32 offset, const Int32 len) = 0;

    /**
     * @brief Sets the blocking mode of the session socket.
     * @param blocking True to set the socket to blocking mode, false for non-blocking.
     * @return Status code representing success or the specific error that occurred.
     */
    virtual TLSReturnCodes setBlocking(bool blocking) = 0;

    /**
     * @brief Retrieves the underlying socket file descriptor.
     * @return Network socket file descriptor.
     */
    virtual int getSocketFD() = 0;

    /**
     * @brief Sends a shutdown notification to the peer and closes the session.
     * @return Status code representing success or the specific error that occurred.
     */
    virtual TLSReturnCodes shutdown() = 0;

    /**
     * @brief Retrieves the local domain name associated with the session endpoint.
     * @return Local domain name as a string.
     */
    virtual std::string getLocalDomainName() = 0;

    /**
     * @brief Retrieves the remote domain name associated with the session endpoint.
     * @return Remote domain name as a string.
     */
    virtual std::string getRemoteDomainName() = 0;

    /**
     * @brief Retrieves the port number of the remote endpoint.
     * @return Port number.
     */
    virtual UInt16 getRemotePort() = 0;

    /**
     * @brief Retrieves the internet address of the remote session endpoint.
     * @return Shared pointer to an InetAddress object representing the remote address.
     */
    virtual SPIInetAddress getRemoteInetAddress() = 0;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * @brief Checks if the session endpoint supports TLS dropping.
     * @return True if dropping is supported, false otherwise.
     */
    virtual Boolean isDroppable() = 0;

    /**
     * @brief Initiates the process to drop TLS protection for the session.
     * @return Status code representing success or the specific error that occurred.
     */
    virtual TLSReturnCodes dropTLS() = 0;
#endif

    /**
     * @brief Retrieves the current drop status of the session.
     * @return Current drop status as a TLSDropStatus enum value.
     */
    virtual TLSDropStatus getDropState() = 0;

    /**
     * @brief Sets a listener for session status changes.
     * @param listener Function to be called when the session status changes.
     */
    virtual void setSessionStatusListener(TLSSessionStatusListener listener) = 0;

    /**
     * @brief Sets a listener for TLS drop status changes.
     * @param listener Function to be called when the drop status changes.
     */
    virtual void setDropStatusListener(TLSDropStatusListener listener) = 0;
};

using SPTLSSessionEndpoint = std::shared_ptr<ITLSSessionEndpoint>;
using TLSSessionEndpointResult = TLSResult<SPTLSSessionEndpoint>;


} // namespace tls
} // namespace vwg

#endif // SRC_TLSSESSION_H_
