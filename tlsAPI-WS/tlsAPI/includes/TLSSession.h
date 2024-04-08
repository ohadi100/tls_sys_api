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

#ifndef SRC_TLSSESSION_H_
#define SRC_TLSSESSION_H_


#include <functional>
#include <string>
#include <memory>

#include "TLSApiTypes.h"
#include "vwgtypes.h"
#include "TLSReturnCodes.h"
#include "vwgtypes.h"

using namespace vwg::types;


namespace vwg
{
namespace tls
{
enum TLSDropStatus : UInt32 {
    TLSDROP_SECURED,
    TLSDROP_DROPPED,
    TLSDROP_REQUESTED,
    TLSDROP_SEND_LOCKED,
    TLSDROP_PERFORMED
};

/**
 * \brief Defines the possible status values of the session.
 */
enum TLSSessionStatus : UInt32 {
    /**
     * \brief TLSSESSION_SECURED shall be the default case.
     * This indicates that the connection is active an security is active.
     */
    TLSSESSION_SECURED,

    /**
     * \brief TLSSESSION_UNSECURED is only be supported in case the TLS can be dropped.
     * This indicates that the connection is active but security was dropped.
     */
    TLSSESSION_UNSECURED,

    /**
     * \brief TLSSESSION_BROKEN indicates that a connection is not working anymore, due to errors.
     */
    TLSSESSION_BROKEN,

    /**
     * \brief TLSSESSION_CLOSED indicates that a connection is closed.
     */
    TLSSESSION_CLOSED

};

/**
 * \brief Defines the EOF value 0 in case that the connection is closed.
 * This can happen if a closed on a socket is made and there are pending receive and send.
 * Please be aware of that EOF is defined as -1
 */
const int TLS_EOF = 0;


class ITLSSessionEndpoint;

using SPITLSSessionEndpoint = std::shared_ptr<ITLSSessionEndpoint>;


/**
 * \typedef This defines a C-style listener function to listen to the status changes of the session.
 */
using TLSSessionStatusListener = std::function<void(SPITLSSessionEndpoint endpoint, const TLSSessionStatus status)>;


/**
 * \typedef This defines a listener function type to listen to the status changes.
 */
using TLSDropStatusListener = std::function<void(SPITLSSessionEndpoint endpoint, const TLSDropStatus status)>;

/**
 * \brief Represents a communication session between a service provider and a service consumer.
 * This interface must be implemented by the supplier.
 *
 *  Herewith one user can make send and receive data between the service provider and a service consumer
 *  The calls are basically blocking and will return until the operations is performed.
 *  This includes:
 *  - network operations.
 *  - Encrypting or decrypting data.
 *
 */
class ITLSSessionEndpoint : public ITLSSocketBase
{
public:
    ITLSSessionEndpoint() = default;

    virtual ~ITLSSessionEndpoint() = default;


public:
    /* ------------ write functions--------------------- */

    /**
     * \brief Sends a number of bytes from b[0] to b[len-1].
     *
     * \note The method blocks, unless in non-blocking mode.
     * When an operation is repeated in non-blocking mode, it must be repeated with the same arguments.
     *
     * \param[in] b data buffer for sending data from it.
     * \param[in] len buffer's length, in bytes
     *
     * \return the number of send bytes, or a negative value will indicate an error. The value 0 will
     * indicated that the stream is closed (see TLS_EOF) Use getPendingErrors to retrieve the pending error.
     */
    virtual Int32 send(const Byte b[], const Int32 len) = 0;

    /**
     * \brief send a number of bytes from b[0+offset] to b[len-1] starting at b at given offset.
     *
     * \note The method blocks, unless in non-blocking mode.
     * When an operation is repeated in non-blocking mode, it must be repeated with the same arguments.
     *
     * \param[in] b data buffer for sending data from it.
     * \param[in] offset offset from the beginning of the buffer to send data from it.
     * \param[in] len buffer's length, in bytes.
     *
     * \return the number send bytes, or a negative value will indicate an error. The value 0 will
     * indicated that the stream is closed (see TLS_EOF) Use getPendingErrors to retrieve the pending error.
     */
    virtual Int32 send(const Byte b[], const UInt32 offset, const Int32 len) = 0;

    /**
     * \brief Forces to send the bytes.
     * Depending on the underlying socket implementation, it can happen that bytes are still within the send buffer.
     *
     * \return 0 if no error had occurred, or a negative value will indicate an error. The value 0 will indicated that
     * the stream is closed (see TLS_EOF) Use getPendingErrors to retrieve the pending error.
     */
    virtual Int32 flush() = 0;

    /* ------------ read functions--------------------- */

    /**
     * \brief Checks if bytes are available.
     * The method blocks until data are available.
     *
     * \return the number of available bytes.
     */
    virtual Int32 available() = 0;

    /**
     * \brief Receive up to len bytes from stream into the buffer starting at b.
     *
     * \note The method blocks until data are available, unless in non-blocking mode.
     * In case of error use getPendingErrors to retrieve the pending error.
     *
     * \param[in] b buffer to be set with received date.
     * \param[in] len buffer's length, in bytes.
     *
     * \return the number of received bytes, or a negative value will indicate an error. The value 0 will indicated
     * that the stream is closed (see TLS_EOF).
     */
    virtual Int32 receive(Byte b[], const Int32 len) = 0;

    /**
     * \brief Receive up to len bytes from stream into the buffer starting at b at given offset.
     *
     * \note The method blocks until data are available, unless in non-blocking mode.
     *
     * \param[in] b buffer to be set with received date.
     * \param[in] offset offset from beginning of the buffer to set data from it.
     * \param[in] len buffer's length, in bytes.
     *
     * \return the number of number of received, or a negative value will indicate an error. The value 0 will indicated
     * that the stream is closed (see TLS_EOF) Use getPendingErrors to retrieve the pending error.
     */
    virtual Int32 receive(Byte b[], const UInt32 offset, const Int32 len) = 0;

    /**
     * \brief Sets blocking/non-blocking mode for the session. Blocking by default.
     *
     * \return success indication.
     */
    virtual TLSReturnCodes setBlocking(bool blocking) = 0;

    /**
     * \brief Gets the network socket file descriptor.
     *
     * \return the network socket file descriptor.
     */
    virtual int getSocketFD() = 0;

    /**
     * \brief Sends a "close notify" alert to the peer.
     * The method blocks, unless in non-blocking mode.
     *
     * \return success indication.
     */
    virtual TLSReturnCodes shutdown() = 0;

    /**
     * \brief Gets the sSOA domain name of the session endpoint.
     *
     * \return the sSOA domain name of the session endpoint.
     */
    virtual std::string getLocalDomainName() = 0;

    /**
     * \brief Gets the sSOA domain name of the remote session endpoint.
     *
     * \return the sSOA domain name of the remote session endpoint.
     */
    virtual std::string getRemoteDomainName() = 0;

    /**
     * \brief Gets the port of the remote session endpoint .
     *
     * \return Gets the port of the remote session endpoint .
     */
    virtual UInt16 getRemotePort() = 0;

    /**
     * \brief Gets the inet address of the remote session endpoint .
     *
     * \return Gets the inet address of the remote session endpoint .
     */
    virtual SPIInetAddress getRemoteInetAddress() = 0;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * \brief Herewith it it is possible to ask if the session end-point will support TLS dropping or not.
     * It can be that the server will not support dropping, which is not know statically by the client,
     * this is only the convenience method to check if the socket was created droppable or not.
     *
     * \return true when created droppable.
     */
    virtual Boolean isDroppable() = 0;

    /**
     * \brief this is a special method to stop sending and receiving encrypted data over the same connection.
     * Basically there are two versions of the library, one which will support the drop feature and one without drop
     * feature. This is important that the drop feature is not provided for the normal use case, where it not permitted
     * to use drop TLS feature.
     *
     * \return success indication.
     */
    virtual TLSReturnCodes dropTLS() = 0;
#endif

    /**
     * \brief Gets the current TLS drop status.
     *
     * \return the current TLS drop status of the connection.
     */
    virtual TLSDropStatus getDropState() = 0;


    /**
     * \brief Sets the listener function (C++-style) for status changes of the session.
     * This overwrites the listener when already set.
     *
     * \param[in] listener listener function to be set.
     */
    virtual void setSessionStatusListener(TLSSessionStatusListener listener) = 0;

    /**
     * \brief Sets the  listener function (C++ -style) for drop changes of the session.
     * this overwrites the listener when already set.
     */
    virtual void setDropStatusListener(TLSDropStatusListener listener) = 0;
};

using SPTLSSessionEndpoint     = std::shared_ptr<ITLSSessionEndpoint>;
using TLSSessionEndpointResult = TLSResult<SPTLSSessionEndpoint>;

} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_TLSSESSION_H_ */
