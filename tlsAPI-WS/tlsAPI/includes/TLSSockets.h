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

#ifndef SRC_TLSSOCKETS_H_
#define SRC_TLSSOCKETS_H_

#include <memory>

#include "vwgtypes.h"
#include "TLSApiTypes.h"
#include "TLSResult.h"
#include "TLSSession.h"

using namespace vwg::types;

namespace vwg
{
namespace tls
{
/**
 * \brief Server TLS-PSK aware server socket interface.
 * This interface must be implemented by the supplier.
 *
 * For TCP based communication make an accept call to retrieve a connection to the client.
 * The client connection is represented by a TLSSession where one can read and write the data.
 * Within the accept call all needed operations are performed.
 * This includes:
 *  - accept the network connection
 *  - make the TLS or TLS-PSK handshake (see https://tools.ietf.org/html/rfc4279)
 *  - derive the pre shared key from the SSOA domain name
 *  - derive the session key from the pre shared key stored within the trust zone.
 */
class ITLSServerSocket : public ITLSSocketBase
{
public:
    ITLSServerSocket()          = default;
    virtual ~ITLSServerSocket() = default;

public:
    /**
     * \brief This is a blocking call for the server implementation to wait until the client will get a connection.
     * The server may fork several thread to handle each client in an individual thread.
     * This accept covers all needed operations like
     *  - accept the network connection
     *  - make the TLS or TLS-PSK handshake (see https://tools.ietf.org/html/rfc4279)
     *  - derive the pre shared key from the SSOA domain name
     *  - derive the session key from the pre shared key stored within the trust zone.
     *
     * \return a ITLSSessionEndpoint instance when operation was successful, otherwise an error code is delivered.
     */
    virtual TLSSessionEndpointResult accept() = 0;

    /**
     * \brief Sets the socket timeout.
     *
     * \param[in] timeout the new socket timeout value in milliseconds.
     */
    virtual void setSoTimeout(Int32 timeout) = 0;

    /**
     * \brief Gets the network socket file descriptor.
     *
     * \return the network socket file descriptor.
     */
    virtual int getSocketFD() = 0;
};


/**
 * \brief Server TLS-PSK aware client socket interface.
 * This interface must be implemented by the supplier.
 *
 * For TCP based communication make a connect call to retrieve a connection to the server.
 * The server connection is represented by a TLSSession where one can read and write the data.
 * Within the connect call all needed operations are performed.
 * This includes:
 *  - make the TLS or TLS-PSK handshake (see https://tools.ietf.org/html/rfc4279).
 *  - derive the pre shared key from the SSOA domain name.
 *  - derive the session key from the pre shared key stored within the trust zone.
 *
 */
class ITLSClientSocket : public ITLSSocketBase
{
public:
    ITLSClientSocket() = default;

    virtual ~ITLSClientSocket() = default;


public:
    /**
     * \brief a client shall call this method in to get connected to the server.
     * This will do all underling operations like
     *  - make the TLS or TLS-PSK handshake (see https://tools.ietf.org/html/rfc4279)
     *  - derive the pre shared key  from the SSOA domain name
     *  - derive the session key from the pre shared key stored within the trust zone.
     *
     *  \return an ITLSSessionEndpoint instance when operation was successful, otherwise an error code is delivered.
     */
    virtual TLSResult<std::shared_ptr<ITLSSessionEndpoint>> connect() = 0;

    /**
     * \brief Changes the default socket timeout, SO_RCVTIMEO and SO_SNDTIMEO options,
     * according to https://linux.die.net/man/3/setsockopt.
     *
     * \param[in] timeout The new socket timeout value in milliseconds.
     */
    virtual void setSoTimeout(Int32 timeout) = 0;

    /**
     * \brief Gets the network socket file descriptor.
     *
     * \return the network socket file descriptor.
     */
    virtual int getSocketFD() = 0;
};


using SPTLSClientSocket     = std::shared_ptr<ITLSClientSocket>;
using SPTLSServerSocket     = std::shared_ptr<ITLSServerSocket>;
using TLSClientSocketResult = TLSResult<SPTLSClientSocket>;
using TLSServerSocketResult = TLSResult<SPTLSServerSocket>;


} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_TLSSOCKETS_H_ */
