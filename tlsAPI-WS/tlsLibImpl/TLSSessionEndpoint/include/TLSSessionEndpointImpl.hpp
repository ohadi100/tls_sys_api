/**
 * @file TLSSessionEndpointImpl.hpp
 * @brief Implementation of the TLS session endpoint interface.
 *
 * This file provides the implementation details for a TLS session endpoint, which handles
 * the communication between a client and a server through a secure channel. It includes
 * functionality to send and receive data, manage session state, and support optional
 * features such as TLS dropping.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All the information and materials contained herein, including the
 * intellectual and technical concepts, are the property of CARIAD SE and may
 * be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * Reproduction, dissemination, modification, distribution, public
 * performance, public display, or any other use of this source code and/or
 * any other information and/or material contained herein without the prior
 * written consent of CARIAD SE is strictly prohibited and in violation of
 * applicable laws.
 *
 * Possession of this source code and/or related information does not convey
 * or imply any rights to reproduce, disclose or distribute its contents,
 * or to manufacture, use, or sell anything that it may describe, in whole
 * or in part.
 */

#ifndef _TLS_SESSION_ENDPOINT_IMPL_HPP_
#define _TLS_SESSION_ENDPOINT_IMPL_HPP_

#include <cstdint>
#include <memory>

#include "InetAddress.h"
#include "TLSSession.h"
#include "IOStreamIf.hpp"
#include "ITLSEngine.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{

/**
 * @class TLSSessionEndpointImpl
 * @brief Implementation of the ITLSSessionEndpoint interface for handling TLS sessions.
 *
 * This class provides the functionality to manage a TLS session, including sending and receiving data,
 * managing session states, and handling TLS-specific operations like session closure and TLS dropping (if supported).
 */
class TLSSessionEndpointImpl : public ITLSSessionEndpoint
{
public:
    /**
     * @brief Constructs a TLSSessionEndpointImpl object with a given IO stream and TLS engine.
     * @param stream The IO stream interface used for data transmission.
     * @param engine The TLS engine responsible for cryptographic operations.
     * @param isFdManagedLocal Flag indicating whether the file descriptor is managed locally.
     * @param droppable Flag indicating whether TLS dropping is supported.
     */
    TLSSessionEndpointImpl(std::shared_ptr<IOStreamIf> stream, std::shared_ptr<ITLSEngine> engine, bool isFdManagedLocal, bool droppable=false);

    /**
     * @brief Destructor.
     */
    virtual ~TLSSessionEndpointImpl();

    ///@{
    /** @name Write Functions */

    /**
     * @brief Sends data over the session.
     * @param b Pointer to the data buffer to send.
     * @param len Length of the data in bytes.
     * @return Number of bytes sent, or an error code.
     */
    virtual	Int32 send(const Byte b[], const Int32 len);

    /**
     * @brief Sends data from a specific offset over the session.
     * @param b Pointer to the data buffer to send.
     * @param offset Offset from the start of the buffer.
     * @param len Length of the data in bytes.
     * @return Number of bytes sent, or an error code.
     */
    virtual Int32 send(const Byte b[], const UInt32 offset, const Int32 len);

    /**
     * @brief Flushes the send buffer, ensuring all data is sent.
     * @return Success or error code.
     */
    virtual Int32 flush();
    ///@}

    ///@{
    /** @name Read Functions */

    /**
     * @brief Checks the number of bytes available for reading.
     * @return Number of bytes available.
     */
    virtual Int32 available();

    /**
     * @brief Receives data from the session.
     * @param b Buffer to store received data.
     * @param len Maximum length of data to receive.
     * @return Number of bytes received, or an error code.
     */
    virtual Int32 receive(Byte b[], const Int32 len);

    /**
     * @brief Receives data from the session starting at a specific offset in the buffer.
     * @param b Buffer to store received data.
     * @param offset Offset at which to start storing data.
     * @param len Maximum length of data to receive.
     * @return Number of bytes received, or an error code.
     */
    virtual Int32 receive(Byte b[], const UInt32 offset, const Int32 len);

    /**
     * @brief Sets whether the session operates in blocking or non-blocking mode.
     * @param blocking True for blocking mode, false for non-blocking.
     * @return Success or error code.
     */
    virtual TLSReturnCodes setBlocking(bool blocking) override;

    /**
     * @brief Gets the underlying socket file descriptor.
     * @return File descriptor.
     */
    virtual int getSocketFD() override;

    /**
     * @brief Initiates a shutdown of the TLS session.
     * @return Success or error code.
     */
    virtual TLSReturnCodes shutdown() override;
    ///@}

    ///@{
    /** @name Additional Functions from ITLSSocketBase */

    /**
     * @brief Checks if the session is closed.
     * @return True if closed, false otherwise.
     */
    virtual Boolean isClosed() override;

    /**
     * @brief Checks if the session is open.
     * @return True if open, false otherwise.
     */
    virtual Boolean isOpen()  override;
    ///@}

    ///@{
    /** @name Functions Regarding TLS Dropping (Conditional Compilation) */

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * @brief Checks if TLS dropping is supported.
     * @return True if droppable, false otherwise.
     */
    virtual Boolean isDroppable() override;

    /**
     * @brief Initiates the process of dropping TLS.
     * @return Success or error code.
     */
    virtual TLSReturnCodes dropTLS() override;
#endif
    /**
     * @brief Gets the current state of TLS dropping.
     * @return TLS drop status.
     */
    virtual TLSDropStatus getDropState();

    /**
     * @brief Sets the session status listener function.
     * @param listener Listener function to set.
     */
    virtual void setSessionStatusListener(TLSSessionStatusListener listener);

    /**
     * @brief Sets the drop status listener function.
     * @param listener Listener function to set.
     */
    virtual void setDropStatusListener(TLSDropStatusListener listener);
    ///@}

    /**
     * @brief Closes the TLS session.
     */
    virtual void close() override;

    /**
     * @brief Retrieves the local port number of the session.
     * @return Local port number.
     */
    virtual UInt16 getLocalPort() override;

    /**
     * @brief Retrieves the local IP address of the session.
     * @return Local InetAddress.
     */
    virtual SPIInetAddress getLocalInetAddress() override;

    /**
     * @brief Retrieves the domain name of the remote end of the session.
     * @return Domain name string.
     */
    virtual std::string getRemoteDomainName() override;

    /**
     * @brief Retrieves the domain name of the local end of the session.
     * @return Domain name string.
     */
    virtual std::string getLocalDomainName() override;

    /**
     * @brief Retrieves the port number of the remote end of the session.
     * @return Remote port number.
     */
    virtual UInt16 getRemotePort() override;

    /**
     * @brief Retrieves the remote IP address of the session.
     * @return Remote InetAddress.
     */
    virtual SPIInetAddress getRemoteInetAddress() override;

    /**
     * @brief Retrieves the ALPN mode used in the session.
     * @return ALPN mode.
     */
    virtual const AlpnMode& getUsedAlpnMode() const override;

    /**
     * @brief Retrieves the protocol used in the session.
     * @return IANA protocol identifier.
     */
    virtual IANAProtocol getUsedProtocol() const override;

#ifndef UNIT_TEST
private:
#endif //UNIT_TEST

    std::shared_ptr<IOStreamIf> m_stream; ///< Stream used for I/O operations.
    std::shared_ptr<ITLSEngine> m_engine; ///< TLS engine handling cryptographic operations.
    bool m_isFdManagedLocal; ///< Indicates whether the file descriptor is managed locally.
#ifdef TLSAPI_WITH_DROP_SUPPORT
    bool m_droppable; ///< Indicates whether TLS dropping is supported.
    bool m_dropInitiated; ///< Indicates whether TLS drop has been initiated.
    bool m_dropSendCompleted; ///< Indicates whether the TLS drop send has been completed.
    bool m_dropReceived; ///< Indicates whether the TLS drop has been received.
#endif //TLSAPI_WITH_DROP_SUPPORT
};

using TLSSessionEndpointResult = TLSResult<SPITLSSessionEndpoint>;

} // namespace impl
} // namespace tls
} // namespace vwg

#endif /* _TLS_SESSION_ENDPOINT_IMPL_HPP_ */
