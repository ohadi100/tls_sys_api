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
#ifndef USER_IO_STREAM_HPP
#define USER_IO_STREAM_HPP

#include <cstdint>
#include <vector>
#include <mutex>
#include <cstdint>

#include "TLSApiTypes.h"
#include "IOStreamIf.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{
/**
 * @class   UserIOStream
 * @brief   The UserIOStream is a class for user socket stream implementation with additional functions.
 */
class UserIOStream : public IOStreamIf
{
public:
    explicit UserIOStream(const std::shared_ptr<IOStream> userIOStream);

    virtual ~UserIOStream() = default;

    /**
    * int32_t receive(void *buf, uint32_t len);
    * \return the number of bytes received or the relevant error code.

    */
    virtual int32_t receive(void *buf, uint32_t len) override;

    /**
    * int32_t send(const void *buf, uint32_t len);
    * \return the number of bytes sent or the relevant error code.
    */
    virtual int32_t send(const void *buf, uint32_t len) override;

    /**
    * void close();
    */
    virtual void close() override;

    /**
    * bool isOpen();
    * \return true if the stream is open, false otherwise.
    */
    virtual bool isOpen() override;

    /**
    * bool isClosed();
    * \return true if the stream is closed, false otherwise.
    */
    virtual bool isClosed() override;

    /**
    * bool IsBlocking() const;
    * \return a default value.
    */
    virtual bool IsBlocking() const override;

    /**
    * int GetFD() const;
    * \return a default value.
    */
    virtual int GetFD() const override;

    /**
    * SocketType GetConnectionType() const;
    * \return a default value.
    */
    virtual SocketType GetConnectionType() const override;

    /**
    * uint16_t GetLocalPort() const;
    * \return a default value.
    */
    virtual uint16_t GetLocalPort() const override;

    /**
    * buint16_t GetRemotePort() const;
    * \return a default value.
    */
    virtual uint16_t GetRemotePort() const override;

    /**
    * bool SPIInetAddress GetLocalAddress() const;
    * \return a default value.
    */
    virtual SPIInetAddress GetLocalAddress() const override;

    /**
    * SPIInetAddress GetRemoteAddress() const;
    * \return a default value.
    */
    virtual SPIInetAddress GetRemoteAddress() const override;

    /**
    * bool SetBlocking(bool blocking);
    * \return a default value.
    */
    virtual bool SetBlocking(bool blocking) override;

    /**
    * void setSoTimeout(Int32 timeout);
    * \return a default value.
    */
    virtual void setSoTimeout(Int32 timeout) override;

    /**
    * Boolean isConnectionSocket();
    * \return a default value.
    */
    virtual Boolean isConnectionSocket() override;

private:
    std::shared_ptr<IOStream> m_userStream;
};


} // namespace impl
} // namespace tls
} // namespace vwg

#endif // USER_IO_STREAM_HPP