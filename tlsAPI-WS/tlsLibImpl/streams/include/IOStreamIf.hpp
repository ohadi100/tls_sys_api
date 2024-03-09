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
#ifndef IO_STREAM_IMPL_IF_HPP
#define IO_STREAM_IMPL_IF_HPP


#include <cstdint>
#include <vector>
#include <mutex>
#include <cstdint>

#include "IOStream.h"
#include "TLSApiTypes.h"

namespace vwg
{
namespace tls
{
namespace impl
{
/**
 * @class IOStreamIf
 * @brief A class that extends the IOStream class, while still allowing the abstraction.
 * The IOStream class doesn’t contain some methods that the ITLSSocketBase interface does contain.
 * Basically the library stream is extended, and when using the user-defined stream a default value will be returned,
 * in cases where the methods is not included in the IOStream interface class.
 * */
class IOStreamIf : public IOStream
{
public:
    IOStreamIf() = default;

    virtual ~IOStreamIf() = default;

    // Inherited methods
    virtual int32_t receive(void *buf, uint32_t len) = 0;

    virtual int32_t send(const void *buf, uint32_t len) = 0;

    virtual void close() = 0;

    virtual bool isOpen() = 0;

    virtual bool isClosed() = 0;
    // End of inherited methods

    // Extended methods
    virtual bool IsBlocking() const = 0;

    virtual int GetFD() const = 0;

    virtual SocketType GetConnectionType() const = 0;

    virtual uint16_t GetLocalPort() const = 0;

    virtual uint16_t GetRemotePort() const = 0;

    virtual SPIInetAddress GetLocalAddress() const = 0;

    virtual SPIInetAddress GetRemoteAddress() const = 0;

    virtual bool SetBlocking(bool blocking) = 0;

    virtual void setSoTimeout(Int32 timeout) = 0;

    virtual Boolean isConnectionSocket() = 0;

    void setConnectionLoggingName(const std::string &connectionLoggingName) { m_connectionLoggingName = connectionLoggingName; };

    std::string getConnectionLoggingName() const { return m_connectionLoggingName; };
    // End of extended methods

private:
    std::string m_connectionLoggingName;
};

} // namespace impl
} // namespace tls
} // namespace vwg

#endif // IO_STREAM_IMPL_IF_HPP
