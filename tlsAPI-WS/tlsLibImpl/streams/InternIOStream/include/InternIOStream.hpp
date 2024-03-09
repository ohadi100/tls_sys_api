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
#ifndef INTERN_IO_STREAM_HPP
#define INTERN_IO_STREAM_HPP

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
 * @class   InternIOStream
 * @brief   The InternIOStream is a class for internal socket stream implementation.
 */
class InternIOStream : public IOStreamIf
{
public:
    static std::shared_ptr<InternIOStream> GetIOStreamSP(int fd);
    static std::shared_ptr<InternIOStream> GetIOStreamSP(SPIInetAddress inet, UInt16 port);

    explicit InternIOStream(int fd);

    virtual ~InternIOStream() = default;

    InternIOStream(SPIInetAddress inet, UInt16 port);

    virtual int32_t receive(void *buf, uint32_t len) override;

    virtual int32_t send(const void *buf, uint32_t len) override;

    virtual void close() override;

    virtual bool isOpen() override;

    virtual bool isClosed() override;

    virtual bool IsBlocking() const override;

    virtual int GetFD() const override;

    virtual SocketType GetConnectionType() const override;

    virtual uint16_t GetLocalPort() const override;

    virtual uint16_t GetRemotePort() const override;

    virtual SPIInetAddress GetLocalAddress() const override;

    virtual SPIInetAddress GetRemoteAddress() const override;

    virtual bool SetBlocking(bool blocking) override;

    virtual void setSoTimeout(Int32 timeout) override;

    virtual Boolean isConnectionSocket() override;

    virtual bool Connect();

    virtual bool Listen();

    virtual std::shared_ptr<InternIOStream> Accept();
#ifndef UNIT_TEST
private:
#endif
    bool setBlocking(bool blocking);

    int m_fd;
    std::string m_ipAddress;
    struct sockaddr_in m_addr4;
    struct sockaddr_in6 m_addr6;
    struct sockaddr * m_addr;
    uint32_t m_addrSize;
    uint16_t m_port;
    bool m_isOpen = false; // determines if the connection is open
    bool m_isBlocking = true;

    std::deque<std::vector<uint8_t>> m_dataToSend;
    std::mutex m_dataToSendMutex;
};

} // namespace impl
} // namespace tls
} // namespace vwg

#endif // INTERN_IO_STREAM_HPP
