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
#ifndef TEST_IO_STREAM_IMPL_HPP
#define TEST_IO_STREAM_IMPL_HPP

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
     * @class   TLSStreamImpl
     * @brief   The TLSStreamImpl is the base class for all the possible (fd-based) socket streams. The intention
     *          is to use this class' inheritors to provide basic, non-encrypted and non-authenticated communication
     *          within a socket.
     */
    class TestIOStreamImpl : public IOStream
    {
    public:
        static std::shared_ptr<TestIOStreamImpl> GetIOStreamSP(int fd);
        static std::shared_ptr<TestIOStreamImpl> GetIOStreamSP(SPIInetAddress inet, UInt16 port);

        TestIOStreamImpl(int fd);

        TestIOStreamImpl(SPIInetAddress inet, UInt16 port);

        int32_t receive(void *buf, uint32_t len) override;

        int32_t send(const void *buf, uint32_t len) override;

        void close() override;

        bool isOpen() override;

        bool isClosed() override;

        bool IsBlocking() const;

        int GetFD() const;

        bool Connect();

        bool Listen();

        SocketType GetConnectionType() const;

        uint16_t GetLocalPort() const;

        uint16_t GetRemotePort() const;

        SPIInetAddress GetLocalAddress() const;

        SPIInetAddress GetRemoteAddress() const;

        std::shared_ptr<IOStream> Accept();

        virtual ~TestIOStreamImpl();

        bool SetBlocking(bool blocking);

    protected:

        int m_sock;
        std::string m_ipAddress;
        struct sockaddr_in m_addr4;
        struct sockaddr_in6 m_addr6;
        struct sockaddr * m_addr;
        uint32_t m_addrSize;
        uint16_t m_port;
        bool m_isOpen; // determines if the connection is open
        bool m_isBlocking;
        std::deque<std::vector<uint8_t>> m_dataToSend;
        std::mutex m_dataToSendMutex;
    };

} // namespace impl
} // namespace tls
} // namespace vwg

#endif // TEST_IO_STREAM_IMPL_HPP
