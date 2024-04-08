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
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <vector>

#include "TestIOStreamImpl.hpp"


using std::vector;
using vwg::tls::InetAddressFactory;
using vwg::tls::IOStream;
using vwg::tls::SocketType;
using vwg::tls::SPIInetAddress;
using vwg::tls::impl::TestIOStreamImpl;


TestIOStreamImpl::TestIOStreamImpl(int fd)
  : m_sock(fd)
  , m_ipAddress("")
  , m_addr4{}
  , m_addr6{}
  , m_addr{}
  , m_addrSize{}
  , m_port(0)
  , m_isOpen(true)
  , m_isBlocking(true)
{
    std::cout << "new stream created from fd: " << fd << std::endl;
}

TestIOStreamImpl::TestIOStreamImpl(SPIInetAddress inet, UInt16 port)
  : m_addr4{}
  , m_addr6{}
  , m_port(port)
  , m_isOpen(false)
  , m_isBlocking(true)
{
    const int     enable      = 1;
    IInetAddress* inetAddress = inet.get();
    m_ipAddress               = inetAddress->toString();
    memset(&m_addr4, 0, sizeof(m_addr4));
    switch (inetAddress->getSaFamily()) {
    case AF_INET:
        m_sock = ::socket(AF_INET, SOCK_STREAM, 0);
        /*reusing of socket*/

        if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            std::cout << "setsockopt(SO_REEADDR) failed" << std::endl;
        }
        memcpy(&m_addr4.sin_addr, inetAddress->getAddr(), sizeof(m_addr4.sin_addr));
        m_addr4.sin_port   = htons(m_port);
        m_addr4.sin_family = AF_INET;
        m_addr             = reinterpret_cast<struct sockaddr*>(&m_addr4);
        m_addrSize         = sizeof(m_addr4);
        break;

    case AF_INET6:
        m_sock = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            std::cout << "setsockopt(SO_REUSEADDR) failed" << std::endl;
        }
        m_addr6.sin6_family = AF_INET6;
        memcpy(&m_addr6.sin6_addr.s6_addr, inetAddress->getAddr(), sizeof(m_addr6.sin6_addr.s6_addr));
        m_addr6.sin6_port = htons(m_port);
        m_addr            = reinterpret_cast<struct sockaddr*>(&m_addr6);
        m_addrSize        = sizeof(m_addr6);
        break;
    default:
        assert(0);  // should never happened
        break;
    }
}


std::shared_ptr<TestIOStreamImpl>
TestIOStreamImpl::GetIOStreamSP(int fd)
{
    return std::make_shared<TestIOStreamImpl>(fd);
}

std::shared_ptr<TestIOStreamImpl>
TestIOStreamImpl::GetIOStreamSP(SPIInetAddress inet, UInt16 port)
{
    return std::make_shared<TestIOStreamImpl>(inet, port);
}

TestIOStreamImpl::~TestIOStreamImpl()
{
    close();
}

int32_t
TestIOStreamImpl::receive(void* buf, uint32_t len)
{
    ssize_t sz;
    int32_t res;
    sz = ::recv(m_sock, buf, len, 0);

    if (sz < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            res = RC_STREAM_WOULD_BLOCK;
        else
            res = RC_STREAM_IO_ERROR;
    } else {
        res = (int32_t)sz;
    }
    return res;
}

int32_t
TestIOStreamImpl::send(const void* buf, uint32_t length)
{
    std::lock_guard<std::mutex> guard(m_dataToSendMutex);

    if (-1 == m_sock) {
        std::cout << "Trying to send on closed socket" << std::endl;
        return RC_STREAM_IO_ERROR;
    }

    if (nullptr != buf) {
        std::vector<uint8_t> vec;
        vec.insert(vec.begin(), (uint8_t*)buf, (uint8_t*)buf + length);
        m_dataToSend.push_back(vec);
    }

    while (!m_dataToSend.empty()) {
        size_t               size = m_dataToSend.front().size();
        std::vector<uint8_t> vec  = m_dataToSend.front();

        ssize_t actualLength = ::send(m_sock, buf, length, MSG_NOSIGNAL);

        // error during send
        if (actualLength < 0) {
            if (!m_isBlocking) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return length;  // the data to sent was already stored in the buffer
                }
            }

            std::cout << "Can't send - IO error" << std::endl;
            close();
            return RC_STREAM_IO_ERROR;
        }

        // from this point on -  actualLength has to be positive

        // handle partial send
        if ((size_t)actualLength < size) {
            std::cout << "sent only part of the data will resume later on: " << actualLength << std::endl;
            m_dataToSend.pop_front();
            vec.erase(vec.begin(), vec.begin() + actualLength);
            m_dataToSend.push_front(vec);

            return length;  // the data to sent was already stored in the buffer
        }

        if ((size_t)actualLength == size) {
            m_dataToSend.pop_front();
        } else {
            std::cout << "weird error - sent more than buffer" << std::endl;
            return RC_STREAM_IO_ERROR;
        }
    }

    // all sent
    return length;
}

void
TestIOStreamImpl::close()
{
    if (m_sock > 0) {
        if (-1 == ::close(m_sock)) {
            std::cout << "Unable to close socket: : " << m_sock << std::endl;
        } else {
            std::cout << "closed socket: " << m_sock << std::endl;
        }
        m_sock = -1;
    }

    m_isOpen     = false;
    m_isBlocking = true;
}

bool
TestIOStreamImpl::isOpen()
{
    return m_isOpen;
}

bool
TestIOStreamImpl::isClosed()
{
    return !m_isOpen;
}

bool
TestIOStreamImpl::IsBlocking() const
{
    return m_isBlocking;
}

int
TestIOStreamImpl::GetFD() const
{
    return m_sock;
}

bool
TestIOStreamImpl::Connect()
{
    if (m_isOpen) {
        std::cout << "connection already established on socket" << std::endl;
        return false;
    }

    if (m_ipAddress.empty()) {
        std::cout << "IP address is undefined. Unable to connect" << std::endl;
        return false;
    }
    if (-1 == ::connect(m_sock, m_addr, m_addrSize)) {
        std::cout << "Unable to connect to " << m_ipAddress.c_str() << ", " << m_port << std::endl;
        close();
        return false;
    }

    m_isOpen = true;
    return true;
}

bool
TestIOStreamImpl::Listen()
{
    if (m_isOpen) {
        std::cout << "connection already established on socket" << std::endl;
        return false;
    }

    if (m_ipAddress.empty()) {
        std::cout << "Unable to listen on undefined ipAddress" << std::endl;
        return false;
    }

    std::cout << "binding socket: " << m_sock << std::endl;
    if (-1 == ::bind(m_sock, m_addr, m_addrSize)) {
        std::cout << "Unable to bind to " << m_ipAddress.c_str() << ", " << m_port << std::endl;
        close();
        return false;
    }

    std::cout << "listening on socket" << std::endl;
    /*
     * was 0, changed to 1 due to ICAS1 qemu issues.
     */
    if (-1 == ::listen(m_sock, 1)) {
        std::cout << "Unable to listen on socket, err: " << strerror(errno) << std::endl;
        close();
        return false;
    }

    m_isOpen = true;
    return true;
}

std::shared_ptr<IOStream>
TestIOStreamImpl::Accept()
{
    std::cout << "accept started on stream" << std::endl;
    if (!m_isOpen) {
        if (!Listen()) {
            return nullptr;
        }
    }

    std::cout << "calling accept on socket: " << m_sock << std::endl;
    int workingSock = ::accept(m_sock, nullptr, nullptr);
    if (-1 == workingSock) {
        std::cout << "Unable to accept on socket: " << workingSock << std::endl;
        close();
        return nullptr;
    }

    std::cout << "new socket connected: " << workingSock << std::endl;
    std::shared_ptr<TestIOStreamImpl> sharedWorkingSock = TestIOStreamImpl::GetIOStreamSP(workingSock);
    return sharedWorkingSock;
}

SocketType
TestIOStreamImpl::GetConnectionType() const
{
    return SocketType::SOCKETTYPE_STREAM;
}

uint16_t
TestIOStreamImpl::GetLocalPort() const
{
    socklen_t               len;
    struct sockaddr_storage addr;
    uint16_t                port;

    len = sizeof addr;
    getsockname(m_sock, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        auto s = (struct sockaddr_in*)&addr;
        port   = ntohs(s->sin_port);
    } else {
        auto s = (struct sockaddr_in6*)&addr;
        port   = ntohs(s->sin6_port);
    }

    return port;
}

uint16_t
TestIOStreamImpl::GetRemotePort() const
{
    socklen_t               len;
    struct sockaddr_storage addr;
    uint16_t                port;

    len = sizeof addr;
    getpeername(m_sock, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        auto s = (struct sockaddr_in*)&addr;
        port   = ntohs(s->sin_port);
    } else {  // AF_INET6
        auto s = (struct sockaddr_in6*)&addr;
        port   = ntohs(s->sin6_port);
    }

    return port;
}

SPIInetAddress
TestIOStreamImpl::GetLocalAddress() const
{
    socklen_t               len;
    struct sockaddr_storage addr;
    char                    ipstr[INET6_ADDRSTRLEN];

    len = sizeof addr;
    getsockname(m_sock, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        auto s = (struct sockaddr_in*)&addr;
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    } else {  // AF_INET6
        auto s = (struct sockaddr_in6*)&addr;
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
    }

    IInetAddressResult res = InetAddressFactory::makeIPAddress(ipstr);
    if (res.failed()) {
        std::cout << "create IPAddress failed" << std::endl;
    }
    return res.getPayload();
}

SPIInetAddress
TestIOStreamImpl::GetRemoteAddress() const
{
    socklen_t               len;
    struct sockaddr_storage addr;
    char                    ipstr[INET6_ADDRSTRLEN];

    len = sizeof addr;
    getpeername(m_sock, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        auto s = (struct sockaddr_in*)&addr;
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    } else if (addr.ss_family == AF_INET6) {  // AF_INET6
        auto s = (struct sockaddr_in6*)&addr;
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
    } else {
        return nullptr;
    }

    IInetAddressResult res = InetAddressFactory::makeIPAddress(ipstr);
    if (res.failed()) {
        std::cout << "create IPAddress failed" << std::endl;
    }
    return res.getPayload();
}

bool
setBlocking(int fd, bool blocking)
{
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (-1 == flags) {
        return false;
    }
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    return -1 != ::fcntl(fd, F_SETFL, flags);
}

bool
TestIOStreamImpl::SetBlocking(bool blocking)
{
    if (m_sock < 0) {
        std::cout << "socket undefined - unable to set to non-blocking: " << m_sock << std::endl;
        return false;
    }

    if (setBlocking(m_sock, blocking)) {
        m_isBlocking = blocking;
        return true;
    }

    return false;
}