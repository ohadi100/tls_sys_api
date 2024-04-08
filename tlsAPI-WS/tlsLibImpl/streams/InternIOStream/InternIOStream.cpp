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
#include "InternIOStream.hpp"


#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <mutex>
#include <vector>

#include "Logger.hpp"

using std::vector;
using vwg::tls::InetAddressFactory;
using vwg::tls::SocketType;
using vwg::tls::SPIInetAddress;

using namespace vwg::tls::impl;

InternIOStream::InternIOStream(int fd)
  : m_fd(fd)
  , m_ipAddress{}
  , m_addr4{}
  , m_addr6{}
  , m_addrSize(0)
  , m_port(0)
  , m_isOpen(true)
  , m_isBlocking(true)
{
    FND_LOG_INFO << "connectionName = " << getConnectionLoggingName().c_str() << ". new stream created from fd: " << fd;
}

InternIOStream::InternIOStream(SPIInetAddress inet, UInt16 port)
  : m_port(port)
{
    const int     enable      = 1;
    IInetAddress* inetAddress = inet.get();
    m_ipAddress               = inetAddress->toString();
    memset(&m_addr4, 0, sizeof(m_addr4));
    memset(&m_addr6, 0, sizeof(m_addr6));
    switch (inetAddress->getSaFamily()) {
    case AF_INET:
        m_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        memcpy(&m_addr4.sin_addr, inetAddress->getAddr(), sizeof(m_addr4.sin_addr));
        m_addr4.sin_port   = htons(m_port);
        m_addr4.sin_family = AF_INET;
        m_addr             = reinterpret_cast<struct sockaddr*>(&m_addr4);
        m_addrSize         = sizeof(m_addr4);
        break;

    case AF_INET6:
        m_fd = ::socket(AF_INET6, SOCK_STREAM, 0);
        memcpy(&m_addr6.sin6_addr.s6_addr, inetAddress->getAddr(), sizeof(m_addr6.sin6_addr.s6_addr));
        m_addr6.sin6_port   = htons(m_port);
        m_addr6.sin6_family = AF_INET6;
        m_addr              = reinterpret_cast<struct sockaddr*>(&m_addr6);
        m_addrSize          = sizeof(m_addr6);
        break;
    default:
        assert(0);  // should never happened
        break;
    }

    if (setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". setsockopt(SO_REUSEADDR) failed";
    }
}

int32_t
InternIOStream::receive(void* buf, uint32_t len)
{

    if (0 > m_fd || nullptr == buf) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Error receive on socket";
        return RC_STREAM_IO_ERROR;
    }

    ssize_t sz = ::recv(m_fd, buf, len, 0);
    if (sz < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return RC_STREAM_WOULD_BLOCK;
        } else {
            return RC_STREAM_IO_ERROR;
        }
    }

    return (int32_t)sz;
}

int32_t
InternIOStream::send(const void* buf, uint32_t length)
{
    if (0 > m_fd || nullptr == buf || 0 >= length) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Error send on socket";
        return RC_STREAM_IO_ERROR;
    }

    std::vector<uint8_t> vec;
    vec.insert(vec.begin(), (uint8_t*)buf, (uint8_t*)buf + length);

    m_dataToSendMutex.lock();
    m_dataToSend.push_back(vec);
    m_dataToSendMutex.unlock();

    while (!m_dataToSend.empty()) {
        size_t               size = m_dataToSend.front().size();
        std::vector<uint8_t> vec  = m_dataToSend.front();

        ssize_t actualLength = ::send(m_fd, vec.data(), size, MSG_NOSIGNAL);
        // error during send
        if (actualLength < 0) {
            if (!m_isBlocking) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    FND_LOG_DEBUG << "connectionName = " << getConnectionLoggingName().c_str() <<". Can't send now << it will be sent in the future (blocking: " << m_isBlocking;
                    return length;  // the data to sent was already stored in the buffer
                }
            }
            FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Can't send - IO error " <<strerror(errno) << "(" << std::to_string(errno) << ")";
            close();
            return RC_STREAM_IO_ERROR;
        }

        // from this point on -  actualLength has to be positive

        // handle partial send
        if ((size_t)actualLength < size) {
            FND_LOG_DEBUG << "connectionName = " << getConnectionLoggingName().c_str() <<". Sent only part of the data (" << actualLength << "/" << size << ") << will resume later on";
            m_dataToSend.pop_front();
            vec.erase(vec.begin(), vec.begin() + actualLength);
            m_dataToSend.push_front(vec);

            return length;  // the data to sent was already stored in the buffer
        }

        if ((size_t)actualLength == size) {
            m_dataToSend.pop_front();
        } else {
            FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() <<". Weird error - sent more than buffer (" << actualLength << "/" << size << ")";
            return RC_STREAM_IO_ERROR;
        }
    }

    // all sent
    return length;
}

void
InternIOStream::close()
{
    if (m_fd > 0) {
        // Set errno to zero before calling fcntl
        errno = 0;

        // Check if fd is a valid open file descriptor
        if (fcntl(m_fd, F_GETFD) != -1 || errno != EBADF) {
            if (-1 == ::close(m_fd)) {
                FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() <<". Unable to close socket: " << m_fd << " - " << strerror(errno);
            } else {
                FND_LOG_DEBUG << "connectionName = " << getConnectionLoggingName().c_str() << ". Closed socket: " << m_fd;
            }
            m_fd = -1;
        }
    }

    m_isOpen     = false;
    m_isBlocking = true;
}

bool
InternIOStream::isOpen()
{
    return m_isOpen;
}

bool
InternIOStream::isClosed()
{
    return !m_isOpen;
}

bool
InternIOStream::IsBlocking() const
{
    return m_isBlocking;
}

int
InternIOStream::GetFD() const
{
    return m_fd;
}

bool
InternIOStream::Connect()
{
    if (m_isOpen) {
        FND_LOG_INFO << "connectionName = " << getConnectionLoggingName().c_str() << ". Connection already established on socket";
        return false;
    }

    if (0 > m_fd) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Trying to connect a closed socket";
        return false;
    }

    if (m_ipAddress.empty()) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". IP address is undefined. Unable to connect";
        return false;
    }
    if (-1 == ::connect(m_fd, m_addr, m_addrSize)) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() <<". Unable to connect to " << m_ipAddress.c_str() << "(" << m_port << ") - " << strerror(errno);
        close();
        return false;
    }

    m_isOpen = true;
    return true;
}

bool
InternIOStream::Listen()
{
    if (m_isOpen) {
        FND_LOG_INFO << "connectionName = " << getConnectionLoggingName().c_str() << ". Connection already established on socket";
        return false;
    }

    if (0 > m_fd) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Trying to listen on closed socket";
        return false;
    }

    if (m_ipAddress.empty()) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Unable to listen on undefined ipAddress";
        return false;
    }

    FND_LOG_DEBUG << "connectionName = " << getConnectionLoggingName().c_str() << ". Binding socket: " << m_fd;
    if (-1 == ::bind(m_fd, m_addr, m_addrSize)) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Unable to bind to: " <<m_ipAddress.c_str() << "(" << m_port << ") - err: " << strerror(errno);
        close();
        return false;
    }

    FND_LOG_DEBUG << "connectionName = " << getConnectionLoggingName().c_str() << ". Listening on socket";
    /*
     * was 0, changed to 1 due to ICAS1 qemu issues.
     */
    if (-1 == ::listen(m_fd, 1)) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Unable to listen on socket (err: " << strerror(errno) << ")";
        close();
        return false;
    }

    m_isOpen = true;
    return true;
}

std::shared_ptr<InternIOStream>
InternIOStream::Accept()
{
    FND_LOG_VERBOSE << "connectionName = " << getConnectionLoggingName().c_str() << ". Accept started on stream";
    if (0 > m_fd) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Trying to accept on closed socket";
        return nullptr;
    }

    if (!m_isOpen) {
        if (!Listen()) {
            return nullptr;
        }
    }

    FND_LOG_DEBUG << "connectionName = " << getConnectionLoggingName().c_str() << ". Calling accept on socket: " << m_fd;
    int workingSock = ::accept(m_fd, nullptr, nullptr);
    if (-1 == workingSock) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() <<". Unable to accept on socket " << workingSock << " (err: " << strerror(errno) << ")";
        close();
        return nullptr;
    }

    FND_LOG_DEBUG << "connectionName = " << getConnectionLoggingName().c_str() << ". New socket connected: " << workingSock;
    std::shared_ptr<InternIOStream> sharedWorkingSock = std::make_shared<InternIOStream>(workingSock);
    return sharedWorkingSock;
}

SocketType
InternIOStream::GetConnectionType() const
{
    return SocketType::SOCKETTYPE_STREAM;
}

uint16_t
InternIOStream::GetLocalPort() const
{
    struct sockaddr_storage addr;
    uint16_t                port = 0;

    socklen_t len = sizeof addr;
    getsockname(m_fd, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        auto s = (struct sockaddr_in*)&addr;
        port   = ntohs(s->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        auto s = (struct sockaddr_in6*)&addr;
        port   = ntohs(s->sin6_port);
    }

    return port;
}

uint16_t
InternIOStream::GetRemotePort() const
{
    struct sockaddr_storage addr;
    uint16_t                port = 0;

    socklen_t len = sizeof addr;
    getpeername(m_fd, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        auto s = (struct sockaddr_in*)&addr;
        port   = ntohs(s->sin_port);
    } else if (addr.ss_family == AF_INET6) {  // AF_INET6
        auto s = (struct sockaddr_in6*)&addr;
        port   = ntohs(s->sin6_port);
    }

    return port;
}

SPIInetAddress
InternIOStream::GetLocalAddress() const
{
    struct sockaddr_storage addr;
    char                    ipstr[INET6_ADDRSTRLEN];

    socklen_t len = sizeof addr;
    getsockname(m_fd, (struct sockaddr*)&addr, &len);

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
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Create IPAddress failed";
    }
    return res.getPayload();
}

SPIInetAddress
InternIOStream::GetRemoteAddress() const
{
    struct sockaddr_storage addr;
    char                    ipstr[INET6_ADDRSTRLEN];

    socklen_t len = sizeof addr;
    getpeername(m_fd, (struct sockaddr*)&addr, &len);

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
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Create IPAddress failed";
    }
    return res.getPayload();
}

bool
InternIOStream::setBlocking(bool blocking)
{
    int flags = ::fcntl(m_fd, F_GETFL, 0);
    if (-1 == flags) {
        return false;
    }
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    return -1 != ::fcntl(m_fd, F_SETFL, flags);
}

bool
InternIOStream::SetBlocking(bool blocking)
{
    if (m_fd < 0) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Socket undefined - unable to set to non-blocking (fd: " << m_fd << ")";
        return false;
    }

    if (setBlocking(blocking)) {
        m_isBlocking = blocking;
        return true;
    }

    return false;
}

void
InternIOStream::setSoTimeout(Int32 timeout)
{
    if (timeout < 0) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". Timeout cannot be negative";
        return;
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeout;

    if (setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval*)&tv, sizeof(struct timeval))) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". setsockopt(SO_RCVTIMEO) failed";
    }

    if (setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, (struct timeval*)&tv, sizeof(struct timeval))) {
        FND_LOG_ERROR << "connectionName = " << getConnectionLoggingName().c_str() << ". setsockopt(SO_SNDTIMEO) failed: " << std::to_string(errno).c_str();
    }
}

Boolean
InternIOStream::isConnectionSocket()
{
    return true;
}