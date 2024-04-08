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
#include "UserIOStream.hpp"

using namespace vwg::tls::impl;

UserIOStream::UserIOStream(const std::shared_ptr<IOStream> userIOStream)
: m_userStream(userIOStream)
{
}

int32_t UserIOStream::receive(void *buf, uint32_t len)
{
    return m_userStream->receive(buf, len);
}

int32_t UserIOStream::send(const void *buf, uint32_t len)
{
    return m_userStream->send(buf, len);
}

void UserIOStream::close()
{
    m_userStream->close();
}

bool UserIOStream::isOpen()
{
    return m_userStream->isOpen();
}

bool UserIOStream::isClosed()
{
    return m_userStream->isClosed();
}

bool UserIOStream::IsBlocking() const
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    return false;
}

int UserIOStream::GetFD() const
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    return -1;
}

vwg::tls::SocketType UserIOStream::GetConnectionType() const
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    return SOCKETTYPE_STREAM;
}

uint16_t UserIOStream::GetLocalPort() const
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    return 0;
}

uint16_t UserIOStream::GetRemotePort() const
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    return 0;
}

vwg::tls::SPIInetAddress UserIOStream::GetLocalAddress() const
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    return SPIInetAddress();
}

vwg::tls::SPIInetAddress UserIOStream::GetRemoteAddress() const
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    return SPIInetAddress();
}

bool UserIOStream::SetBlocking(bool blocking)
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    (void)blocking;
    return false;
}

void UserIOStream::setSoTimeout(Int32 timeout)
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    (void)timeout;
    return;
}

Boolean UserIOStream::isConnectionSocket()
{
    // The IOStream class doesn’t contain this method, but the ITLSSocketBase interface does contain.
    // It was decided to extend the library’s stream, but return a default value when using a user-defined stream.
    return true;
}
