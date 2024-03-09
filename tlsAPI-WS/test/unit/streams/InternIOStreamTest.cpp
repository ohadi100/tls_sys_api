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


#include <gtest/gtest.h>

#include "InternIOStream.hpp"
#include "InetAddress.h"

// extern return values for socket_mock
extern int connect_rval;
extern int setsockopt_rval;
extern int sock_rval;
extern int close_rval;
extern int listen_rval;
extern int bind_rval;
extern int syncfs_rval;
extern int poll_rval;
extern int accept_rval;
extern int ioctl_rval;
extern int getsockname_rval;
extern int getpeername_rval;
extern ssize_t read_rval;
extern ssize_t write_rval;
extern ssize_t recv_rval;
extern ssize_t send_rval;
extern uint8_t ntohs_rval;


using namespace  vwg::tls;
using namespace  vwg::tls::impl;

class InternIOStreamTest : public ::testing::Test {
protected:
    std::string loopBackIP = "127.0.0.1";
    UInt16 port = 1338;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr*    addr;

    SPIInetAddress createIPAddress()
    {
        IInetAddressResult v4addrLB = InetAddressFactory::makeIPAddress(loopBackIP);
        EXPECT_FALSE(v4addrLB.failed());
        return v4addrLB.getPayload();
    }

    void SetUp() override
    {
        memset(&addr4, 0, sizeof(addr4));
        memset(&addr6, 0, sizeof(addr6));
        memset(&addr, 0, sizeof(addr));
    }

    void TearDown() override
    {
        connect_rval = 0;
        setsockopt_rval = 0;
        sock_rval = 0;
        close_rval = 0;
        listen_rval = 0;
        bind_rval = 0;
        syncfs_rval = 0;
        poll_rval = 0;
        accept_rval = 0;
        ioctl_rval = 0;
        getsockname_rval = 0;
        getpeername_rval = 0;
        read_rval = 0;
        write_rval = 0;
        recv_rval = 0;
        send_rval = 0;
    }


};

/**
 * @ingroup InternIOStreamTest_InternIOStream1
 * @fn TEST_F(InternIOStreamTest, check_members_fd_ctor)
 * @brief Checks that the members have been initialized correctly (constructor by fd)
 */
TEST_F(InternIOStreamTest, check_members_fd_ctor)
{
    int fd = 2;
    InternIOStream stream(fd);

    EXPECT_FALSE(stream.isClosed());
    EXPECT_TRUE(stream.isConnectionSocket());
    EXPECT_TRUE(stream.isOpen());
    EXPECT_EQ(stream.GetFD(), fd);
    EXPECT_EQ(stream.m_ipAddress, "");
    EXPECT_EQ(stream.m_addrSize, 0);
    EXPECT_EQ(stream.m_port, 0);
    EXPECT_EQ(stream.GetConnectionType(), SocketType::SOCKETTYPE_STREAM);
}

/**
 * @ingroup InternIOStreamTest_InternIOStream2
 * @fn TEST_F(InternIOStreamTest, check_members_inet_and_port_ctor_client)
 * @brief Checks that the members have been initialized correctly (client constructor by inet & port)
 */
TEST_F(InternIOStreamTest, check_members_inet_and_port_ctor_client)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream stream(v4addrLB, port);

    EXPECT_TRUE(stream.isClosed());
    EXPECT_TRUE(stream.isConnectionSocket());
    EXPECT_FALSE(stream.isOpen());
    EXPECT_EQ(stream.GetFD(), 2);
    EXPECT_EQ(stream.m_ipAddress, loopBackIP);
    EXPECT_EQ(stream.m_addrSize, sizeof(struct sockaddr_in));
    EXPECT_EQ(stream.m_port, port);
}

/**
 * @ingroup InternIOStreamTest_InternIOStream2
 * @fn TEST_F(InternIOStreamTest, check_members_inet_and_port_ctor_server)
 * @brief Checks that the members have been initialized correctly (server constructor by inet & port)
 */
TEST_F(InternIOStreamTest, check_members_inet_and_port_ctor_server)
{
    sock_rval = 10;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream stream(v4addrLB, port);

    EXPECT_TRUE(stream.isConnectionSocket());
    EXPECT_FALSE(stream.isOpen());
    EXPECT_EQ(stream.GetFD(), 10);
}

/**
 * @ingroup InternIOStreamTest_InternIOStream2
 * @fn TEST_F(InternIOStreamTest, ctor_sock_fail)
 * @brief Checks that the members are invalid after constructor failed to create socket
 */
TEST_F(InternIOStreamTest, ctor_sock_fail)
{
    sock_rval = -1;

    // inet&port ctor
    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_EQ(clientStream.GetFD(), -1);
    EXPECT_EQ(serverStream.GetFD(), -1);
}

/**
 * @ingroup InternIOStreamTest_InternIOStream2
 * @fn TEST_F(InternIOStreamTest, ctor_setsockopt_fail)
 * @brief Checks that the members are invalid after constructor failed to setsockopt
 */
TEST_F(InternIOStreamTest, ctor_setsockopt_fail)
{
    sock_rval = 2;
    setsockopt_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);
}

/**
 * @ingroup InternIOStreamTest_IsBlocking
 * @fn TEST_F(InternIOStreamTest, IsBlocking)
 * @brief Checks IsBlocking
 */
TEST_F(InternIOStreamTest, IsBlocking)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    // defualt value
    EXPECT_TRUE(clientStream.IsBlocking());
    EXPECT_TRUE(serverStream.IsBlocking());

    // set non-blockimg
    EXPECT_TRUE(clientStream.SetBlocking(false));
    EXPECT_TRUE(serverStream.SetBlocking(false));

    // check result
    EXPECT_FALSE(clientStream.IsBlocking());
    EXPECT_FALSE(serverStream.IsBlocking());


    // set blocking
    EXPECT_TRUE(clientStream.SetBlocking(true));
    EXPECT_TRUE(serverStream.SetBlocking(true));

    // set invalid fd
    clientStream.m_fd = -1;
    serverStream.m_fd = -1;

    // set on invalid socket
    EXPECT_FALSE(clientStream.SetBlocking(true));
    EXPECT_FALSE(serverStream.SetBlocking(true));
}

/**
 * @ingroup InternIOStreamTest_getFD
 * @fn TEST_F(InternIOStreamTest, getFD_success)
 * @brief Checks GetFD
 */
TEST_F(InternIOStreamTest, getFD_success)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);
}

/**
 * @ingroup InternIOStreamTest_getFD
 * @fn TEST_F(InternIOStreamTest, getFD_fail)
 * @brief Checks GetFD
 */
TEST_F(InternIOStreamTest, getFD_fail)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    //set m_stream to invalid value
    clientStream.m_fd = -1;
    serverStream.m_fd = -1;

    clientStream.close();
    serverStream.close();

    EXPECT_EQ(clientStream.GetFD(), -1);
    EXPECT_EQ(serverStream.GetFD(), -1);
}

/**
 * @ingroup InternIOStreamTest_send & InternIOStreamTest_receive
 * @fn TEST_F(InternIOStreamTest, send_receive_success)
 * @brief Checks send&receive success
 */
TEST_F(InternIOStreamTest, send_receive_success)
{
    char const sendBuf[1024] = "SEND MESSAGE";
    char receiveBuf[1024] = {0};

    sock_rval = 2;
    setsockopt_rval = 0;
    send_rval = strlen(sendBuf);
    recv_rval = 5;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.send(sendBuf, strlen(sendBuf)), strlen(sendBuf));
    EXPECT_EQ(serverStream.send(sendBuf, strlen(sendBuf)), strlen(sendBuf));

    EXPECT_EQ(clientStream.receive(receiveBuf, strlen(receiveBuf)), recv_rval);
    EXPECT_EQ(serverStream.receive(receiveBuf, strlen(receiveBuf)), recv_rval);
}

/**
 * @ingroup InternIOStreamTest_send & InternIOStreamTest_receive
 * @fn TEST_F(InternIOStreamTest, send_less)
 * @brief Checks send&receive success
 */
TEST_F(InternIOStreamTest, send_less)
{
    char const sendBuf[1024] = "SEND MESSAGE";

    sock_rval = 2;
    setsockopt_rval = 0;
    send_rval = strlen(sendBuf) - 1;
    recv_rval = 5;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.send(sendBuf, strlen(sendBuf)), strlen(sendBuf));
    EXPECT_EQ(serverStream.send(sendBuf, strlen(sendBuf)), strlen(sendBuf));
}


/**
 * @ingroup InternIOStreamTest_send & InternIOStreamTest_receive
 * @fn TEST_F(InternIOStreamTest, send_more)
 * @brief Checks send&receive success
 */
TEST_F(InternIOStreamTest, send_more)
{
    char const sendBuf[1024] = "SEND MESSAGE";

    sock_rval = 2;
    setsockopt_rval = 0;
    send_rval = strlen(sendBuf) + 1;
    recv_rval = 5;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.send(sendBuf, strlen(sendBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.send(sendBuf, strlen(sendBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_send & InternIOStreamTest_receive
 * @fn TEST_F(InternIOStreamTest, send_receive_fail_null_pointer)
 * @brief Checks send&receive respond as expected to null pointer
 */
TEST_F(InternIOStreamTest, send_receive_fail_null_pointer_and_len_zero)
{
    char const* sendBuf = nullptr;
    char* receiveBuf = nullptr;

    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.send(sendBuf, 0), RC_STREAM_IO_ERROR);

    EXPECT_EQ(clientStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.receive(receiveBuf, 0), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_send
 * @fn TEST_F(InternIOStreamTest, send_error_socket)
 * @brief Checks send respond as expected to invalid fd
 */
TEST_F(InternIOStreamTest, send_error_socket)
{
    char const sendBuf[1024] = "SEND MESSAGE";

    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    clientStream.m_fd = -1;
    serverStream.m_fd = -1;

    EXPECT_EQ(clientStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_send
 * @fn TEST_F(InternIOStreamTest, send_error_socket_non_blocking)
 * @brief Checks send respond as expected to invalid fd
 */
TEST_F(InternIOStreamTest, send_error_socket_non_blocking)
{
    char const sendBuf[1024] = "SEND MESSAGE";

    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);

    EXPECT_TRUE(clientStream.SetBlocking(false));

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    clientStream.m_fd = -1;

    EXPECT_EQ(clientStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_send
 * @fn TEST_F(InternIOStreamTest, send_failed)
 * @brief Checks send failed
 */
TEST_F(InternIOStreamTest, send_failed)
{
    char const sendBuf[1024] = "SEND MESSAGE";

    sock_rval = 2;
    setsockopt_rval = 0;
    send_rval = -2;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_send
 * @fn TEST_F(InternIOStreamTest, send_failed_non_blocking)
 * @brief Checks send failed
 */
TEST_F(InternIOStreamTest, send_failed_non_blocking)
{
    char const sendBuf[1024] = "SEND MESSAGE";

    sock_rval = 2;
    setsockopt_rval = 0;
    send_rval = -2;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_TRUE(clientStream.SetBlocking(false));

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_send
 * @fn TEST_F(InternIOStreamTest, send_error_socket)
 * @brief Checks send respond as expected to invalid send system call
 */
TEST_F(InternIOStreamTest, send_error)
{
    char const sendBuf[1024] = "SEND MESSAGE";

    sock_rval = 2;
    setsockopt_rval = 0;
    send_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_send
 * @fn TEST_F(InternIOStreamTest, send_error_socket_non_blocking)
 * @brief Checks send respond as expected to invalid send system call
 */
TEST_F(InternIOStreamTest, send_error_non_blocking)
{
    char const sendBuf[1024] = "SEND MESSAGE";

    sock_rval = 2;
    setsockopt_rval = 0;
    send_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_TRUE(clientStream.SetBlocking(false));

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.send(sendBuf, sizeof(sendBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_receive
 * @fn TEST_F(InternIOStreamTest, receive_error_socket)
 * @brief Checks receive respond as expected to invalid fd
 */
TEST_F(InternIOStreamTest, receive_error_socket)
{
    char receiveBuf[1024] = {0};

    sock_rval = 2;
    setsockopt_rval = 0;
    recv_rval = -2;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    clientStream.m_fd = -1;
    serverStream.m_fd = -1;

    EXPECT_EQ(clientStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_receive
 * @fn TEST_F(InternIOStreamTest, receive_error_socket_non_blocking)
 * @brief Checks receive respond as expected to invalid fd
 */
TEST_F(InternIOStreamTest, receive_error_socket_non_blocking)
{
    char receiveBuf[1024] = {0};

    sock_rval = 2;
    setsockopt_rval = 0;
    recv_rval = -2;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_TRUE(clientStream.SetBlocking(false));

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    clientStream.m_fd = -1;
    serverStream.m_fd = -1;

    EXPECT_EQ(clientStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_receive
 * @fn TEST_F(InternIOStreamTest, receive_error)
 * @brief Checks receive respond as expected to invalid receive system call
 */
TEST_F(InternIOStreamTest, receive_error)
{
    char receiveBuf[1024] = {0};

    sock_rval = 2;
    setsockopt_rval = 0;
    recv_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_receive
 * @fn TEST_F(InternIOStreamTest, receive_error_non_blocking)
 * @brief Checks receive respond as expected to invalid receive system call
 */
TEST_F(InternIOStreamTest, receive_error_non_blocking)
{
    char receiveBuf[1024] = {0};

    sock_rval = 2;
    setsockopt_rval = 0;
    recv_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_TRUE(clientStream.SetBlocking(false));

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_EQ(clientStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
    EXPECT_EQ(serverStream.receive(receiveBuf, sizeof(receiveBuf)), RC_STREAM_IO_ERROR);
}

/**
 * @ingroup InternIOStreamTest_connect
 * @fn TEST_F(InternIOStreamTest, connect_success)
 * @brief Checks connect success
 */
TEST_F(InternIOStreamTest, connect_success)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    connect_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_TRUE(clientStream.Connect());
    EXPECT_TRUE(serverStream.Connect());

    EXPECT_TRUE(clientStream.isOpen());
    EXPECT_TRUE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_connect
 * @fn TEST_F(InternIOStreamTest, connect_after_connect)
 * @brief Checks cannot connect after connect
 */
TEST_F(InternIOStreamTest, connect_after_connect)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    connect_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_TRUE(clientStream.Connect());

    // cannot connect after connect
    EXPECT_FALSE(clientStream.Connect());
}

/**
 * @ingroup InternIOStreamTest_connect
 * @fn TEST_F(InternIOStreamTest, connect_error_socket)
 * @brief Checks connect respond as expected to invalid fd
 */
TEST_F(InternIOStreamTest, connect_error_socket)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    clientStream.m_fd = -1;
    serverStream.m_fd = -1;

    EXPECT_FALSE(clientStream.Connect());
    EXPECT_FALSE(serverStream.Connect());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_connect
 * @fn TEST_F(InternIOStreamTest, connect_error)
 * @brief Checks connect respond as expected to connect system call
 */
TEST_F(InternIOStreamTest, connect_error)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    connect_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_FALSE(clientStream.Connect());
    EXPECT_FALSE(serverStream.Connect());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_listen
 * @fn TEST_F(InternIOStreamTest, listen_success)
 * @brief Checks listen success
 */
TEST_F(InternIOStreamTest, listen_success)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    bind_rval = 0;
    listen_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_TRUE(clientStream.Listen());
    EXPECT_TRUE(serverStream.Listen());

    EXPECT_TRUE(clientStream.isOpen());
    EXPECT_TRUE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_listen
 * @fn TEST_F(InternIOStreamTest, listen_error_socket)
 * @brief Checks listen respond as expected to invalid fd
 */
TEST_F(InternIOStreamTest, listen_error_socket)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    clientStream.m_fd = -1;
    serverStream.m_fd = -1;

    EXPECT_FALSE(clientStream.Listen());
    EXPECT_FALSE(serverStream.Listen());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_listen
 * @fn TEST_F(InternIOStreamTest, listen_after_listen)
 * @brief Checks listen respond as expected to listen after listen
 */
TEST_F(InternIOStreamTest, listen_after_listen)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    bind_rval = 0;
    listen_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_TRUE(clientStream.Listen());
    EXPECT_TRUE(serverStream.Listen());

    EXPECT_TRUE(clientStream.isOpen());
    EXPECT_TRUE(serverStream.isOpen());

    EXPECT_FALSE(clientStream.Listen());
    EXPECT_FALSE(serverStream.Listen());
}

/**
 * @ingroup InternIOStreamTest_listen
 * @fn TEST_F(InternIOStreamTest, listen_after_close)
 * @brief Checks listen respond as expected to listen after close
 */
TEST_F(InternIOStreamTest, listen_after_close)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    close_rval = 0;
    bind_rval = 0;
    listen_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_TRUE(clientStream.Listen());
    EXPECT_TRUE(serverStream.Listen());

    EXPECT_TRUE(clientStream.isOpen());
    EXPECT_TRUE(serverStream.isOpen());

    clientStream.close();
    serverStream.close();

    EXPECT_FALSE(clientStream.Listen());
    EXPECT_FALSE(serverStream.Listen());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_listen
 * @fn TEST_F(InternIOStreamTest, listen_bind_error)
 * @brief Checks listen respond as expected to bind system call
 */
TEST_F(InternIOStreamTest, listen_bind_error)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    bind_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_FALSE(clientStream.Listen());
    EXPECT_FALSE(serverStream.Listen());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_listen
 * @fn TEST_F(InternIOStreamTest, listen_error)
 * @brief Checks listen respond as expected to listen system call
 */
TEST_F(InternIOStreamTest, listen_error)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    bind_rval = 0;
    listen_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_FALSE(clientStream.Listen());
    EXPECT_FALSE(serverStream.Listen());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_accept
 * @fn TEST_F(InternIOStreamTest, accept_success)
 * @brief Checks accept success
 */
TEST_F(InternIOStreamTest, accept_success)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    bind_rval = 0;
    listen_rval = 0;
    accept_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_TRUE(clientStream.Accept());
    EXPECT_TRUE(serverStream.Accept());

    EXPECT_TRUE(clientStream.isOpen());
    EXPECT_TRUE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_accept
 * @fn TEST_F(InternIOStreamTest, accept_listen_error)
 * @brief Checks accept respond as expected to listen system call
 */
TEST_F(InternIOStreamTest, accept_listen_error)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    bind_rval = 0;
    listen_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_FALSE(clientStream.Accept());
    EXPECT_FALSE(serverStream.Accept());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_accept
 * @fn TEST_F(InternIOStreamTest, accept_error_socket)
 * @brief Checks accept respond as expected to invalid fd
 */
TEST_F(InternIOStreamTest, accept_error_socket)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    clientStream.m_fd = -1;
    serverStream.m_fd = -1;

    EXPECT_FALSE(clientStream.Accept());
    EXPECT_FALSE(serverStream.Accept());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());
}

/**
 * @ingroup InternIOStreamTest_accept
 * @fn TEST_F(InternIOStreamTest, accept_error)
 * @brief Checks accept respond as expected to accept system call
 */
TEST_F(InternIOStreamTest, accept_error)
{
    sock_rval = 2;
    setsockopt_rval = 0;
    bind_rval = 0;
    listen_rval = 0;
    accept_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);
    InternIOStream serverStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    EXPECT_FALSE(serverStream.isOpen());
    EXPECT_EQ(serverStream.GetFD(), 2);

    EXPECT_FALSE(clientStream.Accept());
    EXPECT_FALSE(serverStream.Accept());

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_FALSE(serverStream.isOpen());

}

/**
 * @ingroup InternIOStreamTest_setSoTimeout
 * @fn TEST_F(InternIOStreamTest, setSoTimeout_success)
 * @brief Checks setSoTimeout success
 */
TEST_F(InternIOStreamTest, setSoTimeout_success)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    int timeOut = 1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    clientStream.setSoTimeout(timeOut);
}

/**
 * @ingroup InternIOStreamTest_setSoTimeout
 * @fn TEST_F(InternIOStreamTest, setSoTimeout_fail)
 * @brief Checks setSoTimeout fail
 */
TEST_F(InternIOStreamTest, setSoTimeout_fail)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    int timeOut = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    clientStream.setSoTimeout(timeOut);
}

/**
 * @ingroup InternIOStreamTest_setSoTimeout
 * @fn TEST_F(InternIOStreamTest, setSoTimeout_fail)
 * @brief Checks setSoTimeout fail
 */
TEST_F(InternIOStreamTest, setSoTimeout_fail_setsockopt)
{
    sock_rval = 2;
    setsockopt_rval = 0;

    int timeOut = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    setsockopt_rval = -1;
    clientStream.setSoTimeout(timeOut);
}


/**
 * @ingroup InternIOStreamTest_close
 * @fn TEST_F(InternIOStreamTest, close_failed)
 * @brief Checks close failed
 */
TEST_F(InternIOStreamTest, close_failed)
{
    sock_rval       = 2;
    setsockopt_rval = 0;
    close_rval = -1;

    SPIInetAddress v4addrLB = createIPAddress();
    InternIOStream clientStream(v4addrLB, port);

    EXPECT_FALSE(clientStream.isOpen());
    EXPECT_EQ(clientStream.GetFD(), 2);

    clientStream.close();
}