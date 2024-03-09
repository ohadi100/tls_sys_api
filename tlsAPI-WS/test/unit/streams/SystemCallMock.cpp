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
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>

int sock_rval;
int setsockopt_rval;
int connect_rval;
int close_rval;
int listen_rval;
int bind_rval;
int accept_rval;
int syncfs_rval;
int poll_rval;
int ioctl_rval;
int getsockname_rval;
int getpeername_rval;
ssize_t read_rval;
ssize_t write_rval;
ssize_t recv_rval;
ssize_t send_rval;
uint8_t ntohs_rval;


#ifdef DARWIN_M1_HOST
#define __THROW 
#define __SOCKADDR_ARG                struct sockaddr *__restrict
#define __CONST_SOCKADDR_ARG        __const struct sockaddr *
#define __wur 
#endif

int socket(int domain, int type, int protocol) 
{
    (void)domain;
    (void)(type);
    (void)protocol;

    printf("calling mock socket\n");
    return sock_rval;
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) 
{
    (void)fd;
    (void)level;
    (void)optname;
    (void)optval;
    (void)optlen;

    printf("calling mock setsockopt\n");
    return setsockopt_rval;
}

int connect(int fd, const struct sockaddr * addr, socklen_t len)
{
    (void)fd;
    (void)addr;
    (void)len;

    printf("calling mock connect\n");
    return connect_rval;
}

int close(int fd)
{
    (void)fd;

    printf("calling mock close\n");
    return close_rval;
}

int listen(int fd, int n) 
{
    (void)fd;
    (void)n;

    printf("calling mock listen\n");
    return listen_rval;
}

ssize_t read(int fd, void *buf, size_t nbytes)
{
    (void)fd;
    (void)buf;
    (void)nbytes;

    printf("calling mock read\n");
    return read_rval;
}

ssize_t recv(int fd, void *buf, size_t nbytes, int flags)
{
    (void)fd;
    (void)buf;
    (void)nbytes;
    (void)flags;

    printf("calling mock recv\n");
    return recv_rval;
}

int bind(int fd, const struct sockaddr * addr, socklen_t len) 
{
    (void)fd;
    (void)addr;
    (void)len;

    printf("calling mock bind\n");
    return bind_rval;
}

int accept(int fd, struct sockaddr * addr, socklen_t *__restrict addr_len)
{
    (void)fd;
    (void)addr;
    (void)addr_len;

    printf("calling mock accept\n");
    return accept_rval;
}

ssize_t write(int fd, const void *buf, size_t n)
{
    (void)fd;
    (void)buf;
    (void)n;

    printf("calling mock write\n");
    return write_rval;
}

ssize_t send(int fd, const void *buf, size_t n, int flags)
{
    (void)fd;
    (void)buf;
    (void)n;
    (void)flags;

    printf("calling mock send\n");
    return send_rval;
}

int syncfs(int fd) 
{
    (void)fd;

    printf("calling mock syncfs\n");
    return syncfs_rval;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)fds;
    (void)nfds;
    (void)timeout;

    printf("calling mock poll\n");
    return poll_rval;
}

int ioctl(int fd, unsigned long int request, ...) 
{
    (void)fd;
    (void)request;

    printf("calling mock ioctl\n");
    return ioctl_rval;
}

int getsockname(int fd, struct sockaddr * addr, socklen_t *__restrict len) 
{
    (void)fd;
    (void)addr;
    (void)len;

    printf("calling mock getsockname\n");
    return getsockname_rval;
}

int getpeername(int fd, struct sockaddr * addr, socklen_t *__restrict len) 
{
    (void)fd;
    (void)addr;
    (void)len;

    printf("calling mock getpeername\n");
    return getpeername_rval;
}

#ifndef DARWIN_M1_HOST
uint16_t ntohs(uint16_t __netshort)
{
    (void)__netshort;

    printf("calling mock ntohs\n");
    return ntohs_rval;
}
#endif