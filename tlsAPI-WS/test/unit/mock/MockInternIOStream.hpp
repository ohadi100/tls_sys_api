/**
 * 
 * @file MockInternIOStream.hpp
 * 
 * @brief contains the mock InternIOStream class
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


#ifndef MOCK_INTERNAL_IOSTREAM_HPP
#define MOCK_INTERNAL_IOSTREAM_HPP

#include <gmock/gmock.h>

#include "InternIOStream.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{
/**
 * @class MockInternIOStream
 * @brief Class for google mock for InternIOStream class
 */

class MockInternIOStream : public InternIOStream
{
public:
    ~MockInternIOStream() = default;
    MockInternIOStream(int fd)
      : InternIOStream(fd)
    {
    }
    MOCK_METHOD2(receive, int32_t(void* buf, uint32_t len));
    MOCK_METHOD2(send, int32_t(const void* buf, uint32_t len));
    MOCK_METHOD0(flush, Int32(void));
    MOCK_METHOD0(available, Int32(void));
    MOCK_METHOD0(close, void(void));
    MOCK_METHOD0(isOpen, bool(void));
    MOCK_METHOD0(isClosed, bool(void));
    MOCK_CONST_METHOD0(GetFD, int(void));
    MOCK_CONST_METHOD0(GetConnectionType, SocketType(void));
    MOCK_CONST_METHOD0(GetLocalPort, uint16_t(void));
    MOCK_CONST_METHOD0(GetRemotePort, uint16_t(void));
    MOCK_CONST_METHOD0(GetLocalAddress, SPIInetAddress(void));
    MOCK_CONST_METHOD0(GetRemoteAddress, SPIInetAddress(void));
    MOCK_METHOD1(setSoTimeout, void(Int32 timeout));
    MOCK_METHOD0(isConnectionSocket, Boolean(void));
    MOCK_METHOD0(Connect, bool(void));
    MOCK_METHOD0(Accept, std::shared_ptr<InternIOStream>(void));
};

class InternIOStreamUT : public InternIOStream
{
public:
    ~InternIOStreamUT() = default;

    InternIOStreamUT(int fd)
      : InternIOStream(fd)
    {
    }

    InternIOStreamUT(SPIInetAddress inet, UInt16 port)
      : InternIOStream(inet, port)
    {
    }

    bool
    Connect()
    {
        return mMockInternIOStream->Connect();
    }

    static MockInternIOStream *mMockInternIOStream;
};
}  // namespace impl
}  // namespace tls
}  // namespace vwg

#endif  // MOCK_INTERNAL_IOSTREAM_HPP
