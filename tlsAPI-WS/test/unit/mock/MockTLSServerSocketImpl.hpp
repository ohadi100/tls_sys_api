/**
 * 
 * @file MockTLSServerSocketImpl.hpp
 * 
 * @brief contains the mock TLSServerSocketImpl class
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


#ifndef MOCK_TLS_SERVER_SOCKET_IMPL_HPP
#define MOCK_TLS_SERVER_SOCKET_IMPL_HPP

#include <gmock/gmock.h>

#include "TLSServerSocketImpl.hpp"

namespace vwg {
namespace tls {
namespace impl {

/**
 * @class MockTLSServerSocketImpl
 * @brief Class for google mock for TLSServerSocketImpl class
 */

class MockTLSServerSocketImpl : public TLSServerSocketImpl {
public:
  MockTLSServerSocketImpl(std::shared_ptr<InternIOStream> spStream,
                          const std::string &hint,
                          SecurityLevel confidentiality,
                          bool isFdManagedLocal = true, bool droppable = false,
                          bool isConnectionFd = false)
      : TLSServerSocketImpl(spStream, hint, confidentiality, isFdManagedLocal,
                            droppable, isConnectionFd) {}

  MockTLSServerSocketImpl(const MockTLSServerSocketImpl &) = default;

  MOCK_METHOD1(setSoTimeout, void(Int32 timeout));
  MOCK_METHOD0(getSocketFD, int(void));
  MOCK_METHOD0(accept, TLSSessionEndpointResult(void));
  MOCK_METHOD0(isConnectionSocket, Boolean(void));
  MOCK_METHOD0(close, void(void));
  MOCK_METHOD0(isClosed, Boolean(void));
  MOCK_METHOD0(isOpen, Boolean(void));
  MOCK_METHOD0(getLocalPort, UInt16(void));
  MOCK_METHOD0(getLocalInetAddress, SPIInetAddress(void));
  MOCK_METHOD1(createSession, TLSSessionEndpointResult(
                                  std::shared_ptr<InternIOStream> stream));
};

class TLSServerSocketImplUT : public TLSServerSocketImpl {
public:
  TLSServerSocketImplUT(std::shared_ptr<InternIOStream> spStream,
                        const std::string &hint, SecurityLevel confidentiality,
                        bool isFdManagedLocal = true, bool droppable = false,
                        bool isConnectionFd = false)
      : TLSServerSocketImpl(spStream, hint, confidentiality, isFdManagedLocal,
                            droppable, isConnectionFd) {}

  void setSoTimeout(Int32 timeout) {
    mMockTLSServerSocketImpl->setSoTimeout(timeout);
  }

  int getSocketFD() {
    return mMockTLSServerSocketImpl->getSocketFD();
  }

  TLSSessionEndpointResult accept() {
    return mMockTLSServerSocketImpl->accept();
  }

  Boolean isConnectionSocket() {
    return mMockTLSServerSocketImpl->isConnectionSocket();
  }

  void close() {
    mMockTLSServerSocketImpl->close();
  }

  Boolean isClosed() {
    return mMockTLSServerSocketImpl->isClosed();
  }

  Boolean isOpen() {
    return mMockTLSServerSocketImpl->isOpen();
  }

  UInt16 getLocalPort() {
    return mMockTLSServerSocketImpl->getLocalPort();
  }

  SPIInetAddress getLocalInetAddress() {
    return mMockTLSServerSocketImpl->getLocalInetAddress();
  }

  TLSSessionEndpointResult
  getLocalPort(std::shared_ptr<InternIOStream> stream) {
    return mMockTLSServerSocketImpl->createSession(stream);
  }

  static MockTLSServerSocketImpl *mMockTLSServerSocketImpl;
};
} // namespace impl
} // namespace tls
} // namespace vwg

#endif // MOCK_TLS_SERVER_SOCKET_IMPL_HPP
