/**
 * 
 * @file MockPSKEngine.hpp
 * 
 * @brief contains the mock TLSEngine class
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

#ifndef MOCK_PSK_ENGINE_HPP
#define MOCK_PSK_ENGINE_HPP

#include <gmock/gmock.h>

#include "TLSEngine.hpp"

namespace vwg {
namespace tls {
namespace impl {

/**
 * @class MockPSKEngine
 * @brief Class for google mock for TLSEngine class
 */

class MockPSKEngine : public TLSEngine {
public:
  MockPSKEngine(const std::shared_ptr<IOStreamIf> &stream, bool isServer,
                const std::string &hint, SecurityLevel confidentiality);

  MockPSKEngine(const MockPSKEngine &) = default;

  MOCK_METHOD0(DoSSLHandshake, TLSEngineError(void));
  MOCK_METHOD3(Send, TLSEngineError(const uint8_t *data, int32_t bufLength,
                                    int32_t &actualLength));
  MOCK_METHOD3(Receive, TLSEngineError(uint8_t *buffer, int32_t bufLength,
                                       int32_t &actualLength));
  MOCK_METHOD0(Shutdown, TLSEngineError(void));
  MOCK_CONST_METHOD0(GetRemoteHintName, const std::string(void));
  MOCK_CONST_METHOD0(GetHintName, const std::string(void));
  MOCK_METHOD0(Close, void(void));
  MOCK_METHOD0(GetIOStream, const std::shared_ptr<IOStream>(void));
  MOCK_METHOD1(SetStream, void(std::shared_ptr<IOStreamIf> stream));
  MOCK_METHOD1(SetBlocking, TLSEngineError(bool));
  MOCK_CONST_METHOD0(getUsedAlpnMode, const AlpnMode&(void));
  MOCK_CONST_METHOD0(getUsedProtocol, IANAProtocol(void));
#ifdef TLSAPI_WITH_DROP_SUPPORT
    MOCK_METHOD0(DropTLS, TLSEngineError(void));
#endif
};

class PSKEngineUT : public TLSEngine {
public:
  PSKEngineUT(const std::shared_ptr<IOStreamIf> &stream, bool isServer,
              const std::string &hint, SecurityLevel confidentiality)
      : TLSEngine(stream) {
    (void)isServer;
    (void)hint;
    (void)confidentiality;
  }

  TLSEngineError DoSSLHandshake() {
    return mMockPSKEngine->DoSSLHandshake();
  }

  TLSEngineError Send(const uint8_t *data, int32_t bufLength,
                      int32_t &actualLength) {
    return mMockPSKEngine->Send(data, bufLength, actualLength);
  }

  TLSEngineError Receive(uint8_t *buffer, int32_t bufLength,
                         int32_t &actualLength) {
    return mMockPSKEngine->Receive(buffer, bufLength, actualLength);
  };

  TLSEngineError Shutdown() {
    return mMockPSKEngine->Shutdown();
  }

  const std::string GetRemoteHintName() const {
    return mMockPSKEngine->GetRemoteHintName();
  }

  const std::string GetHintName() const {
    return mMockPSKEngine->GetHintName();
  }

  void Close() {
      mMockPSKEngine->Close();
  }

  const std::shared_ptr<IOStream> GetIOStream() {
    return mMockPSKEngine->GetIOStream();
  }

  void SetStream(std::shared_ptr<IOStreamIf> stream) {
    mMockPSKEngine->SetStream((stream));
  }

  TLSEngineError SetBlocking(bool blocking) {
    return mMockPSKEngine->SetBlocking(blocking);
  }

  const AlpnMode& getUsedAlpnMode() const
  {
      return mMockPSKEngine->getUsedAlpnMode();
  }

  IANAProtocol getUsedProtocol() const
  {
      return mMockPSKEngine->getUsedProtocol();
  }

#ifdef TLSAPI_WITH_DROP_SUPPORT
    TLSEngineError DropTLS()
    {
        return mMockPSKEngine->DropTLS();
    }
#endif

  static MockPSKEngine *mMockPSKEngine;
};
} // namespace impl
} // namespace tls
} // namespace vwg

#endif // MOCK_PSK_ENGINE_HPP
