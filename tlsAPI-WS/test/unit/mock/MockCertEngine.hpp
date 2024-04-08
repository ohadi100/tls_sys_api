/**
 * 
 * @file MockCertEngine.hpp
 * 
 * @brief contains the MockCertEngine class
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

#ifndef MOCK_CERT_ENGINE_HPP
#define MOCK_CERT_ENGINE_HPP

#include <gmock/gmock.h>

#include "TLSCertEngine.hpp"
#include "TLSSocketFactory.h"

namespace vwg
{
namespace tls
{
namespace impl
{
/**
 * @class MockCertEngine
 * @brief Class for google mock for TLSEngine class
 */
class MockCertEngine : public TLSCertEngine
{
public:
    MockCertEngine(std::shared_ptr<IOStreamIf> const&       stream,
                   std::string const&                       hostName,
                   std::string const&                       certStoreId,
                   std::string const&                       clientCertificateSetID,
                   std::vector<HashSha256> const&           httpPublicKeyPinningHashs,
                   int                                      timeDelta,
                   bool                                     revocationCheckEnabled,
                   CipherSuiteIds const&                    cipherSuiteIds,
                   TLSCipherSuiteUseCasesSettings const&    cipherSuiteUseCasesSettings,
                   const AlpnMode&                          alpnMode,
                   std::shared_ptr<ITLSOcspHandler> const&  ocspHandler,
                   const uint32_t                           ocspTimeoutMs);

    MockCertEngine(const MockCertEngine&) = default;

    MOCK_METHOD0(DoSSLHandshake, TLSEngineError(void));
    MOCK_METHOD3(Send, TLSEngineError(const uint8_t* data, int32_t bufLength, int32_t& actualLength));
    MOCK_METHOD3(Receive, TLSEngineError(uint8_t* buffer, int32_t bufLength, int32_t& actualLength));
    MOCK_METHOD0(Shutdown, TLSEngineError(void));
    MOCK_CONST_METHOD0(GetRemoteHintName, const std::string(void));
    MOCK_CONST_METHOD0(GetHintName, const std::string(void));
    MOCK_METHOD0(Close, void(void));
    MOCK_METHOD0(GetIOStream, const std::shared_ptr<IOStream>(void));
    MOCK_METHOD1(SetStream, void(std::shared_ptr<IOStreamIf> stream));
    MOCK_CONST_METHOD0(getUsedAlpnMode, const AlpnMode&(void));
    MOCK_CONST_METHOD0(getUsedProtocol, IANAProtocol(void));
    MOCK_CONST_METHOD0(CheckAuthenticTimeCheck, TLSEngineError(void));
    MOCK_CONST_METHOD0(GetOcspHandler, const std::shared_ptr<ITLSOcspHandler>&(void));
#ifdef TLSAPI_WITH_DROP_SUPPORT
    MOCK_METHOD0(DropTLS, TLSEngineError(void));
#endif
};

class CertEngineUT : public TLSCertEngine
{
public:
    CertEngineUT(std::shared_ptr<IOStreamIf> const&         stream,
                 std::string const&                         hostName,
                 std::string const&                         certStoreId,
                 std::string const&                         clientCertificateSetID,
                 std::vector<HashSha256> const&             httpPublicKeyPinningHashs,
                 bool                                       revocationCheckEnabled,
                 CipherSuiteIds const&                      cipherSuiteIds,
                 TLSCipherSuiteUseCasesSettings const&      cipherSuiteUseCasesSettings,
                 const AlpnMode&                            alpnMode,
                 TimeCheckTime                              checkTime,
                 std::shared_ptr<ITLSOcspHandler> const&    ocspHandler,
                 const uint32_t                             ocspTimeoutMs)
      : TLSCertEngine(stream, CHECK_TIME_OFF, ocspHandler, ocspTimeoutMs)
    {
        (void)hostName;
        (void)certStoreId;
        (void)clientCertificateSetID;
        (void)httpPublicKeyPinningHashs;
        (void)revocationCheckEnabled;
        (void)cipherSuiteIds;
        (void)cipherSuiteUseCasesSettings;
        (void)alpnMode;
        (void)checkTime;
    }

    CertEngineUT(std::shared_ptr<IOStreamIf> const& stream)
      : TLSCertEngine(stream, CHECK_TIME_OFF, nullptr, 0)
    {
    }

    TLSEngineError
    DoSSLHandshake()
    {
        return mMockCertEngine->DoSSLHandshake();
    }

    TLSEngineError
    Send(const uint8_t* data, int32_t bufLength, int32_t& actualLength)
    {
        return mMockCertEngine->Send(data, bufLength, actualLength);
    }

    TLSEngineError
    Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength)
    {
        return mMockCertEngine->Receive(buffer, bufLength, actualLength);
    };

    TLSEngineError
    Shutdown()
    {
        return mMockCertEngine->Shutdown();
    }

    const std::string
    GetRemoteHintName() const
    {
        return mMockCertEngine->GetRemoteHintName();
    }

    const std::string
    GetHintName() const
    {
        return mMockCertEngine->GetHintName();
    }

    void
    Close()
    {
        mMockCertEngine->Close();
    }

    const std::shared_ptr<IOStream>
    GetIOStream()
    {
        return mMockCertEngine->GetIOStream();
    }

    void
    SetStream(std::shared_ptr<IOStreamIf> stream)
    {
        mMockCertEngine->SetStream((stream));
    }

    const AlpnMode&
    getUsedAlpnMode() const
    {
        return mMockCertEngine->getUsedAlpnMode();
    }

    IANAProtocol
    getUsedProtocol() const
    {
        return mMockCertEngine->getUsedProtocol();
    }

    TLSEngineError
    CheckAuthenticTimeCheck() const
    {
        return mMockCertEngine->CheckAuthenticTimeCheck();
    }

    const std::shared_ptr<ITLSOcspHandler>&
    GetOcspHandler() const
    {
        return mMockCertEngine->GetOcspHandler();
    }

#ifdef TLSAPI_WITH_DROP_SUPPORT
    TLSEngineError
    DropTLS()
    {
        return mMockCertEngine->DropTLS();
    }
#endif

    static MockCertEngine* mMockCertEngine;
};
}  // namespace impl
}  // namespace tls
}  // namespace vwg

#endif  // MOCK_CERT_ENGINE_HPP
