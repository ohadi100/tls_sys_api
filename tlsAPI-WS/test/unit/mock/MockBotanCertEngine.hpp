/**
 * 
 * @file MockBotanCertEngine.hpp
 * 
 * @brief contains the mock BotanCertEngine
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

#ifndef MOCK_BOTAN_CERT_ENGINE_HPP
#define MOCK_BOTAN_CERT_ENGINE_HPP

#include <gmock/gmock.h>

#include "BotanCertEngine.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{
/**
 * @class MockBotanCertEngine
 * @brief Class for google mock for BotanCertEngine class
 */
class MockBotanCertEngine : public BotanCertEngine
{
public:
    MockBotanCertEngine(
        std::shared_ptr<IOStreamIf>          stream                   ,
        const std::string&                   hostName                  = {},
        std::string                          certStoreId               = {},
        std::string                          clientCertificateSetID    = {},
        const std::vector<HashSha256>        httpPublicKeyPinningHashs = {},
        const bool                           revocationCheckEnabled    = true,
        const CipherSuiteIds                 cipherSuiteIds            = {},
        const TLSCipherSuiteUseCasesSettings cipherSuiteSettings       = TLSCipherSuiteUseCasesSettings::CSUSDefault,
        const AlpnMode&                      alpnMode                  = ALPN_OFF,
        const TimeCheckTime&                 checkTime                 = CHECK_TIME_OFF,
        std::shared_ptr<ITLSOcspHandler>     ocspHandler               = nullptr,
        const uint32_t                       ocspTimeoutMs             = 0);

    MockBotanCertEngine(const MockBotanCertEngine&) = default;

    ~MockBotanCertEngine() = default;

    MOCK_METHOD0(DoSSLHandshake, TLSEngineError(void));
    MOCK_METHOD3(Send, TLSEngineError(const uint8_t* data, int32_t bufLength, int32_t& actualLength));
    MOCK_METHOD3(Receive, TLSEngineError(uint8_t* buffer, int32_t bufLength, int32_t& actualLength));
    MOCK_METHOD0(Shutdown, TLSEngineError(void));
    MOCK_CONST_METHOD0(GetRemoteHintName, const std::string(void));
    MOCK_CONST_METHOD0(GetHintName, const std::string(void));
    MOCK_METHOD0(Close, void(void));
    MOCK_METHOD1(SetStream, void(std::shared_ptr<IOStreamIf> stream));
    MOCK_CONST_METHOD0(GetIOStream, const std::shared_ptr<IOStream>(void));
    MOCK_CONST_METHOD0(getUsedAlpnMode, const AlpnMode&(void));
    MOCK_CONST_METHOD0(getUsedProtocol, IANAProtocol(void));
    MOCK_CONST_METHOD0(CheckAuthenticTimeCheck, TLSEngineError(void));
    MOCK_METHOD1(SetReceivedAlert, void(Botan::TLS::Alert::Type));
    MOCK_METHOD0(GetRevocationCheckEnable, bool(void));
    MOCK_METHOD0(GetCipherSuiteUseCase, TLSCipherSuiteUseCasesSettings(void));
};

}  // namespace impl
}  // namespace tls
}  // namespace vwg
#endif  // MOCK_BOTAN_CERT_ENGINE_HPP
