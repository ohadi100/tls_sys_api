/**
 * 
 * @file HelperMock.hpp
 * 
 * @brief contains constructors implementations of MockPSKEngine and MockCertEngine classes
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


#include <gmock/gmock.h>

#include "MockCertEngine.hpp"
#include "MockPSKEngine.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{
MockPSKEngine::MockPSKEngine(const std::shared_ptr<IOStreamIf>& stream,
                             bool                               isServer,
                             const std::string&                 hint,
                             SecurityLevel                      confidentiality)
  : TLSEngine(stream)
{
    (void)isServer;
    (void)hint;
    (void)confidentiality;
}

MockCertEngine::MockCertEngine(std::shared_ptr<IOStreamIf> const&           stream,
                               std::string const&                           hostName,
                               std::string const&                           certStoreId,
                               std::string const&                           clientCertificateSetID,
                               std::vector<HashSha256> const&               httpPublicKeyPinningHashs,
                               int                                          timeDelta,
                               bool                                         revocationCheckEnabled,
                               CipherSuiteIds const&                        cipherSuiteIds,
                               TLSCipherSuiteUseCasesSettings const&        cipherSuiteUseCasesSettings,
                               const AlpnMode&                              alpnMode,
                               std::shared_ptr<ITLSOcspHandler> const&      ocspHandler,
                               const uint32_t                               ocspTimeoutMs)
  : TLSCertEngine(stream, CHECK_TIME_OFF, ocspHandler, ocspTimeoutMs)
{
    (void)hostName;
    (void)certStoreId;
    (void)clientCertificateSetID;
    (void)httpPublicKeyPinningHashs;
    (void)timeDelta;
    (void)revocationCheckEnabled;
    (void)cipherSuiteIds;
    (void)cipherSuiteUseCasesSettings;
    (void)alpnMode;
}

}  // namespace impl
}  // namespace tls
}  // namespace vwg
