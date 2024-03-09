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

#ifndef SACCESSLIB_TLSCLIENTCERTIMPL_H
#define SACCESSLIB_TLSCLIENTCERTIMPL_H

#include "TLSSockets.h"
#include "TLSSocketFactory.h"
#include "TLSSessionEndpointImpl.hpp"
#include "TLSCertEngine.hpp"
#include "ITLSEngine.hpp"
#include "IOStreamIf.hpp"

using vwg::tls::SPIInetAddress;

namespace vwg
{
namespace tls
{
namespace impl
{

    class TLSClientCertImpl : public ITLSClientSocket
    {

    public:
        TLSClientCertImpl(const std::shared_ptr<IOStreamIf>&        stream,
                          const std::string&                        hostName,
                          const CertStoreID&                        certStoreId,
                          const ClientCertificateSetID&             clientCertificateSetID,
                          const CipherSuiteIds&                     cipherSuiteIds,
                          const TLSCipherSuiteUseCasesSettings&     cipherSuiteSettings,
                          const TimeCheckTime&                      checkTime,
                          const std::vector<HashSha256>&            httpPublicKeyPinningHashs,
                          const bool                                revocationCheckEnabled,
                          const std::shared_ptr<ITLSOcspHandler>&   ocspHandler,
                          const uint32_t                            ocspTimeoutMs,
                          bool                                      isFdManagedLocal    = true,
                          const AlpnMode&                           alpnMode            = ALPN_OFF) noexcept;

        // The std::shared_ptr<IOStream> member is destroyed and its memory deallocated when the counter is 0.
        // option 1: the TLSServerSocketImpl owns the object. In TLSClientCertImpl destruction - the counter reaches 0 and the IOstream is destroyed.
        // option 2: the user owns the object. In TLSClientCertImpl destruction - The counter does not reaches 0 and the IOstream is not destroyed.
        ~TLSClientCertImpl();

        virtual TLSResult<std::shared_ptr<ITLSSessionEndpoint>> connect() override;

        virtual Boolean isConnectionSocket() override;

        virtual void close() override;

        virtual Boolean isClosed() override;

        virtual Boolean isOpen() override;

        virtual UInt16 getLocalPort() override;

        virtual SPIInetAddress getLocalInetAddress() override;

        virtual void setSoTimeout(Int32 timeout) override;

        virtual int getSocketFD() override;

        virtual const AlpnMode& getUsedAlpnMode() const  override;

        virtual IANAProtocol getUsedProtocol() const  override;

#ifndef UNIT_TEST
        private:
#endif
        TLSResult<std::shared_ptr<ITLSSessionEndpoint>> createSession();

        std::shared_ptr<IOStreamIf> m_stream;
        std::shared_ptr<TLSCertEngine> m_engine;
        const std::string m_hostName;
        const std::string m_certStoreId;
        const std::string m_clientCertificateSetID;
        const CipherSuiteIds m_cipherSuiteIds;
        const TLSCipherSuiteUseCasesSettings m_cipherSuiteSettings;
        const TimeCheckTime m_checkTime;
        const std::vector<HashSha256> m_httpPublicKeyPinningHashs;
        const bool m_revocationCheckEnabled;
        bool m_isFdManagedLocal;
        const AlpnMode m_alpnMode;
        std::shared_ptr<ITLSOcspHandler> m_ocspHandler;
        const uint32_t m_ocspTimeoutMs;
    };

} // namespace impl
} // namespace tls
} // namespace vwg

#endif //SACCESSLIB_TLSCLIENTCERTIMPL_H