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

#ifndef SRC_TLSSOCKETFACTORYIMPL_H_
#define SRC_TLSSOCKETFACTORYIMPL_H_

#include <memory>

#include "TLSSocketFactory.h"
#include "InetAddress.h"
#include "IOStreamIf.hpp"
#include "InternIOStream.hpp"

namespace vwg {
namespace tls {
namespace impl {

class TLSSocketFactoryImpl : public ITLSSocketFactory {
public:
    TLSSocketFactoryImpl() = default;

    virtual ~TLSSocketFactoryImpl() = default;

    ApiVersionType getApiVersion() override;

    TLSServerSocketResult createServerSocket(SPIInetAddress inet, UInt16 port,
                                             std::string localDomainName,
                                             SecurityLevel confidentiality,
                                             SocketType socketType) override;

    TLSServerSocketResult createServerSocket(int fd,
                                             const std::string localDomainName,
                                             const SecurityLevel confidentiality) override;

    TLSSessionEndpointResult createPskServerSession(int connectionFd,
                                               const std::string localDomainName,
                                               const SecurityLevel confidentiality) override;

    TLSClientSocketResult createClientSocket(SPIInetAddress inet,  UInt16 port,
                                             std::string localDomainName,
                                             SecurityLevel confidentiality,
                                             SocketType socketType) override;

    TLSClientSocketResult createClientSocket(int fd,
                                             const std::string localDomainName,
                                             const SecurityLevel confidentiality) override;

    TLSClientSocketResult createTlsClient(const std::shared_ptr<IOStream> stream,
                                            const std::string& hostName, const CertStoreID& certStoreId,
                                            const  ClientCertificateSetID &clientCertificateSetID,
                                            const CipherSuiteIds& cipherSuiteIds, const TimeCheckTime& checkTime,
                                             const std::vector<HashSha256>& httpPublicKeyPinningHashs,
					    const bool revocationCheckEnabled = false) override;

    TLSClientSocketResult createTlsClient(
            const TLSConnectionSettings &connectionSettings,
            const std::shared_ptr<IOStream> stream,
            const std::string& hostName,
            const CertStoreID& certStoreId,
            const ClientCertificateSetID &clientCertificateSetID,
            const TimeCheckTime& checkTime,
            const std::vector<HashSha256>& httpPublicKeyPinningHashs,
            const bool revocationCheckEnabled = false) noexcept override;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    TLSServerSocketResult createDroppableServerSocket(SPIInetAddress inet, UInt16 port,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality,
                                                      SocketType socketType = SOCKETTYPE_STREAM) override;

    TLSServerSocketResult createDroppableServerSocket(int fd,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality) override;

    TLSClientSocketResult createDroppableClientSocket(SPIInetAddress inet, UInt16 port,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality,
                                                      SocketType socketType = SOCKETTYPE_STREAM) override;

    TLSClientSocketResult createDroppableClientSocket(int fd,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality) override;

    TLSClientSocketResult createDroppableClientSocket(std::shared_ptr<IOStream> stream,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality) override;
#endif

private:
    TLSServerSocketResult createServerSocket(std::shared_ptr<InternIOStream> stream,
                                             const std::string localDomainName,
                                             const vwg::tls::SecurityLevel confidentiality,
                                             bool isFdManagedLocal,
                                             bool droppable=false);

    TLSClientSocketResult createClientSocket(std::shared_ptr<IOStreamIf> stream,
                                             const std::string localDomainName,
                                             const vwg::tls::SecurityLevel confidentiality,
                                             bool isFdManagedLocal,
                                             bool droppable=false);

    ApiVersionType m_apiVersion = ApiVersion;
};

} /* namespace impl */
} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_TLSSOCKETFACTORYIMPL_H_ */
