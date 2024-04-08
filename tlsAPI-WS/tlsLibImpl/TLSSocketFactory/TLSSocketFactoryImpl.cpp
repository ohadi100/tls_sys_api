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


#include "TLSSocketFactory.h"

#include <memory>

#ifdef UNIT_TEST

#include "MockInternIOStream.hpp"
#include "MockTLSServerSocketImpl.hpp"

#else
#include "InternIOStream.hpp"
#include "TLSServerSocketImpl.hpp"
#endif

#include "TLSResult.h"
#include "TLSSocketFactoryImpl.hpp"
#include "TLSClientSocketImpl.hpp"
#include "TLSClientCertImpl.hpp"
#include "UserIOStream.hpp"


#include "Logger.hpp"

using vwg::tls::TLSResult;
using vwg::tls::TLSServerSocketResult;
using vwg::tls::TLSClientSocketResult;
using vwg::tls::TLSSessionEndpointResult;
using vwg::tls::impl::TLSSocketFactoryImpl;

#define UNUSED __attribute__((unused))

// Private functions
TLSServerSocketResult TLSSocketFactoryImpl::createServerSocket(std::shared_ptr<InternIOStream> stream,
                                                               const std::string localDomainName,
                                                               const vwg::tls::SecurityLevel confidentiality,
                                                               bool isFdManagedLocal,
                                                               bool droppable/*=false*/) {
    TLSServerSocketResult res(
            std::make_shared<TLSServerSocketImpl>(stream, localDomainName, confidentiality, isFdManagedLocal,
                                                  droppable));
    return res;
}

TLSClientSocketResult TLSSocketFactoryImpl::createClientSocket(std::shared_ptr<IOStreamIf> stream,
                                                               const std::string localDomainName,
                                                               const vwg::tls::SecurityLevel confidentiality,
                                                               bool isFdManagedLocal,
                                                               bool droppable/*=false*/) {
    return TLSResult<SPTLSClientSocket>(
            std::make_shared<TLSClientSocketImpl>(stream, localDomainName, confidentiality, isFdManagedLocal,
                                                  droppable));
}
// End of private functions

vwg::tls::ApiVersionType TLSSocketFactoryImpl::getApiVersion() {
    return m_apiVersion;
}

TLSServerSocketResult TLSSocketFactoryImpl::createServerSocket(SPIInetAddress inet, UInt16 port,
                                                               const std::string localDomainName,
                                                               SecurityLevel confidentiality,
                                                               UNUSED SocketType socketType) {
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(inet, port);
    return createServerSocket(stream, localDomainName, confidentiality, true);
}

TLSServerSocketResult TLSSocketFactoryImpl::createServerSocket(int fd, const std::string localDomainName,
                                                               const vwg::tls::SecurityLevel confidentiality) {
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(fd);
    return createServerSocket(stream, localDomainName, confidentiality, false);
}

TLSSessionEndpointResult TLSSocketFactoryImpl::createPskServerSession(int connectionFd,
                                                                      const std::string localDomainName,
                                                                      const SecurityLevel confidentiality) {
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(connectionFd);
#ifdef UNIT_TEST
    TLSServerSocketResult resServerSocket(
            std::make_shared<TLSServerSocketImplUT>(stream, localDomainName, confidentiality, false, false, true));
#else
    TLSServerSocketResult resServerSocket(std::make_shared<TLSServerSocketImpl>(stream, localDomainName, confidentiality, false, false, true));
#endif
    if (resServerSocket.succeeded()) {
        auto serverSocket = resServerSocket.getPayload();
        return serverSocket->accept();
    }

    return TLSSessionEndpointResult(resServerSocket.getErrorCode());
}

TLSClientSocketResult TLSSocketFactoryImpl::createClientSocket(SPIInetAddress inet, UInt16 port,
                                                               const std::string localDomainName,
                                                               SecurityLevel confidentiality,
                                                               UNUSED SocketType socketType) {
#ifdef UNIT_TEST
    std::shared_ptr<InternIOStream> stream = make_shared<InternIOStreamUT>(inet, port);
#else
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(inet, port);
#endif
    if (!stream->Connect()) {
        return TLSClientSocketResult(RC_TLS_CONNECT_FAILED);
    }
    return createClientSocket(stream, localDomainName, confidentiality, true);
}

TLSClientSocketResult TLSSocketFactoryImpl::createClientSocket(int fd, const std::string localDomainName,
                                                               const vwg::tls::SecurityLevel confidentiality) {
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(fd);
    return createClientSocket(stream, localDomainName, confidentiality, false);
}

TLSClientSocketResult TLSSocketFactoryImpl::createTlsClient(const std::shared_ptr<IOStream> stream,
                                                            const std::string &hostName, const CertStoreID &certStoreId,
                                                            const ClientCertificateSetID &clientCertificateSetID,
                                                            const CipherSuiteIds &cipherSuiteIds,
                                                            const TimeCheckTime &checkTime,
                                                            const std::vector<HashSha256> &httpPublicKeyPinningHashs,
                                                            const bool revocationCheckEnabled) {
    std::shared_ptr<IOStreamIf> streamSp = std::make_shared<UserIOStream>(stream);
    return TLSResult<SPTLSClientSocket>(std::make_shared<TLSClientCertImpl>(streamSp, hostName, certStoreId,
                                                                  clientCertificateSetID, cipherSuiteIds,
                                                                  TLSCipherSuiteUseCasesSettings::CSUSDefault,
                                                                  checkTime, httpPublicKeyPinningHashs,
                                                                  revocationCheckEnabled, nullptr, 0, false));
}

TLSClientSocketResult TLSSocketFactoryImpl::createTlsClient(
        const TLSConnectionSettings &connectionSettings,
        const std::shared_ptr<IOStream> stream,
        const std::string &hostName,
        const CertStoreID &certStoreId,
        const ClientCertificateSetID &clientCertificateSetID,
        const TimeCheckTime &checkTime,
        const std::vector<HashSha256> &httpPublicKeyPinningHashs,
        const bool revocationCheckEnabled) noexcept {
    std::string cipherSuiteIds{};//CipherSuiteUseCasesSettings in use so cipherSuiteIds is empty
    const TLSCipherSuiteUseCasesSettings cipherSuiteUseCasesSettings = connectionSettings.getCipherSuiteUseCasesSettings();
    if (CSUSEndOfEnum <= cipherSuiteUseCasesSettings) {
        FND_LOG_ERROR << "connectionName: " << connectionSettings.getConnectionLoggingName().c_str() << " . Invalid cipher suite list.";
        return TLSClientSocketResult(RC_TLS_ILLEGAL_PARAMETER);
    }

    std::shared_ptr<IOStreamIf> streamSp = std::make_shared<UserIOStream>(stream);
    streamSp->setConnectionLoggingName(connectionSettings.getConnectionLoggingName());
    return TLSResult<SPTLSClientSocket>(std::make_shared<TLSClientCertImpl>(streamSp,
                                                                  hostName,
                                                                  certStoreId,
                                                                  clientCertificateSetID,
                                                                  cipherSuiteIds,
                                                                  cipherSuiteUseCasesSettings,
                                                                  checkTime,
                                                                  httpPublicKeyPinningHashs,
                                                                  revocationCheckEnabled,
                                                                  connectionSettings.getOcspHandler(),
                                                                  connectionSettings.getOcspTimeoutMs(),
                                                                  false,
                                                                  connectionSettings.getAlpnMode()));
}

#ifdef TLSAPI_WITH_DROP_SUPPORT

TLSServerSocketResult TLSSocketFactoryImpl::createDroppableServerSocket(const SPIInetAddress inet, const UInt16 port,
                                                                        const std::string localDomainName,
                                                                        const SecurityLevel confidentiality,
                                                                        UNUSED SocketType socketType) {
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(inet, port);
    return createServerSocket(stream, localDomainName, confidentiality, true, /*droppable=*/true);
}

TLSServerSocketResult TLSSocketFactoryImpl::createDroppableServerSocket(const int fd, const std::string localDomainName,
                                                                        const SecurityLevel confidentiality) {
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(fd);
    return createServerSocket(stream, localDomainName, confidentiality, false, /*droppable=*/true);
}

TLSClientSocketResult TLSSocketFactoryImpl::createDroppableClientSocket(const SPIInetAddress inet, const UInt16 port,
                                                                        const std::string localDomainName,
                                                                        const SecurityLevel confidentiality,
                                                                        UNUSED SocketType socketType) {
#ifdef UNIT_TEST
    std::shared_ptr<InternIOStream> stream = make_shared<InternIOStreamUT>(inet, port);
#else
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(inet, port);
#endif
    if (!stream->Connect()) {
        return TLSClientSocketResult(RC_TLS_CONNECT_FAILED);
    }
    return createClientSocket(stream, localDomainName, confidentiality, true, /*droppable=*/true);
}

TLSClientSocketResult TLSSocketFactoryImpl::createDroppableClientSocket(const int fd, const std::string localDomainName,
                                                                        const SecurityLevel confidentiality) {
    std::shared_ptr<InternIOStream> stream = std::make_shared<InternIOStream>(fd);
    return createClientSocket(stream, localDomainName, confidentiality, false, /*droppable=*/true);
}

TLSClientSocketResult TLSSocketFactoryImpl::createDroppableClientSocket(const std::shared_ptr<IOStream> stream,
                                                                        const std::string localDomainName,
                                                                        const SecurityLevel confidentiality) {
    std::shared_ptr<IOStreamIf> streamSp = std::make_shared<UserIOStream>(stream);
    return createClientSocket(streamSp, localDomainName, confidentiality, false, /*droppable=*/true);
}

#endif