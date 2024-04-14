/**
 * @file TLSSocketFactoryImpl.h
 * @brief Implementation of the ITLSSocketFactory interface for creating TLS sockets.
 *
 * This file provides the implementation details of TLSSocketFactoryImpl which encapsulates
 * the functionality necessary for creating various types of TLS-secured sockets including
 * server sockets, client sockets, and session endpoints, potentially supporting droppable connections.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All information and materials contained herein, including intellectual and technical concepts,
 * are the property of CARIAD SE and may be covered by patents, patents in process, and are protected
 * by trade secret and/or copyright law.
 *
 * The reproduction, dissemination, modification, distribution, public performance, public display,
 * or any other use of this source code without the prior written consent of CARIAD SE is strictly prohibited
 * and in violation of applicable laws. The receipt or possession of this source code does not convey
 * or imply any rights to reproduce, disclose or distribute its contents, or to manufacture, use,
 * or sell anything that it may describe, in whole or in part.
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

/**
 * @class TLSSocketFactoryImpl
 * @brief Implementation of ITLSSocketFactory for creating different types of TLS sockets.
 *
 * TLSSocketFactoryImpl provides methods to create server and client TLS sockets with various configurations,
 * including support for pre-shared keys (PSK) and certificate-based sessions. It can also create droppable
 * sockets if the build is configured with TLSAPI_WITH_DROP_SUPPORT.
 */
class TLSSocketFactoryImpl : public ITLSSocketFactory {
public:
    /**
     * @brief Constructs a TLSSocketFactoryImpl object.
     */
    TLSSocketFactoryImpl() = default;

    /**
     * @brief Destructs the TLSSocketFactoryImpl object.
     */
    virtual ~TLSSocketFactoryImpl() = default;

    /**
     * @brief Retrieves the API version implemented by this factory.
     *
     * @return The implemented API version as ApiVersionType.
     */
    ApiVersionType getApiVersion() override;

    /**
     * @brief Creates a TLS secured server socket.
     *
     * @param[in] inet Internet address where the server will be bound.
     * @param[in] port Port number for the socket.
     * @param[in] localDomainName Domain name for identifying the server in the network.
     * @param[in] confidentiality Security level of the connection.
     * @param[in] socketType Type of the socket, default is stream (TCP).
     * @return A TLSServerSocketResult containing either a pointer to the server socket or an error code.
     */
    TLSServerSocketResult createServerSocket(SPIInetAddress inet, UInt16 port,
                                             std::string localDomainName,
                                             SecurityLevel confidentiality,
                                             SocketType socketType = SOCKETTYPE_STREAM) override;

    /**
     * @brief Creates a TLS secured server socket using an existing file descriptor.
     *
     * @param[in] fd File descriptor for the socket.
     * @param[in] localDomainName Domain name for identifying the server in the network.
     * @param[in] confidentiality Security level of the connection.
     * @return A TLSServerSocketResult containing either a pointer to the server socket or an error code.
     */
    TLSServerSocketResult createServerSocket(int fd,
                                             const std::string localDomainName,
                                             const SecurityLevel confidentiality) override;

    /**
     * @brief Creates a pre-shared key (PSK) server session.
     *
     * @param[in] connectionFd File descriptor for the connection.
     * @param[in] localDomainName Domain name for identifying the server in the network.
     * @param[in] confidentiality Security level of the connection.
     * @return A TLSSessionEndpointResult containing either a pointer to the session endpoint or an error code.
     */
    TLSSessionEndpointResult createPskServerSession(int connectionFd,
                                                    const std::string localDomainName,
                                                    const SecurityLevel confidentiality) override;

    /**
     * @brief Creates a TLS secured client socket.
     *
     * @param[in] inet Internet address of the server to connect.
     * @param[in] port Port number of the socket.
     * @param[in] localDomainName Domain name for identifying the client in the network.
     * @param[in] confidentiality Security level of the connection.
     * @param[in] socketType Type of the socket, default is stream (TCP).
     * @return A TLSClientSocketResult containing either a pointer to the client socket or an error code.
     */
    TLSClientSocketResult createClientSocket(SPIInetAddress inet, UInt16 port,
                                             std::string localDomainName,
                                             SecurityLevel confidentiality,
                                             SocketType socketType = SOCKETTYPE_STREAM) override;

    /**
     * @brief Creates a TLS secured client socket using an existing file descriptor.
     *
     * @param[in] fd File descriptor for the socket.
     * @param[in] localDomainName Domain name for identifying the client in the network.
     * @param[in] confidentiality Security level of the connection.
     * @return A TLSClientSocketResult containing either a pointer to the client socket or an error code.
     */
    TLSClientSocketResult createClientSocket(int fd,
                                             const std::string localDomainName,
                                             const SecurityLevel confidentiality) override;

    /**
     * @brief Creates a TLS secured client using a custom stream and advanced options.
     *
     * @param[in] stream IOStream used for the connection.
     * @param[in] hostName Host name to use for the connection.
     * @param[in] certStoreId Identifier for the certificate store.
     * @param[in] clientCertificateSetID Identifier for the client certificate set.
     * @param[in] cipherSuiteIds List of cipher suites to use.
     * @param[in] checkTime Time checks for certificate validation.
     * @param[in] httpPublicKeyPinningHashs List of hashes for HTTP Public Key Pinning.
     * @param[in] revocationCheckEnabled Flag to enable revocation checking.
     * @return A TLSClientSocketResult containing either a pointer to the client socket or an error code.
     */
    TLSClientSocketResult createTlsClient(const std::shared_ptr<IOStream> stream,
                                          const std::string& hostName, const CertStoreID& certStoreId,
                                          const ClientCertificateSetID &clientCertificateSetID,
                                          const CipherSuiteIds& cipherSuiteIds, const TimeCheckTime& checkTime,
                                          const std::vector<HashSha256>& httpPublicKeyPinningHashs,
                                          const bool revocationCheckEnabled = false) override;

    /**
     * @brief Creates a TLS secured client with advanced connection settings.
     *
     * @param[in] connectionSettings Settings for the TLS connection including ALPN modes.
     * @param[in] stream IOStream used for the connection.
     * @param[in] hostName Host name to use for the connection.
     * @param[in] certStoreId Identifier for the certificate store.
     * @param[in] clientCertificateSetID Identifier for the client certificate set.
     * @param[in] checkTime Time checks for certificate validation.
     * @param[in] httpPublicKeyPinningHashs List of hashes for HTTP Public Key Pinning.
     * @param[in] revocationCheckEnabled Flag to enable revocation checking.
     * @return A TLSClientSocketResult containing either a pointer to the client socket or an error code.
     */
    TLSClientSocketResult createTlsClient(
            const TLSConnectionSettings &connectionSettings,
            const std::shared_ptr<IOStream> stream,
            const std::string& hostName,
            the CertStoreID& certStoreId,
            the ClientCertificateSetID &clientCertificateSetID,
            the TimeCheckTime& checkTime,
            the std::vector<HashSha256>& httpPublicKeyPinningHashs,
            the bool revocationCheckEnabled = false) noexcept override;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * @brief Creates a droppable TLS secured server socket.
     *
     * @param[in] inet Internet address where the server will be bound.
     * @param[in] port Port number for the socket.
     * @param[in] localDomainName Domain name for identifying the server in the network.
     * @param[in] confidentiality Security level of the connection.
     * @param[in] socketType Type of the socket, default is stream (TCP).
     * @return A TLSServerSocketResult containing either a pointer to the server socket or an error code.
     */
    TLSServerSocketResult createDroppableServerSocket(SPIInetAddress inet, UInt16 port,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality,
                                                      SocketType socketType = SOCKETTYPE_STREAM) override;

    /**
     * @brief Creates a droppable TLS secured server socket using an existing file descriptor.
     *
     * @param[in] fd File descriptor for the socket.
     * @param[in] localDomainName Domain name for identifying the server in the network.
     * @param[in] confidentiality Security level of the connection.
     * @return A TLSServerSocketResult containing either a pointer to the server socket or an error code.
     */
    TLSServerSocketResult createDroppableServerSocket(int fd,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality) override;

    /**
     * @brief Creates a droppable TLS secured client socket.
     *
     * @param[in] inet Internet address of the server to connect.
     * @param[in] port Port number of the socket.
     * @param[in] localDomainName Domain name for identifying the client in the network.
     * @param[in] confidentiality Security level of the connection.
     * @param[in] socketType Type of the socket, default is stream (TCP).
     * @return A TLSClientSocketResult containing either a pointer to the client socket or an error code.
     */
    TLSClientSocketResult createDroppableClientSocket(SPIInetAddress inet, UInt16 port,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality,
                                                      SocketType socketType = SOCKETTYPE_STREAM) override;

    /**
     * @brief Creates a droppable TLS secured client socket using an existing file descriptor.
     *
     * @param[in] fd File descriptor for the socket.
     * @param[in] localDomainName Domain name for identifying the client in the network.
     * @param[in] confidentiality Security level of the connection.
     * @return A TLSClientSocketResult containing either a pointer to the client socket or an error code.
     */
    TLSClientSocketResult createDroppableClientSocket(int fd,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality) override;

    /**
     * @brief Creates a droppable TLS secured client socket using a custom stream.
     *
     * @param[in] stream IOStream used for the connection.
     * @param[in] localDomainName Domain name for identifying the client in the network.
     * @param[in] confidentiality Security level of the connection.
     * @return A TLSClientSocketResult containing either a pointer to the client socket or an error code.
     */
    TLSClientSocketResult createDroppableClientSocket(std::shared_ptr<IOStream> stream,
                                                      std::string localDomainName,
                                                      SecurityLevel confidentiality) override;
#endif

private:
    /**
     * @brief Helper function to create a server socket with an InternIOStream.
     *
     * @param[in] stream IOStream used for the connection.
     * @param[in] localDomainName Domain name for identifying the server in the network.
     * @param[in] confidentiality Security level of the connection.
     * @param[in] isFdManagedLocal Flag indicating if the file descriptor is managed locally.
     * @param[in] droppable Flag indicating if the socket is droppable.
     * @return A TLSServerSocketResult containing either a pointer to the server socket or an error code.
     */
    TLSServerSocketResult createServerSocket(std::shared_ptr<InternIOStream> stream,
                                             const std::string localDomainName,
                                             const vwg::tls::SecurityLevel confidentiality,
                                             bool isFdManagedLocal,
                                             bool droppable=false);

    /**
     * @brief Helper function to create a client socket with an IOStreamIf.
     *
     * @param[in] stream IOStream used for the connection.
     * @param[in] localDomainName Domain name for identifying the client in the network.
     * @param[in] confidentiality Security level of the connection.
     * @param[in] isFdManagedLocal Flag indicating if the file descriptor is managed locally.
     * @param[in] droppable Flag indicating if the socket is droppable.
     * @return A TLSClientSocketResult containing either a pointer to the client socket or an error code.
     */
    TLSClientSocketResult createClientSocket(std::shared_ptr<IOStreamIf> stream,
                                             const std::string localDomainName,
                                             the vwg::tls::SecurityLevel confidentiality,
                                             bool isFdManagedLocal,
                                             bool droppable=false);

    ApiVersionType m_apiVersion = ApiVersion; ///< API version supported by this factory.
};

} /* namespace impl */
} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_TLSSOCKETFACTORYIMPL_H_ */
