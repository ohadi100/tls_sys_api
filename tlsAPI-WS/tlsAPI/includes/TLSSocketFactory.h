/**
 * @file TLSSocketFactory.h
 * @brief Interface definition for the TLS socket factory used to create secured TLS server and client sockets.
 *
 * This file provides the interface for a TLS socket factory, which is capable of creating both server and client
 * sockets that are secured using TLS. This involves handling all underlying network and security configurations.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All information and materials contained herein, including intellectual and technical concepts,
 * are the property of CARIAD SE and may be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * The reproduction, dissemination, modification, distribution, public performance, display or any other use of this
 * source code and/or any other information and/or material contained herein without the prior written consent of
 * CARIAD SE is strictly prohibited and in violation of applicable laws.
 */

#ifndef SRC_TLSSOCKETFACTORY_H_
#define SRC_TLSSOCKETFACTORY_H_

#include <memory>
#include <vector>
#include "vwgtypes.h"
#include "TLSApiTypes.h"
#include "TLSSession.h"
#include "TLSSockets.h"
#include "IOStream.h"
#include "CipherSuitesDefinitions.h"

namespace vwg {
namespace tls {

using ClientCertificateSetID = std::string;
const ClientCertificateSetID CLINET_CERTIFICATE_SET_BASE = "BASE";
using HashSha256 = std::vector<char>;
using CertStoreID = std::string;

/**
 * @class ITLSSocketFactory
 * @brief Interface for the TLS socket factory responsible for creating TLS-secured sockets.
 *
 * This interface provides methods to create TLS-secured server and client sockets based on predefined
 * security levels and configurations. The factory is intended to handle all aspects of socket creation,
 * including applying security protocols and configurations.
 */
class ITLSSocketFactory {
public:
    ITLSSocketFactory() = default;
    virtual ~ITLSSocketFactory() = default;

    /**
     * @brief Retrieves the API version implemented by the factory.
     * @return The API version as a string.
     * @since 1.1.0
     */
    virtual ApiVersionType getApiVersion() const = 0;

    /**
     * @brief Creates a TLS-secured server socket using the specified parameters.
     * @param inet The internet address where the server will listen.
     * @param port The port number on which the server will accept connections.
     * @param localDomainName The domain name associated with the server for SSOA.
     * @param securityLevel The security level required for the connections.
     * @param socketType The type of socket, default is STREAM (TCP).
     * @return A result structure containing either the server socket or an error code.
     */
    virtual TLSServerSocketResult createServerSocket(SPIInetAddress inet, const UInt16 port,
                                                     const std::string localDomainName, const SecurityLevel securityLevel,
                                                     const SocketType socketType = SOCKETTYPE_STREAM) = 0;

    /**
     * @brief Creates a TLS-secured server session using an existing file descriptor.
     * @param connectionFd The file descriptor for an already established connection.
     * @param localDomainName The domain name associated with the server for SSOA.
     * @param confidentiality The required confidentiality level for the session.
     * @return A result structure containing either the session endpoint or an error code.
     */
    virtual TLSSessionEndpointResult createPskServerSession(int connectionFd, const std::string localDomainName,
                                                            const SecurityLevel confidentiality) = 0;

    /**
     * @brief Creates a TLS-secured server socket using an existing file descriptor.
     * @param fd The file descriptor for an already established socket.
     * @param localDomainName The domain name associated with the server for SSOA.
     * @param confidentiality The required confidentiality level for the session.
     * @return A result structure containing either the server socket or an error code.
     */
    virtual TLSServerSocketResult createServerSocket(int fd, const std::string localDomainName,
                                                     const SecurityLevel confidentiality) = 0;

    /**
     * @brief Creates a TLS-secured client socket using the specified parameters.
     * @param inet The internet address of the server to connect to.
     * @param port The port number on which to establish the connection.
     * @param localDomainName The domain name associated with the client for SSOA.
     * @param confidentiality The required confidentiality level for the connection.
     * @param socketType The type of socket, default is STREAM (TCP).
     * @return A result structure containing either the client socket or an error code.
     */
    virtual TLSClientSocketResult createClientSocket(SPIInetAddress inet, const UInt16 port,
                                                     const std::string localDomainName, const SecurityLevel confidentiality,
                                                     const SocketType socketType = SOCKETTYPE_STREAM) = 0;

    /**
     * @brief Creates a TLS-secured client socket using an existing file descriptor.
     * @param fd The file descriptor for an already connected socket.
     * @param localDomainName The domain name associated with the client for SSOA.
     * @param confidentiality The required confidentiality level for the connection.
     * @return A result structure containing either the client socket or an error code.
     */
    virtual TLSClientSocketResult createClientSocket(int fd, const std::string localDomainName,
                                                     const SecurityLevel confidentiality) = 0;

    /**
     * @brief Creates a TLS-secured client endpoint using certificates over a given socket stream.
     * @param stream The stream representing the socket where encrypted data are read from or written to.
     * @param hostName The hostname for server verification and SNI.
     * @param certStoreId The ID of the certificate store containing necessary certificates.
     * @param clientCertificateSetID Identifier for the client certificate set to use.
     * @param cipherSuiteIds List of cipher suites to use.
     * @param checkTime Optional time check for certificate validation.
     * @param httpPublicKeyPinningHashs Optional support for HTTP Public Key Pinning.
     * @param revocationCheckEnabled Flag to enable OCSP revocation checking.
     * @return A result structure containing either the client socket or an error code.
     * @deprecated Since version 1.1.0, please use method with ALPN support.
     */
    virtual TLSClientSocketResult createTlsClient(const std::shared_ptr<IOStream> stream, const std::string& hostName,
                                                  const CertStoreID& certStoreId, const ClientCertificateSetID& clientCertificateSetID,
                                                  const CipherSuiteIds& cipherSuiteIds, const TimeCheckTime& checkTime,
                                                  const std::vector<HashSha256>& httpPublicKeyPinningHashs,
                                                  const bool revocationCheckEnabled = false) = 0;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * @brief Creates a droppable TLS-secured server socket. Available only in special MOD socks builds.
     * @param inet The internet address where the server will listen.
     * @param port The port number on which the server will accept connections.
     * @param localDomainName The domain name associated with the server for SSOA.
     * @param securityLevel The security level required for the connections.
     * @param socketType The type of socket, typically STREAM (TCP).
     * @return A result structure containing either the server socket or an error code.
     */
    virtual TLSServerSocketResult createDroppableServerSocket(SPIInetAddress inet, const UInt16 port,
                                                              const std::string localDomainName, const SecurityLevel securityLevel,
                                                              const SocketType socketType = SOCKETTYPE_STREAM) = 0;

    /**
     * @brief Creates a droppable TLS-secured client socket. Available only in special MOD socks builds.
     * @param inet The internet address of the server to connect to.
     * @param port The port number on which to establish the connection.
     * @param localDomainName The domain name associated with the client for SSOA.
     * @param securityLevel The required confidentiality level for the connection.
     * @param socketType The type of socket, typically STREAM (TCP).
     * @return A result structure containing either the client socket or an error code.
     */
    virtual TLSClientSocketResult createDroppableClientSocket(SPIInetAddress inet, const UInt16 port,
                                                              const std::string localDomainName, the SecurityLevel securityLevel,
                                                              const SocketType socketType = SOCKETTYPE_STREAM) = 0;
#endif
};

using ITLSSocketFactoryResult = TLSResult<std::shared_ptr<ITLSSocketFactory>>;

} // namespace tls
} // namespace vwg

#endif /* SRC_TLSSOCKETFACTORY_H_ */
