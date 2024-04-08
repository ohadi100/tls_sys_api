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


#ifndef SRC_TLSSOCKETFACTORY_H_
#define SRC_TLSSOCKETFACTORY_H_


#include <memory>
#include <vector>

#include "vwgtypes.h"
#include "TLSApiTypes.h"
#include "TLSSession.h"
#include "TLSSockets.h"
#include "IOStream.h"
#include "CipherSuitesDefenitions.h"

namespace vwg
{
namespace tls
{
using ClientCertificateSetID                           = std::string;
const ClientCertificateSetID CLINET_CERTICATE_SET_BASE = "BASE";
using HashSha256                                       = std::vector<char>;
using CertStoreID                                      = std::string;


/**
 * \brief This is the interface of the socket factory.
 * One need to get an instance of this interface to create a server or a client socket.
 * Use the function initTLSLib to get the instance of the factory.
 * The implementation will have only one instance of the factory.
 */
class ITLSSocketFactory
{
public:
    ITLSSocketFactory()          = default;
    virtual ~ITLSSocketFactory() = default;

public:
    /**
     *   \brief  Gets the api version which is implemented.
     *   \return the API Version.
     *   \since 1.1.0
     */
    virtual ApiVersionType getApiVersion() = 0;

    /**
     * \brief Factory for creation of TLS secured server socket.
     *
     * This factory method will create underlying server socket and will use a SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reasons for this are:
     * a) to be independent, form the manifest management. So this api can also be used for certificate
     * based TLS connections, which will not have an security manifest (see CE Device Support).
     * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
     * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port as a
     * separated function.
     *
     * The PSK Key Mapping must be also defined as an external dependency.
     *
     * \param[in] inet the given Inet address for the socket, where the server network socket is opened. see
     * http://man7.org/linux/man-pages/man2/socket.2.html keep in mind the a system can have more than one inet address,
     * therefore one need to provide the IP address.
     * \param[in] port the port number of the socket.
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key have to be used. (see Secure service
     * communication Secure service-oriented architecture (sSOA) Technische Entwicklung, Querschnittslastenheft: LAH.000.036).
     * \param[in] securityLevel the SSOA confidentiality (see Secure service communication LHA).
     * This call will accept only the security levels AUTHENTIC_WITHPSK, CONFIDENTIAL_WITHPSK.
     * \param[in] socketType defines the socket to be stream socket (TCP).
     *
     * \return
     * <p> TLSServerSocketResult with socket or error code, the expected error code can be:
     *  <ul>
     *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
     *    <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_SUCCESSFUL</li>
     *    <li>RC_TLS_INIT_FAILED</li>
     *    <li>RC_TLS_PROGRAMMING_ERROR_RESULT</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_PEER_CLOSED</li>
     *    <li>RC_TLS_INVALID_IP</li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     *  </ul>
     * </p>
     */
    virtual TLSServerSocketResult createServerSocket(SPIInetAddress      inet,
                                                     const UInt16        port,
                                                     const std::string   localDomainName,
                                                     const SecurityLevel securityLevel,
                                                     const SocketType    socketType = SOCKETTYPE_STREAM) = 0;

    /**
     * \brief Factory for creation of TLS secured server socket.
     *
     * This factory method will create underlying server socket and will use a SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reasons for this are:
     * a) to be independent, form the manifest management. So this api can also be used for certificate
     * based TLS connections, which will not have an security manifest (see CE Device Support).
     * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
     * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port as a
     * separated function.
     *
     * The PSK Key Mapping must be also defined as an external dependency.
     *
     * \param[in] connectionFd the FD is an already open and accepted connection.
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key have to be used.
     * (see Secure service communication Secure service-oriented architecture (sSOA)
     * Technische Entwicklung, Querschnittslastenheft: LAH.000.036).
     * \param[in] confidentiality the SSOA confidentiality (see Secure service communication LHA).
     * This call will accept only the security levels AUTHENTIC_WITHPSK, CONFIDENTIAL_WITHPSK.
     * 
     * \note TLS lib will close only file descriptors that are created by the library and is not responsible for closing file descriptors created by the user. externally created file descriptors should be closed by the user.
     *
     * \return
     * <p> TLSSessionEndpointResult with socket after handshake or error code the expected error code can be:
     *  <ul>
     *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
     *    <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_SUCCESSFUL</li>
     *    <li>RC_TLS_INIT_FAILED</li>
     *    <li>RC_TLS_PROGRAMMING_ERROR_RESULT</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_PEER_CLOSED</li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     *  </ul>
     * </p>
     */
    virtual TLSSessionEndpointResult createPskServerSession(int                 connectionFd,
                                                            const std::string   localDomainName,
                                                            const SecurityLevel confidentiality) = 0;

    /**
     * \brief Factory for creation of TLS secured server socket.
     *
     * This factory method will create underlying server socket and will use a SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reasons for this are:
     * a) to be independent, form the manifest management. So this api can also be used for certificate based TLS connections,
     * which will not have an security manifest (see CE Device Support).
     * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
     * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port as a
     * separated function.
     *
     * The PSK Key Mapping must be also defined as an external dependency
     *
     * \param[in] fd the fd of the socket. Responsibility is solely by the user of the api, the lib assumes the
     * fd is already initiated.
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key have to be used.
     * (see Secure service communication Secure service-oriented architecture (sSOA) Technische
     * Entwicklung, Querschnittslastenheft: LAH.000.036).
     * \param[in] confidentiality the SSOA confidentiality (see Secure service communication LHA).
     * This call will accept only the security levels AUTHENTIC_WITHPSK, CONFIDENTIAL_WITHPSK.
     * 
     * \note TLS lib will close only file descriptors that are created by the library and is not responsible for closing file descriptors created by the user. externally created file descriptors should be closed by the user.
     *
     * \return
     * <p> TLSServerSocketResult with socket or error code the expected error code can be :
     *  <ul>
     *    <li>RC_TLS_SUCCESSFUL</li> <li>RC_TLS_WOULD_BLOCK_WRITE</li> <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_INIT_FAILED</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_PROGRAMMING_ERROR_RESULT</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_PEER_CLOSED</li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     *  </ul>
     * </p>
     */
    virtual TLSServerSocketResult createServerSocket(int                 fd,
                                                     const std::string   localDomainName,
                                                     const SecurityLevel confidentiality) = 0;

    /**
     * \brief Factory for creation of TLS secured client socket.
     *
     * This factory method will create underlying server socket and will use an SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reasons for this are:
     * a) to be independent, form the manifest management. So this api can
     * also be used for certificate based TLS connections, which will not have an security manifest (see CE Device Support).
     * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
     * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port as a
     * separated function.
     *
     * The PSK Key Mapping must be also defined as an external dependency.
     *
     * \param[in] inet the given Inet address for the server to connect.
     * \param[in] port the port number of the socket.
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key have to be used.
     * (see Secure service communication Secure service-oriented architecture (sSOA) Technische Entwicklung,
     * Querschnittslastenheft: LAH.000.036).
     * \param[in] confidentiality the SSOA confidentiality (see Secure service
     * communication LHA) This call will accept only the security levels AUTHENTIC_WITHPSK or CONFIDENTIAL_WITHPSK.
     *
     * \return
     * <p> TLSClientSocketResult with socket or an error code, the expected error code can be:
     *  <ul>
     *    <li>RC_TLS_SUCCESSFUL </li>
     *    <li>RC_TLS_INIT_FAILED </li>
     *    <li>RC_TLS_CONNECT_FAILED</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     *    <li>RC_TLS_INVALID_IP</li>
     *  </ul>
     * </p>
     */
    virtual TLSClientSocketResult createClientSocket(SPIInetAddress      inet,
                                                     const UInt16        port,
                                                     const std::string   localDomainName,
                                                     const SecurityLevel confidentiality,
                                                     const SocketType    socketType = SOCKETTYPE_STREAM) = 0;

    /**
     * \brief Factory for creation of TLS secured client socket.
     *
     * This factory method will create underlying server socket and will use an SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reasons for this are:
     * a) to be independent, form the manifest management. So this api can
     * also be used for certificate based TLS connections, which will not have an security manifest (see CE Device Support).
     * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
     * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port as a
     * separated function.
     *
     * The PSK Key Mapping must be also defined as an external dependency.
     *
     * \param[in] fd the fd of the socket. Must be connected before creating. responsibilty is solely by the
     * user of the api.
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key
     * have to be used. (see Secure service communication Secure service-oriented architecture (sSOA) Technische
     * Entwicklung, Querschnittslastenheft: LAH.000.036).
     * \param[in] confidentiality  the SSOA confidentiality (see Secure service communication LHA)
     * This call will accept only the security levels AUTHENTIC_WITHPSK or CONFIDENTIAL_WITHPSK.
     * 
     * \note TLS lib will close only file descriptors that are created by the library and is not responsible for closing file descriptors created by the user. externally created file descriptors should be closed by the user.
     *
     * \return <p> TLSClientSocketResult with socket or an error code the expected error code:
     * can be <ul> <li>RC_TLS_SUCCESSFUL </li> <li>RC_TLS_INIT_FAILED </li> <li>RC_TLS_CONNECT_FAILED</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     * </ul></p>
     */
    virtual TLSClientSocketResult createClientSocket(int                 fd,
                                                     const std::string   localDomainName,
                                                     const SecurityLevel confidentiality) = 0;

    /**
    * \brief factory for creation of TLS secured client end point on top of a given socket using certificates,
    * using a stream instead of a socket.
    *
    * <p>
    * This connection will use the common TLS certificate based handshake according to the RFC 5246 for mutual
    * authorization ( https://www.ietf.org/rfc/rfc5246.txt ).
    * this factory method will a session endpoint on top of a given OS client socket  (see
    * http://pubs.opengroup.org/onlinepubs/7908799/xns/socket.html).
    * It assumes the the socket is already bounded and accepted, by the user of the method. In general it is within the
    * method user responsibility to manage the socket.
    * Especially it is important the the method user will not manipulate the socket in parallel nor call the
    * creatTlsClientEndpoint multiple times on the same socket.
    * Any derivation  may cause unexpected behavior.
    * The method will try to make the TLS handshake on the given connection, which may fail to the undefined state of
    * the socket connection.
    * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
    * mandatory parameter. The reasons for this are:
    * a) to be independent, form the manifest management. So this api can also be used for certificate based TLS
    * connections, which will not have an security manifest (see CE Device Support).
    * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
    * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port
    * as a separated function.
    * </p>
    *
    * <p>
    * Security aspects.
    * 1. The TLS connect will be always use "Service Name Indication". The "Service Name Indication" will be implemented
    * according to <b>RFC 6066</b> (see https://tools.ietf.org/html/rfc6066).
    * The "Service Name Indication" check will using the given domain name, which have to to be compliant to <b>RFC 5890</b>.
    * 2. Certficates....
    * </p>
    *
    * \param[in] stream this is stream implementation playing the role of the socket where the encrypted data are written
    * to or read from. The stream must be connected before the creating. If a multi-threaded system is used,
    * make sure that the stream implementation includes a timeout value in the send and receive operations,
    * without compromising the server's ability to listen and accept overtime.
    * \param[in] hostName :
    * a) use the name to ensure the backend server will be authentic (server ID verification)
    * b) this must be valid host(domain) name for performing "Service Name Indication" (SNI)  (see also
    * ps://de.wikipedia.org/wiki/Server_Name_Indication)
    * the domainName must not be empty, it is mandatory to perform the "Service Name Indication" and
    * "server ID verification" in any case.
    * \param[in] certStoreId the ID of the certificate store. This certificate store shall be located in the trust zone
    * and contain all relevant certificates.
    * predefined "VMKS": for VKMS  Root Certificate(s), other for Trust Stores as contained in VI Trust Store Container
    * \param[in] clientCertificateSetID this defines the usage of the client key. This will define the if the key is used,
    * if yes the location where the key is located and the key ID   within the store.
    * \param[in] cipherSuiteIds A vector containing the list of supported cipher suites (ciphers defined in TLS- QLAH).
    * If vector is empty (or contain only invalid options), default cipher pre defined use case will be used
    * (TLSCipherSuiteUseCasesSettings::CSUSDefault use case).
    * \param[in] checkTime do the time check in addition to the certificate validity check. This check will verify
    * if the certificate check time. This check can be omitted, by using null for this parameter.
    * \param[in] httpPublicKeyPinningHashs this is optional to support the HTTP Public Key pinning according to RFC 7469 (see
    * https://tools.ietf.org/html/rfc7469 for the RFC and https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning for more
    * details).
    * basically this means at least one pin value must match any certificate in the full certificate chain.
    * \param[in] revocationCheckEnabled this is optional if set OCSP will be used.
    *
    * \return
     * <p> TLSClientSocketResult with socket or error code the expected error code can be:
    *  <ul>
    *    <li>RC_TLS_SUCCESSFUL </li>
    *    <li>RC_TLS_INIT_FAILED </li>
    *    <li>RC_TLS_CONNECT_FAILED</li>
    *    <li>RC_TLS_IO_ERROR</li>
    *    <li>RC_TLS_WOULD_BLOCK_READ</li>
    *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
    *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
    *    <li>RC_TLS_BAD_RECORD_MAC </li>
    *    <li>RC_TLS_RECORD_OVERFLOW  </li>
    *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
    *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
    *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
    *    <li>RC_TLS_ACCESS_DENIED </li>
    *    <li>RC_TLS_DECODE_ERROR </li>
    *    <li>RC_TLS_DECRYPT_ERROR  </li>
    *    <li>RC_TLS_PROTOCOL_VERSION  </li>
    *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
    *    <li>RC_TLS_NO_RENEGOTIATION  </li>
    *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
    *    <li>RC_TLS_PEER_CLOSED</li>
    *    <li>RC_TLS_SEND_AFTER_SHUTDOWN</li>
    *    <li>RC_TLS_PUBLIC_KEY_PINNING_FAILED </li>
    *    <li>RC_TLS_BAD_CERTIFICATE </li>
    *    <li>RC_TLS_UNSUPPORTED_CERTIFICATE </li>
    *    <li>RC_TLS_CERTIFICATE_REVOKED </li>
    *    <li>RC_TLS_CERTIFICATE_EXPIRE </li>
    *    <li>RC_TLS_CERTIFICATE_UNKNOWN </li>
    *    <li>RC_TLS_UNKNOWN_CA </li>
    *  </ul>
    * </p>
    *
    * @deprecated this method becomes deprecated since 1.1.0, please use method with ALPN support.
    *
    */
    virtual TLSClientSocketResult createTlsClient(const std::shared_ptr<IOStream> stream,
                                                  const std::string&              hostName,
                                                  const CertStoreID&              certStoreId,
                                                  const ClientCertificateSetID&   clientCertificateSetID,
                                                  const CipherSuiteIds&           cipherSuiteIds,
                                                  const TimeCheckTime&            checkTime,
                                                  const std::vector<HashSha256>&  httpPublicKeyPinningHashs,
                                                  const bool                      revocationCheckEnabled = false) = 0;

   /**
    * \brief Factory for creation of TLS secured client end point on top of a given socket using certificates, using a
    * stream instead of a socket.
    * <p>
    * This connection will use the common TLS certificate based handshake according to the RFC 5246 for
    * mutual authorization (https://www.ietf.org/rfc/rfc5246.txt).
    * this factory method will a session endpoint on top of a given OS client socket (see
    * http://pubs.opengroup.org/onlinepubs/7908799/xns/socket.html).
    * It assumes the socket is already bounded and accepted, by the user of the method. In general it is within the
    * method user responsibility to manage the socket.
    * Especially it is important the method user will not manipulate the socket in parallel nor call the
    * creatTlsClientEndpoint multiple times on the same socket.
    * Any derivation may cause unexpected behavior.
    * The method will try to make the TLS handshake on the given connection, which may fail to the undefined state
    * of the socket connection.
    * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
    * mandatory parameter. The reasons for this are
    * a) to be independent, form the manifest management. So this api can also be used for certificate based TLS
    * connections, which will not have an security manifest (see CE Device Support).
    * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
    * confidentiality correct. Therefore it may be a useful method to have the method
    * getConfidentality4Port as a separated function.
    * </p>
    *
    * <p>
    * Security aspects.
    * 1. The TLS connect will be always use "Service Name Indication". The "Service Name Indication" will be implemented
    * according to <b>RFC 6066</b> (see https://tools.ietf.org/html/rfc6066)
    * The "Service Name Indication" check will using the given domain name, which have to to be compliant to <b>RFC 5890</b>.
    * 2. Certificates....
    * </p>
    *
    * \param[in] connectionSettings This basic setting is used to define the ALPN mode and the set of cipher suite used.
    *  There is a set of predefined setting which can be used.
    * \param[in] stream   this is stream implementation playing the role of the socket where the encrypted data
    * are written to or read from. The stream must be connected before the creating.
    * If a multi-threaded system is used, make sure that the stream implementation includes a timeout value
    * in the send and receive operations, without compromising the server's ability to listen and accept overtime.
    * \param[in] hostName
    * a) use the name to ensure the backend server will be authentic (server ID verification).
    * b) this must be valid host(domain) name for performing "Service Name Indication" (SNI)
    * (see also ps://de.wikipedia.org/wiki/Server_Name_Indication) domainName must not be empty, it is mandatory to
    * perform the "Service Name Indication" and "server ID verification" in any case.
    * \param[in] certStoreId the ID of the certificate store. This certificate store shall be located in the trust zone and
    * contain all relevant certificates. predefined "VMKS": for VKMS  Root Certificate(s),
    * other for Trust Stores as contained in VI Trust Store Container.
    * \param[in] clientCertificateSetID this defines the usage of the client key. This will define the if the key is used,
    * if yes the location where the key is located and the key ID   within the store.
    * \param[in] checkTime do the time check in addition to the certificate validity check. This check will verify
    * if the certificate check time. This check can be omitted, by using null for this parameter.
    * \param[in] httpPublicKeyPinningHashs this is an optional to support the HTTP Public Key pinning according to RFC 7469
    * (see https://tools.ietf.org/html/rfc7469 for the RFC and https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
    * for more details). basically this means at least one pin value must match any certificate in the
    * full certificate chain.
    * \param[in] revocationCheckEnabled this is optional if set OCSP will be used.
    *
    * \return
    * <p> TLSClientSocketResult with socket or an error code, the expected error code can be:
    *  <ul>
    *    <li>RC_TLS_SUCCESSFUL </li>
    *    <li>RC_TLS_INIT_FAILED </li>
    *    <li>RC_TLS_CONNECT_FAILED</li>
    *    <li>RC_TLS_IO_ERROR</li>
    *    <li>RC_TLS_WOULD_BLOCK_READ</li>
    *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
    *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
    *    <li>RC_TLS_BAD_RECORD_MAC </li>
    *    <li>RC_TLS_RECORD_OVERFLOW  </li>
    *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
    *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
    *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
    *    <li>RC_TLS_ACCESS_DENIED </li>
    *    <li>RC_TLS_DECODE_ERROR </li>
    *    <li>RC_TLS_DECRYPT_ERROR  </li>
    *    <li>RC_TLS_PROTOCOL_VERSION  </li>
    *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
    *    <li>RC_TLS_NO_RENEGOTIATION  </li>
    *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
    *    <li>RC_TLS_PEER_CLOSED</li>
    *    <li>RC_TLS_SEND_AFTER_SHUTDOWN</li>
    *    <li>RC_TLS_PUBLIC_KEY_PINNING_FAILED </li>
    *    <li>RC_TLS_BAD_CERTIFICATE </li>
    *    <li>RC_TLS_UNSUPPORTED_CERTIFICATE </li>
    *    <li>RC_TLS_CERTIFICATE_REVOKED </li>
    *    <li>RC_TLS_CERTIFICATE_EXPIRE </li>
    *    <li>RC_TLS_CERTIFICATE_UNKNOWN </li>
    *    <li>RC_TLS_NO_APPLICATION_PROTOCOL</li>
    *    <li>RC_TLS_UNKNOWN_CA </li>
    *  </ul>
    * </p>
    *
    * \since 1.1.0
    */
    virtual TLSClientSocketResult createTlsClient(
            const TLSConnectionSettings &connectionSettings,
            const std::shared_ptr<IOStream> stream,
            const std::string& hostName,
            const CertStoreID& certStoreId,
            const ClientCertificateSetID &clientCertificateSetID,
            const TimeCheckTime& checkTime,
            const std::vector<HashSha256>& httpPublicKeyPinningHashs,
            const bool revocationCheckEnabled = false) noexcept = 0;

    /**
     * \def use the define <b> TLSAPI_WITH_DROP_SUPPORT </b> to generate the special library for the MOD socks implementation.
     * Only for the MOD socks implementation the sockets with droppable shall be present. The default the library implementation shall not provide droppable sockets.
     */
	 #ifdef TLSAPI_WITH_DROP_SUPPORT

    /**
     * \brief Factory for creation of TLS secured server socket.
     *
     * <b> Caution! This method all only be present for the MOD socks implementation. By default the method shall not be
     * present. This function shall be present only in the generated library for the MOD socks implementation. use
     * definition TLSAPI_WITH_DROP_SUPPORT  provided by the makefile to generate special MOD socks. </b>
     *
     * This factory method will create underlying server socket and will use an SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reasons for this are:
     * a) to be independent, form the manifest management. So this api can also be used for certificate based TLS connections,
     * which will not have an security manifest (see CE Device Support).
     * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the confidentiality correct.
     * Therefore it may be a useful method to have the method getConfidentality4Port as a separated function.
     *
     * The PSK Key Mapping must be also defined a an external dependency.
     *
     * \param[in] inet the given Inet address for the socket, where the server network socket is opened. see
     * http://man7.org/linux/man-pages/man2/socket.2.html keep in mind the a system can have more than one inet address,
     * therefore one need to provide the IP address.
     * \param[in] port the port number of the socket
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key have to be used.
     * (see Secure service communication Secure service-oriented architecture (sSOA) Technische Entwicklung, Querschnittslastenheft:
     * LAH.000.036).
     * \param[in] securityLevel the SSOA confidentiality (see Secure service communication LHA).
     * \param[in] socketType defines the socket to be stream socket (TCP).
     *
     * \return
     * <p> TLSServerSocketResult with socket or error code the expected error code can be:
     *  <ul>
     *   <li>RC_TLS_WOULD_BLOCK_WRITE</li>
     *    <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_SUCCESSFUL</li>
     *    <li>RC_TLS_INIT_FAILED</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_PROGRAMMING_ERROR_RESULT</li>
     *    <li>RC_TLS_DROPPING_NOTSUPPORTED</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_PEER_CLOSED</li>
     *    <li>RC_TLS_INVALID_IP</li>
     *    <li>RC_TLS_DROPPING_FAILED        </li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     *  </ul>
     * </p>
     */
    virtual TLSServerSocketResult createDroppableServerSocket(SPIInetAddress      inet,
                                                              const UInt16        port,
                                                              const std::string   localDomainName,
                                                              const SecurityLevel securityLevel,
                                                              const SocketType    socketType = SOCKETTYPE_STREAM) = 0;

    /**
     * \brief Factory for creation of TLS secured server socket.
     *
     * <b>Caution! This method all only be present for the MOD socks implementation. By default the method shall not be
     * present. This function shall be present only in the generated library for the MOD socks implementation. use
     * definition TLSAPI_WITH_DROP_SUPPORT  provided by the makefile to generate special MOD socks. </b>
     *
     * this factory method will create underlying server socket and will use an SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reason for this is a) to be independent, form the manifest management. So this api can
     * also be used for certificate based TLS connections, which will not have an security manifest (see CE Device
     * Support). b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
     * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port as a
     * separated function.
     *
     * The PSK Key Mapping must be also defined a an external dependency.
     *
     * \param[in] fd the fd of the socket. Must be connected before creating. responsibilty is solely by the user of the api.
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key
     * have to be used. (see Secure service communication Secure service-oriented architecture (sSOA) Technische
     * Entwicklung, Querschnittslastenheft: LAH.000.036).
     * \param[in] confidentiality the SSOA confidentiality (see Secure service communication LHA).
     * 
     * \note TLS lib will close only file descriptors that are created by the library and is not responsible for closing file descriptors created by the user. externally created file descriptors should be closed by the user.
     *
     * \return
     * <p> TLSServerSocketResult with socket or error code the expected error code can be:
     *  <ul>
     *    <li>RC_TLS_SUCCESSFUL</li>
     *    <li>RC_TLS_INIT_FAILED</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_PROGRAMMING_ERROR_RESULT</li>
     *    <li>RC_TLS_DROPPING_NOTSUPPORTED</li>
     *    <li>RC_TLS_DROPPING_FAILED		</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_PEER_CLOSED</li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     *  </ul>
     * </p>
     */
    virtual TLSServerSocketResult createDroppableServerSocket(int           fd,
                                                              std::string   localDomainName,
                                                              SecurityLevel confidentiality) = 0;

    /**
     * \brief Factory for creation of TLS secured client socket.
     *
     * <b>Caution! This method all only be present for the MOD socks implementation. By default the method shall not be
     * present. This function shall be present only in the generated library for the MOD socks implementation. use
     * definition TLSAPI_WITH_DROP_SUPPORT  provided by the makefile to generate special MOD socks. </b>
     *
     * This factory method will create underlying server socket and will use an SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reasons for this are:
     * a) to be independent, form the manifest management. So this api can also be used for certificate based TLS connections,
     * which will not have an security manifest (see CE Device Support).
     * b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
     * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port as a separated function.
     *
     * The PSK Key Mapping must be also defined as an external dependency.
     *
     * \param[in] inet the given Inet address for the server to connect.
     * \param[in] port the port number of the socket
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key have to be used.
     * (see Secure service communication Secure service-oriented architecture (sSOA) Technische Entwicklung,
     * Querschnittslastenheft: LAH.000.036).
     * \param[in] securityLevel the SSOA confidentiality (see Secure service communication LHA).
     * \param[in] socketType defines the socket to be stream socket (TCP).
     *
     * \return
     * <p> TLSClientSocketResult with socket or error code the expected error code can be:
     *  <ul>
     *    <li>RC_TLS_DROPPING_NOTSUPPORTED</li>
     *    <li>RC_TLS_DROPPING_FAILED        </li>
     *    <li>RC_TLS_INVALID_IP</li>
     *    <li>RC_TLS_SUCCESSFUL </li>
     *    <li>RC_TLS_INIT_FAILED </li>
     *    <li>RC_TLS_CONNECT_FAILED</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     * </ul>
     * </p>
     */
    virtual TLSClientSocketResult createDroppableClientSocket(SPIInetAddress      inet,
                                                              const UInt16        port,
                                                              const std::string   localDomainName,
                                                              const SecurityLevel securityLevel,
                                                              const SocketType    socketType = SOCKETTYPE_STREAM) = 0;

    /**
     * \brief Factory for creation of TLS secured client socket.
     *
     * <b> Caution! This method all only be present for the MOD socks implementation. By default the method shall not be
     * present. This function shall be present only in the generated library for the MOD socks implementation. use
     * definition TLSAPI_WITH_DROP_SUPPORT  provided by the makefile to generate special MOD socks. </b>
     *
     * This factory method will create underlying server socket and will use a SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reason for this is a) to be independent, form the manifest management. So this api can
     * also be used for certificate based TLS connections, which will not have an security manifest (see CE Device
     * Support). b) in case of port multiplexing in conjunction with IP routing this can be difficult to calculate the
     * confidentiality correct. Therefore it may be a useful method to have the method getConfidentality4Port as a
     * separated function.
     *
     * The PSK Key Mapping must be also defined as an external dependency.
     *
     * \param[in] fd the fd of the socket. Must be connected before creating. responsibility is solely by the
     * user of the api.
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key
     * have to be used. (see Secure service communication Secure service-oriented architecture (sSOA) Technische
     * Entwicklung, Querschnittslastenheft: LAH.000.036).
     * \param[in] confidentiality the SSOA confidentiality (see Secure service communication LHA).
     * 
     * \note TLS lib will close only file descriptors that are created by the library and is not responsible for closing file descriptors created by the user. externally created file descriptors should be closed by the user.
     *
     * \return
     * <p> TLSClientSocketResult with socket or error code the expected error code can be:
     *  <ul>
     *    <li>RC_TLS_DROPPING_NOTSUPPORTED</li> <li>RC_TLS_DROPPING_FAILED        </li>
     *    <li>RC_TLS_SUCCESSFUL </li>
     *    <li>RC_TLS_INIT_FAILED </li>
     *    <li>RC_TLS_CONNECT_FAILED</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     *  </ul>
     * </p>
     */
    virtual TLSClientSocketResult createDroppableClientSocket(int           fd,
                                                              std::string   localDomainName,
                                                              SecurityLevel confidentiality) = 0;

    /**
     * \brief Factory for creation of TLS secured client socket.
     *
     * <b> Caution! This method all only be present for the MOD socks implementation. By default the method shall not be
     * present. This function shall be present only in the generated library for the MOD socks implementation.
     * use definition TLSAPI_WITH_DROP_SUPPORT  provided by the makefile to generate special MOD socks. </b>
     *
     * This factory method will create underlying server socket and will use a SSL library.
     * In contrast to the EB/Conti solution the network socket is created by the TLSSocket and the confidentiality is a
     * mandatory parameter. The reason for this is
     * a) to be independent, form the manifest management. So this api can also be used for certificate based TLS
     * connections, which will not have an security manifest (see CE Device Support). b) in case of port multiplexing in
     * conjunction with IP routing this can be difficult to calculate the confidentiality correct. Therefore it may be a
     * useful method to have the method getConfidentality4Port as a separated function.
     *
     * The PSK Key Mapping must be also defined a an external dependency.
     *
     * \param[in] stream the socket stream. Must be connected before creating. responsibilty is solely by the user of the api.
     * \param[in] localDomainName the SSOA defined domain name. Depending on the domain name the PSK key have to be
     * used. (see Secure service communication Secure service-oriented architecture (sSOA) Technische Entwicklung,
     * Querschnittslastenheft: LAH.000.036).
     * \param[in] confidentiality the SSOA confidentiality (see Secure service
     * communication LHA).
     *
     * \return
     * <p> TLSClientSocketResult with socket or error code the expected error code can be:
     *  <ul>
     *    <li>RC_TLS_DROPPING_NOTSUPPORTED</li>
     *    <li>RC_TLS_DROPPING_FAILED        </li>
     *    <li>RC_TLS_SUCCESSFUL </li>
     *    <li>RC_TLS_INIT_FAILED </li>
     *    <li>RC_TLS_CONNECT_FAILED</li>
     *    <li>RC_TLS_IO_ERROR</li>
     *    <li>RC_TLS_WOULD_BLOCK_READ</li>
     *    <li>RC_TLS_WOULD_BLOCK_WRITE</li>
     *    <li>RC_TLS_UNEXPECTED_MESSAGE </li>
     *    <li>RC_TLS_BAD_RECORD_MAC </li>
     *    <li>RC_TLS_RECORD_OVERFLOW  </li>
     *    <li>RC_TLS_DECOMPRESSION_FAILURE </li>
     *    <li>RC_TLS_HANDSHAKE_FAILURE  </li>
     *    <li>RC_TLS_ILLEGAL_PARAMETER </li>
     *    <li>RC_TLS_ACCESS_DENIED </li>
     *    <li>RC_TLS_DECODE_ERROR </li>
     *    <li>RC_TLS_DECRYPT_ERROR  </li>
     *    <li>RC_TLS_PROTOCOL_VERSION  </li>
     *    <li>RC_TLS_INSUFFICIENT_SECURITY  </li>
     *    <li>RC_TLS_NO_RENEGOTIATION  </li>
     *    <li>RC_TLS_UNSUPPORTED_EXTENSION </li>
     *  </ul>
     * </p>
     */
    virtual TLSClientSocketResult createDroppableClientSocket(std::shared_ptr<IOStream> stream,
                                                              std::string               localDomainName,
                                                              SecurityLevel             confidentiality) = 0;

#endif
};


using ITLSSocketFactoryResult = TLSResult<std::shared_ptr<ITLSSocketFactory>>;

} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_TLSSOCKETFACTORY_H_ */
