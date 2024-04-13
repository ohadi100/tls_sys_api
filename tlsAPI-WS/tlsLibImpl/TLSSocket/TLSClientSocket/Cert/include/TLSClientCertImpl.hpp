/**
 * @file TLSClientCertImpl.h
 * @brief Defines the TLSClientCertImpl class which implements ITLSClientSocket interface for TLS client certificate operations.
 *
 * This file provides the class definition for TLSClientCertImpl, which is responsible for managing
 * TLS client socket operations using client certificates. It handles the creation of TLS sessions,
 * managing socket connections, and performing socket operations in a secure manner with the use of
 * client certificates.
 *
 * @copyright
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

namespace vwg {
namespace tls {
namespace impl {

/**
 * @class TLSClientCertImpl
 * @brief Implements ITLSClientSocket for handling TLS client socket operations using certificates.
 *
 * This class manages the secure client socket operations, including connecting, sending, and receiving data
 * over TLS using client certificates. It utilizes ITLSEngine for establishing and maintaining the secure connection.
 */
class TLSClientCertImpl : public ITLSClientSocket {
public:
    /**
     * @brief Constructs a TLSClientCertImpl with the specified parameters.
     *
     * Initializes a TLS client socket with configuration for certificates, cipher suites, and optional settings.
     *
     * @param stream A shared pointer to the underlying IO stream interface.
     * @param hostName Host name or IP address for the TLS connection.
     * @param certStoreId Identifier for the certificate store.
     * @param clientCertificateSetID Identifier for the client certificate set.
     * @param cipherSuiteIds List of cipher suite IDs to be used.
     * @param cipherSuiteSettings Settings for cipher suite use cases.
     * @param checkTime Settings for time validation.
     * @param httpPublicKeyPinningHashs List of SHA-256 hashes for HTTP public key pinning.
     * @param revocationCheckEnabled Flag to enable/disable certificate revocation check.
     * @param ocspHandler A shared pointer to the OCSP handler.
     * @param ocspTimeoutMs Timeout in milliseconds for OCSP responses.
     * @param isFdManagedLocal Flag to manage file descriptor locally.
     * @param alpnMode ALPN mode to be used.
     */
    TLSClientCertImpl(const std::shared_ptr<IOStreamIf>& stream,
                      const std::string& hostName,
                      const CertStoreID& certStoreId,
                      const ClientCertificateSetID& clientCertificateSetID,
                      const CipherSuiteIds& cipherSuiteIds,
                      const TLSCipherSuiteUseCasesSettings& cipherSuiteSettings,
                      const TimeCheckTime& checkTime,
                      const std::vector<HashSha256>& httpPublicKeyPinningHashs,
                      const bool revocationCheckEnabled,
                      const std::shared_ptr<ITLSOcspHandler>& ocspHandler,
                      const uint32_t ocspTimeoutMs,
                      bool isFdManagedLocal = true,
                      const AlpnMode& alpnMode = ALPN_OFF) noexcept;

    /**
     * @brief Destructor for TLSClientCertImpl.
     *
     * Ensures proper cleanup of resources, especially the underlying IO stream if owned by this instance.
     */
    ~TLSClientCertImpl();

    virtual TLSResult<std::shared_ptr<ITLSSessionEndpoint>> connect() override;
    virtual Boolean isConnectionSocket() override;
    virtual void
