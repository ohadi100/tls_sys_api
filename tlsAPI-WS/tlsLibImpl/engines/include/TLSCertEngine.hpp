/**
 * @file TLSCertEngine.hpp
 * @brief Defines the TLSCertEngine class which implements the ITLSEngine interface.
 *
 * This file contains the definition of the TLSCertEngine class, which provides
 * functionalities to handle TLS operations such as handshake, sending and receiving
 * data securely, and managing TLS sessions with OCSP support.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All information and materials contained herein, including intellectual and technical
 * concepts, are the property of CARIAD SE and may be covered by patents, patents in process,
 * and are protected by trade secret and/or copyright law.
 *
 * Reproduction, dissemination, modification, distribution, public performance,
 * public display, or any other use of this source code without the prior written consent
 * of CARIAD SE is strictly prohibited and in violation of applicable laws.
 *
 * Possession of this source code does not convey or imply any rights to reproduce,
 * disclose, or distribute its contents, or to manufacture, use, or sell anything that it
 * may describe, in whole or in part.
 */

#ifndef SACCESSLIB_TLSCERTENGINE_HPP
#define SACCESSLIB_TLSCERTENGINE_HPP

#include <functional>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "IOStreamIf.hpp"
#include "ITLSEngine.hpp"
#include "TLSEngine.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{

/**
 * @class TLSCertEngine
 * @brief TLS Certificate Engine for managing secure communications.
 *
 * TLSCertEngine implements ITLSEngine to provide methods for TLS communication using
 * certificates. It supports operations like SSL handshake, sending and receiving data,
 * and session management.
 */
class TLSCertEngine : public ITLSEngine
{
public:
    /**
     * @brief Constructs a TLSCertEngine with a stream and optional time checks.
     *
     * @param stream The underlying IO stream used by the engine to perform I/O operations.
     * @param checkTime Specifies time checking parameters to validate certificate validity against.
     */
    TLSCertEngine(std::shared_ptr<IOStreamIf> const& stream, const TimeCheckTime& checkTime);

    /**
     * @brief Constructs a TLSCertEngine with OCSP support.
     *
     * @param stream The underlying IO stream used by the engine.
     * @param checkTime Time check settings for certificate validation.
     * @param ocspHandler Handler for OCSP requests and responses.
     * @param ocspTimeoutMs Timeout in milliseconds for OCSP responses.
     */
    TLSCertEngine(std::shared_ptr<IOStreamIf> const&      stream,
                  const TimeCheckTime&                    checkTime,
                  std::shared_ptr<ITLSOcspHandler> const& ocspHandler,
                  const uint32_t                          ocspTimeoutMs);

    /**
     * @brief Destructor.
     */
    virtual ~TLSCertEngine() = default;

    /**
     * @brief Performs the SSL handshake.
     *
     * @return TLS engine error code indicating the result of the handshake.
     */
    virtual TLSEngineError DoSSLHandshake() = 0;

    /**
     * @brief Sends data securely over the TLS connection.
     *
     * @param buffer Pointer to the data buffer.
     * @param bufLength Length of the buffer.
     * @param actualLength Length of the data actually sent.
     * @return TLS engine error code.
     */
    virtual TLSEngineError Send(const uint8_t* buffer, int32_t bufLength, int32_t& actualLength) = 0;

    /**
     * @brief Receives data securely over the TLS connection.
     *
     * @param buffer Pointer to the buffer to store received data.
     * @param bufLength Length of the buffer.
     * @param actualLength Length of the data actually received.
     * @return TLS engine error code.
     */
    virtual TLSEngineError Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) = 0;

    /**
     * @brief Sets the blocking mode for the underlying stream.
     *
     * @param blocking True for blocking mode, false for non-blocking.
     * @return TLS engine error code.
     */
    virtual TLSEngineError SetBlocking(bool blocking);

    /**
     * @brief Initiates a shutdown of the TLS session by sending a close notify alert.
     *
     * @return TLS engine error code.
     */
    virtual TLSEngineError Shutdown() = 0;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * @brief Initiates the TLS drop process.
     *
     * This is only available if TLSAPI_WITH_DROP_SUPPORT is defined.
     * @return TLS engine error code.
     */
    virtual TLSEngineError DropTLS() override;
#endif

    /**
     * @brief Returns the IOStream associated with the TLS engine.
     *
     * @return Shared pointer to the IOStream.
     */
    const std::shared_ptr<IOStreamIf> GetIOStream() const;

    /**
     * @brief Returns the OCSP handler used by the TLS engine.
     *
     * @return Shared pointer to the OCSP handler.
     */
    const std::shared_ptr<ITLSOcspHandler>& GetOcspHandler() const;

    /**
     * @brief Returns the timeout for OCSP responses.
     *
     * @return Timeout in milliseconds.
     */
    uint32_t GetOcspTimeout() const;

    /**
     * @brief Validates the system time against the expected time settings.
     *
     * @return TLS engine error code based on the time check result.
     */
    virtual TLSEngineError CheckAuthenticTimeCheck() const;

    /**
     * @brief Returns the cipher suite settings used by the engine.
     *
     * @return Cipher suite settings.
     */
    virtual TLSCipherSuiteUseCasesSettings GetCipherSuiteUseCase() const;

    /**
     * @brief Checks if revocation checking is enabled.
     *
     * @return True if enabled, otherwise false.
     */
    bool GetRevocationCheckEnable() const;

    /**
     * @brief Checks if the hard fail fallback mechanism is active.
     *
     * @return True if active, otherwise false.
     */
    bool IsHardFailFallbackMechanismActive() const;

#ifndef UNIT_TEST
protected:
#endif
    std::shared_ptr<IOStreamIf>      m_stream; ///< Stream used for I/O operations.
    TimeCheckTime const              m_checkTime; ///< Time check settings.
    TLSCipherSuiteUseCasesSettings   m_cipherSuiteUseCase; ///< Cipher suite configuration.
    std::shared_ptr<ITLSOcspHandler> m_ocspHandler; ///< OCSP handler for certificate validation.
    uint32_t const                   m_ocspTimeoutMs; ///< Timeout for OCSP responses.
    bool                             m_revocationCheckEnabled; ///< Flag to enable certificate revocation checking.
    std::string                      m_connectionLoggingName; ///< Name for logging connections.
};

}  // namespace impl
}  // namespace tls
}  // namespace vwg

#endif  // SACCESSLIB_TLSCERTENGINE_HPP
