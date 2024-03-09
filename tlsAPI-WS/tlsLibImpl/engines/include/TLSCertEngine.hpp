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

#ifndef SACCESSLIB_TLSCERTENGINE_HPP
#define SACCESSLIB_TLSCERTENGINE_HPP

#include <functional>

#include <vwgtypes.h>
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
 * \enum TLSEngineErrors
 *
 * \brief Generic error values for any tls engine.
 */
class TLSCertEngine : public ITLSEngine
{
public:
    /**
     * \brief Constructor.
     *
     * \param[in] stream the underlying IOStreamIf used by the engine to perform actual input/output.
     * \param[in] checkTime do the time check in addition to the certificate validity check. This check will verify if
     * the certificate check time. This check can be omitted, by using null for this parameter.
     */
    TLSCertEngine(std::shared_ptr<IOStreamIf> const& stream, const TimeCheckTime& checkTime);

    /**
     * \brief Constructor.
     *
     * \param[in] stream the underlying IOStreamIf used by the engine to perform actual input/output.
     * \param[in] checkTime do the time check in addition to the certificate validity check. This check will verify if
     * the certificate check time. This check can be omitted, by using null for this parameter.
     * \param[in] ocspHandler Instance that implements ITLSOcspHandler interface that define methods to handle
     * ocsp requests and responses.
     * \param[in] ocspTimeoutMs OCSP timeout in milliseconds.
     */
    TLSCertEngine(std::shared_ptr<IOStreamIf> const&      stream,
                  const TimeCheckTime&                    checkTime,
                  std::shared_ptr<ITLSOcspHandler> const& ocspHandler,
                  const uint32_t                          ocspTimeoutMs);

    /**
     * \brief Destructor.
     */
    virtual ~TLSCertEngine() = default;

    /**
     * \brief Performs the TLS handshake, according to the arguments provided in the constructor.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError DoSSLHandshake() = 0;

    /**
     * \brief Sends a buffer to the other side.
     *
     * \param[in] buffer an unencrypted buffer of size 'length', which will be encrypted and sent through the
     * underlying (inheriting) TLS engine. This argument must be pre-allocated (either statically or
     * dynamically) by the callee.
     * \param[in] bufLength length of unencrypted buffer.
     * \param[out] actualLength length of unencrypted buffer actually sent.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Send(const uint8_t* buffer, int32_t bufLength, int32_t& actualLength) = 0;

    /**
     * \brief Receives a buffer from the other side.
     *
     * \param[in] bufLength - length of unencrypted buffer to read.
     * \param[in] actualLength - length of unencrypted buffer actually read.
     * \param[out] buffer - a buffer of size 'length' to receive the data. 'buffer' should be pre-allocated (either
     * statically or dynamically) by the callee.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) = 0;

    /**
     * \brief Sets blocking/non-blocking mode for the stream. Blocking by default.
     *
     * \param[in] blocking the new mode.
     *
     * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
     */
    virtual TLSEngineError SetBlocking(bool blocking);

    /**
     * \brief Sends a "close notify" alert to the peer.
     */
    virtual TLSEngineError Shutdown() = 0;

/**
 * \def use the define <b> TLSAPI_WITH_DROP_SUPPORT </b> to generate the special library for the MOD socks
 * implementation. Only for the MOD socks implementation the sockets with droppable shall be present. The default
 * the library implementation shall not provide droppable sockets.
 */
#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * \brief Initiates drop TLS with the peer.
     */
    virtual TLSEngineError DropTLS() override;
#endif

    /**
     * \brief Gets the accompanying IOStream.
     *
     * \return the accompanying IOStream.
     */
    const std::shared_ptr<IOStream> GetIOStream() const;

    /**
     * \brief Gets the OCSP Handler object.
     *
     * \return a shared pointer reference to the handler object.
     */
    const std::shared_ptr<ITLSOcspHandler>& GetOcspHandler() const;

    /**
     * \brief Gets the OCSP response receive timeout in milliseconds.
     *
     * \return an unsigned integer which contains the timeout value in milliseconds.
     */
    uint32_t GetOcspTimeout() const;

    /**
     * \brief Checks the authentication of the system time, by comparing to m_checkTime,
     * should be called at the handshake time.
     *
     * \return  RC_TLS_ENGINE_SUCCESSFUL if |(m_checkTime.expectedTime - systemTime)| <=
     * |m_checkTime.permittedDeviation| otherwise RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED or another error.
     */
    virtual TLSEngineError CheckAuthenticTimeCheck() const;

    /**
     * \brief Gets engine's used cipher suite group.
     *
     * \return The used cipher suite group.
     */
    virtual TLSCipherSuiteUseCasesSettings GetCipherSuiteUseCase() const;

    /**
     * \brief Gets engine's revocation check enable flag.
     *
     * \return the revocation check enable flag.
     */
    bool GetRevocationCheckEnable() const;

    /**
     * \brief Gets indication if the hard fail fallback mechanism is active
     *
     * \return the hard fail fallback mechanism status
     */
    bool IsHardFailFallbackMechanismActive() const;

#ifndef UNIT_TEST
protected:
#endif
    std::shared_ptr<IOStreamIf>      m_stream;
    TimeCheckTime const              m_checkTime;
    TLSCipherSuiteUseCasesSettings   m_cipherSuiteUseCase;
    std::shared_ptr<ITLSOcspHandler> m_ocspHandler;
    uint32_t const                   m_ocspTimeoutMs;
    bool                             m_revocationCheckEnabled;
    std::string                      m_connectionLoggingName;
};

}  // namespace impl
}  // namespace tls
}  // namespace vwg


#endif  // SACCESSLIB_TLSCERTENGINE_HPP
