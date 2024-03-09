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

#ifndef SACCESSLIB_ITLSENGINE_HPP
#define SACCESSLIB_ITLSENGINE_HPP

#include <functional>
#include <cstdint>
#include <memory>
#include <string>

#include "vwgtypes.h"
#include "IOStream.h"
#include "TLSApiTypes.h"

using namespace std;
using namespace vwg::types;

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
    typedef enum
    {
        RC_TLS_ENGINE_SUCCESSFUL = 0,
        RC_TLS_ENGINE_SPECIFIC_ERROR,
        RC_TLS_ENGINE_FATAL_ERROR,
        RC_TLS_ENGINE_UNKNOWN_ERROR,
        RC_TLS_ENGINE_WOULD_BLOCK_READ,
        RC_TLS_ENGINE_WOULD_BLOCK_WRITE,
        RC_TLS_ENGINE_NOT_SUPPORTED,
        RC_TLS_ENGINE_SEND_AFTER_SHUTDOWN,
        RC_TLS_ENGINE_PEER_CLOSED,
        RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED,
        RC_TLS_ENGINE_MAX_PERMITTED_DEVIATION,
        RC_TLS_PUBLIC_KEY_PINNING_FAILED = 1003,

        /* From the alert codes in rfc5246
         * the number of the alert code + 2000 to avoid number clashes. */

        RC_TLS_ENGINE_UNEXPECTED_MESSAGE = 2010,
        RC_TLS_ENGINE_BAD_RECORD_MAC = 2020,
        RC_TLS_ENGINE_RECORD_OVERFLOW  = 2022,
        RC_TLS_ENGINE_DECOMPRESSION_FAILURE = 2030,
        RC_TLS_ENGINE_HANDSHAKE_FAILURE = 2040,
        RC_TLS_ENGINE_BAD_CERTIFICATE = 2042,
        RC_TLS_ENGINE_UNSUPPORTED_CERTIFICATE = 2043,
        RC_TLS_ENGINE_CERTIFICATE_REVOKED   = 2044,
        RC_TLS_ENGINE_CERTIFICATE_EXPIRED  = 2045,
        RC_TLS_ENGINE_CERTIFICATE_UNKNOWN   = 2046,
        RC_TLS_ENGINE_ILLEGAL_PARAMETER    = 2047,
        RC_TLS_ENGINE_UNKNOWN_CA    = 2048,
        RC_TLS_ENGINE_ACCESS_DENIED     = 2049,
        RC_TLS_ENGINE_DECODE_ERROR     = 2050,
        RC_TLS_ENGINE_DECRYPT_ERROR       = 2051,
        RC_TLS_ENGINE_PROTOCOL_VERSION   = 2070,
        RC_TLS_ENGINE_INSUFFICIENT_SECURITY   = 2071,
        RC_TLS_ENGINE_NO_RENEGOTIATION = 2100,
        RC_TLS_ENGINE_UNSUPPORTED_EXTENSION = 2110,
        RC_TLS_ENGINE_CERTIFICATE_UNOBTAINABLE = 2111,
        RC_TLS_ENGINE_UNRECOGNIZED_NAME = 2112,
        RC_TLS_ENGINE_BAD_CERTIFICATE_STATUS_RESPONSE = 2113,
        RC_TLS_ENGINE_BAD_CERTIFICATE_HASH_VALUE = 2114,
        RC_TLS_ENGINE_NO_APPLICATION_PROTOCOL = 2120,
        RC_TLS_ENGINE_TEE_ACCESS_ERROR = 3000,
        RC_TLS_ENGINE_CERTSTORE_NOT_FOUND,
        RC_TLS_ENGINE_UNKNOWN_CLIENT_CERTIFICATE_SET_ID,
        RC_TLS_ENGINE_CLIENT_CERTIFICATE_SET_IDERROR,

    } TLSEngineError;

    typedef enum
    {
        TLS_PSK_CLIENT = 0,
        TLS_PSK_SERVER,
        TLS_CERT_CLIENT
    } TLSEngineType;

    struct pskData
    {
        std::string remoteHint;
        std::string hint;
    };

    /**
    * \class TLSEngine
    *
     * \brief The TLSEngine is the base class for all possible SSL engines (WolfSSL, Botan, etc). The class provides
    * a basic API that all sub-classes must implement, to provide basic and common functionality, such
    * as: sending and receiving data, performing the SSL handshake, providing authentication parameters...
    */
    class ITLSEngine
    {
    public:
        /**
         * \brief Constructor.
         */
        ITLSEngine() = default;

        /**
         * \brief Destructor.
         */
        virtual ~ITLSEngine() = default;

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
        virtual TLSEngineError Send(const uint8_t * buffer, int32_t bufLength, int32_t& actualLength) = 0;

        /**
         * \brief Receives a buffer from the other side.
         *
         * \param[in] bufLength length of unencrypted buffer to read.
         * \param[in] actualLength length of unencrypted buffer actually read.
         * \param[out] buffer a buffer of size 'length' to receive the data. 'buffer' should be pre-allocated (either
         * statically or dynamically) by the callee.
         *
         * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
         */
        virtual TLSEngineError Receive(uint8_t * buffer, int32_t bufLength, int32_t& actualLength) = 0;

        /**
         * \brief Sets blocking/non-blocking mode for the stream. Blocking by default.
         *
         * \param[in] blocking the new mode.
         *
         * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
         */
        virtual TLSEngineError SetBlocking(bool blocking) = 0;

        /**
         * \brief Sends a "close notify" alert to the peer.
         *
         * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
         */
        virtual TLSEngineError Shutdown() = 0;

#ifdef TLSAPI_WITH_DROP_SUPPORT
        /**
         * \brief Initiates drop TLS with the peer.
         *
         * \return RC_TLS_SUCCESSFUL if succeeded, otherwise an error code.
         */
        virtual TLSEngineError DropTLS() = 0;
#endif

        /**
         * \brief Closes the underlying TLS connection and release any resources that are used. Also closes the
         * accompanying IOStream.
         */
        virtual void Close() = 0;

        /**
         * \brief Gets the accompanying IOStream.
         * \return the accompanying IOStream.
         */
        virtual const std::shared_ptr<IOStream> GetIOStream() const = 0;
        virtual const std::string GetRemoteHintName() const = 0;
        virtual const std::string GetHintName() const = 0;

        /**
        * \brief Gets the provided AlpnMode.
        *
        * \return the provided AlpnMode, if no AlpnMode is specified than the const AlpnMode::NO_ALPN is returned.
        * In this case only HTTP 1.1 is used.
        *
        * \since 1.1.0
        */
        virtual const AlpnMode& getUsedAlpnMode() const = 0;

        /**
        * \brief Gets the used INANAProtocol.
        *
        * \return the used INANAProtocol, inn case ALPN is unused returns IANAProtocol::HTTP.
        *
        * \since 1.1.0
        */
        virtual IANAProtocol getUsedProtocol() const = 0;
    };

    TLSReturnCodes EngineToTLSReturnCode(TLSEngineError err);

} // namespace impl
} // namespace tls
} // namespace vwg

#endif //SACCESSLIB_ITLSENGINE_HPP
