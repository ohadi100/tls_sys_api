/**
 * @file ITLSEngine.hpp
 * @brief Interface for TLS engines used in secure communication.
 *
 * This file declares the ITLSEngine interface, which defines common operations for TLS engines such
 * as performing handshakes, sending and receiving data securely, and managing connection lifecycle.
 * Implementations of this interface could be tailored for different cryptographic libraries.
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
 * @enum TLSEngineError
 * @brief Enumerates the various TLS engine error codes.
 *
 * These error codes are used to identify different types of errors that may occur during
 * the operation of a TLS engine, such as during the handshake or data transmission.
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

    /* From the alert codes in RFC 5246
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

/**
 * @enum TLSEngineType
 * @brief Defines types of TLS engine operations.
 */
typedef enum
{
    TLS_PSK_CLIENT = 0,
    TLS_PSK_SERVER,
    TLS_CERT_CLIENT
} TLSEngineType;

/**
 * @struct pskData
 * @brief Holds PSK data used in TLS handshakes.
 */
struct pskData
{
    std::string remoteHint;
    std::string hint;
};

/**
 * @class ITLSEngine
 * @brief Interface defining the operations required by all TLS engine implementations.
 *
 * This interface abstracts the functionality required to perform secure transmissions
 * over network sockets, including performing handshakes, sending and receiving data, and
 * managing session state.
 */
class ITLSEngine
{
public:
    /**
     * @brief Destructor.
     */
    virtual ~ITLSEngine() = default;

    /**
     * @brief Performs the TLS handshake.
     *
     * @return TLSEngineError code indicating the result of the handshake.
     */
    virtual TLSEngineError DoSSLHandshake() = 0;

    /**
     * @brief Sends a data buffer over the TLS connection.
     *
     * @param[in] buffer Buffer containing the data to send.
     * @param[in] bufLength Length of the buffer.
     * @param[out] actualLength Length of the data actually sent.
     * @return TLSEngineError code indicating the result of the operation.
     */
    virtual TLSEngineError Send(const uint8_t *buffer, int32_t bufLength, int32_t& actualLength) = 0;

    /**
     * @brief Receives a data buffer over the TLS connection.
     *
     * @param[out] buffer Buffer to store the received data.
     * @param[in] bufLength Length of the buffer.
     * @param[out] actualLength Length of the data actually received.
     * @return TLSEngineError code indicating the result of the operation.
     */
    virtual TLSEngineError Receive(uint8_t *buffer, int32_t bufLength, int32_t& actualLength) = 0;

    /**
     * @brief Sets the blocking mode of the underlying I/O stream.
     *
     * @param[in] blocking If true, sets the stream to blocking mode; otherwise, non-blocking.
     * @return TLSEngineError code indicating the result of the operation.
     */
    virtual TLSEngineError SetBlocking(bool blocking) = 0;

    /**
     * @brief Initiates a graceful shutdown of the TLS connection by sending a close_notify alert.
     *
     * @return TLSEngineError code indicating the result of the shutdown.
     */
    virtual TLSEngineError Shutdown() = 0;

#ifdef TLSAPI_WITH_DROP_SUPPORT
    /**
     * @brief Initiates the TLS drop process.
     *
     * @return TLSEngineError code indicating the result of the operation.
     */
    virtual TLSEngineError DropTLS() = 0;
#endif

    /**
     * @brief Closes the TLS connection and releases all associated resources.
     */
    virtual void Close() = 0;

    /**
     * @brief Retrieves the underlying IOStream object associated with the TLS engine.
     *
     * @return Shared pointer to the IOStream used by the TLS engine.
     */
    virtual const std::shared_ptr<IOStream> GetIOStream() const = 0;
    virtual const std::string GetRemoteHintName() const = 0;
    virtual const std::string GetHintName() const = 0;

    /**
     * @brief Retrieves the ALPN mode used in the TLS connection.
     *
     * @return ALPN mode indicating the protocol negotiated.
     */
    virtual const AlpnMode& getUsedAlpnMode() const = 0;

    /**
     * @brief Retrieves the protocol used in the TLS connection, as defined by IANA.
     *
     * @return IANAProtocol value indicating the protocol used.
     */
    virtual IANAProtocol getUsedProtocol() const = 0;
};

/**
 * @brief Converts a TLSEngineError to a TLSReturnCodes.
 *
 * @param err The TLSEngineError to convert.
 * @return Corresponding TLSReturnCodes value.
 */
TLSReturnCodes EngineToTLSReturnCode(TLSEngineError err);

} // namespace impl
} // namespace tls
} // namespace vwg

#endif //SACCESSLIB_ITLSENGINE_HPP
