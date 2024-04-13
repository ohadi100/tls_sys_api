/**
 * @file TLSReturnCodes.h
 * @brief Defines return codes for TLS operations within the vwg::tls namespace.
 *
 * This file contains an enumeration of return codes used across the TLS implementation to denote
 * success, various error conditions, and specific protocol-related issues as defined by relevant RFCs.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
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

#ifndef SRC_TLSRETURNCODES_H_
#define SRC_TLSRETURNCODES_H_

#include "vwgtypes.h"
using namespace vwg::types;

namespace vwg {
namespace tls {

/**
 * @enum TLSReturnCodes
 * @brief Enumeration of return codes for TLS operations.
 */
enum TLSReturnCodes : Int32 {
    RC_TLS_SUCCESSFUL = 0,  ///< Operation successful

    // Initialization and connection failures
    RC_TLS_INIT_FAILED,     ///< Initialization of TLS failed
    RC_TLS_CONNECT_FAILED,  ///< Connection attempt failed
    RC_TLS_ACCEPT_FAILED,   ///< Accepting connection failed

    // Domain and key errors
    RC_TLS_INVALID_DOMAIN,  ///< Invalid domain name
    RC_TLS_KEY_MISSING,     ///< No valid key for connection
    RC_TLS_KEY_ERROR,       ///< Error deriving session key from PSK

    // Usage and state errors
    RC_TLS_USAGE_AFTER_CLEANUP,  ///< Using library functions after cleanup

    // Input/Output and protocol errors
    RC_TLS_IO_ERROR,             ///< Input/Output error
    RC_TLS_WOULD_BLOCK_READ,     ///< Non-blocking operation would block (read)
    RC_TLS_WOULD_BLOCK_WRITE,    ///< Non-blocking operation would block (write)

    // Connection state errors
    RC_TLS_PEER_CLOSED,          ///< Peer unexpectedly closed connection
    RC_TLS_AUTHENTIC_TIMECHECK_FAILED,  ///< Authentic time check failed
    RC_TLS_MAX_PERMITTED_DEVIATION,     ///< Maximum permitted time deviation exceeded
    RC_TLS_SEND_AFTER_SHUTDOWN,  ///< Attempt to send after shutdown

    // IP address and protocol specific errors
    RC_TLS_INVALID_IP = 1000,    ///< Invalid IP address
    RC_TLS_DROPPING_NOTSUPPORTED,///< Dropping not supported
    RC_TLS_DROPPING_FAILED,      ///< Dropping failed

    // Security and certification errors
    RC_TLS_PUBLIC_KEY_PINNING_FAILED, ///< Public key pinning failed

    // Alert codes (from RFC 5246) offset by 2000 to avoid clashes
    RC_TLS_UNEXPECTED_MESSAGE = 2010,
    RC_TLS_BAD_RECORD_MAC = 2020,
    RC_TLS_RECORD_OVERFLOW  = 2022,
    RC_TLS_DECOMPRESSION_FAILURE = 2030,
    RC_TLS_HANDSHAKE_FAILURE = 2040,
    RC_TLS_BAD_CERTIFICATE = 2042,
    RC_TLS_UNSUPPORTED_CERTIFICATE = 2043,
    RC_TLS_CERTIFICATE_REVOKED   = 2044,
    RC_TLS_CERTIFICATE_EXPIRED  = 2045,
    RC_TLS_CERTIFICATE_UNKNOWN   = 2046,
    RC_TLS_ILLEGAL_PARAMETER    = 2047,
    RC_TLS_UNKNOWN_CA    = 2048,   // Typo corrected from 'UNKOWN_CA'
    RC_TLS_ACCESS_DENIED     = 2049,
    RC_TLS_DECODE_ERROR     = 2050,
    RC_TLS_DECRYPT_ERROR       = 2051,
    RC_TLS_PROTOCOL_VERSION   = 2070,
    RC_TLS_INSUFFICIENT_SECURITY   = 2071,
    RC_TLS_NO_RENEGOTIATION = 2100,
    RC_TLS_UNSUPPORTED_EXTENSION = 2110,
    RC_TLS_CERTIFICATE_UNOBTAINABLE = 2111,
    RC_TLS_UNRECOGNIZED_NAME = 2112,
    RC_TLS_BAD_CERTIFICATE_STATUS_RESPONSE = 2113,
    RC_TLS_BAD_CERTIFICATE_HASH_VALUE = 2114,
    RC_TLS_NO_APPLICATION_PROTOCOL = 2120,

    // Trust Zone and certificate store errors
    RC_TLS_TEE_ACCESS_ERROR = 3000,
    RC_TLS_CERTSTORE_NOT_FOUND,
    RC_TLS_UNKNOWN_CLIENT_CERTIFICATE_SET_ID,
    RC_TLS_CLIENT_CERTIFICATE_SET_IDERROR,

    // Programming and usage errors
    RC_TLS_PROGRAMMING_ERROR_RESULT = -1000, ///< Indicative of a programming error
};

} // namespace tls
} // namespace vwg

#endif /* SRC_TLSRETURNCODES_H_ */
