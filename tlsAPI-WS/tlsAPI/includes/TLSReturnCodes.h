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


#ifndef SRC_TLSRETURNCODES_H_
#define SRC_TLSRETURNCODES_H_

#include "vwgtypes.h"

using namespace vwg::types;

namespace vwg {
namespace tls {

enum TLSReturnCodes : Int32
{
    RC_TLS_SUCCESSFUL = 0,


    RC_TLS_INIT_FAILED = 1,
    RC_TLS_CONNECT_FAILED,
    RC_TLS_ACCEPT_FAILED,

    /**
    * This shall be returned when the domain name provided by the application
    * is not valid according to the sSOA domain name specification.
    */
    RC_TLS_INVALID_DOMAIN,

    /**
    * this shall be returned in case there is no valid key for the provider consumer connection defined.
    */
    RC_TLS_KEY_MISSING,

    /**
    * This shall be returned in case there will be a error to derive the session key from the PSK key.
    * This error shall cover all the errors due to the trust zone handling.
    * The library shall cover all diagnostic related requirements and created according trace information.
    */
    RC_TLS_KEY_ERROR,

    /**
    * This error shall be returned when the library functions/class are used after calling the cleanup method.
    */
    RC_TLS_USAGE_AFTER_CLEANUP,

    /**
    * This shall be returned due to IO/protocol error.
    */
    RC_TLS_IO_ERROR,

    /**
    * This shall be returned in non-blocking mode when the operation would block.
    * The caller is advised to check the error code and repeat the operation
    * when the socket is ready for read/write, according to the error code.
    */
    RC_TLS_WOULD_BLOCK_READ,
    RC_TLS_WOULD_BLOCK_WRITE,

    /**
    * This shall be returned due to peer unexpectedly closing the connection.
    */
    RC_TLS_PEER_CLOSED,
    /**
    * This shall be returned due to authentic time check failed.
    */
    RC_TLS_AUTHENTIC_TIMECHECK_FAILED,
    /**
    * This shall be returned if |permitted deviation (check time member)| >= MAX_PERMITTED_DEVIATION.
    */
    RC_TLS_MAX_PERMITTED_DEVIATION,
    /**
    * This shall be returned due to attempting to send after shutdown.
    */
    RC_TLS_SEND_AFTER_SHUTDOWN,

    /**
    * \brief this will be returned, an invalid IP address is given by the user and the IP address validation failed.
    */
    RC_TLS_INVALID_IP = 1000,
    RC_TLS_DROPPING_NOTSUPPORTED,
    RC_TLS_DROPPING_FAILED,

    /*
    * brief RC_TLS_PUBLIC_KEY_PINNING_FAILED shall be returned in case the operation (e.g. TLS handshake) will fail. This shall improve the error finding during development.
    */
    RC_TLS_PUBLIC_KEY_PINNING_FAILED,

    /* From the alert codes in rfc5246
    * the number of the alert code + 2000 to avoid number clashes. */

    RC_TLS_UNEXPECTED_MESSAGE = 2010,
    RC_TLS_BAD_RECORD_MAC = 2020,
    /* ignore until official defined in the TLS-RFC. Until than the error will be mapped to the common failure code
    * RC_TLS_DECRYPTION_FAILD_RESERVED = 2021, */
    RC_TLS_RECORD_OVERFLOW  = 2022,
    RC_TLS_DECOMPRESSION_FAILURE = 2030,
    RC_TLS_HANDSHAKE_FAILURE = 2040,
    /* ignore until official defined in the TLS-RFC. Until than the error will be mapped to the common failure code
    *   RC_TLS_NO_CERTIFICATE_RESERVED = 2041, */
    RC_TLS_BAD_CERTIFICATE = 2042,
    RC_TLS_UNSUPPORTED_CERTIFICATE = 2043,
    RC_TLS_CERTIFICATE_REVOKED   = 2044,
    RC_TLS_CERTIFICATE_EXPIRED  = 2045,
    RC_TLS_CERTIFICATE_UNKNOWN   = 2046,
    RC_TLS_ILLEGAL_PARAMETER    = 2047,
    RC_TLS_UNKOWN_CA    = 2048,	   // Deprecated
    RC_TLS_UNKNOWN_CA    = 2048,   // RMA Correction of typo added.
    RC_TLS_ACCESS_DENIED     = 2049,
    RC_TLS_DECODE_ERROR     = 2050,
    RC_TLS_DECRYPT_ERROR       = 2051,
    /*  ignore until official defined in the TLS-RFC. Until than the error will be mapped to the common failure code
    * RC_TLS_EXPORT_RESTRICTION_RESERVED   = 2060, */
    RC_TLS_PROTOCOL_VERSION   = 2070,
    RC_TLS_INSUFFICIENT_SECURITY   = 2071,
    RC_TLS_NO_RENEGOTIATION = 2100,
    RC_TLS_UNSUPPORTED_EXTENSION = 2110,
    RC_TLS_CERTIFICATE_UNOBTAINABLE = 2111,
    RC_TLS_UNRECOGNIZED_NAME = 2112,
    RC_TLS_BAD_CERTIFICATE_STATUS_RESPONSE = 2113,
    RC_TLS_BAD_CERTIFICATE_HASH_VALUE = 2114,

    /**
    * This is used for the ALPN extension,
    * for details please see https://tools.ietf.org/rfc/rfc7301.txt chapter 3.2.
    * In the event that the server supports no protocols that the client advertises, than this error is returned.
    * @since 1.1.0
    */
    RC_TLS_NO_APPLICATION_PROTOCOL = 2120,

    /**
    * The TEE report an error while performing the operation.
    * This can be either permission problem or other TEE specific problems.
    */
    RC_TLS_TEE_ACCESS_ERROR = 3000,

    /**
    * The TEE does not contain a certificate store (aka “truststore” aka “root certificate bundle” in other docs) for given certStoreId.
    * Depending on the library implementation and the used SSL implementation the message RC_TLS_UNKOWN_CA can be returned.
    */
    RC_TLS_CERTSTORE_NOT_FOUND,

    /**
    * The given certificate set id is unknown. it shall be one of the permitted values CLINET_CERTICATE_SET_BASE = "BASE" or CLINET_CERTICATE_SET_VKMS = "VKMS"
    * or the project specific.
    */
    RC_TLS_UNKNOWN_CLIENT_CERTIFICATE_SET_ID,

    /**
    * The TEE does not contain client certificate set and/or private key for given clientCertificateSetID.
    * Depending on the library implementation and the used SSL implementation the message RC_TLS_NO_CERTIFICATE_RESERVED can be returned.
    */
    RC_TLS_CLIENT_CERTIFICATE_SET_IDERROR,

    /**
    * This error will be present if an invalid error message is created by the library.
    * This will indicate a programming error of the library.
    */
    RC_TLS_PROGRAMMING_ERROR_RESULT = -1000,
};



} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_TLSRETURNCODES_H_ */
