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


#ifndef INCLUDES_CIPHERSUITESDEFENITIONS_H_
#define INCLUDES_CIPHERSUITESDEFENITIONS_H_

#include "vwgtypes.h"

namespace vwg {
namespace tls {

 /**
  * \brief This enum defines the list of permitted cipher suits.
  */
 enum CipherSuiteId : vwg::types::UInt16
 {
     TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
     TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
     TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F,
     TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E,
     TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
     TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
     TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA,
     TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009,
     TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A,
     TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,
     TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,
     TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,
     TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
     TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B,
     TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
     TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D,
     TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C,
     TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,
     TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
     TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
     TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
 };


 using CipherSuiteIds = std::string;

} // namespace tls
} // namespace vwg


#endif /* INCLUDES_CIPHERSUITESDEFENITIONS_H_ */
