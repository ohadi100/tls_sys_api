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


#ifndef SRC_TLSLIBAPI_H_
#define SRC_TLSLIBAPI_H_

#include <memory>

#include "TLSResult.h"
#include "InetAddress.h"
#include "TLSSockets.h"
#include "TLSSocketFactory.h"

/**
 *\brief This is the entry point of the library, basically one user have to call <b>initTLSLib</b>
 * to create a factory in order to retrieve the objects for the communication between provider and consumer.
 */

namespace vwg {
namespace tls {

/**
 * \brief This is the entry point for the library.
 * This will return the Socket factory when all initialization needed are successfully performed.
 * These is basically initialization of:
 * - the TLS/SSL library
 * - communication to the trust zone
 *
 * \return the TLSSocketFactory or an error code.
 */
extern ITLSSocketFactoryResult initTLSLib();

/**
 * \brief Use this method to cleanup the implementation.
 * This can be used to cleanup the TLS library (e.g. Wolf SSL or Botan SSL).
 * after this the  ITLSSocketFactory will not return any socket instance.
 */
extern void cleanupTLSLib();

} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_TLSLIBAPI_H_ */
