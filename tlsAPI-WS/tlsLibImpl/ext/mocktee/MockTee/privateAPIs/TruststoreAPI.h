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


#if !defined(EA_DFB90FA2_E3FB_4d74_A488_E1FE334E5F27__INCLUDED_)
#define EA_DFB90FA2_E3FB_4d74_A488_E1FE334E5F27__INCLUDED_

#include "TEETypes.h"

namespace vwg {
namespace tee {
namespace impl {

class TruststoreAPI
{

public:
	TruststoreAPI() {

	}

	virtual ~TruststoreAPI() {

	}

	/**
	 * Retrieves a certificate bundle from a truststore.
	 * \param trustStoreId ID of the truststore to retrive the bundle from
	 * \return CertificateBundle on success, an empty CertificateBundle otherwise
	 */
	virtual CertificateBundle get_root_cert_bundle(TrustStoreID trustStoreId) =0;

	/**
	 * Sets a full certificate bundle to a truststore, previous content will be deleted.
	 * \param trustStoreId ID of the truststore to store the bundle in
	 * \param certBundle ... tbd ...
	 * \return 0 on success, non-zero otherwise
	 */
	virtual Error set_root_cert_bundle(TrustStoreID trustStoreId, CertificateBundle certBundle) =0;

	/**
	 * Clears/Removes all truststores.
	 * \return 0 on success, non-zero otherwise
	 */
	virtual Error remove_all_truststores() =0;

};

} /* namespace impl */
} /* namespace tee */
} /* namespace vwg */

#endif // !defined(EA_DFB90FA2_E3FB_4d74_A488_E1FE334E5F27__INCLUDED_)
