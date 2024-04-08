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


#ifndef TLSTEEAPI_H
#define TLSTEEAPI_H

#include "TEETypes.h"

namespace vwg {
namespace tee {


class TLSTEEAPI
{

public:
	static std::shared_ptr<TLSTEEAPI> get_instance();

public:
	TLSTEEAPI() {

	}

	virtual ~TLSTEEAPI() {

	}

	/**
	 * WIP: Derives a TLS session key from a private key (VKMS).
	 * \param clientHint hint of the client
	 * \param serverHint hint of the server
	 * \param key reference to the key data structure
	 */
	virtual bool get_psk(IdentityHint clientHint, IdentityHint serverHint, SessionKey * key) =0;

 	/**
	 * Retrieves a certificate bundle from a truststore (TrustStore or VKMS).
	 * \param store_id ID of the truststore to retrive the bundle from
	 * \return CertificateBundle on success, an empty CertificateBundle otherwise
	 */
	virtual CertificateBundle get_root_cert_bundle(TrustStoreID store_id) =0;

	/**
	 * Returns a client chain (one or more) of certificates from MOS-Storage or VKMS.
	 * \param key_id ID of the certificate chain
	 * \return The certificate chain on success, otherwise an empty certificate chain
	 */
	virtual CertificateChain get_client_cert(ClientCertID key_id) =0;

	/**
	 * Returns the private key of a client certificate from the ClientCert-Storage.
	 * NOTE: private key access only during development!
	 * \param key_id ID of the client certificate
	 * \return the key data on success, otherwise an empty key
	 */
	virtual Key get_client_cert_private_key(ClientCertID key_id) =0;

};

} /* namespace tee */
} /* namespace vwg */

#endif /* TLSTEEAPI_H */
