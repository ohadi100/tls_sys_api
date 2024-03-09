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


#if !defined(EA_86F54401_A3D1_4cc2_9DEB_45C9018F98D7__INCLUDED_)
#define EA_86F54401_A3D1_4cc2_9DEB_45C9018F98D7__INCLUDED_

#include "TEETypes.h"

namespace vwg {
namespace tee {
namespace impl {

class VKMSCryptoAPI
{

public:
	VKMSCryptoAPI() {

	}

	virtual ~VKMSCryptoAPI() {

	}

	/**
	 * WIP: Derives a TLS session key from a private key.
	 * \param clientHint domain hint of the client
	 * \param serverHint domain hint of the server
	 * \param key pointer to the ke data structure
	 * \return true on success, false otherwise
	 */
	virtual bool get_psk(IdentityHint clientHint, IdentityHint serverHint, SessionKey * key) =0;

	/**
	 * Returns the Base certificate chain of the VKMS.
	 * \return Base certificate chain certificate on success, empty certificate chain otherwise
	 */
	virtual CertificateChain get_client_cert(ClientCertID keyId) =0;

	/**
	 * Returns a private key of the Base certificate chain of the VKMS.
	 * FOR DEVELOPMENT PURPOSES ONLY !
	 * \return private key on success, empty certificate chain otherwise
	 */
	virtual Key get_private_key(ClientCertID keyId) =0;

	/**
	 * Returns the root certificate of the VKMS.
	 * \return Root certificate on success, empty certificate otherwise
	 */
	virtual CertificateBundle get_cert_vkms_root() =0;

	/**
	 * Returns the VIN stored in the VKMS.
	 * \return Valid VIN on success, empty VIN otherwise
	 */
	virtual VIN get_vkms_vin() =0;

	/**
	 * tbd
	 */
	virtual bool validate_signature(ClientCertID keyId, Signature signature) =0;

	/**
	 * Performs signature generation on the given data with the supplied hash function.
	 * \param keyId ID of the certificate/key to use
	 * \param content The data to sign
	 * \param hashFunction The hash function to use in signature generation
	 * \return The Signature on success, otherwise an empty Signature
	 */
	virtual Signature generate_signature(ClientCertID keyId, ByteVector content, HashFunction hashFunction) =0;

};

} /* namespace impl */
} /* namespace tee */
} /* namespace vwg */

#endif // !defined(EA_86F54401_A3D1_4cc2_9DEB_45C9018F98D7__INCLUDED_)
