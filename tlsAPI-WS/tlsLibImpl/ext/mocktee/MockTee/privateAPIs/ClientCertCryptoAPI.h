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


#if !defined(EA_FA9CF962_CC39_49ec_9744_511874A43B27__INCLUDED_)
#define EA_FA9CF962_CC39_49ec_9744_511874A43B27__INCLUDED_

#include "TEETypes.h"

namespace vwg {
namespace tee {
namespace impl {


class ClientCertCryptoAPI
{

public:
	ClientCertCryptoAPI() {

	}

	virtual ~ClientCertCryptoAPI() {

	}

	/**
	 * Returns a public key associated with a client certificate from
	 * ClientCert-Storage or VKMS.
	 * \param keyId ID of the public key
	 * \return The key data on success, otherwise an empty key
	 */
	virtual Key get_public_key(ClientCertID keyId) =0;

	/**
	 * Returns a private key associated with a client certificate from
	 * ClientCert-Storage or VKMS.
	 * NOTE: private key access only during development !
	 * \param keyId ID of the private key
	 * \return The key data on success, otherwise an empty key
	 */
	virtual Key get_private_key(ClientCertID keyId) =0;

	/**
	 * Returns a client chain of certificates (one or more) from
	 * ClientCert-Storage or VKMS.
	 * \param keyId ID of the certificate chain
	 * \return The certificate chain on success, otherwise an empty key
	 */
	virtual CertificateChain get_client_cert(ClientCertID keyId) =0;


public:
	/**
	 * Generates a private key an stores it under the given ID, used for
	 * temporary UC-Key generation.
	 * \param keyId ID of the private key to be generated
	 * \return 0 on success, non-zero otherwise
	 */
	virtual Error generate_private_key(ClientCertID keyId) =0;

	/**
	 * Generates a certificate signing request with a key associated with the
	 * provided key ID and some default parameters.
	 * \param commonName Common Name to be used in the CSR
	 * \param keyId ID of the private key to use
	 * \return The CSR on success, otherwise an empty CSR
	 */
	virtual CSR generate_csr(String commonName, ClientCertID keyId) =0;

	/**
	 * Performs signature generation on the given data with the supplied hash
	 * function.
	 * \param keyId ID of the certificate/key to use
	 * \param content The data to sign
	 * \param hashFunction The hash function to use in signature generation
	 * \return The Signature on success, otherwise an empty Signature
	 */
	virtual Signature generate_signature(ClientCertID keyId, ByteVector content, HashFunction hashFunction) =0;

	/**
	 * Moves a stored private key with a signed certificate to a non temporary
	 * client cert storage.
	 * \param clientCertificateChain Signed certificate from a CA (as an answer to the CSR)
	 * \param srcKey ID of the private key to move
	 * \param targetKey ID of the certificate/private key to store
	 * \return 0 on success, non-zero otherwise
	 */
	virtual Error set_client_cert_and_move_key(CertificateChain clientCertificateChain, ClientCertID srcKey, ClientCertID targetKey) =0;

	/**
	 * tbd
	 */
	virtual void decrypt_data(ByteVector data) =0;

};

} /* namespace impl */
} /* namespace tee */
} /* namespace vwg */

#endif // !defined(EA_FA9CF962_CC39_49ec_9744_511874A43B27__INCLUDED_)
