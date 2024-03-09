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


#ifndef CLIENTCERTTEEINTERFACECLASS
#define CLIENTCERTTEEINTERFACECLASS

#include "ClientCertCryptoAPI.h"
#include "VKMSCryptoAPI.h"
#include "ClientCertInitializerAPI.h"

namespace vwg {
namespace tee {
namespace impl {


class ClientCertTeeInterfaceClass : public ClientCertInitializerAPI
{

public:
	// prevent copies
	ClientCertTeeInterfaceClass(const ClientCertTeeInterfaceClass&) = delete;
	ClientCertTeeInterfaceClass & operator=(const ClientCertTeeInterfaceClass&) = delete;

	static std::shared_ptr<ClientCertTeeInterfaceClass> get_instance()
    {
		static std::shared_ptr<ClientCertTeeInterfaceClass> instance =
			std::shared_ptr<ClientCertTeeInterfaceClass>(
				new ClientCertTeeInterfaceClass()
			);
		return instance;
    }

	~ClientCertTeeInterfaceClass();

	Error generate_private_key(ClientCertID keyId) override;
	CSR generate_csr(String commonName, ClientCertID keyId) override;
	Signature generate_signature(ClientCertID keyId, ByteVector content, HashFunction hashFunction) override;
	Key get_public_key(ClientCertID keyId) override;
	CertificateChain get_client_cert(ClientCertID keyId) override;
	Error set_client_cert_and_move_key(CertificateChain clientCertificateChain, ClientCertID srcKeyId, ClientCertID targetKeyId) override;
	CertificateBundle get_root_cert_bundle(TrustStoreID trustStoreId) override;
	VIN get_vkms_vin() override;

private:
	// force use of get_instance
	ClientCertTeeInterfaceClass();

private:
	std::unique_ptr<ClientCertCryptoAPI> m_ClientCertCryptoAPI;
	std::unique_ptr<VKMSCryptoAPI> m_VKMSCryptoAPI;

};

} /* namespace impl */
} /* namespace tee */
} /* namespace vwg */

#endif /* CLIENTCERTTEEINTERFACECLASS */
