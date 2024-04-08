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


#ifndef MOCKTEECLIENTCERTIMPL_H
#define MOCKTEECLIENTCERTIMPL_H

#include <mutex>

#include "ClientCertCryptoAPI.h"

namespace vwg {
namespace tee {
namespace impl {


class MockTEEClientCertImpl : public ClientCertCryptoAPI
{

public:
	MockTEEClientCertImpl();
	virtual ~MockTEEClientCertImpl();

	Key get_public_key(ClientCertID keyId) override;
	Key get_private_key(ClientCertID keyId) override;
	CertificateChain get_client_cert(ClientCertID keyId) override;

protected:
	Error generate_private_key(ClientCertID keyId) override;
	CSR generate_csr(String commonName, ClientCertID keyId) override;
	Signature generate_signature(ClientCertID keyID, ByteVector content, HashFunction hashFunction) override;
	Error set_client_cert_and_move_key(CertificateChain clientCertificateChain, ClientCertID sourceKeyId, ClientCertID targetKeyId) override;
	void decrypt_data(ByteVector data) override;

protected:
	std::mutex m_fileLockMutex;

};

} /* namespace impl */
} /* namespace tee */
} /* namespace vwg */

#endif /* MOCKTEECLIENTCERTIMPL_H */
