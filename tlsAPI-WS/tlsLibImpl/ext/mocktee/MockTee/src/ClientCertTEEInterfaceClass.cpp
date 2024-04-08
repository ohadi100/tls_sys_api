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


#include "ClientCertTEEInterfaceClass.h"
#include "MockTEEClientCertImpl.h"
#include "MockTEEVKMSImpl.h"
#include "TEEIds.h"

using vwg::tee::impl::ClientCertTeeInterfaceClass;
using namespace vwg::tee;
using namespace vwg::tee::impl::teeids;

ClientCertTeeInterfaceClass::ClientCertTeeInterfaceClass()
{
	// get required interfaces
	m_ClientCertCryptoAPI = std::unique_ptr<ClientCertCryptoAPI>(new MockTEEClientCertImpl());
	m_VKMSCryptoAPI = std::unique_ptr<VKMSCryptoAPI>(new MockTEEVKMSImpl());
}


ClientCertTeeInterfaceClass::~ClientCertTeeInterfaceClass()
{
}


Error ClientCertTeeInterfaceClass::generate_private_key(ClientCertID keyId)
{
	return m_ClientCertCryptoAPI->generate_private_key(keyId);
}


CSR ClientCertTeeInterfaceClass::generate_csr(String commonName, ClientCertID keyId)
{
	CSR csr;

	// allow the creation of a csr only for selected ids
	if (MOS_CSR == keyId)
	{
		csr = m_ClientCertCryptoAPI->generate_csr(commonName, keyId);
	}

	return csr;
}


Signature ClientCertTeeInterfaceClass::generate_signature(ClientCertID keyId, ByteVector content, HashFunction hashFunction)
{
	Signature signature;
	// route to VKMS or ClientCertStore
	if (VKMS_BASE == keyId)
	{
		signature = m_VKMSCryptoAPI->generate_signature(keyId, content, hashFunction);
	}
	else if (MOS == keyId)
	{
		signature = m_ClientCertCryptoAPI->generate_signature(keyId, content, hashFunction);
	}
	return signature;
}


Key ClientCertTeeInterfaceClass::get_public_key(ClientCertID keyId)
{
	Key key;

	// return public keys from the ClientCertStore
	if (MOS_CSR == keyId || MOS == keyId)
	{
		key = m_ClientCertCryptoAPI->get_public_key(keyId);
	}

	return key;
}

CertificateChain ClientCertTeeInterfaceClass::get_client_cert(ClientCertID keyId)
{
	CertificateChain certificate;

	// route to VKMS or ClientCertStore
	if (VKMS_BASE == keyId)
	{
		certificate = m_VKMSCryptoAPI->get_client_cert(keyId);
	}
	else if (MOS == keyId)
	{
		certificate = m_ClientCertCryptoAPI->get_client_cert(keyId);
	}

	return certificate;
}


Error ClientCertTeeInterfaceClass::set_client_cert_and_move_key(
	CertificateChain clientCertificateChain,
	ClientCertID srcKeyId,
	ClientCertID targetKeyId )
{
	return m_ClientCertCryptoAPI->set_client_cert_and_move_key(clientCertificateChain, srcKeyId, targetKeyId);
}


CertificateBundle ClientCertTeeInterfaceClass::get_root_cert_bundle(TrustStoreID trustStoreId)
{
	// the ClientCertInitializerAPI requires access to the VKMS root cert only
	if (VKMS_ROOT == trustStoreId)
	{
		return m_VKMSCryptoAPI->get_cert_vkms_root();
	}
	else
	{
		return CertificateBundle();
	}
}

VIN ClientCertTeeInterfaceClass::get_vkms_vin()
{
	return m_VKMSCryptoAPI->get_vkms_vin();
}
