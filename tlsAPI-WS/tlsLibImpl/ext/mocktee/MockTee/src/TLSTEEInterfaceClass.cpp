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


#include "TLSTEEInterfaceClass.h"

#include <iostream>

#include "MockTEEClientCertImpl.h"
#include "MockTEEVKMSImpl.h"
#include "MockTEETrustStoreImpl.h"
#include "TEEIds.h"

using vwg::tee::impl::TLSTEEInterfaceClass;
using namespace vwg::tee;
using namespace vwg::tee::impl::teeids;

TLSTEEInterfaceClass::TLSTEEInterfaceClass()
{
	// get required interfaces
	m_ClientCertCryptoAPI = std::unique_ptr<ClientCertCryptoAPI>(new MockTEEClientCertImpl());
	m_TruststoreAPI = std::unique_ptr<TruststoreAPI>(new MockTEETrustStoreImpl());
	m_VKMSCryptoAPI = std::unique_ptr<VKMSCryptoAPI>(new MockTEEVKMSImpl());
}


TLSTEEInterfaceClass::~TLSTEEInterfaceClass()
{
}

bool TLSTEEInterfaceClass::get_psk(IdentityHint clientHint, IdentityHint serverHint,SessionKey * key)
{
	// preshared keys are handled by the VKMS
	return m_VKMSCryptoAPI->get_psk(clientHint, serverHint, key);
}


CertificateBundle TLSTEEInterfaceClass::get_root_cert_bundle(TrustStoreID store_id)
{
	// route to VKMS or TrustStore
	if (VKMS_ROOT == store_id)
	{
		return m_VKMSCryptoAPI->get_cert_vkms_root();
	}
	else
	{
		return m_TruststoreAPI->get_root_cert_bundle(store_id);
	}
}


CertificateChain TLSTEEInterfaceClass::get_client_cert(ClientCertID key_id)
{
	CertificateChain certificate;

	// route to VKMS or ClientCertStore
	if (VKMS_BASE == key_id)
	{
		certificate = m_VKMSCryptoAPI->get_client_cert(key_id);
	}
	else if (MOS == key_id)
	{
		certificate = m_ClientCertCryptoAPI->get_client_cert(key_id);
	}

	return certificate;
}

/**
 * NOTE: usage of the private key outside mocktee has to be discussed
 *       and is only used for development purposes
 */
Key TLSTEEInterfaceClass::get_client_cert_private_key(ClientCertID key_id)
{
	Key key;
	// route to VKMS or ClientCertStore
	if (VKMS_BASE == key_id)
	{
		key = m_VKMSCryptoAPI->get_private_key(key_id);
	}
	else
	{
		key = m_ClientCertCryptoAPI->get_private_key(key_id);
	}

	return key;
}
