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


#include "TrustStoreUpdateTEEInterfaceClass.h"
#include "MockTEETrustStoreImpl.h"
#include "MockTEEVKMSImpl.h"
#include "TEEIds.h"

using vwg::tee::impl::TrustStoreUpdateTEEInterfaceClass;
using namespace vwg::tee;
using namespace vwg::tee::impl::teeids;

TrustStoreUpdateTEEInterfaceClass::TrustStoreUpdateTEEInterfaceClass()
{
	// get required interfaces
	m_TruststoreAPI = std::unique_ptr<TruststoreAPI>(new MockTEETrustStoreImpl());
	m_VKMSCryptoAPI = std::unique_ptr<VKMSCryptoAPI>(new MockTEEVKMSImpl());
}


TrustStoreUpdateTEEInterfaceClass::~TrustStoreUpdateTEEInterfaceClass()
{
}


CertificateBundle TrustStoreUpdateTEEInterfaceClass::get_root_cert_bundle(TrustStoreID trustStoreId)
{
	// route to VKMS or Truststore
	if (VKMS_ROOT == trustStoreId)
	{
		return m_VKMSCryptoAPI->get_cert_vkms_root();
	}
	else
	{
		return m_TruststoreAPI->get_root_cert_bundle(trustStoreId);
	}
}


Error TrustStoreUpdateTEEInterfaceClass::set_root_cert_bundle(TrustStoreID trustStoreId, CertificateBundle certificateBundle)
{
	// only the TrustStore root certs can be written
	return m_TruststoreAPI->set_root_cert_bundle(trustStoreId, certificateBundle);
}


Error TrustStoreUpdateTEEInterfaceClass::remove_all_truststores()
{
	return m_TruststoreAPI->remove_all_truststores();
}
