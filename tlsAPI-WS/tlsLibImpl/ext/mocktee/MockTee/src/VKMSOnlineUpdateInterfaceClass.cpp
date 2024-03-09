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


#include "VKMSOnlineUpdateInterfaceClass.h"

#include <string>
#include <cstring>
#include <iostream>
#include <sstream>

#include "MockTEEClientCertImpl.h"
#include "MockTEEVKMSImpl.h"
#include "TEEIds.h"
#include "Log.h"

using vwg::tee::impl::VKMSOnlineUpdateInterfaceClass;
using namespace vwg::tee;
using namespace vwg::tee::impl::teeids;

VKMSOnlineUpdateInterfaceClass::VKMSOnlineUpdateInterfaceClass()
{
    m_VkmsUpdateAPI = std::unique_ptr<VKMSUpdateAPI>{new MockTEEVKMSImpl()};
}

////////////////////////////////////////////////
// Interface to VKMSOnlineUpdateAPI.h
////////////////////////////////////////////////
Error VKMSOnlineUpdateInterfaceClass::vkms_handle_dlc(ByteVector dlc)
{
    return m_VkmsUpdateAPI->handle_dlc(dlc);
}

Error VKMSOnlineUpdateInterfaceClass::vkms_get_certificate(ClientCertID typeId, CertificateBundle &certificate)
{
	return m_VkmsUpdateAPI->retrieve_certificate(typeId, certificate);
}

Error VKMSOnlineUpdateInterfaceClass::vkms_get_identity_hash(ByteVector &targetHash, const ByteVector &challenge)
{
	return m_VkmsUpdateAPI->calculate_identity_hash(targetHash, challenge);
}

Error VKMSOnlineUpdateInterfaceClass::vkms_get_pss_hash(ByteVector &targetHash)
{
    return m_VkmsUpdateAPI->calculate_pss_hash(targetHash);
}

Error VKMSOnlineUpdateInterfaceClass::vkms_get_training_counter(uint16_t &tc)
{
    return m_VkmsUpdateAPI->retrieve_training_counter(tc);
}

Error VKMSOnlineUpdateInterfaceClass::vkms_get_vkms_vin(ByteVector &vin)
{
    return m_VkmsUpdateAPI->retrieve_vkms_vin(vin);
}

Error VKMSOnlineUpdateInterfaceClass::ecu_get_part_number(std::string &pn)
{
    return m_VkmsUpdateAPI->retrieve_part_number(pn);
}

Error VKMSOnlineUpdateInterfaceClass::ecu_get_diagnostic_id(std::string &dId)
{
    return m_VkmsUpdateAPI->retrieve_diagnostic_id(dId);
}

Error VKMSOnlineUpdateInterfaceClass::ecu_get_fazit_id_string(std::string &fIdString)
{
    return m_VkmsUpdateAPI->retrieve_fazit_id_string(fIdString);
}
