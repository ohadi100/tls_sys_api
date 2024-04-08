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


#ifndef VKMSONLINEUPDATEINTERFACECLASS_H
#define VKMSONLINEUPDATEINTERFACECLASS_H

#include "VKMSOnlineUpdateAPI.h"
#include "VKMSUpdateAPI.h"

namespace vwg {
namespace tee {
namespace impl {


class VKMSOnlineUpdateInterfaceClass : public VKMSOnlineUpdateAPI
{

public:
	~VKMSOnlineUpdateInterfaceClass(){};

	// singleton pattern
	static std::shared_ptr<VKMSOnlineUpdateInterfaceClass> get_instance()
	{
		static auto instance = std::shared_ptr<VKMSOnlineUpdateInterfaceClass>( new VKMSOnlineUpdateInterfaceClass() );
		return instance;
	}
	// disable copy constructor and assignment operator
	VKMSOnlineUpdateInterfaceClass(const VKMSOnlineUpdateInterfaceClass&) = delete;
	VKMSOnlineUpdateInterfaceClass & operator=(const VKMSOnlineUpdateInterfaceClass&) = delete;

	// Interface to VKMSOnlineUpdateAPI.h
	//VKMS
	Error vkms_handle_dlc(ByteVector dlc) override;
  	Error vkms_get_certificate(ClientCertID typeId, CertificateBundle &certificate) override;
	Error vkms_get_identity_hash(ByteVector &targetHash, const ByteVector &challange) override;
    Error vkms_get_pss_hash(ByteVector &targetHash) override;
    Error vkms_get_training_counter(uint16_t &tc) override;
    Error vkms_get_vkms_vin(ByteVector &vin) override;
	// ECU
	Error ecu_get_part_number(std::string &pn) override;
	Error ecu_get_diagnostic_id(std::string &dId) override;
	Error ecu_get_fazit_id_string(std::string &fIdString) override;


private:
	// force use of get_instance()
	VKMSOnlineUpdateInterfaceClass();

private:
	std::unique_ptr<VKMSUpdateAPI> m_VkmsUpdateAPI;

};

} /* namespace impl */
} /* namespace tee */
} /* namespace vwg */

#endif /* VKMSONLINEUPDATEINTERFACECLASS_H */
