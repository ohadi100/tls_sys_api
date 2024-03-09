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


#ifndef VKMSONLINEUPDATEAPI_H
#define VKMSONLINEUPDATEAPI_H

#include "TEETypes.h"

namespace vwg {
namespace tee {


class VKMSOnlineUpdateAPI
{

public:
	static std::shared_ptr<VKMSOnlineUpdateAPI> get_instance();

public:
	VKMSOnlineUpdateAPI()
	{}

	virtual ~VKMSOnlineUpdateAPI()
  {}

  /**
   * Handle an incoming download container (DLC).
   * \param[in] dlc: The download container as a ByteVector (std::vector<uint8_t>)
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error vkms_handle_dlc(ByteVector dlc) = 0;

  /**
   * Get a certificate stored by VKMS.
   * \param[in] typeId: The Type of requested certificate
   *                  - s. TEEIds.h: const ClientCertID VKMS_ECU_BASE ("VKMS_ECU_BASE")
   * \param[out] certificate: The requested certificate as a string
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error vkms_get_certificate(ClientCertID typeId, CertificateBundle &certificate) = 0;

  /**
   * Get the calculated Identity Hash from VKMS.
   * \param[out] targetHash: The calculated IdentityHash
   * \param[in]  challenge: The challenge to calculate the IdentityHash
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error vkms_get_identity_hash(ByteVector &targetHash, const ByteVector &challenge) = 0;

  /**
   * Get a hash value of the PSS key.
   * \param[out] targetHash: The calculated PSS Hash
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error vkms_get_pss_hash(ByteVector &targetHash) = 0;

  /**
   * Get the ECU Training Counter
   * \param[out] tc: The ECU Training Counter
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error vkms_get_training_counter(uint16_t &tc) = 0;

  /**
   * Get the VIN stored by VKMS.
   * \param[out] vin: The requested vin as a SecureVector_U8 (Botan::secure_vector<uint8_t>);
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error vkms_get_vkms_vin(ByteVector &vin) = 0;

  /**
   * 	PROVISIONAL
   *    !!! Maybe not part of this API -> Have to be discussed with VW
   * Get the ECU Part Number.
   * \param[out] pn: The requested ecu_partnumber
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error ecu_get_part_number(std::string &pn) = 0;

  /**
   * 	PROVISIONAL
   *    !!! Maybe not part of this API -> Have to be discussed with VW
   * Get the ECU Diagnostic ID.
   * \param[out] dId: The requested ecu_diagnostic_id
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error ecu_get_diagnostic_id(std::string &dId) = 0;

  /**
   * 	PROVISIONAL
   *    !!! Maybe not part of this API -> Have to be discussed with VW
   * Get the ECU FAZIT ID String.
   * \param[out] fIdString: The requested ecu_fazit_id_string
   * \return Error: Return code of the method
   *              - = 0 -> OK
   *              - <> 0 -> NOK
  */
  virtual Error ecu_get_fazit_id_string(std::string &fIdString) = 0;

};  // class VKMSOnlineUpdateAPI

} /* namespace tee */
} /* namespace vwg */

#endif /* VKMSONLINEUPDATEAPI_H */
