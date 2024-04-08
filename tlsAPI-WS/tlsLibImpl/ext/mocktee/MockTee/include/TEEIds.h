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


#ifndef TEEIDS_H
#define TEEIDS_H

#include "TEETypes.h"

namespace vwg {
namespace tee {
namespace impl {
namespace teeids {


const ClientCertID MOS ("MOS");
const ClientCertID MOS_CSR ("MOS_CSR");

const ClientCertID VKMS_BASE ("BASE");
const TrustStoreID VKMS_ROOT ("VKMS");

const TrustStoreID UC_01 ("UC_01");
const TrustStoreID UC_02 ("UC_02");
const TrustStoreID UC_03 ("UC_03");

const std::string MOCKTEE_CCSTORE_FOLDER ("/vwos/data/variable/shared/MockTeeStorage/ClientCertStore/");
const std::string MOCKTEE_TRUSTSTORE_FOLDER ("/vwos/data/variable/shared/MockTeeStorage/TrustStore/");
const std::string MOCKTEE_VKMS_FOLDER ("/vwos/data/static/tls/");

const std::string TEST_CCSTORE_FOLDER ("testfiles/ClientCertStore/");
const std::string TEST_TRUSTSTORE_FOLDER ("testfiles/TrustStore/");
const std::string TEST_VKMS_FOLDER ("testfiles/VKMS/");

const std::string VKMS_BASE_FILENAME ("VKMS_ECU_BASE");
const std::string VKMS_ROOT_FILENAME ("VKMS_ROOT");

const std::string CERT_POSTFIX ("_CERT.pem");
const std::string KEY_POSTFIX ("_KEY.pem");
const std::string TRUSTSTORE_POSTFIX ("_TS.pem");

enum KEY_TYPE_ID
{
	PSS = 1,				// Permanenter Steuergeräte-individueller Schlüssel	- (256 Bit) - symmetrisch
	FSS,					// Fahrzeug Steuergeräte-individueller Schlüssel 	- (256 Bit) - symmetrisch - allg.
	FSS_MOD,				// Fahrzeug Steuergeräte-individueller Schlüssel 	- (256 Bit) - symmetrisch - MOD
	FSS_ANTITHEFT,			// Fahrzeug Steuergeräte-individueller Schlüssel 	- (256 Bit) - symmetrisch - Diebstahlkschutz
	DLC_SECURITYKEY = 7,	// DLC-Sicherungsschlüssel 							- (256 Bit) - symmetrisch
	GAS_ECU = 10,			// Privater assymetrischer Steuergeräteschlüssel 	- (256 Bit) - asymmetrisch
};


} /* namespace teeids */
} /* namespace impl */
} /* namespace tee */
} /* namespace vwg */

#endif /* TEEIDS_H */
