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


#ifndef MOCKTEEVKMSIMPL_H
#define MOCKTEEVKMSIMPL_H

#include <mutex>
#include <map>

#include <botan/secmem.h>

#include "VKMSCryptoAPI.h"
#include "VKMSUpdateAPI.h"
#include "TEETypes.h"

namespace vwg {
namespace tee {
namespace impl {

using PSKeyTable = std::unordered_map<PSKKeyID, std::unique_ptr<KeyData>>;
using Domain2KeyMap = std::unordered_map<std::string, std::uint32_t>;
using KeyStringsMap = std::map<uint16_t, Key>;

enum KeyLoadMode {
	STANDARD = 1,
	DLC_DOWNLOAD,
};

enum CRT_TYPE_ID
{
	ROOT_CRT = 1,
	BASE_CRT,
	L1_CRT,
	L2_CRT,
};

enum KEY_TYPE_ID
{
	PSS = 1,				// Permanenter Steuergeräte-individueller Schlüssel	- (256 Bit) - symmetrisch
	FSS,					// Fahrzeug Steuergeräte-individueller Schlüssel 	- (256 Bit) - symmetrisch - allg.
	FSS_MOD,				// Fahrzeug Steuergeräte-individueller Schlüssel 	- (256 Bit) - symmetrisch - MOD
	FSS_ANTITHEFT,			// Fahrzeug Steuergeräte-individueller Schlüssel 	- (256 Bit) - symmetrisch - Diebstahlkschutz
	DLC_SECURITYKEY = 7,	// DLC-Sicherungsschlüssel 							- (256 Bit) - symmetrisch
	GAS_ECU = 10,			// Privater assymetrischer Steuergeräteschlüssel 	- (256 Bit) - asymmetrisch
};

enum LOAD_SECURE_STUFF
{
	FROM_RAM	= 0,
	FROM_FILE	= 1,
};

class MockTEEVKMSImpl : public VKMSCryptoAPI, public VKMSUpdateAPI
{

public:
	MockTEEVKMSImpl();
	virtual ~MockTEEVKMSImpl();

	/* VKMSCryptoAPI.h implementation */
	bool get_psk(IdentityHint clientHint, IdentityHint serverHint, SessionKey * key) override;
	virtual bool validate_signature(ClientCertID keyId, Signature signature) override;
	CertificateBundle get_cert_vkms_root() override;
	CertificateChain get_client_cert(ClientCertID keyID) override;
	Key get_private_key(ClientCertID keyID) override;
	VIN get_vkms_vin() override;

	Signature generate_signature(ClientCertID keyID, ByteVector content, HashFunction hashFunction) override;

	/* VKMSUpdateAPI.h implementation */
	// VKMS
	Error handle_dlc(ByteVector dlc) override;
	Error retrieve_certificate(ClientCertID typeId, CertificateBundle &certificate) override;
 	Error calculate_identity_hash(ByteVector &targetHash, const ByteVector &challange) override;
	Error calculate_pss_hash(ByteVector &targetHash) override;
 	Error retrieve_training_counter(uint16_t &tc) override;
 	Error retrieve_vkms_vin(ByteVector &vin) override;
	// ECU
	Error retrieve_part_number(std::string &pn) override;
	Error retrieve_diagnostic_id(std::string &dId) override;
	Error retrieve_fazit_id_string(std::string &fIdString) override;

	Error derive_key(Botan::secure_vector<uint8_t> &m_parentKey, Botan::secure_vector<uint8_t> &derived_key, uint16_t typeId, uint16_t trainingCounter, uint16_t key_length);
	Error get_DLC_key(Botan::secure_vector<uint8_t> &dlcKey);
	Error proccess_DLC_blocks(KeyStringsMap &in_map, Botan::secure_vector<uint8_t> decrypted_payload, int num_blocks);
	Error generate_keys_string(std::string &out_str, KeyStringsMap &in_map);
	Error write_key_data(std::string out_str);
	Error write_cert_data(std::string out_str, uint16_t vkms_id);


protected:

	Error load_domains(Domain2KeyMap &domain2KeyMap);
	Error load_keys(KeyLoadMode Mode, PSKeyTable &KeyMap);
	Error build_keys_map();
	SessionKey *derive_session_key_for_psk(PSKKeyID keyID);
	std::string get_node_of_domain(const std::string& domain) const;
	std::uint32_t get_key_id(const IdentityHint &clientHint, const IdentityHint &serverHint) const;

	PSKeyTable m_PSKeyMap;
	PSKeyTable m_PSKeyMap_DLCUpdate;
	Domain2KeyMap m_domain2KeyMap;
	std::mutex m_fileLockMutex;

};

} /* namespace impl */
} /* namespace tee */
} /* namespace vwg */

#endif // !defined(EA_896B63D4_64AC_4b9f_BBA1_97BC9C63A452__INCLUDED_)
