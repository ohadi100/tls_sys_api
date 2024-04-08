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


#include "MockTEEVKMSImpl.h"
#include "TEETypes.h"
#include "TEEIds.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <memory>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <locale>
#include <utility>
#include <math.h>
#include <random>

#include <botan/exceptn.h>
#include <botan/x509cert.h>
#include <botan/x509_key.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>
#include <botan/data_src.h>
#include <botan/stl_compatibility.h>
#include <botan/mac.h>
#include <botan/hex.h>
#include <botan/cipher_mode.h>
#include <botan/gcm.h>
#include <botan/aead.h>
#include <botan/hash.h>
#include <botan/rsa.h>

#include "Log.h"

using vwg::tee::impl::MockTEEVKMSImpl;
using namespace vwg::tee;
using namespace vwg::tee::impl::teeids;

MockTEEVKMSImpl::MockTEEVKMSImpl()
{
	// load predefined derived psk keys and domain maps
	if(build_keys_map() != Error::OK)
	{
		throw std::runtime_error("MockTee failed to load keys. Missing \"domains.tsv\" and/or \"keys.tsv\"");
	}
}

MockTEEVKMSImpl::~MockTEEVKMSImpl() {}


//Error MockTEEVKMSImpl::load_domains(Domain2KeyMap &domain2KeyMap, LOAD_SECURE_STUFF Mode)
Error MockTEEVKMSImpl::load_domains(Domain2KeyMap &domain2KeyMap)
{
	std::string DOMAIN_KEY_MAP_FILE = MOCKTEE_VKMS_FOLDER + "domains.tsv";
	std::ifstream domains_input(DOMAIN_KEY_MAP_FILE, std::fstream::in);
	/* Storage of domain maps taken from the TLSLib reference implementation. */
	if(!domains_input)
	{
		return Error::FILE_NOT_FOUND;
	}

	std::string line;
	std::string client, server;
	PSKKeyID key;

	domain2KeyMap.clear();

	while(std::getline(domains_input, line))
	{
		std::istringstream is(line);
		is >> client >> server >> key;
		domain2KeyMap.insert(make_pair(client + "<>" + server, key));
	}

	return Error::OK;
}

//Error MockTEEVKMSImpl::load_keys(KeyLoadMode Mode, LOAD_SECURE_STUFF KeySource, PSKeyTable &KeyMap)
Error MockTEEVKMSImpl::load_keys(KeyLoadMode Mode, PSKeyTable &KeyMap)
{
	/* Storage of private keys taken from the TLSLib reference implementation. */
	/* Keys are read from file and handed to the TLSLib "unchanged". */
	/* I.e. without actually deriving a key in derive_session_key_for_PSK(...). */

	std::string KEYS_FILE; //= MOCKTEE_VKMS_FOLDER + "keys.tsv"
	switch(Mode)
	{
		case KeyLoadMode::STANDARD:
			KEYS_FILE = MOCKTEE_VKMS_FOLDER + "keys.tsv";
			break;
		case KeyLoadMode::DLC_DOWNLOAD:
			KEYS_FILE = MOCKTEE_VKMS_FOLDER + "keys_DlcDownload.tsv";
			break;
		default:
			return Error::INVALID_PARAMETER;
	}


    std::ifstream keys_input(KEYS_FILE, std::fstream::in);

	/* Storage of domain maps taken from the TLSLib reference implementation. */
	if(!keys_input)
	{
		return Error::FILE_NOT_FOUND;
	}

	std::string line;
	int line_num = 1;
    PSKKeyID key;
    std::string data;

	KeyMap.clear();
    while(getline(keys_input, line))
    {
        std::istringstream is(line);
        is >> key >> data;

        std::string token;
        std::istringstream datais(data);

        auto keyData = Botan::make_unique<SessionKey>();

        while(std::getline(datais, token, ':'))
        {
            if(keyData->length >= sizeof(keyData->value))
                return Error::INVALID_PARAMETER;

			keyData->value[keyData->length] = stoi(token, 0, 16);
			keyData->length++;
		}

        KeyMap.insert(make_pair(key, std::move(keyData)));
		++line_num;
    }

	return Error::OK;
}

Error MockTEEVKMSImpl::build_keys_map()
{
	LOG_DEBUG("Start");
	Error ret;

	LOG_DEBUG("load_domains(m_domain2KeyMap)");


	ret = load_domains(m_domain2KeyMap);
	if(ret == Error::OK)
	{
		ret = load_keys(KeyLoadMode::STANDARD, m_PSKeyMap);
		LOG_DEBUG("load_keys(KeyLoadMode::STANDARD, &m_PSKeyMap)");
	}
	else
	{
		LOG_DEBUG("FAILED - load_domains(m_domain2KeyMap)");
		return ret;
	}

	if(ret == Error::OK){
		ret = load_keys(KeyLoadMode::DLC_DOWNLOAD, m_PSKeyMap_DLCUpdate);
		LOG_DEBUG("load_keys(KeyLoadMode::DLC_DOWNLOAD, &m_PSKeyMap_DLCUpdate)");
	}
	else
	{
		LOG_DEBUG("FAILED - load_keys(KeyLoadMode::STANDARD, &m_PSKeyMap)");
		return ret;
	}


	if(ret != Error::OK) {
        LOG_DEBUG("FAILED - load_keys(KeyLoadMode::DLC_DOWNLOAD, &m_PSKeyMap_DLCUpdate)");
        return ret;
    }

	LOG_DEBUG("Done");
	return Error::OK;
}

bool MockTEEVKMSImpl::get_psk(IdentityHint clientHint, IdentityHint serverHint, SessionKey *outKey)
{
	// retrieve the key id based on the client and server domain combination
    auto keyId = get_key_id(clientHint, serverHint);
    SessionKey *key;

	// get a derived key from the key with the selected key id (mocked, no derivation)
    key = derive_session_key_for_psk(keyId);

    if (!key)
    {
        return false;
    }

    if(sizeof(key->value) < key->length)
    {
        return false;
    }
    memcpy(outKey->value, key->value, key->length);
    outKey->length = key->length;
    return true;
}

std::string MockTEEVKMSImpl::get_node_of_domain(const std::string &domain) const
{
	// get a node name from the domein string
    return domain.substr((domain.find_last_of('.')) + 1);
}

std::uint32_t MockTEEVKMSImpl::get_key_id(const IdentityHint &clientHint, const IdentityHint &serverHint) const
{
    std::string clientNode = get_node_of_domain(clientHint);
    std::string serverNode = get_node_of_domain(serverHint);

	// retrieve derived key from domain2KeyMap
    std::string toFind = clientNode + "<>" + serverNode;
    auto found = m_domain2KeyMap.find(toFind);
    if(found == m_domain2KeyMap.end())
    {
        toFind = serverNode + "<>" + clientNode;
        found = m_domain2KeyMap.find(toFind);
    }
    if(found == m_domain2KeyMap.end())
    {
        // not in map
        return -1;
    }
    return found->second;
}

SessionKey *MockTEEVKMSImpl::derive_session_key_for_psk(PSKKeyID keyId)
{
	// return a derived session key from the key with the selected key id (mocked, no derivation)
	const auto &found = m_PSKeyMap.find(keyId);
    if(found == m_PSKeyMap.end())
    {
        return NULL;
    }
    return found->second.get();
}


Signature MockTEEVKMSImpl::generate_signature(ClientCertID keyId, ByteVector content, HashFunction hashFunction)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	Signature signature;
	Botan::AutoSeeded_RNG rng;
	std::unique_ptr<Botan::Private_Key> private_key;

	if (VKMS_BASE == keyId)
	{
		if (access((MOCKTEE_VKMS_FOLDER+VKMS_BASE_FILENAME+KEY_POSTFIX).c_str(), F_OK) != -1)
        {
			/* load private key from file */
			Botan::DataSource_Stream keyFile(MOCKTEE_VKMS_FOLDER+VKMS_BASE_FILENAME+KEY_POSTFIX);
			private_key = Botan::PKCS8::load_key(keyFile);

			/* Create signature */
			if (nullptr != private_key.get())
			{
				Botan::PK_Signer signer(*private_key, rng, hashFunction);

				signer.update(content);
				signature = signer.signature(rng);
			}
		}
	}

	return signature;
}


CertificateChain MockTEEVKMSImpl::get_client_cert(ClientCertID keyId)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	CertificateChain certificate;

	if (VKMS_BASE == keyId)
	{
		std::ifstream file(MOCKTEE_VKMS_FOLDER+VKMS_BASE_FILENAME+CERT_POSTFIX);
		if (true == file.is_open())
		{
			// load certificate data from file, return file contents without processing
			std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
			certificate = data;
			file.close();
		}
	}

	return  certificate;
}


Key MockTEEVKMSImpl::get_private_key(ClientCertID keyId)
{
	Key key;
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);

    if (VKMS_BASE == keyId)
	{
    	std::ifstream file(MOCKTEE_VKMS_FOLDER+VKMS_BASE_FILENAME+KEY_POSTFIX);
    	if (true == file.is_open())
    	{
    		std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    		key = data;
    		file.close();
    	}
    }

	return key;
}


CertificateBundle MockTEEVKMSImpl::get_cert_vkms_root()
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	CertificateBundle certificate;

	std::ifstream file(MOCKTEE_VKMS_FOLDER+VKMS_ROOT_FILENAME+CERT_POSTFIX);
	if (true == file.is_open())
	{
		std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		certificate = data;
		file.close();
	}

	return  certificate;
}


VIN MockTEEVKMSImpl::get_vkms_vin()
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	VIN vin;

	std::ifstream file(MOCKTEE_VKMS_FOLDER+"VIN.txt");
	if (true == file.is_open())
	{
		std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		vin = data;
		/* strip possible endl from VIN */
		vin.erase(std::find_if(vin.rbegin(), vin.rend(),
			[](int ch) {
        		return !std::isspace(ch);
    		}).base(), vin.end());
		file.close();
	}

	return  vin;
}


bool MockTEEVKMSImpl::validate_signature(ClientCertID keyId, Signature signature)
{
	(void)keyId;
	(void)signature;
	return false;
}

// Key Derivation Function according to VW VKMS spec.
// Takes the parent key and derivation parameters to create a 256 bit
// symmetrical key. For a 128bit key, truncate off everything past the 16th byte.
//
// Note: This is the only use case where key derivation happens on the ECU. All
// other use cases have been ommited.
Error MockTEEVKMSImpl::derive_key(Botan::secure_vector<uint8_t> &m_parentKey, Botan::secure_vector<uint8_t> &derived_key, uint16_t typeId, uint16_t trainingCounter, uint16_t key_length)
{
	LOG_DEBUG("Start");
	#if LOG_LEVEL == LOG_LEVEL_DEBUG
		std::cout << " - Parent Key(vector - hex) = "  << std::endl;
		std::cout << Botan::hex_encode(m_parentKey) <<"  (" << m_parentKey.size() << " elements)" << std::endl;
	#endif

	for (uint8_t i = 1; i <= (uint8_t) ceil((float) key_length*8 / (float) 256); i++)
	{

		std::vector<uint8_t> derivation_data;

		// first the parent key
		derivation_data.insert(derivation_data.end(), m_parentKey.begin(), m_parentKey.end());

		// i = k/l rounds (k = desired output length, l = length of returned hash)
		// then some invariant stuff
		derivation_data.push_back(i);
		derivation_data.push_back('V');
		derivation_data.push_back('K');
		derivation_data.push_back('M');
		derivation_data.push_back('S');
		derivation_data.push_back(0);

		// Parameter dataset type 2...
		// TypeID of the key that is to be derived
		derivation_data.push_back((uint8_t) ((typeId & 0xFF00) >> 8));
		derivation_data.push_back((uint8_t) ((typeId & 0x00FF) >> 0));

		// Training counter
		derivation_data.push_back((uint8_t) ((trainingCounter & 0xFF00) >> 8));
		derivation_data.push_back((uint8_t) ((trainingCounter & 0x00FF) >> 0));

		// key length in LITTLE ENDIAN
		derivation_data.push_back((uint8_t) ((key_length*8 & 0x00FF) >> 0));
		derivation_data.push_back((uint8_t) ((key_length*8 & 0xFF00) >> 8));


		//std::cout << " - derivation_data(vector - hex) = "  << std::endl;
		//std::cout << Botan::hex_encode(derivation_data) <<"  (" << derivation_data.size() << " elements)" << std::endl;

		// derive key by feeding the data into SHA-256

		std::unique_ptr<Botan::HashFunction> dlcHash(Botan::HashFunction::create("SHA-256"));
		Botan::secure_vector<uint8_t> hash;
		try
		{
			dlcHash->update(derivation_data);
			hash = dlcHash->final();
		}
		catch(Botan::Exception & e)
		{
			#if LOG_LEVEL == LOG_LEVEL_DEBUG
				std::cout << "Botan threw an exception: " << e.what() << std::endl << std::endl;
			#endif
			return Error::CRYPTO_OP_ERROR;
		}
	    derived_key.insert(derived_key.end(),hash.begin(), hash.end());
		derivation_data.clear();
		hash.clear();
	}

	#if LOG_LEVEL == LOG_LEVEL_DEBUG
		std::cout << " - derived_key(vector - hex) = "<< std::endl;
		std::cout << Botan::hex_encode(derived_key) <<"  (" << derived_key.size() << " elements)" << std::endl;
	#endif

	LOG_DEBUG("Done");
	return Error::OK;
}

// Finds and returns the DLC decryption key.
Error MockTEEVKMSImpl::get_DLC_key(Botan::secure_vector<uint8_t> &dlcKey)
{
	LOG_DEBUG("Start");
	/* find DLC key (ID-7) in keymap */
	//std::cout << "Find DLC key (Keymap ID-7)" << std::endl;
	const auto &found = m_PSKeyMap_DLCUpdate.find(0007);
	if(found == m_PSKeyMap_DLCUpdate.end())
	{
		return Error::INVALID_ID;
	}

	dlcKey.assign(found->second.get()->value, found->second.get()->value+32);

	LOG_DEBUG("Done");
	return Error::OK;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////
// Interface to VKMSOnlineUpdateAPI.h
///////////////////////////////////////////////////////////////////////////////////////////////////////

// Takes a vector of bytes containing the received VKMS DLC.
// This function calls all functionality required to decrypt, parse and save a
// DLC. After it returns positively, the key data included in the DLC will be
// loaded in memory.
//
// Note: This function doesn't do all checks that a real VKMS would.
Error MockTEEVKMSImpl::handle_dlc(ByteVector dlc)
{
	LOG_DEBUG("Start");

/////	chk DLC size: preamble (54 Byte) + gmac(16 Byte) = 70 Byte -> [A: LH_VKMS_BE_1682], [A: LH_VKMS_BE_1471]
	//std::cout << "Chk DLC size" << std::endl;
	int size = dlc.size();
	if(size < 70)
	{
		//std::cout << " - DLC size NOK (" << size << ")" << std::endl;
		return Error::INVALID_PARAMETER;
	}
	//std::cout << " - DLC size OK (" << size << ")" << std::endl << std::endl;

	/*  get the "Initvialisierungsvektor" (dlc[1..12]) -> [A: LH_VKMS_BE_1066] */
    Botan::secure_vector<uint8_t> init_vector;
	//std::cout << "Get Initalisierungsvektor" << std::endl;
	//std::cout << " - init_vector(dec) = ";
	for (int j=1; j<13; j++)	// bis 1
	{
		init_vector.push_back(dlc.at(j));	//dlc[0]: Version -> [A: LH_VKMS_BE_1066]
		//std::cout << (int)init_vector.back() << " " ;
	}
	//std::cout <<  "  (" << init_vector.size() << " elements)" << std::endl;

	//std::cout << " - init_vector(hex) = ";
	//std::cout << Botan::hex_encode(init_vector) <<"  (" << init_vector.size() << " elements)" << std::endl;

	//std::cout << " - Done" << std::endl << std::endl;


	// Decrypt (AES-GCM) the payload data starting at 55th byte
	//std::cout << "Decrypt (AES-GCM) the payload data starting at 55th byte" << std::endl;

	Botan::secure_vector<uint8_t>  dlcKey;
	Error ret = get_DLC_key(dlcKey);
	//std::cout << "DLC key (vector - hex) = "<< std::endl;
	//std::cout << Botan::hex_encode(dlcKey) <<"  (" << dlcKey.size() << " elements)" << std::endl << std::endl;
	if(Error::OK != ret)
		return ret;

	Botan::secure_vector<uint8_t> associated_data (dlc.begin(), dlc.begin()+54);
	Botan::secure_vector<uint8_t> payload (dlc.begin()+54, dlc.end());

	//std::cout << " - payload(hex): " << Botan::hex_encode(payload) << "  (" << payload.size() << " elements)" << std::endl;

	// AES-GCM is an AEAD cipher mode. Botan::Cipher_Mode would be too general here, because it does not have all functions we need.
	std::unique_ptr<Botan::Cipher_Mode> cipher(Botan::get_cipher_mode("AES-256/GCM", Botan::DECRYPTION));
	std::unique_ptr<Botan::AEAD_Mode> AEAD_cipher(static_cast<Botan::AEAD_Mode*>(cipher.release()));
	Botan::secure_vector<uint8_t> decrypted_payload;

	try
	{
		AEAD_cipher->set_key(dlcKey);
		AEAD_cipher->set_associated_data(associated_data.data(),54); // GCM tag is computed over the entire DLC, so we need to provide the non-encrypted parts, too.
		AEAD_cipher->start(init_vector);
		AEAD_cipher->finish(payload, 0);

		decrypted_payload.reserve(payload.size()-16); // GCM tag at the end is 16 bytes long and is not part of the actual payload
		decrypted_payload.insert(decrypted_payload.end(), payload.begin(), payload.end());
	}
	catch(Botan::Exception & e)
	{
		#if LOG_LEVEL == LOG_LEVEL_DEBUG
			std::cout << "Botan threw an exception: " << e.what() << std::endl << std::endl;
		#endif
		return Error::CRYPTO_OP_ERROR;
	}
	//std::cout << " - Decrypted DLC payload(hex): " << Botan::hex_encode(decrypted_payload) <<"  (" << decrypted_payload.size() << " elements)" << std::endl;
	//std::cout << " - Done" << std::endl << std::endl;

	int num_blocks = dlc.at(53);
	std::string out_str = "";
	KeyStringsMap keys_map;
	ret = proccess_DLC_blocks(keys_map, decrypted_payload, num_blocks);
	if(Error::OK == ret)
		ret = generate_keys_string(out_str, keys_map);
	if(Error::OK == ret)
		ret = write_key_data(out_str);
	if(Error::OK == ret)
		ret = build_keys_map();

	#if(LOG_LEVEL == LOG_LEVEL_DEBUG)
		std::cout << std::endl;
		LOG_DEBUG("Read generated Key file");
		std::ifstream keys_input( (MOCKTEE_VKMS_FOLDER+"keys_DlcDownload_out.tsv").c_str(), std::fstream::in );
		if(!keys_input)
		{
			LOG_ERROR("File not found");
			ret = Error::FILE_NOT_FOUND;
		}
		else
		{
			std::string line;
			while(getline(keys_input, line))
				std::cout << line << std::endl;
		}
	#endif

	LOG_DEBUG("Delete generated Key file");
	remove( (MOCKTEE_VKMS_FOLDER+"keys_DlcDownload_out.tsv").c_str() );

	LOG_DEBUG("Done");
	return ret;
}

// Iterates over DLC blocks and process each block.
// Each block is handled correctly based on the Key Genus field. Certificates
// are written out by calling write_cert_data() immediately. Everything else
// ends up in out_map.
Error MockTEEVKMSImpl::proccess_DLC_blocks(KeyStringsMap &out_map, Botan::secure_vector<uint8_t> decrypted_payload, int num_blocks)
{
	LOG_DEBUG("Start");
	#if LOG_LEVEL == LOG_LEVEL_DEBUG
		std::cout << " - Block to proccess: " << num_blocks << std::endl;
	#endif
	Error ret = Error::OK;
	int first_byte_ptr = 0;

	for (int k = 0; k< num_blocks; k++)
	{

		//std::cout << "Now at block number: " << k << std::endl;
		uint16_t key_type_id = ((uint16_t)decrypted_payload[first_byte_ptr] << 8) + decrypted_payload[first_byte_ptr+1];
		//std::cout << " - Type ID: " << key_type_id << std::endl;
		uint16_t counter = ((uint16_t)decrypted_payload[first_byte_ptr+2]) + decrypted_payload[first_byte_ptr+3];
		//std::cout << " - Training counter: " << (int)counter << std::endl;
		uint8_t key_genus = decrypted_payload[first_byte_ptr+4];
		//std::cout << " - Genus: " << (int)key_genus << std::endl;
		uint8_t flags = decrypted_payload[first_byte_ptr+5];
		//std::cout << " - Flags: " << (int)flags << std::endl;

		uint16_t data_len = ((uint16_t)decrypted_payload[first_byte_ptr+6] << 8) + decrypted_payload[first_byte_ptr+7];
		//std::cout << " - Key length: " << (int)data_len << std::endl;
		std::vector<uint8_t> key_data = std::vector<uint8_t>(decrypted_payload.begin()+first_byte_ptr+8, decrypted_payload.begin()+first_byte_ptr+8+data_len);
		//std::cout << " - Key: " <<  Botan::hex_encode(key_data) <<"  (" << key_data.size() << " elements)" << std::endl << std::endl;

		first_byte_ptr = first_byte_ptr+8+data_len;

		if (flags == 0x80 && (key_genus == 0x11 || key_genus == 0x12))
		{
			// derive new key according to derivation rules in payload data
			// key_data contains the ID of the parent key
			// Genus defines the length of the resulting key and which of the 3 types of derivation parameters has to be used
			// According to [I: FK_VKMS_243 v2.1 6.2.2019], only the key derivation of Type 2 (for key Genus 0x11, 0x12) can be derived on the ECU.

			// find length according to genus
			uint16_t key_length = 0;
			if(key_genus == 0x11) // SYMM_128
				key_length = 16;
			if(key_genus == 0x12) // SYMM_256
				key_length = 32;

			// Find parent key
			const auto &found = m_PSKeyMap_DLCUpdate.find(((uint16_t)key_data[0]<< 8) + key_data[1]);
		    if(found == m_PSKeyMap_DLCUpdate.end())
		    {
		        return Error::INVALID_ID;
		    }
			Botan::secure_vector<uint8_t> m_parentKey(found->second.get()->value, found->second.get()->value+key_length);

			// call the Key Derivation Function
			Botan::secure_vector<uint8_t> derived_key;
			Error new_ret;
			new_ret = derive_key(m_parentKey, derived_key, key_type_id, counter, key_length);
			if((new_ret != Error::OK) && (ret == Error::OK)) {
                ret = new_ret;
            }

			// copy result to key_data vector
			data_len = key_length;
			key_data.clear();
			key_data.insert(key_data.end(), derived_key.begin(), derived_key.end());
		}

		if(key_genus != 0x01) // not a certificate...
		{
			LOG_DEBUG("write key to key map (out_map[key_type_id] = key_str)");
			std::string key_str = "";
			//pretty up the formatting
			for(int l = 0; l< data_len; l++)
			{
				char byte[3];
				sprintf(byte, "%02x", key_data[l]);
				key_str += byte;
				if(l < data_len-1)
					key_str += ":";
			}

			out_map[key_type_id] = key_str;
		}
		else	// if key_data is a cert, write to .pem file instead
		{
			LOG_DEBUG("save cert to *.pem file");
			std::ostringstream cert_ss;
			cert_ss << key_data.data();
			Error new_ret;
			new_ret = write_cert_data(cert_ss.str(), key_type_id);
			if((new_ret != Error::OK) && (ret == Error::OK)) {
                ret = new_ret;
            }
		}
	}
	LOG_DEBUG("Done");

	return ret;
}


// Goes through the <Type-ID, Key Data> in in_map, formats them correctly and
// adds them to out_str. This string can then be handed to write_key_data().
// Lines for Type-IDs that are not in the map (i.e. there is a gap in-between
// Type-IDs in the map) are filled in with 16 Bytes of zeroes.
Error MockTEEVKMSImpl::generate_keys_string(std::string &out_str, KeyStringsMap &in_map)
{
	// One line for each key in map. WE also need to fill in IDs that have no data.
	LOG_DEBUG("Start");
	if(in_map.empty())
		return Error::INVALID_PARAMETER;

	uint16_t highest_key_id = in_map.rbegin()->first;

	for (uint16_t key_id = 1; key_id <= highest_key_id; key_id++)
	{
		std::stringstream ss;
		ss << std::setw(4) << std::setfill('0') << key_id;
		std::string id = ss.str();
		out_str.append(id);
		out_str.append("	");
		auto key_pair = in_map.find(key_id);
    	if (key_pair != in_map.end())
			out_str.append(key_pair->second);
		else
			out_str.append("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"); // to keep the key loading function from breaking

		out_str += "\n";

	}
	LOG_DEBUG("Done");

	return Error::OK;
}

// Writes the content of out_str to the keys.tsvfile in the /VKMS folder.
// This will not update the in-memory VKMS key data. build_keys_map() has to be
// called again once this function returns with an OK.
Error MockTEEVKMSImpl::write_key_data(std::string out_str)
{
	LOG_DEBUG("Start");
	//std::cout << "Write received key data to file" << std::endl;
	//  write to keys.tsv
/*	#if LOG_LEVEL == LOG_LEVEL_DEBUG
		const std::string KEYS_FILE = MOCKTEE_VKMS_FOLDER+"keys_DlcDownload_out.tsv";
	#else
		const std::string KEYS_FILE = MOCKTEE_VKMS_FOLDER+"keys.tsv";
	#endif
*/	const std::string KEYS_FILE = MOCKTEE_VKMS_FOLDER+"keys_DlcDownload_out.tsv";
	LOG_DEBUG(KEYS_FILE.c_str());

	std::ofstream output;

	output.open(KEYS_FILE, std::fstream::out);
	if(output.is_open())
	{
		output << out_str;
		output.close();
	}
	else
	{
			return Error::FILE_NOT_OPEN;
	}

	LOG_DEBUG("Done");
	return Error::OK;
}


// Writes the content of out_str to the appropriate .PEM file in the /VKMS
// folder. The file name is chosen based on the Type-ID associeted with the
// certificate.
//
// So far only two IDs are implemented and they might be associated with the
// wrong file name. This has to be completed once we have more information.
Error MockTEEVKMSImpl::write_cert_data(std::string out_str, uint16_t vkms_id)
{
	LOG_DEBUG("Start");
	std::unordered_map<uint16_t, std::string>name_map = {{0,""},{0x00B,"VKMS_ECU_BASE_CERT"},{0x00C,"VKMS_ROOT_CERT"}};
	std::string CERT_NAME = name_map[vkms_id];
/*	#if LOG_LEVEL == LOG_LEVEL_DEBUG
		const std::string KEYS_FILE = MOCKTEE_VKMS_FOLDER+CERT_NAME+"_DlcDownload_out.pem";
	#else
		const std::string KEYS_FILE = MOCKTEE_VKMS_FOLDER+CERT_NAME+".pem";
	#endif
*/	const std::string KEYS_FILE = MOCKTEE_VKMS_FOLDER+CERT_NAME+"_DlcDownload_out.pem";
	LOG_DEBUG(KEYS_FILE.c_str());

	std::ofstream output;

	output.open(KEYS_FILE, std::fstream::out);
	if(output.is_open())
	{
		output << out_str;
		output.close();
	}
	else
	{
			LOG_DEBUG("Error::FILE_NOT_OPEN");
			return Error::FILE_NOT_OPEN;
	}

	LOG_DEBUG("Done");
	return Error::OK;
}

//
Error MockTEEVKMSImpl::retrieve_certificate(ClientCertID typeId, CertificateBundle &certificate)
{
	LOG_DEBUG("Start");
	MockTeeError ret = MockTeeError::OK;

	CertificateBundle tempCertificate = get_client_cert(typeId);
	if( tempCertificate != "" )
			certificate = tempCertificate;
	else
	   ret = MockTeeError::INVALID_ID;

	LOG_DEBUG("Done");
	return ret;
}

Error MockTEEVKMSImpl::calculate_identity_hash(ByteVector &targetHash, const ByteVector &challenge)
{
	(void) challenge;
	LOG_DEBUG("Start");

	Error ret = MockTeeError::OK;
	std::string FazitIdStr	= "4142434445464748494A4b4B4D4E4F5051525354555657"; //FAZIT-ID-String ’ABCDEFGHIJKLMNOPQRSTUVW’
	std::string DlcHashStr = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF";
/*
	SecureVect_U8 pssKey;
	ret = VKMS_GetKey(KEY_TYPE_ID::PSS, pssKey);

	LOG_DEBUG_PLAIN("PSS: ");
	LOG_DEBUG_PLAIN(Botan::hex_encode(pssKey).c_str());
*/
	if( ret == Error::OK)
	{
		try
		{
			/* concat data for hash */
			Botan::secure_vector<uint8_t> DlcHash = Botan::hex_decode_locked(DlcHashStr);
			LOG_DEBUG_PLAIN("DlcHash: ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(DlcHash).c_str());

			Botan::secure_vector<uint8_t> FazitId = Botan::hex_decode_locked(FazitIdStr);
			LOG_DEBUG_PLAIN("FazitId: ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(FazitId).c_str());

			LOG_DEBUG_PLAIN("Challenge: ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(challenge).c_str());

			Botan::secure_vector<uint8_t> concatVect;
			concatVect.insert(concatVect.end(),DlcHash.begin(), DlcHash.end());
			concatVect.insert(concatVect.end(),FazitId.begin(), FazitId.end());
			LOG_DEBUG_PLAIN("concatVect: ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(concatVect).c_str());

			/* Build hash */
			std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));

			Botan::secure_vector<uint8_t> finalHash;
			hash->update(concatVect.data(),concatVect.size());
			finalHash = hash->final();
			targetHash.assign(finalHash.begin(), finalHash.end());
			LOG_DEBUG_PLAIN("targetHash (original): ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(targetHash).c_str());
			targetHash.resize(16);
			LOG_DEBUG_PLAIN("targetHash (final): ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(targetHash).c_str());

		}
		catch(Botan::Exception & e)
		{
			#if(LOG_LEVEL == LOG_LEVEL_DEBUG)
				char s[] = "Botan threw an exception: ";
				std::strcat( s,  e.what() );
				LOG_DEBUG( s );
			#endif
			ret =  Error::CRYPTO_OP_ERROR;
		}

	}

	LOG_DEBUG("Done");
	return ret;
/*
Berechnungsvorschrift: (aus: Lastenheft VKMS Backend Lastenheftversion: 1.1 Build 22)
[A: LH_VKMS_BE_1200]
Über den Datenblock d wird ein Hashwert nach dem Verfahren SHA-256 berechnet. Die ersten 16 Byte
der errechneten Prüfsumme sind die Identitätschecksumme.

	1. Konkatenation aus:
		- 16 Byte langen DLC-Verifikationschecksumme
		- 23 Zeichen langen FAZIT-ID-String des Steuergeräts
	2. Über das Ergebnis wird ein Hashwert mit dem Algorithmus SHA256 berechnet.
	3. Die ersten 16 Byte des resultierenden Hashwerts bilden die Identitätschecksumme.

Berechnungsvorschrift: (aus: Fachkonzept - VKMS-Fachkonzept_v0.23)
[I: FK_VKMS_971]
	1. Konkatenation aus:
		- 16 Byte langen Challenge
		- 16 Byte langen DLC-Verifikationschecksumme
		- 23 Zeichen langen FAZIT-ID-String des Steuergeräts
	2. Über das Ergebnis wird ein Hashwert mit dem Algorithmus HMAC-SHA256 berechnet.
	3. Als Schlüssel wird der PSS eingesetzt wird.
	4. Die ersten 16 Byte des resultierenden Hashwerts bilden die Identitätschecksumme.
*/
}


Error MockTEEVKMSImpl::calculate_pss_hash(ByteVector &targetHash)
{
	LOG_DEBUG("Start");

	Error ret = MockTeeError::OK;

	ByteVector pssKey;
//	ret = get_key(KEY_TYPE_ID::PSS, pssKey);

	/* find key in keymap */
	const auto &found = m_PSKeyMap_DLCUpdate.find(KEY_TYPE_ID::PSS);
	if(found == m_PSKeyMap_DLCUpdate.end())
	{
		return Error::INVALID_ID;
	}

	pssKey.assign(found->second.get()->value, found->second.get()->value + found->second.get()->length);

	if( ret == Error::OK)
	{
		try
		{
			LOG_DEBUG_PLAIN("--- PSS: ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(pssKey).c_str());

			const std::string s = "VKMS_PSS_Hash";
			Botan::secure_vector<uint8_t> data(s.begin(), s.end());

			#if(LOG_LEVEL == LOG_LEVEL_DEBUG)
				LOG_DEBUG_PLAIN("--- data (DEC -> CHAR): ");
				for(auto i : data)
					std::cout << (int)i << "\t";
				std::cout << std::endl;
				for(auto c : data)
					std::cout << (char)c << "\t";
				std::cout << std::endl;
			#endif

			LOG_DEBUG_PLAIN("--- data (HEX): ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(data).c_str());

			std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create("HMAC(SHA-256)"));
			if(!mac)
			{
				LOG_ERROR("std::unique_ptr<Botan::MessageAuthenticationCode> mac(...)");
				return Error::CRYPTO_OP_ERROR;
			}

			mac->set_key(pssKey);
			mac->update(data);

			Botan::secure_vector<uint8_t> finalHash;
			finalHash = mac->final();
			targetHash.assign(finalHash.begin(), finalHash.end());
			LOG_DEBUG_PLAIN("--- targetHash (orig): ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(targetHash).c_str());

			#if(LOG_LEVEL == LOG_LEVEL_DEBUG)
				std::cout << std::endl;
				std::cout << "Verification with original data (mac->verify_mac(targetHash): " << (mac->verify_mac(finalHash) ? "success" : "failure")<< std::endl << std::endl;
				LOG_DEBUG_PLAIN("--- Corrupting data: data.back()++ (DEC -> CHAR)");
				data.back()++;
				for(auto i : data)
					std::cout << (int)i << "\t";
				std::cout << std::endl;
				for(auto c : data)
					std::cout << (char)c << "\t";
				std::cout << std::endl;
				std::cout << std::endl;
				//Verify with corrupted data
				mac->update(data);
				std::cout << "Verification with corrupted data (mac->verify_mac(targetHash): " << (mac->verify_mac(finalHash) ? "success" : "failure")<< std::endl << std::endl;
			#endif

			finalHash.resize(16);
			targetHash.resize(16);
			LOG_DEBUG_PLAIN("--- targetHash (final): ");
			LOG_DEBUG_PLAIN(Botan::hex_encode(finalHash).c_str());
		}
		catch(Botan::Exception & e)
		{
			#if(LOG_LEVEL == LOG_LEVEL_DEBUG)
				char s[] = "Botan threw an exception: ";
				std::strcat( s,  e.what() );
				LOG_DEBUG( s );
			#endif
			ret =  Error::CRYPTO_OP_ERROR;
		}

	}

	LOG_DEBUG("Done");
	return ret;
/*
Berechnungsvorschrift: (aus: Lastenheft VKMS Backend Lastenheftversion: 1.1 Build 22)
[A: LH_VKMS_BE_1308]
	1. 	Als Berechnungsfunktion für die Checksumme wird das Verfahren HMAC-SHA256 verwendet, das im Fol-
		genden mit der Syntax HMAC (Schlüssel, Nutzdaten) verwendet wird, wobei jeweils nur die ersten 16
		Bytes des berechneten Hashwerts verwendet werden.
[A: LH_VKMS_BE_1309]
	2.	Der Hashwert h wird berechnet als h = HMAC (K,S), wobei K der zu verarbeitende Schlüssel und S die
		konstante Zeichenkette „VKMS_PSS_Hash“ ist.

Berechnungsvorschrift: (aus: Fachkonzept - VKMS-Fachkonzept_v0.23)
[I: FK_VKMS_972]
	1. Hashwert PSS: h = HMAC(K,S)
		 K = der aktuelle PSS (bei unbedateten Steuergeräten mit dem IS)
		 S = die Zeichenkette „VKMS_PSS_Hash“
	2. Die erste 16 Bytes des Hash ergeben die PSS-Checksumme.
*/
}

// Gives the ECU Trainign Counter -> just MOCKED by random value
Error MockTEEVKMSImpl::retrieve_training_counter(uint16_t &tc)
{
	LOG_DEBUG("Start");
    std::random_device rd;						// Seed with a real random value, if available
    std::default_random_engine rdEng(rd());		// default random engine seed with rd()
    std::uniform_int_distribution<int> uniform_dist(1, 100);	// Choose a random int in the inteval from 1 to 100
	tc = uniform_dist(rdEng);

	LOG_DEBUG("Done");
	return Error::OK;
}


Error MockTEEVKMSImpl::retrieve_vkms_vin(ByteVector &vin)
{
	LOG_DEBUG("Start");
	VIN  vkmsVin = get_vkms_vin();

	vin.clear();
	vin.insert(vin.end(), vkmsVin.begin(), vkmsVin.end() );
	#if(LOG_LEVEL == LOG_LEVEL_DEBUG)
		std::cout << "--- VkmsVin (String): " << vkmsVin << std::endl;
		LOG_DEBUG_PLAIN("--- VkmsVin (DEC -> CHAR): ");
		for(auto i : vin)
			std::cout << (int)i << "\t";
		std::cout << std::endl;
		for(auto c : vin)
			std::cout << (char)c << "\t";
		std::cout << std::endl;
		std::cout << "--- VkmsVin (HEX): " << Botan::hex_encode(vin) << std::endl;

	#endif

	LOG_DEBUG("Done");
	return MockTeeError::OK;
}

Error MockTEEVKMSImpl::retrieve_part_number(std::string &pn)
{
	pn = "1A2345678BC";
	return Error::OK;
}

Error MockTEEVKMSImpl::retrieve_diagnostic_id(std::string &dId)
{
	dId = "0x005F";	// or 0x0075
	return Error::OK;
}

Error MockTEEVKMSImpl::retrieve_fazit_id_string(std::string &fIdString)
{
	fIdString = "WOW-MSG16.09.1900014321";
	return Error::OK;
}
