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


#include "MockTEEClientCertImpl.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <locale>
#include <unistd.h>
#include <stdio.h>

#include <botan/x509cert.h>
#include <botan/x509_key.h>
#include <botan/x509self.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>
#include <botan/data_src.h>

#include "TEEIds.h"
#include "Log.h"

using vwg::tee::impl::MockTEEClientCertImpl;
using namespace vwg::tee;
using namespace vwg::tee::impl::teeids;

MockTEEClientCertImpl::MockTEEClientCertImpl(){

}


MockTEEClientCertImpl::~MockTEEClientCertImpl(){

}


Error MockTEEClientCertImpl::generate_private_key(ClientCertID keyId)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	Key key;
	Botan::AutoSeeded_RNG rng;
	Botan::EC_Group domain = Botan::EC_Group("secp256r1"); // aka prime256v1
	std::unique_ptr<Botan::ECDSA_PrivateKey> keyPair(new Botan::ECDSA_PrivateKey(rng, domain));

	if (MOS_CSR != keyId)
	{
		return MockTeeError::INVALID_ID;
	}
    // encode private key as PEM string
	key = Botan::PKCS8::PEM_encode(*keyPair);

	// write key to file
	std::ofstream keyFile(MOCKTEE_CCSTORE_FOLDER+keyId+KEY_POSTFIX);
	if (!keyFile.is_open())
	{
		return MockTeeError::FILE_NOT_FOUND;
	}

	keyFile << key;
	keyFile.close();

	return MockTeeError::OK;
}


CSR MockTEEClientCertImpl::generate_csr(String commonName, ClientCertID keyId)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	CSR csr;
	Botan::X509_Cert_Options opts;
	std::unique_ptr<Botan::PKCS10_Request> csrRequest;
	Botan::AutoSeeded_RNG rng;
	std::unique_ptr<Botan::Private_Key> private_key;

	if (MOS_CSR == keyId)
	{
		if (!commonName.empty())
		{
			if (access((MOCKTEE_CCSTORE_FOLDER+keyId+KEY_POSTFIX).c_str(), F_OK) != -1)
	        {
				/* load temporary private UC key from file */
				Botan::DataSource_Stream keyFile(MOCKTEE_CCSTORE_FOLDER+keyId+KEY_POSTFIX);
				private_key = Botan::PKCS8::load_key(keyFile);

				if (nullptr != private_key.get())
				{
					// set static content and provided common name
					opts.country = "DE";
					opts.organization = "VWAG";
					opts.common_name = commonName;

					// have Botan create the request
					csrRequest = std::unique_ptr<Botan::PKCS10_Request>(
						new Botan::PKCS10_Request(
							Botan::X509::create_cert_req(
								opts, *private_key, "SHA-256", rng)));
					if (nullptr != csrRequest.get())
					{
						csr = csrRequest->BER_encode();
					}
				}
			}
		}
	}

	return csr;
}


Signature MockTEEClientCertImpl::generate_signature(ClientCertID keyId, ByteVector content, HashFunction hashFunction)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	Signature signature;
	Botan::AutoSeeded_RNG rng;
	std::unique_ptr<Botan::Private_Key> private_key;

	if (MOS == keyId)
	{
		if (access((MOCKTEE_CCSTORE_FOLDER+keyId+KEY_POSTFIX).c_str(), F_OK) != -1)
        {
			/* load private key from file */
			Botan::DataSource_Stream keyFile(MOCKTEE_CCSTORE_FOLDER+keyId+KEY_POSTFIX);
			private_key = Botan::PKCS8::load_key(keyFile);

			if (nullptr != private_key.get())
			{
				/* Create signature */
				Botan::PK_Signer signer(*private_key, rng, hashFunction);
				signer.update(content);
				signature = signer.signature(rng);
			}
		}
	}

	return signature;
}


Key MockTEEClientCertImpl::get_public_key(ClientCertID keyId)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	Key key;
	Botan::AutoSeeded_RNG rng;
	Botan::EC_Group domain = Botan::EC_Group("secp256r1"); // aka prime256v1
	std::unique_ptr<Botan::Private_Key> public_key;

	if ((MOS_CSR == keyId) || (MOS == keyId))
	{
		if (access((MOCKTEE_CCSTORE_FOLDER+keyId+KEY_POSTFIX).c_str(), F_OK) != -1)
        {
			/* load private key from key file */
			Botan::DataSource_Stream keyFile(MOCKTEE_CCSTORE_FOLDER+keyId+KEY_POSTFIX);
			public_key = Botan::PKCS8::load_key(keyFile);

			if (nullptr != public_key.get())
			{
				/* encode public key in PEM format */
				key = Botan::X509::PEM_encode(*public_key);
			}
		}
	}

	return key;
}

Key MockTEEClientCertImpl::get_private_key(ClientCertID keyId)
{
	Key key;
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);

	std::ifstream file(MOCKTEE_CCSTORE_FOLDER+keyId+KEY_POSTFIX);
	if (true == file.is_open())
	{
		std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		key = data;
		file.close();
	}

	return key;
}


CertificateChain MockTEEClientCertImpl::get_client_cert(ClientCertID keyId)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	CertificateChain certificate;

	if (MOS == keyId)
	{
		std::ifstream file(MOCKTEE_CCSTORE_FOLDER+keyId+CERT_POSTFIX);
		if (file.is_open())
		{
			// load certificate data from file, return file contents without processing
			std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
			certificate = data;
		}
	}

	return  certificate;
}


Error MockTEEClientCertImpl::set_client_cert_and_move_key(CertificateChain clientCertificateChain, ClientCertID sourceKeyId, ClientCertID targetKeyId)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	Botan::AutoSeeded_RNG rng;
	std::unique_ptr<Botan::Private_Key> private_key;

    if (clientCertificateChain.empty() && sourceKeyId.empty())
    {
        /* source key and certificate data empty -> delete the target cert and key file */
        if (access((MOCKTEE_CCSTORE_FOLDER+targetKeyId+CERT_POSTFIX).c_str(), F_OK) != -1)
        {
            /* file exists, delete it */
            if ( remove((MOCKTEE_CCSTORE_FOLDER+targetKeyId+CERT_POSTFIX).c_str() ) != 0 )
            {
                /* source private key file exists but is not accessible */
        		return MockTeeError::FILE_NOT_FOUND;
            }
        }
        if (access((MOCKTEE_CCSTORE_FOLDER+targetKeyId+KEY_POSTFIX).c_str(), F_OK) != -1)
        {
            /* file exists, delete it */
            if ( remove((MOCKTEE_CCSTORE_FOLDER+targetKeyId+KEY_POSTFIX).c_str() ) != 0 )
            {
                /* source private key file exists but is not accessible */
        		return MockTeeError::FILE_NOT_FOUND;
            }
        }

        return MockTeeError::OK;
    }

	if (access((MOCKTEE_CCSTORE_FOLDER+sourceKeyId+KEY_POSTFIX).c_str(), F_OK) == -1)
	{
		/* source private key file not found/accessible */
		return MockTeeError::FILE_NOT_FOUND;
	}

	/* load private key from file */
	std::unique_ptr<Botan::DataSource_Stream> keyFile(new Botan::DataSource_Stream(MOCKTEE_CCSTORE_FOLDER+sourceKeyId+KEY_POSTFIX));
	private_key = Botan::PKCS8::load_key(*keyFile);
	keyFile.reset();

	if (nullptr == private_key.get())
	{
		/* source private key file not found/accessible */
		return MockTeeError::FILE_NOT_FOUND;
	}

	std::string private_key_as_pem = Botan::PKCS8::PEM_encode(*private_key);

	/* save private key to file */
	std::ofstream target_key_file(MOCKTEE_CCSTORE_FOLDER+targetKeyId+KEY_POSTFIX);
	if (!target_key_file.is_open())
	{
		return MockTeeError::FILE_NOT_FOUND;
	}

	if (!clientCertificateChain.empty())
	{
		target_key_file << private_key_as_pem;
	}

	target_key_file.close();

	/* save certificate chain to file */
	std::ofstream target_cert_file(MOCKTEE_CCSTORE_FOLDER+targetKeyId+CERT_POSTFIX);
	if (!target_cert_file.is_open())
	{
		return MockTeeError::FILE_NOT_FOUND;
	}

	if (!clientCertificateChain.empty())
	{
		target_cert_file << clientCertificateChain;
	}
	target_cert_file.close();

	/* remove source */
	if( remove( (MOCKTEE_CCSTORE_FOLDER+sourceKeyId+KEY_POSTFIX).c_str() ) != 0 )
	{
		return MockTeeError::FILE_NOT_FOUND;
	}

	return MockTeeError::OK;
}

/**
 * tbd
 */
void MockTEEClientCertImpl::decrypt_data(ByteVector data)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	(void)data;
}
