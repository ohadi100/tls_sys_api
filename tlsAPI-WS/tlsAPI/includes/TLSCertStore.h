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


#ifndef INCLUDES_TLSCERTSTORE_H_
#define INCLUDES_TLSCERTSTORE_H_

/**
 * Experimantal API for a x509 keystore
 * This is not part of the TLS API, but will belong to the set of API needed to implement features for the backend TLS.
 *
 *
 */

/**
 *  enum keystores
 *  list all MOS keystores
 */

/**
 * create a MOS keystore
 *
 */
CertStoreID createMOSKeyStore();

/**
void add_certificate(const X509_Certificate &cert)

Add a certificate to the store
void add_certificate(std::shared_ptr<const X509_Certificate> cert)

Add a certificate already in a shared_ptr to the store
void add_crl(const X509_CRL &crl)

Add a certificate revocation list (CRL) to the store.
void add_crl(std::shared_ptr<const X509_CRL> crl)

Add a certificate revocation list (CRL) to the store as a shared_ptr
*/


#endif /* INCLUDES_TLSCERTSTORE_H_ */
