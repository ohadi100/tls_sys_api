/**
 * @file TLSCertStore.h
 * @brief Experimental API for managing a x509 keystore.
 *
 * This header defines the API for managing certificate keystores, which is essential for handling certificates
 * within the TLS framework but not part of the standard TLS API. It provides functionality to create keystores and
 * manage certificates and certificate revocation lists (CRLs).
 */

#ifndef INCLUDES_TLSCERTSTORE_H_
#define INCLUDES_TLSCERTSTORE_H_

#include <memory>
#include "X509_Certificate.h"
#include "X509_CRL.h"

namespace vwg {
namespace tls {

/**
 * @brief Creates a MOS keystore.
 * @return A handle to the newly created keystore.
 */
CertStoreID createMOSKeyStore();

/**
 * @brief Adds a certificate to the store.
 * @param cert Reference to the certificate to be added.
 */
void add_certificate(const X509_Certificate &cert);

/**
 * @brief Adds a certificate to the store using a shared pointer.
 * @param cert Shared pointer to the certificate to be added.
 */
void add_certificate(std::shared_ptr<const X509_Certificate> cert);

/**
 * @brief Adds a Certificate Revocation List (CRL) to the store.
 * @param crl Reference to the CRL to be added.
 */
void add_crl(const X509_CRL &crl);

/**
 * @brief Adds a Certificate Revocation List (CRL) to the store using a shared pointer.
 * @param crl Shared pointer to the CRL to be added.
 */
void add_crl(std::shared_ptr<const X509_CRL> crl);

} // namespace tls
} // namespace vwg

#endif /* INCLUDES_TLSCERTSTORE_H_ */
