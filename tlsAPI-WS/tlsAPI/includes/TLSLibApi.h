/**
 * @file TLSLibAPI.h
 * @brief Entry point and management functions for the TLS library.
 *
 * Provides the functions necessary to initialize and clean up the TLS library, setting up the environment needed
 * for secure communications. This includes initializing SSL libraries and communication channels.
 */

#ifndef SRC_TLSLIBAPI_H_
#define SRC_TLSLIBAPI_H_

#include "ITLSSocketFactory.h"

namespace vwg {
namespace tls {

/**
 * @brief Initializes the TLS library and returns the socket factory.
 * @return ITLSSocketFactoryResult containing either the factory or an error code if initialization fails.
 */
extern ITLSSocketFactoryResult initTLSLib();

/**
 * @brief Cleans up the TLS library.
 * This function should be called to clean up resources used by the TLS library. After calling this,
 * no more socket instances will be provided by the factory.
 */
extern void cleanupTLSLib();

} // namespace tls
} // namespace vwg

#endif /* SRC_TLSLIBAPI_H_ */
