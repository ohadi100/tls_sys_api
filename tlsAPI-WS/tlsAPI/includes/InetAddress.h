/**
 * @file InetAddress.h
 * @brief Defines the IInetAddress interface and the InetAddressFactory for creating IP address instances.
 *
 * This header file provides the definition of the IInetAddress interface, which represents an immutable
 * IP address. It also includes the InetAddressFactory, which is used to create instances of IInetAddress.
 * The file is crucial for handling IP addresses in network connections where TLS is involved.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All the information and materials contained herein, including the intellectual and technical concepts, 
 * are the property of CARIAD SE and may be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * This notice does not evidence any actual or intended publication or disclosure of this source code, which 
 * includes information that is confidential and/or proprietary and considered trade secrets of CARIAD SE.
 *
 * Any reproduction, modification, distribution, or public display of this source code without the prior 
 * written consent of CARIAD SE is strictly prohibited and in violation of applicable laws.
 *
 * Possession of this source code does not convey any rights to reproduce, disclose, or distribute its contents,
 * or to manufacture, use, or sell anything it may describe, in whole or in part.
 */

#ifndef SRC_INETADDRESS_H_
#define SRC_INETADDRESS_H_

#include <memory>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstddef>
#include <cstring>
#include <string>
#include "vwgtypes.h"
#include "TLSResult.h"

using namespace vwg::types;

namespace vwg {
namespace tls {

/**
 * @class IInetAddress
 * @brief Interface for an IP address, providing an immutable representation of an IP address.
 *
 * This interface provides methods to validate, retrieve, and interact with IP addresses. It is designed
 * to be used in networking operations, especially those requiring secure connections.
 */
class IInetAddress {
public:
    /**
     * @brief Constructor that initializes the address memory to zero.
     */
    IInetAddress() { memset(m_addr, 0, sizeof(m_addr)); }
    virtual ~IInetAddress() = default;

    /**
     * @brief Checks if the IP address is a valid IPv6 address.
     * @return True if this is a valid IPv6 address, otherwise false.
     */
    virtual Boolean isIPv6() = 0;

    /**
     * @brief Checks if the IP address is a valid IPv4 address.
     * @return True if this is a valid IPv4 address, otherwise false.
     */
    virtual Boolean isIPv4() = 0;

    /**
     * @brief Returns a string representation of the IP address.
     * @return String representation of the IP address.
     */
    virtual std::string toString() = 0;

    /**
     * @brief Checks if the IP address is valid. Should always return true as factory ensures validity.
     * @return True if valid, otherwise false.
     */
    virtual Boolean isValid() = 0;

    /**
     * @brief Initiates validation of the IP address, not typically required by the application.
     * @return Underlying error code if validation fails.
     */
    virtual UInt32 validate() = 0;

    /**
     * @brief Retrieves the socket address family of the IP address.
     * @return The socket address family.
     */
    virtual sa_family_t getSaFamily() = 0;

    /**
     * @brief Gets the raw IP address data.
     * @return Pointer to the raw IP address data.
     */
    virtual uint8_t* getAddr() {
        return m_addr;
    }

protected:
    uint8_t m_addr[16]; ///< Storage for the raw IP address data.
};

/**
 * @typedef SPIInetAddress
 * @brief Convenience typedef for shared_ptr to IInetAddress.
 */
using SPIInetAddress = std::shared_ptr<IInetAddress>;

/**
 * @typedef IInetAddressResult
 * @brief Convenience typedef for TLSResult encapsulating a shared_ptr to IInetAddress.
 */
using IInetAddressResult = TLSResult<SPIInetAddress>;

/**
 * @class InetAddressFactory
 * @brief Factory class for creating IInetAddress instances.
 *
 * Provides static methods to create IInetAddress objects from string representations of IP addresses,
 * ensuring the validity of the addresses before returning them.
 */
class InetAddressFactory {
private:
    InetAddressFactory() = default;

public:
    /**
     * @brief Creates an IInetAddress from a string representing an IPv4 or IPv6 address.
     *
     * Validates the input string and returns an IInetAddress if valid.
     * @param inetAddr String representation of the IP address (e.g., "::2" or "192.168.1.1").
     * @return IInetAddressResult containing either the IInetAddress object or an error.
     */
    static IInetAddressResult makeIPAddress(const std::string& inetAddr);

    /**
     * @brief Overloaded method for creating an IInetAddress from a C-style string IP address.
     *
     * Validates the input string and returns an IInetAddress if valid.
     * @param inetAddr C-style string representation of the IP address.
     * @return IInetAddressResult containing either the IInetAddress object or an error.
     */
    static IInetAddressResult makeIPAddress(const char* inetAddr);
};

} // namespace tls
} // namespace vwg

#endif /* SRC_INETADDRESS_H_ */
