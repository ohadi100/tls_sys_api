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

namespace vwg
{
namespace tls
{

/**
 * \brief Representation an interface of an IP address. Basically this will give you an immutable IP address interface.
 */
class IInetAddress
{
public:
    IInetAddress() { memset(m_addr, 0, sizeof(m_addr)); }
    virtual ~IInetAddress() = default;

public:
    /**
     * \brief Checks if this a valid IPv6 address.
     *
     * \return true if this is a valid IPv6 address.
     */
    virtual Boolean isIPv6() = 0;

    /**
     * \brief Checks if this is a valid IPv6 address.
     *
     * \return true if this is a valid IPv6 address
     */
    virtual Boolean isIPv4() = 0;

    /**
     * \brief Makes a sting representation of the IP address.
     *
     * \return string representation of the IP address
     */
    virtual std::string toString() = 0;

    /**
     * \brief Checks if this is a valid IP address.
     * basically this will always be true, because the factory InetAddressFactory will only
     * return valid IInetAddress objects.
     *
     * \return string representation of the IP address.
     */
    virtual Boolean isValid() = 0;

    /**
     * \brief Starts the IP address validation.
     * this is maybe not needed by the application.
     * 
     * \return an underlying error code.
     */
    virtual UInt32 validate() = 0;

    /**
     * \brief This gives the sa_family_t of the IP address.
     * this belongs to the socket API, and will be used by the implementation of the library when creating the network
     * socket. see also http://man7.org/linux/man-pages/man2/bind.2.html for the SaFamily.
     * 
     * \return SaFamily of the IP address.
     */
    virtual sa_family_t getSaFamily() = 0;

    /**
     * \brief get the IP address.
     * 
     * \return IP address
     */
    virtual uint8_t*
    getAddr()
    {
        return m_addr;
    }

protected:
    uint8_t m_addr[16];
};


/**
 * \typedef This is a convince type definition. This will be simple encapsulated shared_ptr<IInetAddress>
 */
using SPIInetAddress = std::shared_ptr<IInetAddress>;

/**
 * \typedef This is a convince type definition. This will be simple encapsulated TLSResult<shared_ptr<IInetAddress>>
 */
using IInetAddressResult = TLSResult<SPIInetAddress>;

/**
 * \brief This a definition of a the factory to create instances of the IInetAddress.
 * The supplier has to provide the implementation of the static methods by this class.
 * Basically there is no need to create an instance of this class.
 */
class InetAddressFactory
{
private:
    InetAddressFactory() = default;

public:
    /**
     * \brief Factory method to create a valid IP IPv4 / IPv6 Address object.
     * The given string will be validated and an IInetAddress is returned if valid.
     * 
     * \param[in] inetAddr a string which defines an IP address. e.g "::2" or "4:6:7...".
     * 
     * \return a valid IInetAddress or an error if not valid.
     */
    static IInetAddressResult makeIPAddress(const std::string inetAddr);

    /**
     * \brief Factory method to create a valid IP IPv4 / IPv6 Address object.
     * The given string will be validated and an IInetAddress is returned if valid.
     * 
     * \param[in] inetAddr a string which defines a IP address. e.g "127.0.0.1"
     * 
     * \return a valid IInetAddress or an error if not valid.
     */
    static IInetAddressResult makeIPAddress(const char* inetAdd);
};
} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_INETADDRESS_H_ */
