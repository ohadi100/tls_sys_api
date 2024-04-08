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


#ifndef SRC_INETV4ADDRESS_H_
#define SRC_INETV4ADDRESS_H_


#include <memory>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <string>

#include "InetAddress.h"

namespace vwg
{
namespace tls
{
namespace impl
{

class IPInetAddressImpl : public IInetAddress
{

public:
	/**
	  * \brief IPv4 default constructor for "0.0.0.0"
	  */
	IPInetAddressImpl();

	/**
	  * \brief IPv4 Address constructor
	  * \param ipAddr            Input const IPv4 Address
	  */
	IPInetAddressImpl(const std::string& ipAddr);

	/**
	  * \brief IPv4 default destructor
	  */
	virtual ~IPInetAddressImpl() = default;

    /**
	  * \brief IPv4 string representation
	  */
	std::string toString() override;

    /**
	  * \brief Returns "false"
	  */
	bool isIPv6() override;

    /**
	  * \brief Returns "true"
	  */
	bool isIPv4() override;

    /**
	  * \brief Verifies input validity
	  */
	bool isValid() override;

    /**
	  * \brief Returns AF_INET for IPv4 Address Family
	  */
	sa_family_t getSaFamily() override;

	UInt32 validate() override;

private:
	const std::string m_strAddr;
	sa_family_t m_family;
    bool m_valid;
};

} /* namespace impl */
} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_INETV4ADDRESS_H_ */
