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


#include <memory>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <string>

#include "IPInetAddressImpl.hpp"

using vwg::tls::impl::IPInetAddressImpl;

IPInetAddressImpl::IPInetAddressImpl()

		: m_strAddr("0.0.0.0"), m_valid(false)
{
}

IPInetAddressImpl::IPInetAddressImpl(const std::string& ipAddr)
	: m_strAddr(ipAddr)
{
	validate();
}


sa_family_t IPInetAddressImpl::getSaFamily()
{
	return m_family;
}

bool IPInetAddressImpl::isValid()
{
	return m_valid;
}

std::string IPInetAddressImpl::toString()
{
	return m_strAddr;
}

bool IPInetAddressImpl::isIPv6()
{
    return AF_INET6 == m_family;
}

bool IPInetAddressImpl::isIPv4()
{
	return AF_INET == m_family;
}

UInt32 IPInetAddressImpl::validate()
{
	m_family = (m_strAddr.find(':') == std::string::npos) ? (sa_family_t)AF_INET : (sa_family_t)AF_INET6;
	m_valid = inet_pton(m_family, m_strAddr.c_str(), &m_addr) == 1;

	return 0;
}
