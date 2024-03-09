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


#include <gtest/gtest.h>

#include "InetAddress.h"
#include <arpa/inet.h>

using namespace vwg::tls;

/**
 * @ingroup IPInetAddress_makeIPAddress
 * @fn TEST(InetAddressFactory,Valid_IPv6_addresses)
 * @brief Check valid IPv6 addresses
 */
TEST(InetAddressFactory, Valid_IPv6_addresses) {
  std::vector<std::string> valid{
      "1:2:3:4:5:6:7:8", "0001:0002:0003:0004:0005:0006:0007:0008",
      "0001::0008",      "::1",
      "::ffff:1.2.3.4",
  };

  for (auto &addr : valid) {
    char binaddr[16] = {0};

    EXPECT_TRUE(inet_pton(AF_INET6, addr.c_str(), &binaddr) == 1);

    auto ret = InetAddressFactory::makeIPAddress(addr);
    EXPECT_TRUE(ret.succeeded());
    auto ip = ret.getPayload();
    ip->validate();
    EXPECT_TRUE(ip->isValid());
    EXPECT_TRUE(ip->isIPv6())
        << "ERROR: IP " << ip->toString() << " should be IPv6";
    EXPECT_FALSE(ip->isIPv4())
        << "ERROR: IP " << ip->toString() << " should be IPv4";
    EXPECT_TRUE(ip->toString() == addr);
    EXPECT_TRUE(ip->getSaFamily() == AF_INET6);

    auto ipv6 = dynamic_cast<IInetAddress *>(ip.get());
    auto ba = ipv6->getAddr();
    EXPECT_TRUE(memcmp(binaddr, ba, sizeof(binaddr)) == 0);

    ret = InetAddressFactory::makeIPAddress(addr.c_str());
    EXPECT_TRUE(ret.succeeded());
    ip = ret.getPayload();
    EXPECT_TRUE(ip->isIPv6())
        << "ERROR: IP " << ip->toString() << " should be IPv6";
    EXPECT_FALSE(ip->isIPv4())
        << "ERROR: IP " << ip->toString() << " should be IPv4";
    EXPECT_TRUE(ip->toString() == addr);
    EXPECT_TRUE(ip->getSaFamily() == AF_INET6);

    ipv6 = dynamic_cast<IInetAddress *>(ip.get());
    ba = ipv6->getAddr();
    EXPECT_TRUE(memcmp(binaddr, ba, sizeof(binaddr)) == 0);
  }
}

/**
 * @ingroup IPInetAddress_makeIPAddress
 * @fn TEST(InetAddressFactory,Invalid_IPv6_addresses)
 * @brief Check invalid IPv6 addresses
 */
TEST(InetAddressFactory, Invalid_IPv6_addresses) {
  std::vector<std::string> invalid{
      "",
      "1:2:3:4:5:6:7:",
      "0001:0002:0003:0004:0005:0006:0007:0008:0009",
      "0001::0002::0008",
      "00001::1",
      "::ffff:1.2.3.4.5",
  };

  for (auto &addr : invalid) {
    auto ret = InetAddressFactory::makeIPAddress(addr);
    EXPECT_TRUE(ret.failed());

    ret = InetAddressFactory::makeIPAddress(addr.c_str());
    EXPECT_TRUE(ret.failed());
  }
}

/**
 * @ingroup IPInetAddress_makeIPAddress
 * @fn TEST(InetAddressFactory,Valid_IPv4_addresses)
 * @brief Check valid IPv4 addresses
 */
TEST(InetAddressFactory, Valid_IPv4_addresses) {
  std::vector<std::string> valid{
      "1.2.3.4",
      "11.22.33.44",
      "101.102.103.104",
  };

  for (auto &addr : valid) {
    char binaddr[4] = {0};

    EXPECT_TRUE(inet_pton(AF_INET, addr.c_str(), &binaddr) == 1);

    auto ret = InetAddressFactory::makeIPAddress(addr);
    EXPECT_TRUE(ret.succeeded());
    auto ip = ret.getPayload();
    EXPECT_TRUE(ip->isIPv4());
    EXPECT_FALSE(ip->isIPv6());
    EXPECT_TRUE(ip->toString() == addr);
    EXPECT_TRUE(ip->getSaFamily() == AF_INET);

    auto ipv4 = dynamic_cast<IInetAddress *>(ip.get());
    auto ba = ipv4->getAddr();
    EXPECT_TRUE(memcmp(binaddr, ba, sizeof(binaddr)) == 0);

    ret = InetAddressFactory::makeIPAddress(addr.c_str());
    EXPECT_TRUE(ret.succeeded());
    ip = ret.getPayload();
    EXPECT_TRUE(ip->isIPv4());
    EXPECT_FALSE(ip->isIPv6());
    EXPECT_TRUE(ip->toString() == addr);
    EXPECT_TRUE(ip->getSaFamily() == AF_INET);

    ipv4 = dynamic_cast<IInetAddress *>(ip.get());
    ba = ipv4->getAddr();
    EXPECT_TRUE(memcmp(binaddr, ba, sizeof(binaddr)) == 0);
  }
}

/**
 * @ingroup IPInetAddress_makeIPAddress
 * @fn TEST(InetAddressFactory,Invalid_IPv4_addresses)
 * @brief Check invalid IPv4 addresses
 */
TEST(InetAddressFactory, Invalid_IPv4_addresses) {
  std::vector<std::string> invalid{
      "", "1.2.3.4.5", "1.2.3.256", "0.0.0.0.", "255..255.255",
  };

  for (auto &addr : invalid) {
    auto ret = InetAddressFactory::makeIPAddress(addr);
    EXPECT_TRUE(ret.failed());

    ret = InetAddressFactory::makeIPAddress(addr.c_str());
    EXPECT_TRUE(ret.failed());
  }
}
