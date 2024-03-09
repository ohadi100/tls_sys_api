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


#ifndef TEETYPES_H
#define TEETYPES_H

#include <vector>
#include <unordered_map>
#include <memory>
#include <string>
#include <cstdint>
#include <chrono>

namespace vwg {
namespace tee {


using TrustStoreID = std::string;
using ClientCertID = std::string;

using String = std::string;
using Key = std::string;
using DateAndTime = std::chrono::system_clock::time_point;
using CertificateChain = std::string;
using CertificateBundle = std::string;
using VIN = std::string;
using Signature = std::vector<uint8_t>;
using CSR = std::vector<uint8_t>;

enum class MockTeeError : std::uint32_t {
	OK = 0,
	FILE_NOT_FOUND,
	FILE_NOT_OPEN,
	INVALID_PARAMETER,
	INVALID_ID,
	CRYPTO_OP_ERROR};

using Error = MockTeeError;
using ByteVector = std::vector<uint8_t>;
using HashFunction = std::string;

using IdentityHint = std::string;
using PSKKeyID = int32_t;

struct KeyData
{
	uint32_t length;
	uint8_t  value[64];
};

using SessionKey = KeyData;


} /* namespace tee */
} /* namespace vwg */

#endif
