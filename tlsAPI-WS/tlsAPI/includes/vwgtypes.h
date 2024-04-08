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

#ifndef SRC_VWGTYPES_H_
#define SRC_VWGTYPES_H_

#include <cstdint>
#include <array>

namespace vwg {
namespace types {

using  Boolean =  bool;
typedef std::uint8_t UInt8;
typedef std::uint16_t UInt16;
typedef std::uint32_t UInt32;
typedef std::uint64_t UInt64;


typedef std::int8_t Int8;
typedef std::int16_t Int16;
typedef std::int32_t Int32;
typedef std::int64_t Int64;

using Byte =  UInt8;


using UUID = std::array<UInt8, 16>;


} // namespace stdtypes
} // namespace vwg



#endif /* SRC_VWGTYPES_H_ */
