/**
 * @file vwgtypes.h
 * @brief Type definitions for Volkswagen Group (VWG) projects.
 *
 * This file contains type definitions using standard C++ fixed-width integer types
 * and other custom type aliases used across Volkswagen Group (VWG) software projects.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All the information and materials contained herein, including the
 * intellectual and technical concepts, are the property of CARIAD SE and may
 * be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * Reproduction, dissemination, modification, distribution, public
 * performance, public display, or any other use of this source code and/or
 * any other information and/or material contained herein without the prior
 * written consent of CARIAD SE is strictly prohibited and in violation of
 * applicable laws.
 *
 * Possession of this source code and/or related information does not convey
 * or imply any rights to reproduce, disclose or distribute its contents,
 * or to manufacture, use, or sell anything that it may describe, in whole
 * or in part.
 */

#ifndef SRC_VWGTYPES_H_
#define SRC_VWGTYPES_H_

#include <cstdint>
#include <array>

namespace vwg {
namespace types {

/**
 * @typedef Boolean
 * @brief Alias for boolean data type in C++.
 */
using Boolean = bool;

/**
 * @typedef UInt8
 * @brief Unsigned 8-bit integer type.
 */
typedef std::uint8_t UInt8;

/**
 * @typedef UInt16
 * @brief Unsigned 16-bit integer type.
 */
typedef std::uint16_t UInt16;

/**
 * @typedef UInt32
 * @brief Unsigned 32-bit integer type.
 */
typedef std::uint32_t UInt32;

/**
 * @typedef UInt64
 * @brief Unsigned 64-bit integer type.
 */
typedef std::uint64_t UInt64;

/**
 * @typedef Int8
 * @brief Signed 8-bit integer type.
 */
typedef std::int8_t Int8;

/**
 * @typedef Int16
 * @brief Signed 16-bit integer type.
 */
typedef std::int16_t Int16;

/**
 * @typedef Int32
 * @brief Signed 32-bit integer type.
 */
typedef std::int32_t Int32;

/**
 * @typedef Int64
 * @brief Signed 64-bit integer type.
 */
typedef std::int64_t Int64;

/**
 * @typedef Byte
 * @brief Alias for unsigned 8-bit integer, typically used for raw data.
 */
using Byte = UInt8;

/**
 * @typedef UUID
 * @brief Type definition for Universally Unique Identifier (UUID) represented as a 16-byte array.
 */
using UUID = std::array<UInt8, 16>;

} // namespace types
} // namespace vwg

#endif /* SRC_VWGTYPES_H_ */
