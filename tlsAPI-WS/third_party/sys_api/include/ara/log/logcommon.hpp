/**
 * \file logcommon.hpp
 *
 * \brief Common System-API definitions for logging
 *
 * \copyright 2021 Volkswagen AG
 */

/*
 * R17-10 SWS_LOG refers to the Autosar software specification for logging
 * from the Autosar release 17-10.
 */

#ifndef ARA_LOG_LOGCOMMON_HPP_
#define ARA_LOG_LOGCOMMON_HPP_

/*
 * The following standard library header files are included to make this
 * System-API header file self-contained.  Their inclusion, however, is not
 * part of the System-API.  That is, client code can assume the System-API
 * header files to be self-contained, but client code that makes use of
 * declarations from standard header files shall include these files itself.
 */

#include <cstdint>     // Fixed width integer types
#include <type_traits> // underlying_type

/*
 * The use of the namespace ara::log is not described in R17-10 SWS_LOG.  For
 * backwards compatibility with existing E3-1.1 code, however, the System-API
 * specifies that logging declarations are added to ara::log.
 */

namespace ara {
namespace log {

/**
 * \brief R17-10 SWS_LOG_00018
 */
enum class LogLevel: std::uint8_t {
    kOff,
    kFatal,
    kError,
    kWarn,
    kInfo,
    kDebug,
    kVerbose
};

/**
 * \brief R17-10 SWS_LOG_00019
 */
enum class LogMode: std::uint8_t {
    kRemote  = 0x01,
    kFile    = 0x02,
    kConsole = 0x04
};

/**
 * \brief According to R17-10 SWS_LOG_00019, an OR operator has to be
 * provided.  Details about its signature are left open.  (To be clarified:
 * Does the operator have to be constexpr for compatibility with existing
 * E3-1.1 code?)  For the System-API the signature is defined as follows:
 */
LogMode operator|(LogMode lhs, LogMode rhs) noexcept;

/**
 * \brief According to R17-10 SWS_LOG_00019, an AND operator has to be
 * provided.  Details about its signature are left open.  For the System-API
 * the signature is defined as follows:
 */
typename std::underlying_type<LogMode>::type operator&(LogMode lhs, LogMode rhs) noexcept;

} /* namespace log */
} /* namespace ara */

#endif /* ARA_LOG_LOGCOMMON_HPP_ */
