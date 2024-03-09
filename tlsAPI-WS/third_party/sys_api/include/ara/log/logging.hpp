/**
 * \file logging.hpp
 *
 * \brief Main System-API header for logging
 *
 * \copyright 2021 Volkswagen AG
 */

/*
 * R17-10 SWS_LOG refers to the Autosar software specification for logging
 * from the Autosar release 17-10.
 */

/*
 * R17-10 SWS_LOG does not describe a header file logging.hpp.  For backwards
 * compatibility with existing E3-1.1 code, however, the System-API specifies
 * that a header file logging.hpp has to be provided and shall contain the
 * declarations as given in this file (except where comments indicate
 * something different).
 */

#ifndef ARA_LOG_LOGGING_HPP_
#define ARA_LOG_LOGGING_HPP_

/*
 * Note that logging.hpp includes logger.hpp, which from a technical
 * perspective is not necessary: A forward declaration of class Logger would
 * be sufficient.  For backwards compatibility with existing E3-1.1 code,
 * however, the System-API specifies that logging.hpp shall include also
 * logger.hpp.
 */

#include "logcommon.hpp" // Loglevel, LogMode
#include "logger.hpp"    // Logger
#include "logstream.hpp" // LogStream, LogRawBuffer, LogHex<n>, LogBin<n>

/*
 * The following standard library header files are included to make this
 * System-API header file self-contained.  Their inclusion, however, is not
 * part of the System-API.  That is, client code can assume the System-API
 * header files to be self-contained, but client code that makes use of
 * declarations from standard header files shall include these files itself.
 */

#include <cstdint> // Fixed width integer types
#include <string>  // string

/*
 * The use of the namespace ara::log is not described in R17-10 SWS_LOG.  For
 * backwards compatibility with existing E3-1.1 code, however, the System-API
 * specifies that logging declarations are added to ara::log.
 */

namespace ara {
namespace log {

/**
 * \brief The directory path for the log mode kFile is optional according to
 * SWS_LOG_00004.  This is solved in the System-API by making the
 * directoryPath a default parameter of function InitLogging.
 */
void InitLogging(std::string appId, std::string appDescription, LogLevel appDefLogLevel, LogMode logMode, std::string directoryPath = "") noexcept;

/**
 * \brief R17-10 SWS_LOG_00021
 */
Logger &CreateLogger(std::string ctxId, std::string ctxDescription) noexcept;

/**
 * \brief R17-10 SWS_LOG_00022
 */
LogHex8 HexFormat(std::uint8_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00023
 */
LogHex8 HexFormat(std::int8_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00024
 */
LogHex16 HexFormat(std::uint16_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00025
 */
LogHex16 HexFormat(std::int16_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00026
 */
LogHex32 HexFormat(std::uint32_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00027
 */
LogHex32 HexFormat(std::int32_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00028
 */
LogHex64 HexFormat(std::uint64_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00029
 */
LogHex64 HexFormat(std::int64_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00030
 */
LogBin8 BinFormat(std::uint8_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00031
 */
LogBin8 BinFormat(std::int8_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00032
 */
LogBin16 BinFormat(std::uint16_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00033
 */
LogBin16 BinFormat(std::int16_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00034
 */
LogBin32 BinFormat(std::uint32_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00035
 */
LogBin32 BinFormat(std::int32_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00036
 */
LogBin64 BinFormat(std::uint64_t value) noexcept;

/**
 * \brief R17-10 SWS_LOG_00037
 */
LogBin64 BinFormat(std::int64_t value) noexcept;

/*
 * R17-10 SWS_LOG_00038 specifies a template function RawBuffer to create
 * LogRawBuffer objects that are used to print out binary information.  The
 * creation and printing of LogRawBuffer objects is intentionally not made
 * part of the System-API, because R17-10 SWS_LOG leaves important aspects
 * unspecified, for example information about the life time of data in
 * LogRawBuffer objects, or, the use of RawBuffer with data types like
 * std::vector.
 */

/*
 * According to R17-10 SWS_LOG_00064 to SWS_LOG_00069, the following are
 * defined as methods of class Logger.  However, different pieces of example
 * code in R17-10 indicate that there are also the following corresponding
 * namespace-scoped functions.  These are also defined to be part of the
 * System-API.
 */

/**
 * \brief Added to the System-API in analogy to R17-10 SWS_LOG_00064
 */
LogStream LogFatal() noexcept;

/**
 * \brief Added to the System-API in analogy to R17-10 SWS_LOG_00065
 */
LogStream LogError() noexcept;

/**
 * \brief Added to the System-API in analogy to R17-10 SWS_LOG_00066
 */
LogStream LogWarn() noexcept;

/**
 * \brief Added to the System-API in analogy to R17-10 SWS_LOG_00067
 */
LogStream LogInfo() noexcept;

/**
 * \brief Added to the System-API in analogy to R17-10 SWS_LOG_00068
 */
LogStream LogDebug() noexcept;

/**
 * \brief Added to the System-API in analogy to R17-10 SWS_LOG_00069
 */
LogStream LogVerbose() noexcept;

/**
 * \brief R17-10 SWS_LOG_00070
 */
bool IsLogEnabled(LogLevel logLevel) noexcept;

} /* namespace log */
} /* namespace ara */

#endif /* ARA_LOG_LOGGING_HPP_ */
