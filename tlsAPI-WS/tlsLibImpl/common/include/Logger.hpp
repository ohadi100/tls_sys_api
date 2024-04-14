/**
 * @file Logger.hpp
 * @copyright (c) 2023 Volkswagen Group
 *
 * @brief Provides a logging utility for the TLS library, encapsulating different logging mechanisms for
 * production and unit testing environments.
 *
 * Detailed explanation of copyright and permission notices.
 */

#ifndef LOGGER_HPP
#define LOGGER_HPP

#ifndef UNIT_TEST
#include "ara/log/logging.h" 
#else
#include <ctime>
#include <cstring>
#include <iostream>
#endif

namespace vwg
{
namespace tls
{
namespace impl
{
#ifndef UNIT_TEST

/**
 * @brief Retrieves a static instance of ara::log::Logger specific for the TLS module.
 * 
 * @return Reference to the ara::log::Logger instance.
 */
inline ara::log::Logger& getLogger() noexcept 
{
    static ara::log::Logger& logger = ara::log::CreateLogger("TLS", "TLS library");
    return logger;
}

/// Macros for various log levels using ARA log
#define FND_LOG_VERBOSE vwg::tls::impl::getLogger().LogVerbose()
#define FND_LOG_DEBUG vwg::tls::impl::getLogger().LogDebug()
#define FND_LOG_INFO vwg::tls::impl::getLogger().LogInfo()
#define FND_LOG_WARN vwg::tls::impl::getLogger().LogWarn()
#define FND_LOG_ERROR vwg::tls::impl::getLogger().LogError()
#define FND_LOG_FATAL vwg::tls::impl::getLogger().LogFatal()

#else

/**
 * @brief Helper function to get current time as a string.
 * 
 * @return Current system time formatted as a string.
 */
static inline char *timenow();

/// Macros for various log levels using standard output for unit testing
#define FND_LOG_VERBOSE std::cout << vwg::tls::impl::timenow() << "  Verbose: "
#define FND_LOG_DEBUG std::cout << vwg::tls::impl::timenow() << "  Debug: "
#define FND_LOG_INFO std::cout << vwg::tls::impl::timenow() << "  Info: "
#define FND_LOG_WARN std::cout << vwg::tls::impl::timenow() << "  * Warning: * "
#define FND_LOG_ERROR std::cout << vwg::tls::impl::timenow() << "  *** Error: *** "
#define FND_LOG_FATAL std::cout << vwg::tls::impl::timenow() << "  *** Fatal: *** "

/**
 * @brief Implements the helper function timenow to fetch current system time formatted as a string.
 * 
 * @return Pointer to a character array containing the formatted date and time.
 */
static inline char *timenow() {
    static char buffer[64];
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, 64, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

#endif

}  // namespace impl
}  // namespace tls
}  // namespace vwg

#endif // LOGGER_HPP
