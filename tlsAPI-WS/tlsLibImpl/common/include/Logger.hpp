/* Copyright (c) 2023 Volkswagen Group */

#ifndef LOGGER_HPP
#define LOGGER_HPP

#ifndef UNIT_TEST
#include "ara/log/logging.h" 
#else
#include <time.h>
#include <string.h>
#include <iostream>
#endif
namespace vwg
{
namespace tls
{
namespace impl
{

#ifndef UNIT_TEST

inline ara::log::Logger& getLogger() noexcept 
{
    static ara::log::Logger& logger = ara::log::CreateLogger("TLS", "TLS library");
    return logger;
}

#define FND_LOG_VERBOSE vwg::tls::impl::getLogger().LogVerbose()
#define FND_LOG_DEBUG vwg::tls::impl::getLogger().LogDebug()
#define FND_LOG_INFO vwg::tls::impl::getLogger().LogInfo()
#define FND_LOG_WARN vwg::tls::impl::getLogger().LogWarn()
#define FND_LOG_ERROR vwg::tls::impl::getLogger().LogError()
#define FND_LOG_FATAL vwg::tls::impl::getLogger().LogFatal()

#else

static inline char *timenow();

#define FND_LOG_VERBOSE std::cout << vwg::tls::impl::timenow() << "  Verbose: " 
#define FND_LOG_DEBUG std::cout << vwg::tls::impl::timenow() << "  Debug: "
#define FND_LOG_INFO std::cout << vwg::tls::impl::timenow() << "  Info: "
#define FND_LOG_WARN std::cout << vwg::tls::impl::timenow() << "  * Warning: * "
#define FND_LOG_ERROR std::cout << vwg::tls::impl::timenow() << "  *** Error: *** "
#define FND_LOG_FATAL std::cout << vwg::tls::impl::timenow() << "  *** Fatal: *** "

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