/**
 * \file logging.hpp
 *
 * \brief This header contains macros for creating log messages
 *
 * \copyright 2021-2022 Volkswagen AG
 */

#ifndef VWG_FND_LOG_LOGGING_HPP_
#define VWG_FND_LOG_LOGGING_HPP_

/*
 * The following header files are included to make this header file
 * self-contained.  Their inclusion, however, is not part of this header
 * file's API.  That is, client code can assume this header file to be
 * self-contained, but client code that makes use of declarations from the
 * below header files shall include these files itself.
 */

#include <ara/log/logcommon.hpp>
#include <ara/log/logger.hpp>
#include <ara/log/logstream.hpp>

// #define FND_LOG_ALL_BUILD_TIME_DISABLED

#ifdef FND_LOG_ALL_BUILD_TIME_DISABLED
#define FND_LOG_FATAL_BUILD_TIME_DISABLED
#define FND_LOG_ERROR_BUILD_TIME_DISABLED
#define FND_LOG_WARN_BUILD_TIME_DISABLED
#define FND_LOG_INFO_BUILD_TIME_DISABLED
#define FND_LOG_DEBUG_BUILD_TIME_DISABLED
#define FND_LOG_VERBOSE_BUILD_TIME_DISABLED
#endif

// FND_LOG_WARN_RUN_TIME_LIKELY_DISABLED
// FND_LOG_INFO_RUN_TIME_LIKELY_DISABLED

#define FND_LOG_priv_ARGS_OUT(...) FND_LOG_priv_ARGS_OUT_HELPER(FND_LOG_priv_NUM(__VA_ARGS__), __VA_ARGS__)
#define FND_LOG_priv_ARGS_OUT_HELPER(count, ...) FND_LOG_priv_ARGS_OUT_HELPER2(count, __VA_ARGS__)
#define FND_LOG_priv_ARGS_OUT_HELPER2(count, ...) FND_LOG_priv_ARGS_OUT_##count(__VA_ARGS__)

#define FND_LOG_priv_ARGS_OUT_1(a) (a)
#define FND_LOG_priv_ARGS_OUT_2(a, b) (a) << (b)
#define FND_LOG_priv_ARGS_OUT_3(a, b, c) (a) << (b) << (c)
#define FND_LOG_priv_ARGS_OUT_4(a, b, c, d) (a) << (b) << (c) << (d)
#define FND_LOG_priv_ARGS_OUT_5(a, b, c, d, e) (a) << (b) << (c) << (d) << (e)
#define FND_LOG_priv_ARGS_OUT_6(a, b, c, d, e, f) (a) << (b) << (c) << (d) << (e) << (f)
#define FND_LOG_priv_ARGS_OUT_7(a, b, c, d, e, f, g) (a) << (b) << (c) << (d) << (e) << (f) << (g)
#define FND_LOG_priv_ARGS_OUT_8(a, b, c, d, e, f, g, h) (a) << (b) << (c) << (d) << (e) << (f) << (g) << (h)
#define FND_LOG_priv_ARGS_OUT_9(a, b, c, d, e, f, g, h, i) (a) << (b) << (c) << (d) << (e) << (f) << (g) << (h) << (i)

#define FND_LOG_priv_NUM(...) FND_LOG_priv_SELECT_10TH(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1, throwaway)
#define FND_LOG_priv_SELECT_10TH(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, ...) a10

#define FND_LOG_priv_MESSAGE_RUN_TIME_LIKELY_DISABLED(level, logfunc, logger, ...) \
    do {                                                                           \
        if (logger.IsLogEnabled(ara::log::LogLevel::level)) {                      \
            logger.logfunc() << FND_LOG_priv_ARGS_OUT(__VA_ARGS__);                \
        }                                                                          \
    } while (false)

#define FND_LOG_priv_MESSAGE_RUN_TIME_LIKELY_ENABLED(level, logfunc, logger, ...) \
    do {                                                                          \
        logger.logfunc() << FND_LOG_priv_ARGS_OUT(__VA_ARGS__);                   \
    } while (false)

#ifdef FND_LOG_FATAL_BUILD_TIME_DISABLED
    #define FND_LOG_FATAL(logger, ...)
#else
    #define FND_LOG_FATAL(logger, ...) FND_LOG_priv_MESSAGE_RUN_TIME_LIKELY_ENABLED(kFatal, LogFatal, logger, __VA_ARGS__)
#endif

#ifdef FND_LOG_ERROR_BUILD_TIME_DISABLED
    #define FND_LOG_ERROR(logger, ...)
#else
    #define FND_LOG_ERROR(logger, ...) FND_LOG_priv_MESSAGE_RUN_TIME_LIKELY_ENABLED(kError, LogError, logger, __VA_ARGS__)
#endif

#ifdef FND_LOG_WARN_BUILD_TIME_DISABLED
    #define FND_LOG_WARN(logger, ...)
#elif defined(FND_LOG_WARN_RUN_TIME_LIKELY_DISABLED)
    #define FND_LOG_WARN(logger, ...) FND_LOG_priv_MESSAGE_RUN_TIME_LIKELY_DISABLED(kWarn, LogWarn, logger, __VA_ARGS__)
#else
    #define FND_LOG_WARN(logger, ...) FND_LOG_priv_MESSAGE_RUN_TIME_LIKELY_ENABLED(kWarn, LogWarn, logger, __VA_ARGS__)
#endif

#ifdef FND_LOG_INFO_BUILD_TIME_DISABLED
    #define FND_LOG_INFO(logger, ...)
#elif defined(FND_LOG_INFO_RUN_TIME_LIKELY_DISABLED)
    #define FND_LOG_INFO(logger, ...) FND_LOG_priv_MESSAGE_RUN_TIME_LIKELY_DISABLED(kInfo, LogInfo, logger, __VA_ARGS__)
#else
    #define FND_LOG_INFO(logger, ...) FND_LOG_priv_MESSAGE_RUN_TIME_LIKELY_ENABLED(kInfo, LogInfo, logger, __VA_ARGS__)
#endif

#define FND_LOG_priv_MESSAGE_WITH_SOURCE_LOCATION(level, logfunc, logger, ...)                          \
    do {                                                                                                \
        if (logger.IsLogEnabled(ara::log::LogLevel::level)) {                                           \
            logger.logfunc() << __FILE__ ":" << __LINE__ << ": " << FND_LOG_priv_ARGS_OUT(__VA_ARGS__); \
        }                                                                                               \
    } while (false)

#ifdef FND_LOG_DEBUG_BUILD_TIME_DISABLED
    #define FND_LOG_DEBUG(logger, ...)
#else
    #define FND_LOG_DEBUG(logger, ...) FND_LOG_priv_MESSAGE_WITH_SOURCE_LOCATION(kDebug, LogDebug, logger, __VA_ARGS__)
#endif

#ifdef FND_LOG_VERBOSE_BUILD_TIME_DISABLED
    #define FND_LOG_VERBOSE(logger, ...)
#else
    #define FND_LOG_VERBOSE(logger, ...) FND_LOG_priv_MESSAGE_WITH_SOURCE_LOCATION(kVerbose, LogVerbose, logger, __VA_ARGS__)
#endif

#endif /* VWG_FND_LOG_LOGGING_HPP_ */
