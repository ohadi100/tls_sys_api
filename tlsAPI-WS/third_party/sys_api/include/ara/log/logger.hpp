/**
 * \file logger.hpp
 *
 * \brief System-API header for class Logger
 *
 * \copyright 2021 Volkswagen AG
 */

/*
 * R17-10 SWS_LOG refers to the Autosar software specification for logging
 * from the Autosar release 17-10.
 */

/*
 * R17-10 SWS_LOG does not describe a header file logstream.hpp.  For
 * backwards compatibility with existing E3-1.1 code, however, the System-API
 * specifies that a header file logstream.hpp has to be provided and shall
 * contain the declarations as given in this file (except where comments
 * indicate something different).
 */

#ifndef ARA_LOG_LOGGER_HPP_
#define ARA_LOG_LOGGER_HPP_

#include "logcommon.hpp" // LogLevel
#include "logstream.hpp" // LogStream

/*
 * The following standard library header files are needed by the mocking
 * support that is part of this header file, but which is not defined to be
 * part of the System-API.
 */

#include <memory> // unique_ptr
#include <string> // string

/*
 * The use of the namespace ara::log is not described in R17-10 SWS_LOG.  For
 * backwards compatibility with existing E3-1.1 code, however, the System-API
 * specifies that logging declarations are added to ara::log.
 */

namespace ara {
namespace log {

class Logger final {
public:
    /*
     * In R17-10 SWS_LOG nothing is mentioned about constructors for Logger or
     * its destructor.  Client code is expected to use createLogger to obtain
     * Logger instances.  And, according to R17-10 SWS_LOG_00005, management
     * of logger objects is the responsibility of the logging framework.
     * Therefore, the System-API does not specify any constructors for Logger,
     * but leaves this open for the implementation.  To clarify that client
     * code is not expected to create and delete Logger objects directly, the
     * destructor is declared private in this header file.  However, it is not
     * a requirement on implementations that the destructor has to be private
     * or that there has to be a destructor at all.
     */

    /*
     * Since according to R17-10 SWS_LOG_00005 management of logger objects is
     * the responsibility of the logging framework, and, for backwards
     * compatibility with E3-1.1 software, the System-API specifies the
     * special member functions to be deleted.
     */
    Logger() = delete;
    Logger(Logger const &) = delete;
    Logger &operator=(Logger const &) = delete;
    Logger(Logger &&) = delete;
    Logger &operator=(Logger &&) = delete;

    /**
     * \brief R17-10 SWS_LOG_00064
     */
    LogStream LogFatal() noexcept;

    /**
     * \brief R17-10 SWS_LOG_00065
     */
    LogStream LogError() noexcept;

    /**
     * \brief R17-10 SWS_LOG_00066
     */
    LogStream LogWarn() noexcept;

    /**
     * \brief R17-10 SWS_LOG_00067
     */
    LogStream LogInfo() noexcept;

    /**
     * \brief R17-10 SWS_LOG_00068
     */
    LogStream LogDebug() noexcept;

    /**
     * \brief R17-10 SWS_LOG_00069
     */
    LogStream LogVerbose() noexcept;

    /**
     * \brief R17-10 SWS_LOG_00070
     */
    bool IsLogEnabled(LogLevel logLevel) noexcept;

/*
 * The following private section is only here for mocking support.  It is not
 * part of the System-API - other implementations of the System-API can look
 * completely different.
 */

private:
    friend Logger &CreateLogger(std::string ctxId, std::string ctxDescription) noexcept;
    friend LogStream::LogStream(LogLevel logLevel, Logger const &logger) noexcept;

    Logger(std::string const &ctxId, std::string const &ctxDescription) noexcept;
    ~Logger();

    class LoggerImpl;
    std::unique_ptr<LoggerImpl> pImpl;
};

} /* namespace log */
} /* namespace ara */

#endif /* ARA_LOG_LOGGER_HPP_ */
