/**
 * \file logstream.hpp
 *
 * \brief System-API header for class LogStream
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

#ifndef ARA_LOG_LOGSTREAM_HPP_
#define ARA_LOG_LOGSTREAM_HPP_

#include "logcommon.hpp" // LogLevel

/*
 * The following standard library header files are included to make this
 * System-API header file self-contained.  Their inclusion, however, is not
 * part of the System-API.  That is, client code can assume the System-API
 * header files to be self-contained, but client code that makes use of
 * declarations from standard header files shall include these files itself.
 */

#include <cstdint> // Fixed width integer types
#include <string>  // string
#include <utility> // forward

/*
 * The following standard library header files are needed by the mocking
 * support that is part of this header file, but which is not defined to be
 * part of the System-API.
 */

#include <memory> // unique_ptr

/*
 * The use of the namespace ara::log is not described in R17-10 SWS_LOG.  For
 * backwards compatibility with existing E3-1.1 code, however, the System-API
 * specifies that logging declarations are added to ara::log.
 */

namespace ara {
namespace log {

class Logger;

/*
 * R17-10 SWS_LOG specifies the existence of the following types, but does not
 * give any details about their internal structure.  However, later in Autosar
 * 19-03 the structure is defined, thus, for the system API we use that
 * definition and therefore the structs shall be defined as follows:
 */
struct LogHex8 { std::uint8_t value; };
struct LogHex16 { std::uint16_t value; };
struct LogHex32 { std::uint32_t value; };
struct LogHex64 { std::uint64_t value; };
struct LogBin8 { std::uint8_t value; };
struct LogBin16 { std::uint16_t value; };
struct LogBin32 { std::uint32_t value; };
struct LogBin64 { std::uint64_t value; };

class LogStream final {
public:
    /**
     * \brief R17-10 SWS_LOG does not specify any constructor for LogStream
     * explicitly.  However, the relationship of an instance of class
     * LogStream to a LogLevel and a logging context can be concluded.  For
     * compatibility with existing E3-1.1 software, the System-API defines the
     * following constructor:
     */
    LogStream(LogLevel logLevel, Logger const &logger) noexcept;

    /**
     * \brief R17-10 SWS_LOG Section 7.3
     */
    ~LogStream();

    /*
     * R17-10 SWS_LOG does not make any statements about copyability or
     * moveability of LogStream objects.  Only from a piece of example code in
     * R17-10 SWS_LOG section 7.3 it follows that there has to be at least a
     * copy or move constructor.  Further, section 7.3. claims that
     * return-value-optimization shall be applied to LogStream objects.  For
     * these reasons and for compatibility with existing E3-1.1 code, of the
     * special member functions (except for the destructor, see above), only
     * the move constructor is declared.  There shall be NO IMPLEMENTATION for
     * the move constructor, however: Uses of std::move shall lead to link
     * errors.
     */
    LogStream() = delete;
    LogStream(LogStream const &) = delete;
    LogStream &operator=(LogStream const &) = delete;
    LogStream(LogStream &&) noexcept;
    LogStream &operator=(LogStream &&) = delete;

    /**
     * \brief The noexcept specifier is missing in R17-10 SWS_LOG_00039 and
     * was added here because "All Log*() interfaces are designed to guarantee
     * no-throw behavior.  Actually this applies for the whole Logging API."
     */
    void Flush() noexcept;

    /**
     * \brief R17-10 SWS_LOG_00040
     */
    LogStream &operator<<(bool value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00041
     */
    LogStream &operator<<(std::uint8_t value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00042
     */
    LogStream &operator<<(std::uint16_t value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00043
     */
    LogStream &operator<<(std::uint32_t value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00044
     */
    LogStream &operator<<(std::uint64_t value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00045
     */
    LogStream &operator<<(std::int8_t value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00046
     */
    LogStream &operator<<(std::int16_t value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00047
     */
    LogStream &operator<<(std::int32_t value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00048
     */
    LogStream &operator<<(std::int64_t value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00049
     */
    LogStream &operator<<(float value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00050
     */
    LogStream &operator<<(double value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00051
     */
    LogStream &operator<<(char const *value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00053
     */
    LogStream &operator<<(LogHex8 const &value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00054
     */
    LogStream &operator<<(LogHex16 const &value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00055
     */
    LogStream &operator<<(LogHex32 const &value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00056
     */
    LogStream &operator<<(LogHex64 const &value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00057
     */
    LogStream &operator<<(LogBin8 const &value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00058
     */
    LogStream &operator<<(LogBin16 const &value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00059
     */
    LogStream &operator<<(LogBin32 const &value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00060
     */
    LogStream &operator<<(LogBin64 const &value) noexcept;

    /*
     * R17-10 SWS_LOG_00061 specifies an operator to print out LogRawBuffer
     * objects as a means to print out binary information.  The creation and
     * printing of LogRawBuffer objects is intentionally not made part of the
     * System-API, because R17-10 SWS_LOG leaves important aspects
     * unspecified, for example information about the life time of data in
     * LogRawBuffer objects, or, the use of RawBuffer with data types like
     * std::vector.
     */

    /**
     * \brief R17-10 SWS_LOG_00062
     */
    LogStream &operator<<(std::string const &value) noexcept;

    /**
     * \brief R17-10 SWS_LOG_00063
     */
    LogStream &operator<<(LogLevel value) noexcept;

/*
 * The following private section is only here for mocking support.  It is not
 * part of the System-API - other implementations of the System-API can look
 * completely different.
 */

private:
    class LogStreamImpl;
    std::unique_ptr<LogStreamImpl> pImpl;
};

/*
 * The following function template is not part of R17-10 SWS_LOG, but it is
 * nevertheless part of the System-API to ensure backwards compatibiltiy with
 * existing E3-1.1 code.  The purpose of the code is the following: Assume
 * some client code defines a custom type T, and, in addition, the operator
 *     LogStream &operator<<(LogStream &out, T &value)
 * This operator (call it operator-v1) will allow to write code like;
 *     T myT;
 *     LogInfo() << 20 << myT;
 * However, this operator can not handle the following case:
 *     T myT;
 *     LogInfo() << myT;
 * because this would require to have the operator
 *     LogStream &operator<<(LogStream &&out, T &value)
 * called operator-v2.  For the case that a developer does not provide such an
 * operator-v2, the following function template will provide a default
 * implementation that falls back on the operator-v1.
 */
template <typename T>
LogStream &operator<<(LogStream &&logStream, T &&value) noexcept {
    return logStream << std::forward<T>(value);
}

} /* namespace log */
} /* namespace ara */

#endif /* ARA_LOG_LOGSTREAM_HPP_ */
