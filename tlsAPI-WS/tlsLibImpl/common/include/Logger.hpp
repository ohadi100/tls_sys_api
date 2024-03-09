/**
 * 
 * @file       Logger.hpp
 * 
 * @brief      Write to a log output with different logging levels.
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


#ifndef _LOGGER_HPP_
#define _LOGGER_HPP_

#include <functional>
#include <mutex>
#include <vector>

#include "Singleton.hpp"

#define LOG_COMMON(log_level, ...) common::Logger::GetInstance().WriteLog(log_level, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define LOG_VERBOSE(...)   LOG_COMMON(common::LogLevel::LOG_LEVEL_VERBOSE, __VA_ARGS__)
#define LOG_DEBUG(...)     LOG_COMMON(common::LogLevel::LOG_LEVEL_DEBUG,   __VA_ARGS__)
#define LOG_INFO(...)      LOG_COMMON(common::LogLevel::LOG_LEVEL_INFO,    __VA_ARGS__)
#define LOG_WARNING(...)   LOG_COMMON(common::LogLevel::LOG_LEVEL_WARNING, __VA_ARGS__)
#define LOG_ERROR(...)     LOG_COMMON(common::LogLevel::LOG_LEVEL_ERROR,   __VA_ARGS__)
#define LOG_FATAL(...)     LOG_COMMON(common::LogLevel::LOG_LEVEL_FATAL,   __VA_ARGS__)
#define LOG_CLEAN(...)     LOG_COMMON(common::LogLevel::LOG_LEVEL_CLEAN,   __VA_ARGS__)



namespace common
{
    extern const char * levelNames[];

    enum class LogLevel : int32_t
    {
        LOG_LEVEL_FATAL = 0,
        LOG_LEVEL_ERROR = 1,
        LOG_LEVEL_WARNING = 2,
        LOG_LEVEL_INFO = 3,
        LOG_LEVEL_DEBUG = 4,
        LOG_LEVEL_VERBOSE = 5,
        LOG_LEVEL_CLEAN = 6
    };


    /**
     * @class   LogHandler
     * @brief   The class is the actuall logger output handler. in order to have a log printed,
     *          an instance of this calss must be registered to the logger
     */
    class LogHandler
    {

    public:
        /**
        * @fn      LogHandler().
        * @brief   Default Constructor.
        * @param   none.
        * @return  none.
        */
        LogHandler() = default;

        /**
        * @fn      logHandler().
        * @brief   an actual handler that outputs the log
        * @param   LogLevel level - the level of the log (debug/info/etc').
        * @return  const char * log - the actual line of log.
        */
        virtual void HandleLogLine(LogLevel level, const char * log) = 0;
    };


    /**
     * @class   Logger
     * @brief   The class implements logging functionality with different levels of verbosity and logging level.
                The class uses an enum class LogLevel to set up a different logging levels by name and number.
     *          It has variables to hold:
     *          - The text that comes along with the severity (LOG_LEVEL_ERROR -> "ERROR"),
     *          - An ostringstream to allow easier building of strings,
     *          - A callback-function vector of which functions needs to be invoked when a new log is added,
     *          - A mutex to ensure thread-safety,
     *          - The global log level.
     *          This class is accessed across the board, by any and all other classes and entities in this project.
     *          ara::log must be initialized (if used).
     */
    class Logger : public common::Singleton<Logger>
    {

    public:

        /**
         * @fn      virtual ~Logger().
         * @brief   Default Destructor.
         * @param   none.
         * @return  none.
         */
        virtual ~Logger() = default;

        /**
         * @fn      void RegisterLogCallback(LogHandler * handler).
         * @brief   Register a callback function to be called upon the logger invocation
         * @param   LogHandler * handler - a handler class that is called when a log line is printed.
         * @return  none.
         */
        void RegisterLogHandler(LogHandler *handler);

        /**
         * @fn      void ClearLogCallbacks().
         * @brief   Remove all registered callbacks from the logger.
         * @param   none.
         * @return  none.
         */
        void ClearLogHandlers();

        /**
         * @fn      void WriteLog(LogLevel level, const char * funcName, uint32_t line, const char * fmt, ...).
         * @brief   Write to logger message with file and line.
         * @param   LogLevel level.
         * @param   const char * funcName - name of the file that generated the log.
         * @param   uint32_tline - line number that generated the log.
         * @param   const char * fmt - format of the data to write.
         * @param   ... - arguments based on the format.
         * @return  none.
         */
        void WriteLog(common::LogLevel level, const char * fullFilename, const char * funcName, uint32_t line, const char * fmt, ...);

    protected:

        /**
         * @fn      Logger().
         * @brief   constructor - sets the relevant logger callback
         * @param   none.
         * @return  none.
         */
        Logger() = default;
        friend class common::Singleton<Logger>;

        std::mutex m_mutex;

        std::vector<LogHandler*> m_logHandlers;
    };


} // namespace common

#endif // _LOGGER_HPP_
