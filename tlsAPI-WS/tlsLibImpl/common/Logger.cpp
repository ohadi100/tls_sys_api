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

#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "Logger.hpp"
#include "LogHandlers.hpp"

#define MAX_LOG_LINE_LENGTH (2048)

using common::Logger;
using common::LogHandler;
using common::LogLevel;

using std::mutex;
using std::function;
using std::lock_guard;

const char * common::levelNames[] = { "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "VERBOSE" };


void Logger::RegisterLogHandler(LogHandler *handler)
{
    for (LogHandler * handlerIter : m_logHandlers)
    {
        if (handlerIter == handler)
        {
            return;     // no need to register the same handler twice
        }
    }

    m_logHandlers.push_back(handler);
}

void Logger::ClearLogHandlers()
{
    m_logHandlers.clear();
}

void Logger::WriteLog(LogLevel level, const char* fullFilename, const char * funcName, uint32_t line, const char * fmt, ...)
{
    if (!funcName || !fmt)
    {
        return;
    }

    char buf[MAX_LOG_LINE_LENGTH];
    int len = 0;

    const char * filename = strrchr(fullFilename, '/');

    if (!filename)
    {
        filename = fullFilename;
    }
    else
    {
        filename++; // remove the actual '/'
    }

    if (LogLevel::LOG_LEVEL_CLEAN != level)
    {
        len = snprintf(buf, sizeof(buf), "%s/%s(%d)", filename, funcName, line);
        int padding = 47 - len;
        if (padding > 0)
        {
            memset(buf+len, ' ', (uint32_t)padding);
            buf[45] = '|';
            len += padding;
        }
        else
        {
            buf[len++] = ' ';
            buf[len++] = '|';
            buf[len++] = ' ';
        }
    }
    else
    {
        level = LogLevel::LOG_LEVEL_INFO;
    }

    va_list args;
    va_start(args, fmt);
    len += vsnprintf(buf + len, sizeof(buf) - len, fmt, args);
    va_end(args);

    if (len > (int)(sizeof(buf) - 1))

    {
        len = snprintf(buf, sizeof(buf), "%s(%d) - log line too long", funcName, line);
        level = LogLevel::LOG_LEVEL_ERROR;
    }

    buf[len] = '\0';

    std::lock_guard<std::mutex> lock(m_mutex);
    for (LogHandler * handler : m_logHandlers)
    {
        handler->HandleLogLine(level, buf);
    }
}
