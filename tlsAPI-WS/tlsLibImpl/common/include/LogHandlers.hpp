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

#ifndef __LOG_HANDLER_HPP__
#define __LOG_HANDLER_HPP__

#include "Logger.hpp"

#include <iostream>
#include <time.h>
#include <map>
#include <thread>

namespace common
{

class LinuxLogHandler : public LogHandler
{
public:
    LinuxLogHandler() = default;

    void HandleLogLine(LogLevel level, const char * log)
    {
        char logPrefix[256] = {0};
        size_t prefixLen;

        // thread id
        std::thread::id this_id = std::this_thread::get_id();
        std::map<std::thread::id, uint32_t>::const_iterator it = m_threadNumbers.find(this_id);
        if (it == m_threadNumbers.end())
        {
            m_threadNumbers[this_id] = m_threadCount++;
        }
        prefixLen = (size_t)snprintf(logPrefix, sizeof(logPrefix), "%d> ", m_threadNumbers[this_id]);

        time_t time;
        struct timespec timeSpec;
        if (-1 == clock_gettime(CLOCK_REALTIME, &timeSpec))
        {
            std::cerr << "error getting time";
            return;
        }

        time = timeSpec.tv_sec;

        struct tm * tm_info = localtime(&time);
        if (nullptr == tm_info)
        {
            strncpy(logPrefix+prefixLen, "CAN'T GET TIME", 15);
            prefixLen += 15;
        }
        else
        {
            prefixLen += strftime(logPrefix+prefixLen, sizeof(logPrefix)-prefixLen, "%d/%m %H:%M:%S", tm_info);
        }



        snprintf(logPrefix+prefixLen, sizeof(logPrefix)-prefixLen, " | %-7s | ", common::levelNames[static_cast<uint32_t>(level)]);

        // actually write the log
        std::cout<< logPrefix<< log << std::endl;
    }

private:

    std::map<std::thread::id, uint32_t> m_threadNumbers;
    uint32_t m_threadCount;

};

}   // namespace common

#endif // !__LOG_HANDLER_H__