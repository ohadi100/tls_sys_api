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

 
#ifndef Log__fcj289z64fh33fh__H
#define Log__fcj289z64fh33fh__H

#include <cstring>

namespace devtools {

#define LOG_LEVEL_NONE  0x00
#define LOG_LEVEL_ERROR 0x01
#define LOG_LEVEL_INFO  0x02
#define LOG_LEVEL_DEBUG 0x03

/*
 * Do not change the default log level.
 * To change the log level, define LOG_LEVEL to the appropriate level in your
 * main file, test file or (even better) pass it as a compile option. See if
 * the CMakeLists.txt supports setting a log level.
*/
#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_NONE
#endif

#define FILE___NAME strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define LOG_ERROR(message)  fprintf(stderr, "| ERROR | %s::%s::%d | %s\n", FILE___NAME, __FUNCTION__, __LINE__, message)
#define LOG_ERROR_PLAIN(message)  fprintf(stderr, "%s\n", message)
#else
#define LOG_ERROR(message)
#define LOG_ERROR_PLAIN(message)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define LOG_INFO(message)   fprintf(stderr, "| INFO  | %s::%s::%d | %s\n", FILE___NAME, __FUNCTION__, __LINE__, message)
#define LOG_INFO_PLAIN(message)  fprintf(stderr, "%s\n", message)
#else
#define LOG_INFO(message)
#define LOG_INFO_PLAIN(message)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_DEBUG(message)  fprintf(stderr, "| DEBUG | %s::%s::%d | %s\n", FILE___NAME, __FUNCTION__, __LINE__, message)
#define LOG_DEBUG_PLAIN(message)  fprintf(stderr, "%s\n", message)
#else
#define LOG_DEBUG(message)
#define LOG_DEBUG_PLAIN(message)
#endif

} /* namespace devtools */

#endif // Log__fcj289z64fh33fh__H
