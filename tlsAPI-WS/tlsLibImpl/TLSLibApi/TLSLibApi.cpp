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

#include <vwg/fnd/logging.hpp>

#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "TLSSocketFactoryImpl.hpp"
#include "Globals.hpp"
#include "LogHandlers.hpp"

#if defined(UNIT_TEST)
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "MockWolfSSL.hpp"
#elif defined(TLS_ENGINE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#ifdef WOLFSSL_LOGS_DIRECT_TO_SYSLOG
#include <wolfssl/wolfcrypt/logging.h>
#endif
#ifdef LOGS_DIRECT_TO_SYSLOG
#include <vwg/fnd/log/logging.hpp>
#include <ara/log/logging.hpp>
using namespace ara::log;
static constexpr char const* contextId = "sysapi_tls";
static constexpr char const* contextDescription = "sysapi_tls lib";
Logger &logger = CreateLogger(contextId, contextDescription);
  
//#include <string>
using namespace ara::log;
#endif
#elif defined(TLS_ENGINE_BOTAN)
#include <botan/version.h>
#else
    #error "need a tls engine"
#endif

using vwg::tls::TLSResult;
using vwg::tls::ITLSSocketFactory;

using vwg::tls::impl::TLSSocketFactoryImpl;

static common::LinuxLogHandler logHandler;
static std::mutex mtx;
static bool initDone = false;
TLSResult<std::shared_ptr<ITLSSocketFactory>> tlsFactory; 

#ifdef TLS_ENGINE_WOLFSSL
#ifdef WOLFSSL_LOGS_DIRECT_TO_SYSLOG
static void wolfSSL_LoggingCallback(const int logLevel, const char* const logMessage)
{
    switch(logLevel)
    {
    case ERROR_LOG:
    #ifndef LOGS_DIRECT_TO_SYSLOG
        LOG_ERROR(logMessage);
    #else
        FND_LOG_ERROR(logger, logMessage);
    #endif 
        break;
    case INFO_LOG:
    #ifndef LOGS_DIRECT_TO_SYSLOG
        LOG_INFO(logMessage);
    #else
        FND_LOG_WARN(logger, logMessage);
    #endif 
        break;
    case ENTER_LOG:
    case LEAVE_LOG:
    case OTHER_LOG: // explicit fall-through for ENTER_LOG/LEAVE_LOG/OTHER_LOG log levels to verbose
    #ifndef LOGS_DIRECT_TO_SYSLOG
        LOG_VERBOSE(logMessage);
    #else
        FND_LOG_VERBOSE(logger, logMessage);
    #endif 
        break;
    default:
    #ifndef LOGS_DIRECT_TO_SYSLOG
        LOG_FATAL(logMessage);
    #else
        FND_LOG_FATAL(logger, logMessage);
    #endif 
        break;
    }
}
#endif // WOLFSSL_LOGS_DIRECT_TO_SYSLOG
#endif // TLS_ENGINE_WOLFSSL

TLSResult<std::shared_ptr<ITLSSocketFactory>> vwg::tls::initTLSLib()
{
    std::unique_lock<std::mutex> lock(mtx);
    if(!initDone)
    {
        common::Logger::GetInstance().RegisterLogHandler(&logHandler);

#if defined(TLS_ENGINE_BOTAN)
    #define EXPECTED_BOTAN_VERSION (BOTAN_VERSION_CODE_FOR(2,8,0))
    #if BOTAN_VERSION_CODE != EXPECTED_BOTAN_VERSION
        #error "Botan version unsupported"
    #endif

    if (!Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH).empty())
        return ITLSSocketFactoryResult(RC_TLS_INIT_FAILED);
#elif defined(TLS_ENGINE_WOLFSSL) || defined(UNIT_TEST)
    #define EXPECTED_WOLFSSL_VERSION 0x05006006 ///  5.6.6
    #if LIBWOLFSSL_VERSION_HEX < EXPECTED_WOLFSSL_VERSION
        #error "WolfSSL version unsupported"
    #endif

    int ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        LOG_ERROR("TLS initialization error detected: wolfssl failed with error code: %d", ret);
    }

#ifdef WOLFSSL_LOGS_DIRECT_TO_SYSLOG
    if (0 != wolfSSL_Debugging_ON()) {
        LOG_WARNING("Failed to init wolfSSL debugging");
    } else {
        if (0 != wolfSSL_SetLoggingCb(&wolfSSL_LoggingCallback)) {
            LOG_WARNING("Failed to set logger CB for wolfSSL");
        }
    }
#endif // WOLFSSL_LOGS_DIRECT_TO_SYSLOG
#else
    #error "need a tls engine"
#endif

        initDone = true;
    }
    else
    {
       LOG_INFO("TLS lib was already initialized"); 
       return tlsFactory;
    }

    tlsFactory = ITLSSocketFactoryResult(std::make_shared<TLSSocketFactoryImpl>());

    LOG_INFO("TLS lib initialized");

    return tlsFactory;
}

void vwg::tls::cleanupTLSLib()
{
#if defined(TLS_ENGINE_WOLFSSL) || defined(UNIT_TEST)
    std::unique_lock<std::mutex> lock(mtx);
    if(initDone)
    {
        wolfSSL_Cleanup();
        initDone = false;
    }
    else
    {
        LOG_ERROR("TLS lib was not initialized");
    }
#elif defined(TLS_ENGINE_BOTAN)
#else
    #error "need a tls engine"
#endif 
}
