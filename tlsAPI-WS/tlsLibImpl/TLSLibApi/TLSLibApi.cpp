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

#include "Logger.hpp"

#include "TLSLibApi.h"
#include "TLSSocketFactory.h"
#include "TLSSocketFactoryImpl.hpp"

#if defined(UNIT_TEST)
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "MockWolfSSL.hpp"
#else
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif

using vwg::tls::TLSResult;
using vwg::tls::ITLSSocketFactory;

using vwg::tls::impl::TLSSocketFactoryImpl;

static std::mutex mtx;
static bool initDone = false;
TLSResult<std::shared_ptr<ITLSSocketFactory>> tlsFactory; 


TLSResult<std::shared_ptr<ITLSSocketFactory>> vwg::tls::initTLSLib()
{
    std::unique_lock<std::mutex> lock(mtx);
    if(!initDone)
    {

    #define EXPECTED_WOLFSSL_VERSION 0x05006006 ///  5.6.6
    #if LIBWOLFSSL_VERSION_HEX < EXPECTED_WOLFSSL_VERSION
        #error "WolfSSL version unsupported"
    #endif

    int ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        FND_LOG_ERROR << "TLS initialization error detected: wolfssl failed with error code: %d" << ret;
    }
        initDone = true;
    }
    else
    {
       FND_LOG_INFO << "TLS lib was already initialized"; 
       return tlsFactory;
    }

    tlsFactory = ITLSSocketFactoryResult(std::make_shared<TLSSocketFactoryImpl>());

    FND_LOG_INFO << "TLS lib initialized";

    return tlsFactory;
}

void vwg::tls::cleanupTLSLib()
{
    std::unique_lock<std::mutex> lock(mtx);
    if(initDone)
    {
        wolfSSL_Cleanup();
        initDone = false;
    }
    else
    {
        FND_LOG_ERROR << "TLS lib was not initialized";
    }
}
