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

#include "TLSCertEngine.hpp"


#include "Logger.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

using vwg::tls::TLSCipherSuiteUseCasesSettings;
using vwg::tls::ITLSOcspHandler;
using vwg::tls::impl::TLSCertEngine;
using vwg::tls::impl::TLSEngineError;
using vwg::tls::IOStream;
using std::string;
using std::vector;

TLSCertEngine::TLSCertEngine(std::shared_ptr<IOStreamIf> const& stream, const TimeCheckTime &checkTime)
    : m_stream(stream),
      m_checkTime(checkTime),
      m_cipherSuiteUseCase(CSUSDefault),
      m_ocspHandler(nullptr),
      m_ocspTimeoutMs(0),
      m_revocationCheckEnabled(false),
      m_connectionLoggingName(stream->getConnectionLoggingName())
{
}

TLSCertEngine::TLSCertEngine(std::shared_ptr<IOStreamIf> const& stream, const TimeCheckTime &checkTime,
                             std::shared_ptr<ITLSOcspHandler> const& ocspHandler, const uint32_t ocspTimeoutMs)
        : m_stream(stream),
          m_checkTime(checkTime),
          m_cipherSuiteUseCase(CSUSDefault),
          m_ocspHandler(ocspHandler),
          m_ocspTimeoutMs(ocspTimeoutMs),
          m_revocationCheckEnabled(false),
          m_connectionLoggingName(stream->getConnectionLoggingName())
{
}

const std::shared_ptr<IOStream> TLSCertEngine::GetIOStream() const
{
    return m_stream;
}

#ifdef TLSAPI_WITH_DROP_SUPPORT
vwg::tls::impl::TLSEngineError TLSCertEngine::DropTLS()
{
    return RC_TLS_ENGINE_NOT_SUPPORTED;
}
#endif

vwg::tls::impl::TLSEngineError TLSCertEngine::SetBlocking(bool blocking)
{
    if(m_stream->SetBlocking(blocking))
    {
        return RC_TLS_ENGINE_SUCCESSFUL;
    }
    return RC_TLS_ENGINE_FATAL_ERROR;
}

TLSEngineError
TLSCertEngine::CheckAuthenticTimeCheck() const
{
    //if time check required, the times (m_checkTime.expectedTime and system time)
    // are valid and m_checkTime.permittedDeviation<MAX_PERMITTED_DEVIATION,
    // then check if |m_checkTime.expectedTime  - system_time.now()| <= |permittedDeviation|

    const std::time_t expectedTimeSec = m_checkTime.expectedTime;
    if (0 == expectedTimeSec)  // no time check required
    {
        FND_LOG_VERBOSE << "Authentic time check: no time check required";
        return RC_TLS_ENGINE_SUCCESSFUL;
    }

    time_t currentTimeSec;
    time(&currentTimeSec);

    FND_LOG_DEBUG << "Authentic time check: STARTED! Started check for connectionName: " << m_connectionLoggingName.c_str() <<". System time: " << currentTimeSec << " [sec] << expected time: " << m_checkTime.expectedTime <<" [sec] << permitted deviation: " << m_checkTime.permittedDeviation << " [sec]";

    const unsigned int absPermittedDeviation = abs(m_checkTime.permittedDeviation);
    if (MAX_PERMITTED_DEVIATION <=
        absPermittedDeviation)  // The |permittedDeviation| shall be less than one day (86400sec)
    {
        FND_LOG_ERROR << "Authentic time check: FAILED! The permitted deviation is too big! Permitted deviation: " << absPermittedDeviation << " [sec]";
        return RC_TLS_ENGINE_MAX_PERMITTED_DEVIATION;
    }

    if (-1 == currentTimeSec) { //Attempt to get system time has failed
        FND_LOG_ERROR << "Authentic time check: FAILED! Could not get system time.";
        return RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED;
    }

    struct tm* timeRes = (localtime(&currentTimeSec));
    if (nullptr == timeRes) {//Attempt to convert time to local time has failed
        FND_LOG_ERROR << "Authentic time check: FAILED! Could not convert system time to local time.";
        return RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED;
    }
    struct tm currentTm = *timeRes;

    timeRes = (localtime(&m_checkTime.expectedTime));
    if (nullptr == timeRes) {//Attempt to convert time to local time has failed
        FND_LOG_ERROR << "Authentic time check: FAILED! Could not convert expected time to local time.";
        return RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED;
    }
    struct tm expectedTm = *timeRes;

    // We would expect that the time diff shall be < 86400 sec (one day), then the difference in the years must be <=1,
    // then we can first check: -1 <= (currentYear - expectedYear) <= 1, that's equals to: |currentYear - expectedYear|<= 1.
    // But the calculation (currentYear - expectedYear) can overflow, since currentYear could be too big or too small (in attack),
    // so we can check the same in this way: (-1 + expectedYear) <= currentYear <= (1 + expectedYear)
    const int currentYear = currentTm.tm_year, expectedYear = expectedTm.tm_year, threshold = 1;
    if (currentYear <= (threshold + expectedYear) &&
        (-threshold + expectedYear) <= currentYear) {  // |(currentYear - expectedYear)| <= threshold
        // difftime may be incorrect in case of (m_checkTime.expectedTime-currentTime) overflows it can be in case the
        // currentTime is too big or too small, therefore we checked if the times are valid and if  -1 <= (currentYear -expectedYear) <= 1
        double diffSec = difftime(expectedTimeSec, currentTimeSec);
        if (abs(diffSec) <= static_cast<double>(absPermittedDeviation)) {
            //|expectedTime  - system_time.now()| <= |permittedDeviation|
            std::stringstream formattedDiffSec;
            formattedDiffSec << std::setprecision(3) << abs(diffSec);
            FND_LOG_DEBUG << "Authentic time check: SUCCEEDED! Authentic time check finished successfully! System time: " << currentTimeSec << " [sec] << time difference: " << formattedDiffSec.str() << " [sec]";
            return RC_TLS_ENGINE_SUCCESSFUL;
        }
    }

    FND_LOG_ERROR << "Authentic time check: FAILED! Time difference between system time and expected time is too big!";
    return RC_TLS_ENGINE_AUTHENTIC_TIMECHECK_FAILED;

}

TLSCipherSuiteUseCasesSettings
TLSCertEngine::GetCipherSuiteUseCase() const
{
    return m_cipherSuiteUseCase;
}

const std::shared_ptr<ITLSOcspHandler>&
TLSCertEngine::GetOcspHandler() const
{
    return m_ocspHandler;
}

uint32_t
TLSCertEngine::GetOcspTimeout() const
{
    return m_ocspTimeoutMs;
}

bool
TLSCertEngine::GetRevocationCheckEnable() const
{
    return m_revocationCheckEnabled;
}

bool
TLSCertEngine::IsHardFailFallbackMechanismActive() const
{
    return (GetRevocationCheckEnable() && ((GetCipherSuiteUseCase() != CSUSLegacy) && (GetCipherSuiteUseCase() != CSUSDefaultWithSoftFail)));
}