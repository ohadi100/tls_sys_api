/**
 * 
 * @file MockTLSOcspHandler.hpp
 * 
 * @brief contains the mock TLSOcspHandler class
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


#ifndef MOCK_TLSOCSPHANDLER_HPP
#define MOCK_TLSOCSPHANDLER_HPP

#include <gmock/gmock.h>

#include "TLSApiTypes.h"

namespace vwg
{
namespace tls
{
class MockTLSOcspHandler
{
public:
    MockTLSOcspHandler()  = default;
    ~MockTLSOcspHandler() = default;

    MOCK_METHOD1(cacheResponses, void(const std::vector<TLSOcspCachedResponse>& responses));
    MOCK_METHOD1(processRequests,
                 std::future<std::vector<TLSOcspRequestResponse>>(const std::vector<TLSOcspRequest>& requests));
};

class MockTLSOcspHandlerUT : public ITLSOcspHandler
{
public:
    MockTLSOcspHandlerUT()  = default;
    ~MockTLSOcspHandlerUT() = default;

    virtual void
    cacheResponses(const std::vector<TLSOcspCachedResponse>& responses) noexcept override
    {
        return mMockTLSOcspHandler->cacheResponses(responses);
    }

    virtual std::future<std::vector<TLSOcspRequestResponse>>
    processRequests(const std::vector<TLSOcspRequest>& requests) noexcept override
    {
        return mMockTLSOcspHandler->processRequests(requests);
    }

    static MockTLSOcspHandler* mMockTLSOcspHandler;
};
}  // namespace tls
}  // namespace vwg

#endif  // MOCK_TLSOCSPHANDLER_HPP
