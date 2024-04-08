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


#ifndef TLS_CERT_ENGINE_HELP_TEST_HPP
#define TLS_CERT_ENGINE_HELP_TEST_HPP

#include "TLSCertEngine.hpp"

using namespace vwg::tls::impl;
using namespace vwg::tls;

class TLSCertEngineHelpTest : public TLSCertEngine
{
public:
    TLSCertEngineHelpTest(std::shared_ptr<IOStreamIf> stream, TimeCheckTime checkTime)
      : TLSCertEngine(stream, checkTime)
    {
    }

    TLSEngineError
    DoSSLHandshake() override
    {
        throw std::bad_function_call();
    }

    TLSEngineError
    Send(const uint8_t* buffer, int32_t bufLength, int32_t& actualLength) override
    {
        (void)buffer;
        (void)bufLength;
        (void)actualLength;

        throw std::bad_function_call();
    }

    TLSEngineError
    Receive(uint8_t* buffer, int32_t bufLength, int32_t& actualLength) override
    {
        (void)buffer;
        (void)bufLength;
        (void)actualLength;

        throw std::bad_function_call();
    }

    TLSEngineError
    Shutdown() override
    {
        throw std::bad_function_call();
    }

    void Close() override
    {

    }

    const std::string
    GetRemoteHintName() const override
    {
        throw std::bad_function_call();
    }

    const std::string
    GetHintName() const override
    {
        throw std::bad_function_call();
    }

    const AlpnMode&
    getUsedAlpnMode() const override
    {
        throw std::bad_function_call();
    }

    IANAProtocol
    getUsedProtocol() const override
    {
        throw std::bad_function_call();
    }
};
#endif  // TLS_CERT_ENGINE_HELP_TEST_HPP