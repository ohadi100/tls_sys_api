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


#include "TLSTEEAPI.h"

#ifdef UNIT_TEST
#include "MockTLSTEEAPI.hpp"
#else
#include "TLSTEEInterfaceClass.h"
using vwg::tee::impl::TLSTEEInterfaceClass;
#endif

using vwg::tee::TLSTEEAPI;
/**
 * Returns a shared_ptr of the API instance created as a singleton
 * \return shared_ptr of the singleton API instance
 */
std::shared_ptr<TLSTEEAPI> TLSTEEAPI::get_instance()
{
#ifdef UNIT_TEST
    return tee::TLSTEEUT::mMockTLSTEEAPI;
#else
    return TLSTEEInterfaceClass::get_instance();
#endif
}
