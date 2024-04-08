/**
 * 
 * @file MockTLSTEEAPI.hpp
 * 
 * @brief contains the mock TLSTEEAPI class
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


#ifndef MOCK_TLS_TEE_API_HPP
#define MOCK_TLS_TEE_API_HPP

#include <gmock/gmock.h>

#include "TLSTEEAPI.h"

namespace vwg {
namespace tee {

class MockTLSTEEAPI : public TLSTEEAPI {
public:
  MockTLSTEEAPI() = default;

  MockTLSTEEAPI(const MockTLSTEEAPI &) = default;

  MOCK_METHOD3(get_psk, bool(IdentityHint clientHint, IdentityHint serverHint,
                             SessionKey *key));
  MOCK_METHOD1(get_root_cert_bundle, CertificateBundle(TrustStoreID store_id));
  MOCK_METHOD1(get_client_cert, CertificateChain(ClientCertID key_id));
  MOCK_METHOD1(get_client_cert_private_key, Key(ClientCertID key_id));
};

class TLSTEEUT : public TLSTEEAPI {
public:
  TLSTEEUT() = default;
  virtual ~TLSTEEUT() = default;

  virtual bool get_psk(IdentityHint clientHint, IdentityHint serverHint,
                       SessionKey *key) {
    return mMockTLSTEEAPI->get_psk(clientHint, serverHint, key);
  }

  virtual CertificateBundle get_root_cert_bundle(TrustStoreID store_id) {
    return mMockTLSTEEAPI->get_root_cert_bundle(store_id);
  }

  virtual CertificateChain get_client_cert(ClientCertID key_id) {
    return mMockTLSTEEAPI->get_client_cert(key_id);
  }

  virtual Key get_client_cert_private_key(ClientCertID key_id) {
    return mMockTLSTEEAPI->get_client_cert_private_key(key_id);
  }

  static std::shared_ptr<MockTLSTEEAPI> mMockTLSTEEAPI;
};

} // namespace tee
} // namespace vwg

#endif // MOCK_TLS_TEE_API_HPP
