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

#ifndef MOCK_WOLFSSL_HPP
#define MOCK_WOLFSSL_HPP

#include <gmock/gmock.h>

#include "WolfSSLHelperMock.hpp"

class MockWolfSSL : public WolfSSLHelperMock
{
public:
    MockWolfSSL() = default;
    MockWolfSSL(const MockWolfSSL&) = default;
    virtual ~MockWolfSSL() = default;

    MOCK_METHOD2(wolfSSL_get_ex_data, void*(const WOLFSSL*, int));
    MOCK_METHOD2(wolfSSL_get_error, int(WOLFSSL*, int));
    MOCK_METHOD2(wolfSSL_get_alert_history, int(WOLFSSL*, WOLFSSL_ALERT_HISTORY* history));
    MOCK_METHOD0(wolfTLSv1_2_method, WOLFSSL_METHOD*(void));
    MOCK_METHOD1(wolfSSL_CTX_new, WOLFSSL_CTX*(WOLFSSL_METHOD*));
    MOCK_METHOD1(wolfSSL_CTX_free, void(WOLFSSL_CTX*));
    MOCK_METHOD2(wolfSSL_CTX_set_psk_server_callback, void(WOLFSSL_CTX*, wc_psk_server_callback));
    MOCK_METHOD3(wolfSSL_ALPN_GetProtocol, int(WOLFSSL* ssl, char** protocol_name, unsigned short* size));
    MOCK_METHOD1(wolfSSL_shutdown, int(WOLFSSL* ssl));
    MOCK_METHOD1(wolfSSL_get_shutdown, int(const WOLFSSL* ssl));
    MOCK_METHOD2(wolfSSL_dtls_set_using_nonblock, void(WOLFSSL*, int));
    MOCK_METHOD4(wolfSSL_recv, int(WOLFSSL*, void*, int sz, int flags));
    MOCK_METHOD4(wolfSSL_send, int(WOLFSSL*, const void*, int sz, int flags));
    MOCK_METHOD3(wolfSSL_X509_get_pubkey_buffer, int(WOLFSSL_X509*, unsigned char* , int*));
    MOCK_METHOD2(wolfSSL_get_chain_X509, WOLFSSL_X509*(WOLFSSL_X509_CHAIN*, int idx));
    MOCK_METHOD1(wolfSSL_X509_free, void(WOLFSSL_X509* x509));
    MOCK_METHOD1(wolfSSL_get_peer_chain, WOLFSSL_X509_CHAIN*(WOLFSSL* ssl));
    MOCK_METHOD1(wolfSSL_connect, int(WOLFSSL* ssl));
    MOCK_METHOD3(wolfSSL_UseOCSPStapling, int(WOLFSSL* ssl, unsigned char status_type, unsigned char options));
    MOCK_METHOD1(wolfSSL_EnableOCSPStapling, int(WOLFSSL* ssl));
    MOCK_METHOD2(wolfSSL_CTX_set_psk_client_callback, void(WOLFSSL_CTX*, wc_psk_client_callback));
    MOCK_METHOD2(wolfSSL_CTX_SetMinVersion, int(WOLFSSL_CTX*, int));
    MOCK_METHOD4(wolfSSL_use_PrivateKey_buffer, int(WOLFSSL*, const unsigned char*, long, int));
    MOCK_METHOD4(wolfSSL_use_certificate_buffer, int(WOLFSSL*, const unsigned char*, long, int));
    MOCK_METHOD2(wolfSSL_set_cipher_list, int(WOLFSSL*, const char*));
    MOCK_METHOD2(wolfSSL_CTX_SetIORecv, void(WOLFSSL_CTX*, CallbackIORecv));
    MOCK_METHOD2(wolfSSL_CTX_SetIOSend, void(WOLFSSL_CTX*, CallbackIOSend));
    MOCK_METHOD1(wolfSSL_new, WOLFSSL*(WOLFSSL_CTX*));
    MOCK_METHOD1(wolfSSL_free, void(WOLFSSL*));
    MOCK_METHOD2(wolfSSL_use_psk_identity_hint, int(WOLFSSL*, const char*));
    MOCK_METHOD2(wolfSSL_SetIOReadCtx, void(WOLFSSL* ssl, void* ctx));
    MOCK_METHOD2(wolfSSL_SetIOWriteCtx, void(WOLFSSL* ssl, void* ctx));
    MOCK_METHOD3(wolfSSL_set_ex_data, int(WOLFSSL*, int, void*));
    MOCK_METHOD1(wolfSSL_accept, int(WOLFSSL*));
    MOCK_METHOD2(wolfSSL_ERR_error_string, char*(unsigned long, char*));
    MOCK_METHOD1(wc_InitSha256, int(wc_Sha256*));
    MOCK_METHOD3(wc_Sha256Hash, int(const byte* data, word32 size, byte* hash));
    MOCK_METHOD3(wc_Sha256Update, int(wc_Sha256*, const byte*, word32));
    MOCK_METHOD2(wc_Sha256Final, int(wc_Sha256*, byte*));
    MOCK_METHOD4(Base64_Encode_NoNl, int(const byte* in, word32 inLen, byte* out, word32* outLen));
    MOCK_METHOD0(wolfSSLv23_client_method, WOLFSSL_METHOD*(void));
    MOCK_METHOD4(wolfSSL_CTX_load_verify_buffer, int(WOLFSSL_CTX*, const unsigned char*, long, int));
    MOCK_METHOD2(wolfSSL_UseSupportedCurve, int(WOLFSSL* ssl, word16 name));
    MOCK_METHOD4(wolfSSL_UseALPN,
                 int(WOLFSSL* ssl, char* protocol_name_list, unsigned int protocol_name_listSz, unsigned char options));
    MOCK_METHOD4(wolfSSL_UseSNI, int(WOLFSSL*, unsigned char, const void*, unsigned short));
    MOCK_METHOD2(wolfSSL_EnableOCSP, int(WOLFSSL*, int));
    MOCK_METHOD4(wolfSSL_SetOCSP_Cb, int(WOLFSSL*, CbOCSPIO, CbOCSPRespFree, void*));
    MOCK_METHOD3(wolfSSL_set_verify, void(WOLFSSL*, int, VerifyCallback));
    MOCK_METHOD2(wolfSSL_X509_STORE_CTX_get_ex_data, void*(WOLFSSL_X509_STORE_CTX*, int));
    MOCK_METHOD0(wolfSSL_get_ex_data_X509_STORE_CTX_idx, int(void));
    MOCK_METHOD3(wolfSSL_d2i_OCSP_RESPONSE, OcspResponse*(OcspResponse**, const unsigned char**, int));
    MOCK_METHOD1(wolfSSL_OCSP_RESPONSE_free, void(OcspResponse*));
    MOCK_METHOD1(wolfSSL_CTX_EnableOCSPMustStaple, int(WOLFSSL_CTX*));
    MOCK_METHOD1(wolfSSL_get_chain_count, int(WOLFSSL_X509_CHAIN*));
    MOCK_METHOD2(wolfSSL_X509_ext_isSet_by_NID, int(WOLFSSL_X509*, int));
    MOCK_METHOD2(wolfSSL_X509_check_issued, int(WOLFSSL_X509 *issuer, WOLFSSL_X509 *subject));
    MOCK_METHOD1(wolfSSL_X509_get_isCA, int(WOLFSSL_X509*));
    MOCK_METHOD5(wolfSSL_get_chain_cert_pem, int(WOLFSSL_X509_CHAIN* chain, int idx, unsigned char* buf, int inLen, int* outLen));
    MOCK_METHOD3(wolfSSL_X509_get_name_oneline, char*(WOLFSSL_X509_NAME* name, char* in, int sz));
    MOCK_METHOD1(wolfSSL_X509_get_issuer_name, WOLFSSL_X509_NAME*(WOLFSSL_X509* cert));
    MOCK_METHOD1(wolfSSL_X509_get_subject_name, WOLFSSL_X509_NAME*(WOLFSSL_X509* cert));
    MOCK_METHOD2(wolfSSL_check_domain_name, int(WOLFSSL*, const char*));
    MOCK_METHOD0(wolfSSL_Init, int(void));
    MOCK_METHOD0(wolfSSL_Cleanup, int(void));
    MOCK_METHOD2(wolfSSL_get_chain_length, int(WOLFSSL_X509_CHAIN* chain, int idx));
};

class MockWolfSSLUT
{
public:
    MockWolfSSLUT()          = default;
    virtual ~MockWolfSSLUT() = default;

    static MockWolfSSL* mMockWolfSSL;
};
#endif  // MOCK_WOLFSSL_HPP
