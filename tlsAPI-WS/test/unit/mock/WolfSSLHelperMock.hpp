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

#ifndef WOLFSSL_HELPER_MOCK_HPP
#define WOLFSSL_HELPER_MOCK_HPP

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/coding.h>

class WolfSSLHelperMock
{
    virtual void* wolfSSL_get_ex_data(const WOLFSSL*, int) = 0;

    virtual int wolfSSL_get_error(WOLFSSL*, int) = 0;

    virtual int wolfSSL_get_alert_history(WOLFSSL*, WOLFSSL_ALERT_HISTORY* history) = 0;

    virtual WOLFSSL_METHOD* wolfTLSv1_2_method() = 0;

    virtual WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*) = 0;

    virtual void wolfSSL_CTX_free(WOLFSSL_CTX*) = 0;

    virtual void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX*, wc_psk_server_callback) = 0;

    virtual int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char** protocol_name, unsigned short* size) = 0;

    virtual int wolfSSL_shutdown(WOLFSSL* ssl) = 0;

    virtual int wolfSSL_get_shutdown(const WOLFSSL* ssl) = 0;

    virtual void wolfSSL_dtls_set_using_nonblock(WOLFSSL*, int) = 0;

    virtual int wolfSSL_recv(WOLFSSL*, void*, int sz, int flags) = 0;

    virtual int wolfSSL_send(WOLFSSL*, const void*, int sz, int flags) = 0;

    virtual int wolfSSL_X509_get_pubkey_buffer(WOLFSSL_X509* x509, unsigned char* buf, int* len) = 0;

    virtual WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN*, int idx) = 0;

    virtual void wolfSSL_X509_free(WOLFSSL_X509* x509) = 0;

    virtual WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl) = 0;

    virtual int wolfSSL_connect(WOLFSSL* ssl) = 0;

    virtual int wolfSSL_check_domain_name(WOLFSSL*, const char*) = 0;

    virtual int wolfSSL_UseOCSPStapling(WOLFSSL* ssl, unsigned char status_type, unsigned char options) = 0;

    virtual int wolfSSL_EnableOCSPStapling(WOLFSSL* ssl) = 0;

    virtual void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX*, wc_psk_client_callback) = 0;

    virtual int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX*, int) = 0;

    virtual int wolfSSL_use_PrivateKey_buffer(WOLFSSL*, const unsigned char*, long, int) = 0;

    virtual int wolfSSL_use_certificate_buffer(WOLFSSL*, const unsigned char*, long, int) = 0;

    virtual int wolfSSL_set_cipher_list(WOLFSSL*, const char*) = 0;

    virtual void wolfSSL_CTX_SetIORecv(WOLFSSL_CTX*, CallbackIORecv) = 0;

    virtual void wolfSSL_CTX_SetIOSend(WOLFSSL_CTX*, CallbackIOSend) = 0;

    virtual WOLFSSL* wolfSSL_new(WOLFSSL_CTX*) = 0;

    virtual void wolfSSL_free(WOLFSSL*) = 0;

    virtual int wolfSSL_use_psk_identity_hint(WOLFSSL*, const char*) = 0;

    virtual void wolfSSL_SetIOReadCtx(WOLFSSL* ssl, void* ctx) = 0;

    virtual void wolfSSL_SetIOWriteCtx(WOLFSSL* ssl, void* ctx) = 0;

    virtual int wolfSSL_set_ex_data(WOLFSSL*, int, void*) = 0;

    virtual int wolfSSL_accept(WOLFSSL*) = 0;

    virtual char* wolfSSL_ERR_error_string(unsigned long, char*) = 0;

    virtual int wc_Sha256Hash(const byte* data, word32 size, byte* hash) = 0;

    virtual int Base64_Encode_NoNl(const byte* in, word32 inLen, byte* out, word32* outLen) = 0;

    virtual WOLFSSL_METHOD* wolfSSLv23_client_method() = 0;

    virtual int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX*, const unsigned char*, long, int) = 0;

    virtual int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name) = 0;

    virtual int wolfSSL_UseALPN(WOLFSSL*      ssl,
                                char*         protocol_name_list,
                                unsigned int  protocol_name_listSz,
                                unsigned char options) = 0;

    virtual int wolfSSL_UseSNI(WOLFSSL*, unsigned char, const void*, unsigned short) = 0;

    virtual int wolfSSL_EnableOCSP(WOLFSSL*, int) = 0;

    virtual int wolfSSL_SetOCSP_Cb(WOLFSSL*, CbOCSPIO, CbOCSPRespFree, void*) = 0;

    virtual void wolfSSL_set_verify(WOLFSSL*, int, VerifyCallback) = 0;

    virtual void* wolfSSL_X509_STORE_CTX_get_ex_data(WOLFSSL_X509_STORE_CTX*, int) = 0;

    virtual int wolfSSL_get_ex_data_X509_STORE_CTX_idx() = 0;

    virtual OcspResponse* wolfSSL_d2i_OCSP_RESPONSE(OcspResponse**, const unsigned char**, int) = 0;

    virtual void wolfSSL_OCSP_RESPONSE_free(OcspResponse*) = 0;

    virtual int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx) = 0;

    virtual int wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN*) = 0;

    virtual int wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509*, int) = 0;

    virtual int wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx) = 0;
};
#endif  // WOLFSSL_HELPER_MOCK_HPP
