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

#include <wolfssl/options.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/coding.h>

#include "MockWolfSSL.hpp"

void*
wolfSSL_get_ex_data(const WOLFSSL *ssl, int val)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_ex_data(ssl, val);
}

int
wolfSSL_get_error(WOLFSSL *ssl, int val)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_error(ssl, val);
}

int
wolfSSL_get_alert_history(WOLFSSL *ssl, WOLFSSL_ALERT_HISTORY* history)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_alert_history(ssl, history);
}

WOLFSSL_METHOD*
wolfTLSv1_2_method(void)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfTLSv1_2_method();
}

WOLFSSL_CTX*
wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_new(method);
}

void
wolfSSL_CTX_free(WOLFSSL_CTX *ctx)
{
    MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_free(ctx);
}

void
wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX *ctx, wc_psk_server_callback callback)
{
    MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_set_psk_server_callback(ctx, callback);
}

int
wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char** protocol_name, unsigned short* size)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_ALPN_GetProtocol(ssl, protocol_name, size);
}

int
wolfSSL_shutdown(WOLFSSL* ssl)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_shutdown(ssl);
}

int
wolfSSL_get_shutdown(const WOLFSSL* ssl)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_shutdown(ssl);
}

void
wolfSSL_dtls_set_using_nonblock(WOLFSSL *ssl, int val)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_dtls_set_using_nonblock(ssl, val);
}

int
wolfSSL_recv(WOLFSSL* ssl, void* buf, int sz, int flags)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_recv(ssl, buf, sz, flags);
}

int
wolfSSL_send(WOLFSSL* ssl, const void* buf, int sz, int flags)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_send(ssl, buf, sz, flags);
}

int
wolfSSL_X509_get_pubkey_buffer(WOLFSSL_X509* x509, unsigned char* buf, int* len)
{
    return  MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_get_pubkey_buffer(x509, buf, len);
}

WOLFSSL_X509*
wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN *chain, int idx)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_chain_X509(chain, idx);
}

void
wolfSSL_X509_free(WOLFSSL_X509* x509)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_free(x509);
}

WOLFSSL_X509_CHAIN*
wolfSSL_get_peer_chain(WOLFSSL* ssl)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_peer_chain(ssl);
}

int
wolfSSL_connect(WOLFSSL* ssl)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_connect(ssl);
}

int
wolfSSL_UseOCSPStapling(WOLFSSL* ssl, unsigned char status_type, unsigned char options)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_UseOCSPStapling(ssl, status_type, options);
}

int
wolfSSL_EnableOCSPStapling(WOLFSSL* ssl)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_EnableOCSPStapling(ssl);
}

void
wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX *ctx, wc_psk_client_callback callback)
{
    MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_set_psk_client_callback(ctx, callback);
}

int
wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX *ctx, int val)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_SetMinVersion(ctx, val);
}

int
wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl, const unsigned char* buf, long size, int code)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_use_PrivateKey_buffer(ssl, buf, size, code);
}

int
wolfSSL_use_certificate_buffer(WOLFSSL* ssl, const unsigned char* buf, long size, int code)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_use_certificate_buffer(ssl, buf, size, code);
}

int
wolfSSL_set_cipher_list(WOLFSSL *ssl, const char *buf)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_set_cipher_list(ssl, buf);
}

void
wolfSSL_CTX_SetIORecv(WOLFSSL_CTX *ctx, CallbackIORecv  callbackIORecv)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_SetIORecv(ctx, callbackIORecv);
}

void
wolfSSL_CTX_SetIOSend(WOLFSSL_CTX *ctx, CallbackIOSend callbackIoSend)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_SetIOSend(ctx, callbackIoSend);
}

WOLFSSL*
wolfSSL_new(WOLFSSL_CTX *ctx)
{
   return MockWolfSSLUT::mMockWolfSSL->wolfSSL_new(ctx);
}

void
wolfSSL_free(WOLFSSL *ssl)
{
    MockWolfSSLUT::mMockWolfSSL->wolfSSL_free(ssl);
}

int
wolfSSL_use_psk_identity_hint(WOLFSSL *ssl, const char *ch)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_use_psk_identity_hint(ssl, ch);
}

void
wolfSSL_SetIOReadCtx(WOLFSSL *ssl, void *ctx)
{
    MockWolfSSLUT::mMockWolfSSL->wolfSSL_SetIOReadCtx(ssl, ctx);
}

void
wolfSSL_SetIOWriteCtx(WOLFSSL *ssl, void *ctx)
{
    MockWolfSSLUT::mMockWolfSSL->wolfSSL_SetIOWriteCtx(ssl, ctx);
}

int
wolfSSL_set_ex_data(WOLFSSL *ssl, int val, void *data)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_set_ex_data(ssl, val, data);
}

int
wolfSSL_accept(WOLFSSL *ssl)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_accept(ssl);
}

char*
wolfSSL_ERR_error_string(unsigned long val, char *buf)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_ERR_error_string(val, buf);
}

int wc_Sha256Hash(const byte* data, word32 size, byte* hash)
{
    return MockWolfSSLUT::mMockWolfSSL->wc_Sha256Hash(data, size, hash);
}

int
Base64_Encode_NoNl(const byte* in, word32 inLen, byte* out, word32* outLen)
{
    return MockWolfSSLUT::mMockWolfSSL->Base64_Encode_NoNl(in, inLen, out, outLen);
}

WOLFSSL_METHOD*
wolfSSLv23_client_method(void)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSLv23_client_method();
}

int
wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX *ctx, const unsigned char* buf, long size, int val)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_load_verify_buffer(ctx, buf, size, val);
}

int
wolfSSL_UseSupportedCurve(WOLFSSL *ssl, word16 name)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_UseSupportedCurve(ssl, name);
}

int
wolfSSL_UseALPN(WOLFSSL* ssl, char* protocol_name_list, unsigned int protocol_name_listSz, unsigned char options)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_UseALPN(ssl, protocol_name_list, protocol_name_listSz, options);
}

int
wolfSSL_UseSNI(WOLFSSL *ssl, unsigned char ch, const void *buf, unsigned short size)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_UseSNI(ssl, ch, buf, size);
}

int
wolfSSL_EnableOCSP(WOLFSSL* ssl, int options)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_EnableOCSP(ssl, options);
}

int
wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_SetOCSP_Cb(ssl, ioCb, respFreeCb, ioCbCtx);
}

void
wolfSSL_set_verify(WOLFSSL* ctx, int mode, VerifyCallback cb)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_set_verify(ctx, mode, cb);
}

void*
wolfSSL_X509_STORE_CTX_get_ex_data(WOLFSSL_X509_STORE_CTX* ctx, int idx)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_STORE_CTX_get_ex_data(ctx, idx);
}

int
wolfSSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_ex_data_X509_STORE_CTX_idx();
}

extern "C"
{
	OcspResponse*
	wolfSSL_d2i_OCSP_RESPONSE(OcspResponse** response, const unsigned char** data, int len)
	{
	    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_d2i_OCSP_RESPONSE(response, data, len);
	}

	void
	wolfSSL_OCSP_RESPONSE_free(OcspResponse* response)
	{
	    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_OCSP_RESPONSE_free(response);
	}
}

int
wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_CTX_EnableOCSPMustStaple(ctx);
}

int wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_chain_count(chain);
}

int wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509* x509, int oid)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_ext_isSet_by_NID(x509, oid);
}

int
wolfSSL_X509_check_issued(WOLFSSL_X509 *issuer, WOLFSSL_X509 *subject)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_check_issued(issuer, subject);
}

int
wolfSSL_X509_get_isCA(WOLFSSL_X509* X509)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_get_isCA(X509);
}

int
wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN* chain, int idx, unsigned char* buf, int inLen, int* outLen)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_chain_cert_pem(chain, idx, buf, inLen, outLen);
}

char*
wolfSSL_X509_get_name_oneline(WOLFSSL_X509_NAME* name, char* in, int sz)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_get_name_oneline(name, in, sz);
}

WOLFSSL_X509_NAME*
wolfSSL_X509_get_issuer_name(WOLFSSL_X509* cert)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_get_issuer_name(cert);
}

WOLFSSL_X509_NAME*
wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_X509_get_subject_name(cert);
}

int
wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_check_domain_name(ssl, dn);
}

int
wolfSSL_Init(void)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_Init();
}

int
wolfSSL_Cleanup(void)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_Cleanup();
}

int wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx)
{
    return MockWolfSSLUT::mMockWolfSSL->wolfSSL_get_chain_length(chain, idx);
}