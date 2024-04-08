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
#ifndef WOLFSSL_CONTEXT_HPP
#define WOLFSSL_CONTEXT_HPP

#include <wolfssl/options.h>
#include <wolfssl/ocsp.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <memory>
#include <sstream>
#include "Logger.hpp"

#include "ITLSEngine.hpp"

#include "TLSTEEAPI.h"
#include "WolfSSLCertEngine.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{
static inline uint32_t
ServerPSKCallback(WOLFSSL* ssl, const char* identity, unsigned char* key, uint32_t keyMaxLength)
{
    if (nullptr == ssl || nullptr == identity || nullptr == key || 0 == keyMaxLength) {
        return 0;
    }

    pskData* pData = reinterpret_cast<pskData*>(wolfSSL_get_ex_data(ssl, 0));
    if (nullptr == pData) {
        return 0;
    }
    pData->remoteHint = identity;

    FND_LOG_DEBUG << "*** SERVER ***";

    vwg::tee::SessionKey keyData;
    if (!vwg::tee::TLSTEEAPI::get_instance()->get_psk(pData->remoteHint, pData->hint, &keyData)) {
        FND_LOG_ERROR << "PSK session key not found";
        return 0;
    }

    if (keyMaxLength < keyData.length) {
        FND_LOG_DEBUG << "key length mismatch";
        return 0;
    }

    memset(key, 0, keyMaxLength);
    memcpy(key, keyData.value, keyData.length);

    return keyData.length;
}

static inline uint32_t
ClientPSKCallback(
    WOLFSSL* ssl, const char* hint, char* identity, uint32_t idMaxLength, unsigned char* key, uint32_t keyMaxLength)
{
    if (nullptr == ssl || nullptr == hint || nullptr == identity || 0 == idMaxLength || nullptr == key ||
        0 == keyMaxLength) {
        return 0;
    }

    pskData* pData = reinterpret_cast<pskData*>(wolfSSL_get_ex_data(ssl, 0));
    if (nullptr == pData) {
        return 0;
    }

    strncpy(identity, pData->hint.c_str(), idMaxLength);
    pData->remoteHint = std::string(hint);

    FND_LOG_DEBUG << "*** CLIENT ***";

    vwg::tee::SessionKey keyData;
    if (!vwg::tee::TLSTEEAPI::get_instance()->get_psk(pData->remoteHint, pData->hint, &keyData)) {
        FND_LOG_ERROR << "PSK session key not found";
        return 0;
    }

    if (keyMaxLength < keyData.length) {
        FND_LOG_DEBUG << "key length mismatch";
        return 0;
    }

    memset(key, 0, keyMaxLength);
    memcpy(key, keyData.value, keyData.length);

    return keyData.length;
}

static inline int
recvIO(WOLFSSL* ssl, char* buff, int length, void* ctx)
{
    if (nullptr == ssl || nullptr == buff || 0 >= length || nullptr == ctx) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    IOStream* stream = (IOStream*)ctx;
    int       ret    = stream->receive(buff, length);

    if (ret < 0) {
        switch (ret) {
        case RC_STREAM_WOULD_BLOCK:
            ret = WOLFSSL_CBIO_ERR_WANT_READ;
            break;
        case RC_STREAM_IO_ERROR:
            ret = WOLFSSL_CBIO_ERR_GENERAL;
            break;
        default:
            ret = WOLFSSL_CBIO_ERR_GENERAL;
            break;
        }
    } else if (ret == 0) {
        ret = WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    return ret;
}

static inline int
sendIO(WOLFSSL* ssl, char* buff, int length, void* ctx)
{
    if (nullptr == ssl || nullptr == buff || 0 >= length || nullptr == ctx) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    IOStream* stream = (IOStream*)ctx;
    int       ret    = stream->send(buff, length);

    if (ret < 0) {
        if (RC_STREAM_WOULD_BLOCK == ret) {
            ret = WOLFSSL_CBIO_ERR_WANT_WRITE;
        } else if (RC_STREAM_IO_ERROR == ret) {
            ret = WOLFSSL_CBIO_ERR_GENERAL;
        } else {
            ret = WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    return ret;
}

static inline int
ocspOnlineCallback(void* ctx, const char* url, int urlSz, unsigned char* req, int reqSz, unsigned char** res)
{
    // The OCSP online callback will be called by WolfSSL during the TLS handshake for each certificate in the server's chain when:
    // 1. revocation check is enabled in the engine, and
    // 2. the current certificate has the Authority Information Access (authInfo) extension with the OCSP URL, and
    // 3. the OCSP status of the current certificate was not stapled by the server.
    //
    // This callback will try to communicate with the OCSP service located in the URL provided in the certificate's authInfo extension.
    // We will first check if the OCSP resopsne is locally cached and if so then we will use the cached resopnse instead of sending the request to the OCSP service.
    // 
    // If the connection with the OCSP service was succeeded then the method fills 'res' with the response.
    // WolfSSL will then check if the certificate is revoked or not.
    //
    // this function is called (if needed) before the verifyCallback function.

    FND_LOG_DEBUG << "Entered ocspOnlineCallback.";
    const int WOLFSSL_OCSPONLINECB_ERROR = -1;

    if (nullptr == ctx || nullptr == url || nullptr == req || nullptr == res || 0 >= reqSz || 0 >= urlSz ||
        strlen(url) != (size_t)urlSz) {
        FND_LOG_ERROR << "Invalid parameter";
        FND_LOG_DEBUG << "ctx = 0x%p << url = 0x%p << urlSz = %d << req = 0x%p << reqSz = %d << res = 0x%p";
        return WOLFSSL_OCSPONLINECB_ERROR;
    }

    WolfSSLCertEngine* engine = static_cast<WolfSSLCertEngine*>(ctx);

    std::shared_ptr<ITLSOcspHandler> ocspHandler = engine->GetOcspHandler();
    if (nullptr == ocspHandler) {
        FND_LOG_ERROR << "OCSP Handler is NULL";
        return WOLFSSL_OCSPONLINECB_ERROR;
    }

    std::vector<UInt8>          ocspRawRequest(req, req + reqSz);
    TLSOcspRequest              tlsOcspRequest(url, ocspRawRequest);
    std::vector<TLSOcspRequest> tlsOcspRequestsVector{tlsOcspRequest};

    std::future<std::vector<TLSOcspRequestResponse>> futureOcspProcessResult =
        ocspHandler->processRequests(tlsOcspRequestsVector);

    std::chrono::milliseconds tout(engine->GetOcspTimeout());
    std::future_status        futureStatus = futureOcspProcessResult.wait_for(tout);
    if (std::future_status::ready != futureStatus) {
        FND_LOG_ERROR << "Timeout reached or the task has not been started yet";
        FND_LOG_DEBUG << "future status " << (int)futureStatus;
        return WOLFSSL_OCSPONLINECB_ERROR;
    }

    std::vector<TLSOcspRequestResponse> tlsOcspRequestResponseVector = futureOcspProcessResult.get();
    if (tlsOcspRequestsVector.size() != tlsOcspRequestResponseVector.size()) {
        FND_LOG_ERROR << "Invalid OCSP responses vector size";
        FND_LOG_DEBUG << "vector size " << tlsOcspRequestResponseVector.size();
        return WOLFSSL_OCSPONLINECB_ERROR;
    }

    TLSOcspRequestResponse tlsOcspRequestResponse = tlsOcspRequestResponseVector.front();
    if (tlsOcspRequestResponse.isCorrupted()) {
        std::stringstream xUniqueId, xRequestUniqueId;
        xUniqueId << std::hex << tlsOcspRequest.getUniqueId();
        xRequestUniqueId << std::hex << tlsOcspRequestResponse.getRequestUniqueId();
        FND_LOG_ERROR << "Received OCSP Response is corrupted";
        FND_LOG_DEBUG << "request ID " << xUniqueId.str() << " << response ID " << xRequestUniqueId.str();
        return WOLFSSL_OCSPONLINECB_ERROR;
    }

    if (tlsOcspRequestResponse.getRequestUniqueId() != tlsOcspRequest.getUniqueId()) {
        std::stringstream xUniqueId, xRequestUniqueId;
        xUniqueId << std::hex << tlsOcspRequest.getUniqueId();
        xRequestUniqueId << std::hex << tlsOcspRequestResponse.getRequestUniqueId();
        FND_LOG_ERROR << "Received OCSP response not match to OCSP request";
        FND_LOG_DEBUG << "request ID " << xUniqueId.str() << " << response ID " << xRequestUniqueId.str();
        return WOLFSSL_OCSPONLINECB_ERROR;
    }

    const uint8_t* rawOcspResponse = tlsOcspRequestResponse.getResponse().data();
    const size_t   sizeOfResponse  = tlsOcspRequestResponse.getResponse().size();
    if (nullptr == rawOcspResponse || 0 == sizeOfResponse) {
        FND_LOG_ERROR << "Invalid OCSP response message";
        FND_LOG_DEBUG << "response pointer = " << rawOcspResponse << " << size = " << sizeOfResponse;
        return WOLFSSL_OCSPONLINECB_ERROR;
    }

    // Allocating a buffer for wolfssl verification and validation later on
    *res = new (nothrow) unsigned char[sizeOfResponse];
    if (nullptr == *res) {
        FND_LOG_ERROR << "Failed to allocate buffer for OCSP response message";
        return WOLFSSL_OCSPONLINECB_ERROR;
    }

    std::memcpy(*res, rawOcspResponse, sizeOfResponse);

    engine->setOcspRequestResponseVector(tlsOcspRequestResponseVector);

    return sizeOfResponse;
}

static inline void
ocspResponseFreeCallback(void* ctx, byte* resp)
{
    (void)ctx;

    delete[] resp;
}

}  // namespace impl
}  // namespace tls
}  // namespace vwg

#endif  // WOLFSSL_CONTEXT_HPP
