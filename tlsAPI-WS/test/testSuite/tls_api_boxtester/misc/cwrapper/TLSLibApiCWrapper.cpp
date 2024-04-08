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
#include "TLSLibApiWrapper.hpp"
#include "TestTLSOcspHandler.hpp"
#include <iostream>
#include <vector>

static std::shared_ptr<TestsTLSOcspHandler> OCSP_HANDLER = std::make_shared<TestsTLSOcspHandler>();

extern "C" void* TLSLibApiCWrapper_CreateWrapperInstance()
{
    return (void*)(new TLSLibApiWrapper());
}

extern "C" void TLSLibApiCWrapper_DeleteWrapperInstance(void* instance)
{
    delete ((TLSLibApiWrapper*)instance);
}

extern "C" bool TLSLibApiCWrapper_InitTLSLib()
{
    return TLSLibApiWrapper::InitTLSLib();
}

std::vector<char> hexToBytes(const std::string& hex) {
    std::vector<char> bytesVec;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        bytesVec.push_back(byte);
    }

    return bytesVec;
}

bool
convertHashPinningStrToVec(std::string hashPinningStr, std::vector<std::vector<char>>& hashPinningsVec)
{
    // every hash pinning size in bytes is 44, because hash pinning is
    // calculation of Base64(SHA256(SubjectPublicKeyInfo)).
    // SHA256 output size is 32 bytes, so Base64 of 32 bytes is 44 bytes,
    // because Base64 output size is 4*ceiling(n/3) when n is Base64 input size.
    const uint16_t  HASH_BASE_64_SIZE = 44;
    const uint16_t  HASH_BASE_64_SIZE_NIBBLES = HASH_BASE_64_SIZE * 2;// hashPinningsStr param is in hex so every char is a nibble

    ASSERT_TRUE((0 == (hashPinningStr.size()%HASH_BASE_64_SIZE_NIBBLES)))

    const uint16_t numOfHashPinning = hashPinningStr.size()/HASH_BASE_64_SIZE_NIBBLES;

    for(int i = 0; i<numOfHashPinning; i++)
    {
        std::vector<char> hash = hexToBytes(hashPinningStr.substr(i*HASH_BASE_64_SIZE_NIBBLES,HASH_BASE_64_SIZE_NIBBLES));

        hashPinningsVec.push_back(hash);
    }

    return true;
}

extern "C" bool TLSLibApiCWrapper_CreateTlsClient(void* instance,
                                                  int cipherSuitesUseCase,
                                                  const char* ip,
                                                  uint16_t port,
                                                  const char* hostName,
                                                  const char* certStoreId,
                                                  const char* clientCertificateSetID,
                                                  const char* hashPinnings)
{
    ASSERT_NOT_NULLPTR(instance);
    ASSERT_NOT_NULLPTR(ip);
    ASSERT_NOT_NULLPTR(hostName);
    ASSERT_NOT_NULLPTR(certStoreId);
    ASSERT_NOT_NULLPTR(clientCertificateSetID);
    ASSERT_NOT_NULLPTR(hashPinnings);

    std::string hashPinningsStr(hashPinnings);
    std::vector<std::vector<char>> hashPinningsVec;

    ASSERT_TRUE(convertHashPinningStrToVec(hashPinningsStr, hashPinningsVec));

    return ((TLSLibApiWrapper*)instance)->CreateTLSClient(cipherSuitesUseCase,
                                                          OCSP_HANDLER,
                                                          std::string(ip),
                                                          port,
                                                          std::string(hostName),
                                                          std::string(certStoreId),
                                                          std::string(clientCertificateSetID),
                                                          hashPinningsVec);
}

extern "C" bool TLSLibApiCWrapper_CreateAlpnTlsClient(void* instance,
                                                      const char* alpn_protocol,
                                                      int cipherSuitesUseCase,
                                                      const char* ip,
                                                      uint16_t port,
                                                      const char* hostName,
                                                      const char* certStoreId,
                                                      const char* clientCertificateSetID,
                                                      const char* hashPinnings)
{
    ASSERT_NOT_NULLPTR(instance);
    ASSERT_NOT_NULLPTR(alpn_protocol);
    ASSERT_NOT_NULLPTR(ip);
    ASSERT_NOT_NULLPTR(hostName);
    ASSERT_NOT_NULLPTR(certStoreId);
    ASSERT_NOT_NULLPTR(clientCertificateSetID);

    std::string hashPinningsStr(hashPinnings);
    std::vector<std::vector<char>> hashPinningsVec;

    ASSERT_TRUE(convertHashPinningStrToVec(hashPinningsStr, hashPinningsVec));

    return ((TLSLibApiWrapper*)instance)->CreateTLSClient(std::string(alpn_protocol),
                                                          cipherSuitesUseCase,
                                                          OCSP_HANDLER,
                                                          std::string(ip),
                                                          port,
                                                          std::string(hostName),
                                                          std::string(certStoreId),
                                                          std::string(clientCertificateSetID),
                                                          hashPinningsVec);
}

extern "C" bool TLSLibApiCWrapper_Connect(void* instance)
{
    ASSERT_NOT_NULLPTR(instance);

    return ((TLSLibApiWrapper*)instance)->Connect();
}

extern "C" bool TLSLibApiCWrapper_Send(void* instance, void* data, uint32_t size)
{
    ASSERT_NOT_NULLPTR(instance);
    ASSERT_NOT_NULLPTR(data);

    return ((TLSLibApiWrapper*)instance)->Send((uint8_t*)data, size);
}

extern "C" int TLSLibApiCWrapper_GetUsedProtocol(void* instance)
{
    ASSERT_NOT_NULLPTR(instance);

    return ((TLSLibApiWrapper*)instance)->GetUsedProtocol();
}

extern "C" bool TLSLibApiCWrapper_Shutdown(void* instance)
{
    ASSERT_NOT_NULLPTR(instance);

    return ((TLSLibApiWrapper*)instance)->Shutdown();
}

extern "C" bool TLSLibApiCWrapper_CleanupTLSLib()
{
    TLSLibApiWrapper::CleanupTLSLib();

    return true;
}

extern "C" void TLSLibApiCWrapper_ClearOCSPCache()
{
    OCSP_HANDLER->ClearOCSPCache();
}

extern "C" int TLSLibApiCWrapper_GetOCSPCacheSize()
{
    return OCSP_HANDLER->GetCacheSize();
}

extern "C" int TLSLibApiCWrapper_GetOCSPNumberOfReadsFromCache()
{
    return OCSP_HANDLER->GetNumberOfReadsFromCache();
}

extern "C" void TLSLibApiCWrapper_SetNextOCSPResponseInvalid()
{
    OCSP_HANDLER->AnswerNextWithInvalidResponse();
}