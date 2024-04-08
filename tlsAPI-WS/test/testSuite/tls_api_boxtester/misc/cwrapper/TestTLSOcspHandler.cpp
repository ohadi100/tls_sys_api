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

#include "TestTLSOcspHandler.hpp"

#include "Logger.hpp"

#include <inttypes.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <sstream>

void
TestsTLSOcspHandler::cacheResponses(const std::vector<TLSOcspCachedResponse>& responses) noexcept
{
    std::async(std::launch::async, [&]() -> void {
        for (const TLSOcspCachedResponse& response : responses) {
            std::stringstream xRequestUniqueId;
            xRequestUniqueId << std::hex << response.getRequestUniqueId();
            if (response.getResponse().empty()) {
                FND_LOG_DEBUG << "received empty response caching request with key " << xRequestUniqueId.str() << " << deleting from cache";
                mCachedResponses.erase(response.getRequestUniqueId());
            }
            else {
                FND_LOG_DEBUG << "Caching response with key " << xRequestUniqueId.str();
                mCachedResponses.insert(std::make_pair(response.getRequestUniqueId(), response));
            }
        }
    });
}

std::future<std::vector<TLSOcspRequestResponse>>
TestsTLSOcspHandler::processRequests(const std::vector<TLSOcspRequest>& requests) noexcept
{
    return std::async(std::launch::async, [&]() -> std::vector<TLSOcspRequestResponse> {
        std::vector<TLSOcspRequestResponse> responses;

        try {
            for (const TLSOcspRequest& request : requests) {
                std::stringstream xUniqueId;
                xUniqueId << std::hex << request.getUniqueId();
                FND_LOG_DEBUG << "Processing request with key " << xUniqueId.str();
                auto responseFromCacheRes = mCachedResponses.find(request.getUniqueId());
                if (mCachedResponses.end() != responseFromCacheRes) {
                    auto cachedResponse = (*responseFromCacheRes).second;
                    FND_LOG_DEBUG << "Found response in cache with key " << xUniqueId.str();
                    mIsNextResponseInvalid ? responses.emplace_back(TLSOcspRequestResponse({0x1}, true, cachedResponse.getRequestUniqueId())) :
                                             responses.emplace_back(TLSOcspRequestResponse(cachedResponse.getResponse(), true, cachedResponse.getRequestUniqueId()));
                    mIsNextResponseInvalid = false;                                             
                    mNumberOfCacheReads++;
                    continue; // If the OCSP resopnse of the request was found in the cache, do not send the request to the OCSP service.
                }
                if (mIsNextResponseInvalid) {
                    responses.emplace_back(TLSOcspRequestResponse({0x1}, false, request.getUniqueId()));
                    mIsNextResponseInvalid = false;
                    continue;
                }
                uint16_t    ocspResponderPort       = 0;
                std::string ocspResponderDomainName = "";

                if (!decodeUrl(request.getRequestUrl(), ocspResponderDomainName, ocspResponderPort)) {
                    FND_LOG_ERROR << "Failed to decode OCSP responder's URL";
                    responses.push_back(TLSOcspRequestResponse(request.getUniqueId()));
                    continue;
                }

                int sockFd = 0;
                if (!createTcpConnection(sockFd, ocspResponderDomainName, ocspResponderPort)) {
                    FND_LOG_ERROR << "Failed to create TCP connection to OCSP responder";
                    responses.push_back(TLSOcspRequestResponse(request.getUniqueId()));
                    continue;
                }

                std::string httpOcspRequestMessage = buildHttpOcspRequest(ocspResponderDomainName, request);
                if (!sendMessage(sockFd, httpOcspRequestMessage)) {
                    FND_LOG_ERROR << "Failed to send HTTP POST message to OCSP responder";
                    responses.push_back(TLSOcspRequestResponse(request.getUniqueId()));
                    continue;
                }

                if (!processHttpOcspResponse(sockFd, request, responses)) {
                    FND_LOG_ERROR << "Failed to process received OCSP response";
                    responses.push_back(TLSOcspRequestResponse(request.getUniqueId()));
                    continue;
                }
            }

            return responses;
        } catch (...) {
            FND_LOG_ERROR << "Unexpected exception has been raised.";
            return std::vector<TLSOcspRequestResponse>();
        }
    });
}

bool
TestsTLSOcspHandler::decodeUrl(const std::string& url, std::string& outDomainName, uint16_t& outPort)
{
    const uint32_t    MAX_URL_LEN        = 80;
    const uint32_t    MAX_DIGITS_IN_PORT = 5;
    const std::string HTTP_PREFIX_STRING = "http://";

    if (url.size() > MAX_URL_LEN || url.empty()) {
        return false;
    }

    /*
     * Breaking down the url into scheme, address and port
     * "http://example.com:8080/"
     * "http://127.0.0.1:443/"
     *
     * Making sure the url is http
     */
    if (0 != url.compare(0, HTTP_PREFIX_STRING.size(), HTTP_PREFIX_STRING)) {
        return false;
    }

    /*
     * Getting the address from the url
     */
    size_t start = HTTP_PREFIX_STRING.size();
    size_t end   = url.find(":", start);
    if (std::string::npos == end) {
        return false;
    }
    outDomainName = url.substr(start, end - HTTP_PREFIX_STRING.size());
    if (outDomainName.empty()) {
        return false;
    }

    /*
     * Getting the port from the url
     */
    start                  = end + 1;
    end                    = MAX_DIGITS_IN_PORT;
    std::string portString = url.substr(start, end);
    if (portString.empty()) {
        return false;
    }
    outPort = static_cast<uint16_t>(std::stoi(portString));

    return true;
}

bool
TestsTLSOcspHandler::createTcpConnection(int&               outSockFd,
                                         const std::string& ocspResponderDomainName,
                                         const uint16_t     ocspResponderPort)
{
    const int SOCKET_INVALID = -1;

    hostent*     entry = nullptr;
    sockaddr_in* sin   = nullptr;

    sockaddr_storage addr;
    bzero(&addr, sizeof(addr));

    entry = gethostbyname(ocspResponderDomainName.c_str());
    if (nullptr == entry) {
        return false;
    }

    sin             = reinterpret_cast<sockaddr_in*>(&addr);
    sin->sin_family = AF_INET;
    sin->sin_port   = htons(ocspResponderPort);
    std::memcpy(&sin->sin_addr.s_addr, entry->h_addr_list[0], entry->h_length);

    outSockFd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (0 > outSockFd) {
        return false;
    }

    int connectRet = connect(outSockFd, (sockaddr*)&addr, sizeof(sockaddr_in));
    if (0 != connectRet) {
        close(outSockFd);
        outSockFd = SOCKET_INVALID;
        return false;
    }

    return true;
}

std::string
TestsTLSOcspHandler::buildHttpOcspRequest(const std::string& ocspResponderDomainName, const TLSOcspRequest& request)
{
    std::string httpMessage = "POST";
    httpMessage += " ";
    httpMessage += "/";
    httpMessage += " HTTP/1.1";
    httpMessage += "\r\nHost: ";
    httpMessage += ocspResponderDomainName;
    httpMessage += "\r\nContent-Length: ";
    httpMessage += std::to_string(request.getRequest().size());
    httpMessage += "\r\nContent-Type: ";
    httpMessage += "application/ocsp-request";
    httpMessage += "\r\n";
    httpMessage += "Cache-Control: no-cache";
    httpMessage += "\r\n\r\n";

    std::string requestMessage(request.getRequest().begin(), request.getRequest().end());
    httpMessage += requestMessage;

    return httpMessage;
}

bool
TestsTLSOcspHandler::sendMessage(const int sockFd, const std::string& message)
{
    if (nullptr == message.data()) {
        return false;
    }

    return (send(sockFd, (void*)message.data(), message.size(), 0) == static_cast<ssize_t>(message.size()));
}

bool
TestsTLSOcspHandler::processHttpOcspResponse(const int                            sockFd,
                                             const TLSOcspRequest&                request,
                                             std::vector<TLSOcspRequestResponse>& outResponses)
{
    const size_t HTTP_OCSP_RESPONSE_HEADER_SIZE  = 82;
    const size_t MAX_HTTP_OCSP_RESPONSE_MSG_SIZE = HTTP_OCSP_RESPONSE_HEADER_SIZE + (4 * 1024);

    std::vector<uint8_t> httpOcspResponseMsgVector(MAX_HTTP_OCSP_RESPONSE_MSG_SIZE);
    if (nullptr == httpOcspResponseMsgVector.data()) {
        return false;
    }

    int ret = recv(sockFd, httpOcspResponseMsgVector.data(), httpOcspResponseMsgVector.size(), 0);
    if (ret <= 0) {
        return false;
    }
    if (HTTP_OCSP_RESPONSE_HEADER_SIZE > static_cast<size_t>(ret)) {
        return false;
    }

    std::string httpOcspResponseHeader((const char*)httpOcspResponseMsgVector.data(), HTTP_OCSP_RESPONSE_HEADER_SIZE);
    std::istringstream iss(httpOcspResponseHeader);
    std::string        token;

    iss >> token;
    if ("HTTP/1.0" != token && "HTTP/1.1" != token) {
        return false;
    }

    iss >> token;
    if ("200" != token) {
        return false;
    }

    iss >> token;
    if ("OK" != token) {
        return false;
    }

    iss >> token;
    if ("Content-type:" != token) {
        return false;
    }

    iss >> token;
    if ("application/ocsp-response" != token) {
        return false;
    }

    iss >> token;
    if ("Content-Length:" != token) {
        return false;
    }

    iss >> token;
    uint32_t ocspResponseMessageSize = static_cast<uint32_t>(std::stoi(token));

    iss.setstate(std::ios_base::eofbit);
    if (!iss.eof()) {
        return false;
    }

    if (ret - HTTP_OCSP_RESPONSE_HEADER_SIZE != ocspResponseMessageSize) {
        return false;
    }

    auto derOcspResponseMessageStart = httpOcspResponseMsgVector.begin() + HTTP_OCSP_RESPONSE_HEADER_SIZE;
    auto derOcspResponseMessageEnd   = derOcspResponseMessageStart + ocspResponseMessageSize;

    std::vector<uint8_t> berEncodedResponse(derOcspResponseMessageStart, derOcspResponseMessageEnd);

    // For Vendor - Check if the response is existing in cache by the request unique id.
    // If so, mark the response as isCached = true, otherwise false.

    // Because we're implementing a mock we will mark the response by default as not existing in cache.
    TLSOcspRequestResponse ocspResponse(berEncodedResponse, false, request.getUniqueId());

    outResponses.push_back(ocspResponse);

    return true;
}

void 
TestsTLSOcspHandler::ClearOCSPCache() noexcept
{
    mCachedResponses.clear();
    mNumberOfCacheReads = 0;
}

int 
TestsTLSOcspHandler::GetCacheSize() noexcept
{
    return mCachedResponses.size();
}

int 
TestsTLSOcspHandler::GetNumberOfReadsFromCache() noexcept
{
    return mNumberOfCacheReads;
}

void 
TestsTLSOcspHandler::AnswerNextWithInvalidResponse() noexcept
{
    mIsNextResponseInvalid = true;
}