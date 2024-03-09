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
#ifndef TEST_TLS_OCSP_HANDLER_HPP
#define TEST_TLS_OCSP_HANDLER_HPP

#include "TLSApiTypes.h"
#include <unordered_map>

using namespace vwg::tls;

/**
 * \brief This class implements the ITLSOcspHandler interface for test suites env only
 */
class TestsTLSOcspHandler : public ITLSOcspHandler
{
public:
    TestsTLSOcspHandler()          = default;
    virtual ~TestsTLSOcspHandler() = default;

public:
    /**
     * \brief Cache the OCSP responses
     *
     * \param responses Vector of OCSP responses to cache
     */
    virtual void cacheResponses(const std::vector<TLSOcspCachedResponse>& responses) noexcept override;

    /**
     * \brief Process the OCSP requests and send them to OCSP Proxy process for further processing
     *
     * \details In this mock implementation we directly send the OCSP request to the OCSP responder over TCP socket as
     * HTTP message.
     *
     * \param requests Vector of OCSP requests
     *
     * \return A future that contains a vector of OCSP responses from the OCSP responder or OCSP Proxy cache
     */
    virtual std::future<std::vector<TLSOcspRequestResponse>> processRequests(
        const std::vector<TLSOcspRequest>& requests) noexcept override;

    // clear local responses cache for testing
    void ClearOCSPCache() noexcept;

    int GetCacheSize() noexcept;

    int GetNumberOfReadsFromCache() noexcept;

    void AnswerNextWithInvalidResponse() noexcept;

private:
    /**
     * \brief Decodes an OCSP responder URL address
     *
     * \param url An URL string
     * \param[out] outDomainName An out parameter that contains OCSP responder IP or domain name
     * \param[out] outPort An out parameter that contains the port number
     *
     * \return True if successfully decoded the URL otherwise False.
     */
    bool decodeUrl(const std::string& url, std::string& outDomainName, uint16_t& outPort);

    /**
     * \brief Wraps the OCSP request message with HTTP header
     *
     * \param ocspResponderDomainName A string that contains the OCSP responder IP address / domain name
     * \param request OCSP request message object
     *
     * \return A string that contains a valid HTTP message with OCSP request as a payload
     */
    std::string buildHttpOcspRequest(const std::string& ocspResponderDomainName, const TLSOcspRequest& request);

    /**
     * \brief Creates a TCP socket connection with the OCSP responder server
     *
     * \param[out] sockFd An out parameter that will contain the socket fd if successfully created the socket.
     * \param ocspResponderDomainName A string that contains the OCSP responder IP address / domain name
     * \param ocspResponderPort An out parameter that contains the port number
     *
     * \return True if successfully created the tcp socket otherwise False
     */
    bool createTcpConnection(int& sockFd, const std::string& ocspResponderDomainName, const uint16_t ocspResponderPort);

    /**
     * \brief Sends HTTP message over the TCP socket
     *
     * \param sockFd Socket file descriptor
     * \param message The HTTP message
     *
     * \return True if successfully sent the message otherwise False
     */
    bool sendMessage(const int sockFd, const std::string& message);

    /**
     * \brief Waits for OCSP response message from socket, parse it and add it to responses vector.
     *
     * \param sockFd Socket file descriptor
     * \param request OCSP request message that related to the received OCSP response
     * \param[out] outResponses Vector of OCSP responses
     *
     * \return True if successfully processed the OCSP response and added to responses vector otherwise False
     */
    bool processHttpOcspResponse(const int                            sockFd,
                                 const TLSOcspRequest&                request,
                                 std::vector<TLSOcspRequestResponse>& outResponses);

    std::unordered_map<UInt64, TLSOcspCachedResponse> mCachedResponses;
    int mNumberOfCacheReads = 0;
    bool mIsNextResponseInvalid = false;
};

#endif  // TEST_TLS_OCSP_HANDLER_HPP
