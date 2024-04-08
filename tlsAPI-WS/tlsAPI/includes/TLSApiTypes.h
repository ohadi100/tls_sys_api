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


#ifndef SRC_TLSAPITYPES_H_
#define SRC_TLSAPITYPES_H_

#include <ctime>
#include <functional>
#include <future>
#include <queue>

#include "InetAddress.h"
#include "vwgtypes.h"

using namespace vwg::types;

namespace vwg
{
namespace tls
{
using ApiVersionType = std::string;
const ApiVersionType ApiVersion("TLS_API_1.3");

/**
 *   \brief This enum defines the supported protocols which can be used in case ALPN is used.
 *   Please see the IANAProtocol definitions in RFC7230  https://tools.ietf.org/html/rfc7230.
 *
 *   \since 1.1.0
 */
enum IANAProtocol {
    NONE  = 0,
    HTTP  = 1,
    HTTP2 = 2
    // SPDY_1 = 16, not yet supported.
    // SPDY_2 = 17, not yet supported.
    // SPDY_3 = 18  not yet supported.
};

/**
 *   \brief This class contains some helper methods when conversion from the IANAProtocol enum value to Protocol name.
 *
 *   \since 1.1.0
 */
class IANAProtocolFunction final
{
public:
    IANAProtocolFunction()  = default;
    ~IANAProtocolFunction() = default;

    const std::string ProtocolNameHTTP  = "http/1.1";
    const std::string ProtocolNameHTTP2 = "h2";

    /**
     * \brief Converts IANAProtocol enum value to Protocol name.
     *
     * \param[in] protocol IANA protocol enum value to be converted.
     * \param[out] oProtocolName should be contained the protocol name if converted successfully.
     *
     * \return true if converted successfully, false otherwise.
     */
    bool
    toIANAProtocolName(const IANAProtocol& protocol, std::string& oProtocolName)
    {
        switch (protocol) {
        case IANAProtocol::HTTP:
            oProtocolName = ProtocolNameHTTP;
            return true;

        case IANAProtocol::HTTP2:
            oProtocolName = ProtocolNameHTTP2;
            return true;

        default:
            return false;
        }
    }
};

/**
 * \brief Defines the maximum permitted deviation of |expectedTime  - system_time.now()|.
 * since 1.1.0
 */
const static unsigned int MAX_PERMITTED_DEVIATION = 86400;

/**
 * \brief This is a structure that will be used to pass the authentic time.
 * basically this time will be compared with the system time, as shown below.
 *
 * |expectedTime  - system_time.now() | <= |permittedDeviation|
 *
 * If the difference of the |expectedTime  - system_time.now() | is in the range of the |permittedDeviation|
 * then the  handshake will regarded as legal.
 * The permittedDeviation shall be less than one day (86400sec),
 * if the permittedDeviation is above this it will be used MAX_PERMITTED_DEVIATION
 * if the expectedTime is 0, then time check is not required.
 */
struct TimeCheckTime {
    /**
     * \brief This is expected time to be compared with the system time.
     * please keep in mind that the expected time can be either the authentic time provided by the authentic time
     * service oder the UTC provided by the time service. The time service must be used because the system time is
     * currently not defined and only the ICAS1 will have a RTC.
     */
    std::time_t expectedTime;

    /**
     * \brief A permitted deviation shall be given in seconds.
     */
    int permittedDeviation;
};

/**
 * \brief  Defines that time check is not required.
 */
const static TimeCheckTime CHECK_TIME_OFF = {0, 0};

/**
 * \brief  Defines a default OCSP timeout in milliseconds.
 */
const static UInt32 DEFAULT_OCSP_ONLINE_TIMEOUT_MS = 30000;

/**
 * \brief A setting container for ALPN supporting.
 * There are basically three modes possible:
 *
 * a) ALPN can be provided as a user defined string list. In this case the protocol list is passed to the TLS library
 * without no additional check. This means that an invalid value can cause unexpected errors, if an invalid string is
 * used. The given string must be complaint to chapter "3.1.  The Application-Layer Protocol Negotiation Extension" of
 * RFC 7301.
 *
 * b) ALPN parameter can be provided by a vector of pre defined enum's and constant of the ALPN mode type.
 *
 * c) If an empty list vector is used, then ALPN is unused in the client hello.
 * Basically this shall be identical like the the usage of HTTP protocol, but it can be different if the server is
 * not supporting ALPN.
 *
 * \since 1.1.0
 */
class AlpnMode final
{
public:
    /**
     * \brief Constructor.
     *
     * \param[in] userDefinedAlpnSetting ALPN setting.
     */
    explicit AlpnMode(const std::vector<std::string>& userDefinedAlpnSetting)
      : m_userDefinedALPNisUsed(true)
      , m_userDefinedAlpnSetting(userDefinedAlpnSetting)
    {
    }

    /**
     * \brief Constructor.
     *
     * \param[in] supportedProtocols Supported IANA protocols.
     */
    explicit AlpnMode(const std::vector<IANAProtocol>& supportedProtocols)
      : m_userDefinedALPNisUsed(false)
      , m_supportedProtocols(supportedProtocols)
    {
    }

    virtual ~AlpnMode() = default;

public:
    /**
     * \brief Gets a boolean that tells if the ALPN setting is defined.
     *
     * \return true if ALPN setting is defined, otherwise false.
     */
    bool
    userDefinedALPNisUsed() const
    {
        return m_userDefinedALPNisUsed;
    }

    /**
     * \brief Gets Supported IANA protocols.
     *
     * \return Supported IANA protocols.
     */
    const std::vector<IANAProtocol>&
    getSupportedProtocols() const
    {
        return m_supportedProtocols;
    }

    /**
     * \brief Gets an ALPN setting.
     *
     * \return ALPN setting.
     */
    const std::vector<std::string>&
    getUserDefinedAlpnSetting() const
    {
        return m_userDefinedAlpnSetting;
    }

private:
    bool                      m_userDefinedALPNisUsed;
    std::vector<std::string>  m_userDefinedAlpnSetting;
    std::vector<IANAProtocol> m_supportedProtocols;
};

/**
 * \brief Defines that ALPN is off and the protocol is undecided,
 * this is identical to TLS without any ALPN support.
 */
const static AlpnMode ALPN_OFF = AlpnMode(std::vector<IANAProtocol>{NONE});

/**
 * \brief Defines the default ALPN.
 */
const static AlpnMode ALPN_DEFAULT = AlpnMode(std::vector<IANAProtocol>{HTTP});

/**
 * \brief Defines HTTP2 ALPN.
 */
const static AlpnMode ALPN_HTTP2 = AlpnMode(std::vector<IANAProtocol>{IANAProtocol::HTTP2});

/**
 * \brief Defines all supported ALPN.
 */
const static AlpnMode ALPN_ANY = AlpnMode(std::vector<IANAProtocol>{IANAProtocol::HTTP2, IANAProtocol::HTTP});

/**
 * this enum defines the possible setting cipher suits based on predefined use cases.
 * This will replace the cipher suite list.
 * Especially in case of using TLS1.2 and TLS1.3 in parallel, it may will be more complex.
 * In addition the ECC curves are currently not covered sufficient in the TLS1.0.x.
 * Instead of using the list of cipher suites, a set of use cases can will be defined.
 * Based on the use cases the cipher suites are selected.
 *
 * Please see https://devstack.vwgroup.com/jira/browse/IMAN-46128 for the cipher suits associted to the use cases.
 *
 * <p>
 * <b>CSUSDefault</b>  This defines the default cipher suite set, which is defined for in the according QHAL.
 *              This is the default for all MOD functions.
 *
 *                            - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 *                            - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_AES_128_GCM_SHA256 (TLS1.3 only)
 *                            - TLS_AES_256_GCM_SHA384 (TLS1.3 only)
 *                            - TLS_CHACHA20_POLY1305_SHA256 (TLS1.3 only)
 * 
 * </p>
 * <p>
 * <b>CSUSDefaultWithSoftFail</b>  This contains the same cyphier suite set as CSUSDefault.
 *                      The difference to CSUSDefault, is the beaviour of the revocation check.
 *                      For CSUSDefaultWithSoftFail the revocation check will use the "soft fail" schema.
 * 
 * since 1.2.0
 * </p>
 * <p>
 * <b>CSUSLegacy</b>   This defines the set which contains biggest set of cipher suites.
 *              This is intended for all use case where the access to the internet is needed.
 *              Use cases are online radio, which is using all possible server, which are not under the control of MOD.
 *
 *                            - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 *                            - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_AES_128_GCM_SHA256 (TLS1.3 only)
 *                            - TLS_AES_256_GCM_SHA384 (TLS1.3 only)
 *                            - TLS_CHACHA20_POLY1305_SHA256 (TLS1.3 only)
 *                            - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 *                            - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 *                            - TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
 *                            - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 *                            - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 *                            - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 *                            - TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
 *                            - TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 *                            - TLS_RSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_RSA_WITH_AES_128_CBC_SHA256
 *                            - TLS_RSA_WITH_AES_256_CBC_SHA256
 *                            - TLS_RSA_WITH_AES_128_CBC_SHA
 *                            - TLS_RSA_WITH_AES_256_CBC_SHA
 *                            - TLS_RSA_WITH_3DES_EDE_CBC_SHA
 *                            - TLS_AES_128_CCM_SHA256 (TLS1.3 only)
 *
 * </p>
 * <p>
 * <b>CSUSLongtermSecure</b>   This is most restrictive, this will only contain the cipher suites with high key length.
 *                      It is expected that these cipher suites are most secured for the next years.
 *
 *                            - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 *                            - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
 *                            - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
 *                            - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_AES_256_GCM_SHA384 (TLS1.3 only)
 *                            - TLS_CHACHA20_POLY1305_SHA256 (TLS1.3 only)
 *
 * </p>
 * <p>
 * <b>CSUSIanaRecommended</b>  This is the list of cipher suites which are recommended by IANA.
 *
 *                            - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 *                            - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *                            - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *                            - TLS_AES_128_GCM_SHA256 (TLS1.3 only)
 *                            - TLS_AES_256_GCM_SHA384 (TLS1.3 only)
 *                            - TLS_CHACHA20_POLY1305_SHA256 (TLS1.3 only)
 *                            - TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
 *                            - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
 *                            - TLS_AES_128_CCM_SHA256 (TLS1.3 only)
 * </p>
 *  
 *
 * \since 1.1.0
 */
enum TLSCipherSuiteUseCasesSettings : UInt32 {
    CSUSDefault             = 0,
    CSUSLegacy              = 1,
    CSUSLongtermSecure      = 2,
    CSUSIanaRecommended     = 3,
    CSUSDefaultWithSoftFail = 4,
    CSUSEndOfEnum
};

/**
 *  \brief Defines a string constant for the cipher suits set, with is parallel to the enum.
 *   a string is more flexible for the interface design, but not as an enum.
 *   therefore the enum is used inside the TLS library.
 *   see TLSCipherSuiteUseCasesSettings::CSUSDefault for more detail.
 *
 *   \since 1.1.0
 */
const static std::string CSUSDefaultStr = "default";

/**
 *  \brief Defines a string constant for the cipher suits set, with is parallel to the enum.
 *   a string is more flexible for the interface design, but not as an enum.
 *   therefore the enum is used inside the TLS library.
 *   see TLSCipherSuiteUseCasesSettings::CSUSDefault for more detail.
 *
 *   \since 1.2.0
 */
const static std::string CSUSDefaulWithSoftFailtStr = "default_with_soft_fail";

/**
 *  \brief Defines a string constant for the cipher suits set, with is parallel to the enum.
 *   a string is more flexible for the interface design, but not as an enum.
 *   therefore the enum is used inside the TLS library.
 *   see TLSCipherSuiteUseCasesSettings::CSUSLegacy for more detail.
 *
 *   \since 1.1.0
 */
const static std::string CSUSLegacyStr = "legacy";
/**
 *  \brief Defines a string constant for the cipher suits set, with is parallel to the enum.
 *   a string is more flexible for the interface design, but not as an enum.
 *   therefore the enum is used inside the TLS library.
 *   see TLSCipherSuiteUseCasesSettings::CSUSLongtermSecure for more detail.
 *
 *   \since 1.1.0
 */
const static std::string CSUSLongtermSecureStr = "longterm_secure";
/**
 *  \brief Defines a string constant for the cipher suits set, with is parallel to the enum.
 *   a string is more flexible for the interface design, but not as an enum.
 *   therefore the enum is used inside the TLS library.
 *   see TLSCipherSuiteUseCasesSettings::CSUSIanaRecommended for more detail.
 *
 *   \since 1.1.0
 */
const static std::string CSUSIanaRecommendedStr = "iana_recommended";

/**
 * \brief This class represents a wrapper for a raw OCSP request message.
 */
class TLSOcspRequest final
{
public:
    /**
     * \brief Constructor
     *
     * \param[in] url String which contains the OCSP Responder's URL.
     * \param[in] request Vector of bytes which contains a single OCSP Request encoded in BER format.
     */
    TLSOcspRequest(const std::string& url, const std::vector<UInt8>& request)
      : m_responderUrl(url)
      , m_request(request)
    {
        calculateUniqueId();
    }

    /**
     * \brief Constructor
     *
     * \param[in] url String which contains the OCSP Responder's URL.
     * \param[in] request Vector of bytes which contains a single OCSP Request message encoded in BER format.
     * \param[in] uniqueId OCSP Request's unique hash ID.
     */
    TLSOcspRequest(const std::string& url, const std::vector<UInt8>& request, const UInt64 uniqueId)
      : m_responderUrl(url)
      , m_request(request)
      , m_uniqueId(uniqueId)
    {
    }

    TLSOcspRequest(TLSOcspRequest&&)      = default;
    TLSOcspRequest(const TLSOcspRequest&) = default;
    TLSOcspRequest& operator=(const TLSOcspRequest&) = default;
    TLSOcspRequest& operator=(TLSOcspRequest&&) = default;

    ~TLSOcspRequest() = default;

public:
    /**
     * \brief Gets unique ID that identifies the request.
     *
     * \details This shall be uniquely identifiable the OCSP request so it can be cached.
     * Assuming that the same OCSP request will lead to the same OCSP response (apart from the fact the server is down,
     * cert is revoked or network is not available etc...), one can save and rerun the OCSP request and can use the
     * cached OCSP response.
     *
     * \return OCSP request message unique ID.
     */
    UInt64
    getUniqueId() const noexcept
    {
        return m_uniqueId;
    }

    /**
     * \brief Gets the OCSP request message.
     *
     * \return Vector of bytes that contains the request in BER encoding.
     */
    const std::vector<UInt8>&
    getRequest() const noexcept
    {
        return m_request;
    }

    /**
     * \brief Gets request's OCSP Responder URL.
     *
     * \return string that tells the OCSP responder URL.
     */
    const std::string&
    getRequestUrl() const noexcept
    {
        return m_responderUrl;
    }

private:
    /**
     * \brief Calculates request's unique ID.
     *
     * \details this method calculates a unique ID by doing operations on the OCSP request (without "OCSP extensions")
     * and the responder URL.
     */
    void
    calculateUniqueId()
    {
        std::hash<std::string> strHashCalc;
        std::string            requestString(m_request.begin(), m_request.end());

        // The requestString contains the OCSP request and it can be with "OCSP extensions".
        // Takes only the OCSP request without "OCSP extensions", since the "OCSP extensions" can contain "OCSP Nonce
        // Extension". "OCSP Nonce Extension" generated cryptographically then the nonce value would be different for the
        // same OCSP request, so in order to get the same ID for the same OCSP request it calculates the ID by the OCSP
        // request without "OCSP extensions".
        requestString = requestString.substr(0, OCSP_REQUEST_WITHOUT_EXTENSIONS_SIZE);

        m_uniqueId =
            (UInt64)((strHashCalc(m_responderUrl) ^ (strHashCalc(requestString) << 1)) * 0x9e3779b97f4a7c15ULL);
    }

private:
    std::string        m_responderUrl;
    std::vector<UInt8> m_request;
    UInt64             m_uniqueId;

    /**
     * \brief Contains OCSP request size in bytes without "OCSP extensions" size).
     */
    static constexpr UInt8 OCSP_REQUEST_WITHOUT_EXTENSIONS_SIZE = 73;
};

/**
 * \brief This class represents a wrapper for a raw OCSP response message which used as a result object from the OCSP.
 * Proxy process after requests processing.
 */
class TLSOcspRequestResponse final
{
public:
    /**
     * \brief Constructor.
     *
     * \param[in] response Vector of bytes which contains a single OCSP response encoded message in BER format.
     * \param[in] isCached Indicates if the object cached.
     * \param[in] requestUniqueId The unique ID of the related OCSP request.
     */
    TLSOcspRequestResponse(const std::vector<UInt8>& response, const Boolean isCached, const UInt64 requestUniqueId)
      : m_isCached(isCached)
      , m_response(response)
      , m_requestUniqueId(requestUniqueId)
      , m_isCorrupted(false)
    {
    }

    /**
     * \brief Constructor.
     *
     * \note Use this constructor to build an OCSP request response object with is corrupted.
     *
     * \param[in] requestUniqueId The unique ID of the related OCSP request.
     */
    TLSOcspRequestResponse(const UInt64 requestUniqueId)
      : m_isCached(false)
      , m_response()
      , m_requestUniqueId(requestUniqueId)
      , m_isCorrupted(true)
    {
    }

    TLSOcspRequestResponse(TLSOcspRequestResponse&&)      = default;
    TLSOcspRequestResponse(const TLSOcspRequestResponse&) = default;
    TLSOcspRequestResponse& operator=(const TLSOcspRequestResponse&) = default;
    TLSOcspRequestResponse& operator=(TLSOcspRequestResponse&&) = default;

    ~TLSOcspRequestResponse() = default;

public:
    /**
     * \brief Gets an OCSP Response caching status.
     *
     * \return A boolean flag that indicates if OCSP Response cached or not cached.
     */
    Boolean
    getIsCached() const noexcept
    {
        return m_isCached;
    }

    /**
     * \brief Gets the OCSP response message.
     *
     * \return Vector of bytes that contains the response in BER encoding.
     */
    const std::vector<UInt8>&
    getResponse() const noexcept
    {
        return m_response;
    }

    /**
     * \brief Gets the unique ID of the related OCSP request for this OCSP response.
     *
     * \return OCSP request message unique ID.
     */
    UInt64
    getRequestUniqueId() const noexcept
    {
        return m_requestUniqueId;
    }

    /**
     * \brief Gets a boolean that tells if the response corrupted.
     *
     * \return Response corruption status.
     */
    Boolean
    isCorrupted() const noexcept
    {
        return m_isCorrupted;
    }


private:
    Boolean            m_isCached;
    std::vector<UInt8> m_response;
    UInt64             m_requestUniqueId;
    Boolean            m_isCorrupted;
};

/**
 * \brief This class represents a cached OCSP response message.
 */
class TLSOcspCachedResponse final
{
public:
    /**
     * \brief Constructor.
     *
     * \note all dates are expressed according to ISO8601 in UTC - YYYYMMDDHHMMSSZ.
     *
     * \param[in] response Vector of bytes that contains raw OCSP response message encoded in BER format.
     * \param[in] requestUniqueId Unique ID of the related OCSP request for this OCSP response.
     * \param[in] producedAtDate The time at which the OCSP responder signed this OCSP response.
     * \param[in] nextUpdateDate The time at or before which newer information will be available about the status of the
     * certificate.
     * \param[in] thisUpdateDate The most recent time at which the status being indicated is known by the OCSP
     * responder to have been correct.
     */
    TLSOcspCachedResponse(const std::vector<UInt8>& response,
                          const UInt64              requestUniqueId,
                          const std::string&        producedAtDate,
                          const std::string&        nextUpdateDate,
                          const std::string&        thisUpdateDate)
      : m_response(response)
      , m_requestUniqueId(requestUniqueId)
      , m_producedAt(producedAtDate)
      , m_nextUpdate(nextUpdateDate)
      , m_thisUpdate(thisUpdateDate)
    {
    }

    TLSOcspCachedResponse(TLSOcspCachedResponse&&)      = default;
    TLSOcspCachedResponse(const TLSOcspCachedResponse&) = default;
    TLSOcspCachedResponse& operator=(const TLSOcspCachedResponse&) = default;
    TLSOcspCachedResponse& operator=(TLSOcspCachedResponse&&) = default;

    ~TLSOcspCachedResponse() = default;

public:
    /**
     * \brief Gets the OCSP response message.
     *
     * \return Vector of bytes that contains the response in BER encoding.
     */
    const std::vector<UInt8>&
    getResponse() const noexcept
    {
        return m_response;
    }

    /**
     * \brief Gets the unique ID of the related OCSP request for this OCSP response.
     *
     * \return OCSP request message unique ID.
     */
    UInt64
    getRequestUniqueId() const noexcept
    {
        return m_requestUniqueId;
    }

    /**
     * \brief Gets producedAt date parameter from the response.
     *
     * \note Date is expressed according to ISO8601 in UTC - YYYYMMDDHHMMSSZ.
     *
     * \return String which contains the date in ISO8601 format.
     */
    const std::string&
    getProducedAt() const noexcept
    {
        return m_producedAt;
    }

    /**
     * \brief Gets nextUpdate date parameter from the response.
     *
     * \note Date is expressed according to ISO8601 in UTC - YYYYMMDDHHMMSSZ.
     *
     * \return String which contains the date in ISO8601 format.
     */
    const std::string&
    getNextUpdate() const noexcept
    {
        return m_nextUpdate;
    }

    /**
     * \brief Gets thisUpdate date parameter from the response.
     *
     * \note Date is expressed according to ISO8601 in UTC - YYYYMMDDHHMMSSZ.
     *
     * \return String which contains the date in ISO8601 format.
     */
    const std::string&
    getThisUpdate() const noexcept
    {
        return m_thisUpdate;
    }

private:
    std::vector<UInt8> m_response;
    UInt64             m_requestUniqueId;
    std::string        m_producedAt;
    std::string        m_nextUpdate;
    std::string        m_thisUpdate;
};

/**
 * \brief This interface defines APIs to process and handle OCSP messages.
 */
class ITLSOcspHandler
{
public:
    ITLSOcspHandler()          = default;
    virtual ~ITLSOcspHandler() = default;

public:
    /**
     * \brief Cache the OCSP responses.
     *
     * \note This method shall be executed in a new thread context.
     *
     * \details This method serialize each OCSP response, send it over to OCSP Proxy process via IPC mechanism to
     * save it in cache. This method shall be called after:
     * - "processRequest" execution.
     * - full validation and verification of the OCSP responses.
     *
     * \param[in] responses Vector of OCSP responses to cache.
     */
    virtual void cacheResponses(const std::vector<TLSOcspCachedResponse>& responses) noexcept = 0;

    /**
     * \brief Process the OCSP requests and send them to OCSP Proxy process for further processing.
     *
     * \note This method shall be executed in a new thread context
     * The returned vector shall contain an OCSP request response object FOR EACH ocsp request that was in the requests
     * vector. In case of an error for specific OCSP request handling you shall create an OCSP request response object
     * with the second constructor that builds object by the unique ID only. The order of the responses vector shall be
     * the same as the order in the requests vector.
     *
     * \details This method serialize each OCSP requests, send it over to OCSP Proxy process via IPC mechanism
     * to decide whether to send the requests to OCSP responder or to use the responses that already cached.
     *
     * \param[in] requests Vector of OCSP requests.
     *
     * \return A future that contains a vector of OCSP responses for each OCSP request.
     */
    virtual std::future<std::vector<TLSOcspRequestResponse>> processRequests(
        const std::vector<TLSOcspRequest>& requests) noexcept = 0;
};

/**
 
 * \brief  this class is used to define the TLS connection properties
 * for a backend TLS connection. This class contains a set of configuration properties for the TLS connection.
 * 
 * <p>
 * <b>alpnMode</b><br>
 *    The given ALPN Mode, set detail for ALPN mode at the according class
 * 
 * </p><br>
 * 
 * <p>
 * <b>cipherSuiteSettings</b> <br>
 *   Supported cipher suite set (https://devstack.vwgroup.com/jira/browse/IMAN-46128)
 *   the parameter is given as a string, so it give maximal portability.
 *   If the given sting is not valid the default set is used.
 * </p> <br>
 * 
 * <p>
 * <b>ocspHandler</b> <br>
 *  </p> <br>
 * <b>ocspTimeoutMs</b> <br>
 * </p> <br>
 * 
 * <p>
 * <b>connectionLoggingName</b> <br>
 *  the ConnectionLoggingName 
 *  This is a optional name to identify the connection for logging reasons. 
 *  This name shall be provided by the user of the TLS library to identify the connection in logging
 *   @since 1.2.0<br>
 * 
 * </p> <br>
 * 
 * \since 1.1.0
 */
class TLSConnectionSettings final
{
public:
    /**
     *  \brief Constructor.
     *
     *  \param[in] alpnMode The given ALPN Mode.
     *  \param[in] cipherSuiteSettings Supported cipher suite set (https://devstack.vwgroup.com/jira/browse/IMAN-46128).
     *  \param[in] connectionLoggingName <br>
     *  the ConnectionLoggingName 
     *  This is a optional name to identify the connection for logging reasons. 
     *  This name shall be provided by the user of the TLS library to identify the connection in logging
     *
     */
    TLSConnectionSettings(
        const AlpnMode&                alpnMode,
        TLSCipherSuiteUseCasesSettings cipherSuiteSettings = TLSCipherSuiteUseCasesSettings::CSUSDefault,
        const std::string& connectionLoggingName = "")
      : m_alpnMode(alpnMode)
      , m_ocspHandler(nullptr)
      , m_ocspTimeoutMs(DEFAULT_OCSP_ONLINE_TIMEOUT_MS)
      , m_cipherSuiteSettings(cipherSuiteSettings)
      , m_connectionLoggingName(connectionLoggingName)
    {
    }

    /**
     *  \brief Constructor.
     *
     *  \param[in] alpnMode The given ALPN Mode.
     *  \param[in] ocspHandler OCSP handler.
     *  \param[in] ocspTimeoutMs OCSP timeout in milliseconds.
     *  \param[in] cipherSuiteSettings Supported cipher suite set (https://devstack.vwgroup.com/jira/browse/IMAN-46128).
     *  \param[in] connectionLoggingName <br>
     *  the ConnectionLoggingName 
     *  This is a optional name to identify the connection for logging reasons. 
     *  This name shall be provided by the user of the TLS library to identify the connection in logging
      */
    TLSConnectionSettings(
        const AlpnMode&                  alpnMode,
        std::shared_ptr<ITLSOcspHandler> ocspHandler,
        const UInt32                     ocspTimeoutMs       = DEFAULT_OCSP_ONLINE_TIMEOUT_MS,
        TLSCipherSuiteUseCasesSettings   cipherSuiteSettings = TLSCipherSuiteUseCasesSettings::CSUSDefault,
        const std::string& connectionLoggingName = "")
      : m_alpnMode(alpnMode)
      , m_ocspHandler(ocspHandler)
      , m_ocspTimeoutMs(ocspTimeoutMs)
      , m_cipherSuiteSettings(cipherSuiteSettings)
      , m_connectionLoggingName(connectionLoggingName)
    {
    }

    /**
     *  \brief Creates a TLSConnectionSettings data config object to parametrize the TLS session.
     *
     *  \param[in] alpnMode The given ALPN Mode.
     *  \param[in] cipherSuiteSettings Supported cipher suite set (https://devstack.vwgroup.com/jira/browse/IMAN-46128)
     *   the parameter is given as a string, so it give maximal portability.
     *   If the given string is invalid then the default set is used.
     *  \param[in] connectionLoggingName <br>
     *  the ConnectionLoggingName 
     *  This is a optional name to identify the connection for logging reasons. 
     *  This name shall be provided by the user of the TLS library to identify the connection in logging
      *
     *  \since 1.1.0
     */
    TLSConnectionSettings(
        const AlpnMode& alpnMode, 
        const std::string& cipherSuiteSettings,
        const std::string& connectionLoggingName = "")
      : m_alpnMode(alpnMode)
      , m_ocspHandler(nullptr)
      , m_ocspTimeoutMs(DEFAULT_OCSP_ONLINE_TIMEOUT_MS)
      , m_cipherSuiteSettings(TLSCipherSuiteUseCasesSettings::CSUSDefault)
      , m_connectionLoggingName(connectionLoggingName)
    {
        if (CSUSLegacyStr == cipherSuiteSettings) {
            m_cipherSuiteSettings = TLSCipherSuiteUseCasesSettings::CSUSLegacy;
        } else if (CSUSLongtermSecureStr == cipherSuiteSettings) {
            m_cipherSuiteSettings = TLSCipherSuiteUseCasesSettings::CSUSLongtermSecure;
        } else if (CSUSIanaRecommendedStr == cipherSuiteSettings) {
            m_cipherSuiteSettings = TLSCipherSuiteUseCasesSettings::CSUSIanaRecommended;
        } else if (CSUSDefaulWithSoftFailtStr == cipherSuiteSettings) {
            m_cipherSuiteSettings = TLSCipherSuiteUseCasesSettings::CSUSDefaultWithSoftFail;
        }

        // else CSUSDefault was chosen
    }

    ~TLSConnectionSettings() = default;

    /**
     * \brief Gets the cipher suite use case settings.
     *
     * \return The cipher suite use case settings.
     */
    const TLSCipherSuiteUseCasesSettings&
    getCipherSuiteUseCasesSettings() const
    {
        return m_cipherSuiteSettings;
    }

    /**
     * \brief Gets the ALPN mode.
     *
     * \return The ALPN mode.
     */
    const AlpnMode&
    getAlpnMode() const
    {
        return m_alpnMode;
    }

    /**
     * \brief Gets the OCSP handler.
     *
     * \return The OCSP handler.
     */
    const std::shared_ptr<ITLSOcspHandler>&
    getOcspHandler() const
    {
        return m_ocspHandler;
    }

    /**
     * \brief Gets the OCSP timeout in milliseconds.
     *
     * \return The OCSP handler.
     */
    const UInt32&
    getOcspTimeoutMs() const
    {
        return m_ocspTimeoutMs;
    }

    /**
    *  \brief get the ConnectionLoggingName 
    *   This is a optional name to identify the connection for logging reasons. 
    *   This name shall be provided by the user of the TLS library to identify the connection in logging
    * \return Tthe ConnectionLoggingName 
    *  @since 1.2.0
    */
   std::string getConnectionLoggingName() const
   {
       return m_connectionLoggingName;
   }


private:
    const AlpnMode                   m_alpnMode;
    std::shared_ptr<ITLSOcspHandler> m_ocspHandler;
    const UInt32                     m_ocspTimeoutMs;
    TLSCipherSuiteUseCasesSettings   m_cipherSuiteSettings;
    std::string                      m_connectionLoggingName;
};

const UInt32 MODE_BLOCKING = 0;
const UInt32 MODE_ASYNC    = 1;

/**
 * \brief Defines the SSOA confidentiality.
 *
 * AUTHENTIC_WITHPSK     defines PSK connection with authentication.
 *
 * CONFIDENTIAL_WITHPSK  defines confidential PSK connection.
 */
enum SecurityLevel : UInt32 { AUTHENTIC_WITHPSK = 0, CONFIDENTIAL_WITHPSK = 1 };

/**
 * \brief Defines the socket type.
 *
 * SOCKETTYPE_STREAM     Stream socket.
 *
 * SOCKETTYPE_DATAGRAM   Datagram socket.
 */
enum SocketType : UInt32 { SOCKETTYPE_STREAM = 0, SOCKETTYPE_DATAGRAM = 1 };

enum TLSDropSuppot : UInt32 { TLS_NOT_DROPABLE = 0, TLS_DROPABLE = 1 };

/**
 * \typedef This is an error handler c-style function pointer type.
 * In case of an error the function is called by the TLS library implementation.
 *
 * \param[in] inet the internet address identifying  the connection.
 * \param[in] port the  port  identifying  the connection.
 * \param[in] errorCode the error code
 *
 */
typedef void (*ErrorHandler)(SPIInetAddress inet, const UInt16 port, const TLSReturnCodes errorCode);

class ITLSErrorListener
{
public:
    ITLSErrorListener()          = default;
    virtual ~ITLSErrorListener() = default;

public:
    virtual void errorListener(SPIInetAddress inet, const UInt16 port, const TLSReturnCodes errorCode) = 0;
};

/**
 * \brief This is an interface which defines a set of operation and features have to be available on each socket and
 * session endpoint.
 */
class ITLSSocketBase
{
public:
    ITLSSocketBase()          = default;
    virtual ~ITLSSocketBase() = default;

public:
    /**
     * \brief Gets a boolean that tells if the socket is a Datagram socket.
     *
     * \return true if the socket is a Datagram socket, otherwise false.
     */
    Boolean
    isDatagramSocket()
    {
        return !isConnectionSocket();
    };

    /**
     * \brief Gets a boolean that tells if the socket is a stream socket.
     *
     * \return true if the socket is a stream socket, otherwise false.
     */
    virtual Boolean isConnectionSocket() = 0;

    /**
     * \brief Closes the underlying socket connection.
     * This will immediately close the connection, all pending data may be lost,
     * therefore one user shall call flush before closing.
     * 
     * \note TLS lib will close only file descriptors that are created by the library and is not responsible for closing file descriptors created by the user. externally created file descriptors should be closed by the user.
     */
    virtual void close() = 0;

    /**
     * \brief Checks if the endpoint/connection is closed or not.
     *
     * \return true if endpoint/connection is closed.
     */
    virtual Boolean isClosed() = 0;

    /**
     * \brief Checks if the endpoint/connection is closed or not.
     *
     * \return true if endpoint/connection is closed.
     */
    virtual Boolean isOpen() = 0;

    /**
     * \brief Checks if the endpoint/connection is in some error state.
     *
     * \return true if endpoint/connection is in error state.
     * One use getPendingErrors to read the errors.
     * Depending on the error state the connection is closed already.
     */
    virtual Boolean
    isErrorState()
    {
        return !m_errors.empty();
    };

    /**
     * \brief Gets the port of the local session endpoint/socket.
     *
     * \return Gets the port of the session endpoint/socket.
     */
    virtual UInt16 getLocalPort() = 0;

    /**
     * \brief gets the inet address of the local session endpoint/socket.
     * \returns gets the inet address of the session endpoint/socket.
     */
    virtual SPIInetAddress getLocalInetAddress() = 0;

    /**
     * \brief Reads the pending error related to the underlying socket and TLS library.
     * One may call several times until all errors are read.
     *
     * \return The pending error code (see TLSReturnCodes) or a negative value if there are no pending errors anymore.
     */
    virtual Int32
    getPendingErrors()
    {
        if (m_errors.empty()) {
            return -1;
        }

        Int32 ret = m_errors.front();
        m_errors.pop();
        return ret;
    }

    /**
     * \brief Gets the used AlpnMode.

     * \return The provided ALPN mode, if no AlpnMode is specified then the const AlpnMode::ALPN_OFF is returned.
     *
     * \since 1.1.0
     */
    virtual const AlpnMode& getUsedAlpnMode() const = 0;

    /**
     * \brief  Gets the used INANAProtocol.
     *
     * \return The used IANA protocol, In case ALPN is unused then the const IANAProtocol::NONE is returned.
     *
     * \since 1.1.0
     */
    virtual IANAProtocol getUsedProtocol() const = 0;

protected:
    /**
     * \brief  Adds a pending error to the queue.
     *
     * \since 1.1.0
     */
    virtual void
    addPendingError(Int32 err)
    {
        m_errors.push(err);
    }

    std::queue<Int32> m_errors;
};

} /* namespace tls */
} /* namespace vwg */


#endif /* SRC_TLSAPITYPES_H_ */
