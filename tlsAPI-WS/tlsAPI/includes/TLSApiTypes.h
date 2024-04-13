/**
 * @file TLSApiTypes.h
 * @brief Defines types and interfaces used in the TLS API.
 *
 * This file includes a variety of data structures, classes, and enumerations that are used throughout the TLS API.
 * It defines protocol types, error codes, settings for ALPN and cipher suites, and interfaces for handling OCSP messages.
 * The file is essential for configuring TLS connections and handling their lifecycle and security features.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All information and materials contained herein, including the intellectual and technical concepts, are the property of
 * CARIAD SE and may be protected by copyright, trade secrets, or patents in process. This source code is confidential and
 * proprietary to CARIAD SE and is not intended for publication or disclosure.
 *
 * Unauthorized use, reproduction, dissemination, or distribution of this source code or any portion of it may violate applicable laws.
 */

#ifndef SRC_TLSAPITYPES_H_
#define SRC_TLSAPITYPES_H_

#include <ctime>
#include <functional>
#include <future>
#include <queue>
#include <vector>
#include <string>

#include "InetAddress.h"
#include "vwgtypes.h"

using namespace vwg::types;

namespace vwg {
namespace tls {

const std::string ApiVersion("TLS_API_1.3");

/**
 * @enum IANAProtocol
 * @brief Enumeration of supported protocols for ALPN.
 *
 * Defines protocols that can be negotiated through the ALPN (Application-Layer Protocol Negotiation) process.
 * Refer to IANA Protocol definitions in RFC7230 (https://tools.ietf.org/html/rfc7230).
 */
enum IANAProtocol {
    NONE  = 0, /**< No protocol specified. */
    HTTP  = 1, /**< HTTP/1.1 Protocol. */
    HTTP2 = 2  /**< HTTP/2 Protocol. */
};

/**
 * @class IANAProtocolFunction
 * @brief Helper class to convert IANAProtocol enumeration values to protocol names.
 */
class IANAProtocolFunction final {
public:
    IANAProtocolFunction() = default;
    ~IANAProtocolFunction() = default;

    const std::string ProtocolNameHTTP  = "http/1.1";
    const std::string ProtocolNameHTTP2 = "h2";

    /**
     * @brief Converts an IANAProtocol value to its corresponding protocol name.
     * @param protocol The IANA protocol enumeration to convert.
     * @param oProtocolName Output string to hold the protocol name.
     * @return true if conversion is successful, false otherwise.
     */
    bool toIANAProtocolName(const IANAProtocol& protocol, std::string& oProtocolName) {
        switch (protocol) {
        case HTTP:
            oProtocolName = ProtocolNameHTTP;
            return true;
        case HTTP2:
            oProtocolName = ProtocolNameHTTP2;
            return true;
        default:
            return false;
        }
    }
};

/**
 * @struct TimeCheckTime
 * @brief Structure to pass and check system time against a reference time.
 *
 * Defines the expected system time for operations, allowing deviation within a permitted range.
 */
struct TimeCheckTime {
    std::time_t expectedTime;     /**< Expected time to be compared against system time. */
    int permittedDeviation;       /**< Permitted time deviation in seconds. */
};

const TimeCheckTime CHECK_TIME_OFF = {0, 0}; /**< Time check is disabled. */

/**
 * @class AlpnMode
 * @brief Encapsulates settings for the ALPN extension.
 *
 * Defines the Application-Layer Protocol Negotiation settings for a TLS connection. Supports predefined
 * protocol lists or custom user-defined strings.
 */
class AlpnMode final {
public:
    /**
     * @brief Constructor for predefined protocol list.
     * @param supportedProtocols Vector of IANAProtocol enums.
     */
    explicit AlpnMode(const std::vector<IANAProtocol>& supportedProtocols)
        : m_userDefinedALPNisUsed(false), m_supportedProtocols(supportedProtocols) {}

    /**
     * @brief Constructor for user-defined protocol strings.
     * @param userDefinedAlpnSetting Vector of strings specifying the ALPN protocols.
     */
    explicit AlpnMode(const std::vector<std::string>& userDefinedAlpnSetting)
        : m_userDefinedALPNisUsed(true), m_userDefinedAlpnSetting(userDefinedAlpnSetting) {}

    ~AlpnMode() = default;

    /**
     * @brief Checks if user-defined ALPN settings are used.
     * @return true if user-defined settings are used, false otherwise.
     */
    bool userDefinedALPNisUsed() const { return m_userDefinedALPNisUsed; }

    /**
     * @brief Gets the supported IANA protocols.
     * @return Vector of supported IANA protocols.
     */
    const std::vector<IANAProtocol>& getSupportedProtocols() const { return m_supportedProtocols; }

    /**
     * @brief Gets the user-defined ALPN settings.
     * @return Vector of user-defined ALPN settings.
     */
    const std::vector<std::string>& getUserDefinedAlpnSetting() const { return m_userDefinedAlpnSetting; }

private:
    bool m_userDefinedALPNisUsed;
    std::vector<std::string> m_userDefinedAlpnSetting;
    std::vector<IANAProtocol> m_supportedProtocols;
};

const AlpnMode ALPN_OFF(std::vector<IANAProtocol>{NONE});           /**< ALPN is disabled. */
const AlpnMode ALPN_DEFAULT(std::vector<IANAProtocol>{HTTP});       /**< Default ALPN setting using HTTP. */
const AlpnMode ALPN_HTTP2(std::vector<IANAProtocol>{HTTP2});        /**< ALPN setting using HTTP/2. */
const AlpnMode ALPN_ANY(std::vector<IANAProtocol>{HTTP, HTTP2});    /**< ALPN setting supporting any protocol. */

/**
 * @enum TLSCipherSuiteUseCasesSettings
 * @brief Enumeration of pre-defined cipher suite settings for different use cases.
 *
 * Specifies cipher suites based on use case scenarios. Each setting configures TLS connections to use a certain set
 * of cipher suites, which are selected based on the security needs of the application.
 */
enum TLSCipherSuiteUseCasesSettings : UInt32 {
    CSUSDefault = 0,             /**< Default cipher suites. */
    CSUSLegacy = 1,              /**< Cipher suites for legacy compatibility. */
    CSUSLongtermSecure = 2,      /**< Cipher suites considered secure for long-term use. */
    CSUSIanaRecommended = 3,     /**< Cipher suites recommended by IANA. */
    CSUSDefaultWithSoftFail = 4  /**< Default cipher suites with soft fail for revocation checking. */
};

// Other classes and constants can follow here

} // namespace tls
} // namespace vwg

#endif /* SRC_TLSAPITYPES_H_ */
