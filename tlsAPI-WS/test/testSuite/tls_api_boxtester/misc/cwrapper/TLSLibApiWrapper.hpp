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


#ifndef TLS_LIB_API_WRAPPER_HPP
#define TLS_LIB_API_WRAPPER_HPP

#include <memory>
#include <vector>

/*******************************************************
 * Assert Macros
 *******************************************************/

#define ASSERT_NOT_NULLPTR(ptr) \
{ \
	if (ptr == nullptr) \
	{ \
		printf("%s is null\n", #ptr); \
		return false; \
	} \
}

#define ASSERT_TRUE(expr) \
{ \
	if (!expr) \
	{ \
		printf("%s is false\n", #expr); \
		return false; \
	} \
}

#define ASSERT_OBJ_NO_FAILED(obj) \
{ \
	if (obj.failed()) \
	{ \
		printf("%s failed\n", #obj); \
		return false; \
	} \
}

/*******************************************************
 * Forward Declerations
 *******************************************************/
namespace vwg
{
	namespace tls
	{
		class ITLSSocketFactory;
        class ITLSClientSocket;
        class ITLSSessionEndpoint;
        class ITLSOcspHandler;

		namespace impl
		{
			class TestIOStreamImpl;
		}
	}
}


class TLSLibApiWrapper
{
public:
	TLSLibApiWrapper() = default;
	virtual ~TLSLibApiWrapper() = default;

public:
    static bool InitTLSLib();
    static void CleanupTLSLib();

public:

    /**
     *
     * @return
     */
    bool Connect();

    /**
     *
     * @return
     */
    bool Shutdown();

    /**
     *
     * @param data
     * @param size
     * @return
     */
    bool Send(uint8_t* data, uint32_t size);

    /**
     *
     * @param cipherSuitesUseCase
     * @param ip
     * @param port
     * @param hostName
     * @param certStoreId
     * @param clientCertificateSetID
     * @param cipherSuiteIds
     * @param httpPublicKeyPinningHashes
     * @return
     */
    bool CreateTLSClient(int         cipherSuitesUseCase,
                         std::shared_ptr<vwg::tls::ITLSOcspHandler> const& handler,
                         std::string ip,
                         uint16_t    port,
                         std::string hostName,
                         std::string certStoreId,
                         std::string clientCertificateSetID,
                         std::vector<std::vector<char>> httpPublicKeyPinningHashes);


	/**
	 *
	 * @param ip
	 * @param port
	 * @param hostName
	 * @param certStoreId
	 * @param clientCertificateSetID
	 * @param alpn_protocol
	 * @param httpPublicKeyPinningHashes
	 * @return
	 */
    bool CreateTLSClient(std::string alpn_protocol,
                         int cipherSuitesUseCase,
                         std::shared_ptr<vwg::tls::ITLSOcspHandler> const& handler,
                         std::string ip,
                         uint16_t port,
                         std::string hostName,
                         std::string certStoreId,
                         std::string clientCertificateSetID,
                         std::vector<std::vector<char>> httpPublicKeyPinningHashes);

    int GetUsedProtocol();

private:
    bool createStreamConnection(std::string ip, uint16_t port);

private:
    std::shared_ptr<vwg::tls::ITLSClientSocket> m_clientSocket;
    std::shared_ptr<vwg::tls::ITLSSessionEndpoint> m_sessionep;
    std::shared_ptr<vwg::tls::impl::TestIOStreamImpl> m_ioStream;
};

#endif // TLS_LIB_API_WRAPPER_HPP