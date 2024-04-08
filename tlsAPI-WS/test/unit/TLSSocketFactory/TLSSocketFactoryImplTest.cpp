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

#include <gtest/gtest.h>

#include "IPInetAddressImpl.hpp"
#include "InternIOStream.hpp"
#include "TLSSocketFactoryImpl.hpp"

#include "MockInternIOStream.hpp"
#include "MockTLSServerSocketImpl.hpp"

using namespace vwg::tls;
using namespace vwg::tls::impl;

using ::testing::Return;

MockInternIOStream*      InternIOStreamUT::mMockInternIOStream;
MockTLSServerSocketImpl* TLSServerSocketImplUT::mMockTLSServerSocketImpl;

class TLSSocketFactoryImplTest : public ::testing::Test
{
public:
    std::shared_ptr<InternIOStream> m_stream;
    std::string                     m_localDomainName;
    SecurityLevel                   m_confidentiality;
    SocketType                      m_socketType;
    UInt16                          m_port;
    vwg::tls::SPIInetAddress        m_address;
    int                             m_fd;
    std::string                     m_hostName;
    CipherSuiteIds                  m_cipherSuiteIds;
    TimeCheckTime                   m_checkTime;
    std::vector<HashSha256>         m_httpPublicKeyPinningHashs;
    std::string                     m_certStoreId;
    std::string                     m_clientCertificateSetID;
    TLSSocketFactoryImpl            m_tlsSocketFactory;


    virtual void
    SetUp()
    {
        m_fd                      = 2;
        m_stream                  = std::make_shared<InternIOStream>(m_fd);
        m_confidentiality         = AUTHENTIC_WITHPSK;
        m_localDomainName         = "Local Domain Name";
        m_socketType              = SOCKETTYPE_STREAM;
        m_port                    = 8080;
        std::string stringAddress = "1:2:3:4:5:6:7:8";
        m_address                 = std::make_shared<IPInetAddressImpl>(stringAddress);
        m_hostName                = "server";
        m_cipherSuiteIds          = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        m_checkTime               = {0, 0};
        m_certStoreId             = "SERVERT_ROOT";
        m_clientCertificateSetID  = "CERT ID";

        std::string hint = "hint";
        TLSServerSocketImplUT::mMockTLSServerSocketImpl =
            new MockTLSServerSocketImpl(m_stream, hint, m_confidentiality, true, false, false);
        InternIOStreamUT::mMockInternIOStream = new MockInternIOStream(m_fd);
    }

    virtual void
    TearDown()
    {
        delete TLSServerSocketImplUT::mMockTLSServerSocketImpl;
        TLSServerSocketImplUT::mMockTLSServerSocketImpl = nullptr;

        delete InternIOStreamUT::mMockInternIOStream;
        InternIOStreamUT::mMockInternIOStream = nullptr;
    }
};

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createServerSocket)
 * @brief check createServerSocket functions
 */

TEST_F(TLSSocketFactoryImplTest, createServerSocket)
{
    TLSServerSocketResult res =
        m_tlsSocketFactory.createServerSocket(m_address, m_port, m_localDomainName, m_confidentiality, m_socketType);
    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);
    res = m_tlsSocketFactory.createServerSocket(m_fd, m_localDomainName, m_confidentiality);
    ASSERT_TRUE(res.succeeded());
    EXPECT_EQ(res.getPayload()->getSocketFD(), m_fd);
}

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createPskServerSessionSuccess)
 * @brief createPskServerSession successfully
 */
TEST_F(TLSSocketFactoryImplTest, createPskServerSessionSuccess)
{
    TLSSessionEndpointResult toBeReturned = TLSSessionEndpointResult();

    EXPECT_CALL(*TLSServerSocketImplUT::mMockTLSServerSocketImpl, accept()).Times(1).WillOnce(Return(toBeReturned));

    TLSSessionEndpointResult res =
        m_tlsSocketFactory.createPskServerSession(m_fd, m_localDomainName, m_confidentiality);
    EXPECT_EQ(res.getErrorCode(), res.getErrorCode());
}

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createClientSocketSuccess)
 * @brief createClientSocket successfully
 */
TEST_F(TLSSocketFactoryImplTest, createClientSocketSuccess)
{
    EXPECT_CALL(*InternIOStreamUT::mMockInternIOStream, Connect()).Times(1).WillOnce(Return(true));

    TLSClientSocketResult res;
    res = m_tlsSocketFactory.createClientSocket(m_address,
                                                m_port,
                                                m_localDomainName,
                                                m_confidentiality,
                                                m_socketType);  // mock

    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);

    res = m_tlsSocketFactory.createClientSocket(m_fd, m_localDomainName, m_confidentiality);
    ASSERT_TRUE(res.succeeded());
    EXPECT_EQ(res.getPayload()->getSocketFD(), m_fd);
}

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createClientSocketFailure)
 * @brief get a failure when calling createClientSocket
 */
TEST_F(TLSSocketFactoryImplTest, createClientSocketFailure)
{
    EXPECT_CALL(*InternIOStreamUT::mMockInternIOStream, Connect()).Times(1).WillOnce(Return(false));

    TLSClientSocketResult res;
    res = m_tlsSocketFactory.createClientSocket(m_address,
                                                m_port,
                                                m_localDomainName,
                                                m_confidentiality,
                                                m_socketType);  // mock

    EXPECT_EQ(res.getErrorCode(), RC_TLS_CONNECT_FAILED);

    res = m_tlsSocketFactory.createClientSocket(m_fd, m_localDomainName, m_confidentiality);
    ASSERT_TRUE(res.succeeded());
    EXPECT_EQ(res.getPayload()->getSocketFD(), m_fd);
}

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createTlsClient)
 * @brief check createTlsClient function
 */
TEST_F(TLSSocketFactoryImplTest, createTlsClient)
{
    TLSClientSocketResult res = m_tlsSocketFactory.createTlsClient(m_stream,
                                                                   m_hostName,
                                                                   m_certStoreId,
                                                                   m_clientCertificateSetID,
                                                                   m_cipherSuiteIds,
                                                                   m_checkTime,
                                                                   m_httpPublicKeyPinningHashs);

    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);
}

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createTlsClientUseCaseInterface)
 * @brief check createTlsClient function
 */
TEST_F(TLSSocketFactoryImplTest, createTlsClientUseCaseInterface)
{
    const std::vector<IANAProtocol> protocol{HTTP};
    AlpnMode                        alpnMode{protocol};
    TLSConnectionSettings           connectionSettings(alpnMode);

    TLSClientSocketResult res = m_tlsSocketFactory.createTlsClient(connectionSettings,
                                                                   m_stream,
                                                                   m_hostName,
                                                                   m_certStoreId,
                                                                   m_clientCertificateSetID,
                                                                   m_checkTime,
                                                                   m_httpPublicKeyPinningHashs);
    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);
}

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createTlsClientUseCaseInterfaceFailure)
 * @brief check createTlsClient function
 */
TEST_F(TLSSocketFactoryImplTest, createTlsClientUseCaseInterfaceFailure)
{
    const std::vector<IANAProtocol> protocol{HTTP};
    AlpnMode                        alpnMode{protocol};
    TLSCipherSuiteUseCasesSettings invalidCipherSuiteSettings = CSUSEndOfEnum;
    TLSConnectionSettings           connectionSettings(alpnMode, invalidCipherSuiteSettings);

    TLSClientSocketResult res = m_tlsSocketFactory.createTlsClient(connectionSettings,
                                                               m_stream,
                                                               m_hostName,
                                                               m_certStoreId,
                                                               m_clientCertificateSetID,
                                                               m_checkTime,
                                                               m_httpPublicKeyPinningHashs);
    EXPECT_EQ(res.getErrorCode(), RC_TLS_ILLEGAL_PARAMETER);
}


/**
 * @fn TEST_F(TLSSocketFactoryImplTest, getApiVersion)
 * @brief check getApiVersion function
 */
TEST_F(TLSSocketFactoryImplTest, getApiVersion)
{
    EXPECT_EQ(m_tlsSocketFactory.getApiVersion(), ApiVersion);
}

#ifdef TLSAPI_WITH_DROP_SUPPORT

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createDroppableServerSocket)
 * @brief check createDroppableServerSocket function
 */
TEST_F(TLSSocketFactoryImplTest, createDroppableServerSocket)
{
    // Create Droppable Server Socket with IP&port
    TLSServerSocketResult res = m_tlsSocketFactory.createDroppableServerSocket(
        m_address, m_port, m_localDomainName, m_confidentiality);
    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);

    // Create Droppable Server Socket with fd
    res = m_tlsSocketFactory.createDroppableServerSocket(
        m_fd, m_localDomainName, m_confidentiality);
    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);
}

/**
 * @fn TEST_F(TLSSocketFactoryImplTest, createDroppableClientSocket)
 * @brief check createDroppableClientSocket function
 */
TEST_F(TLSSocketFactoryImplTest, createDroppableClientSocket)
{
    // Create Droppable Client Socket with IP&port
    EXPECT_CALL(*InternIOStreamUT::mMockInternIOStream, Connect()).Times(1).WillOnce(Return(true));

    TLSClientSocketResult res = m_tlsSocketFactory.createDroppableClientSocket(
        m_address, m_port, m_localDomainName, m_confidentiality);
    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);

    // Create Droppable Server Socket with fd
    res = m_tlsSocketFactory.createDroppableClientSocket(
        m_fd, m_localDomainName, m_confidentiality);
    ASSERT_TRUE(res.succeeded());
    EXPECT_NE(res.getPayload(), nullptr);
}

#endif