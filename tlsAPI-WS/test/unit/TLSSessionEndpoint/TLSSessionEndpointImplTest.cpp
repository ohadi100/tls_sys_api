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
#include "MockInternIOStream.hpp"
#include "MockPSKEngine.hpp"
#include "TLSLibApi.h"
#include "TLSSessionEndpointImpl.hpp"

using namespace vwg::tls;
using namespace vwg::tls::impl;
using ::testing::_;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SetArgReferee;
using ::testing::DoAll;

class TLSSessionEndPointImplTest : public ::testing::Test
{
public:
    std::shared_ptr<MockInternIOStream> m_stream;
    std::string                         m_hint;
    SecurityLevel                       m_confidentiality;
    bool                                m_isFdManagedLocal;
    bool                                m_isDroppable;
    std::shared_ptr<ITLSEngine>         m_engine;
    TLSSessionEndpointImpl*             seeLocalFd;
    TLSSessionEndpointImpl*             seeUserFd;

    virtual void
    SetUp()
    {
        int fd             = 2;
        m_stream           = std::make_shared<MockInternIOStream>(fd);
        m_hint             = "1001";
        m_confidentiality  = AUTHENTIC_WITHPSK;
        m_isFdManagedLocal = true;
        m_isDroppable      = false;

        PSKEngineUT::mMockPSKEngine = new MockPSKEngine(m_stream, m_isFdManagedLocal, m_hint, m_confidentiality);

        m_engine = std::make_shared<PSKEngineUT>(m_stream, false /*client*/, m_hint, m_confidentiality);

        seeLocalFd = new TLSSessionEndpointImpl(m_stream, m_engine, m_isFdManagedLocal, m_isDroppable);
        seeUserFd  = new TLSSessionEndpointImpl(m_stream, m_engine, !m_isFdManagedLocal, m_isDroppable);
    }

    void ReceiveCalledTwiceSuccess()  // engine Receive(...) func returns RC_TLS_ENGINE_SUCCESSFUL and actualLength 0
    {
        int32_t firstActualLength  = 5;
        int32_t secondActualLength = 0;
        EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Receive(_, _, _))
            .Times(2)
            .WillOnce(DoAll(SetArgReferee<2>(firstActualLength),
                            Return(RC_TLS_ENGINE_SUCCESSFUL)))  // first time in do-while condition, actualLength will
                                                                // be greater than 0
            .WillOnce(
                DoAll(SetArgReferee<2>(secondActualLength),
                      Return(RC_TLS_ENGINE_SUCCESSFUL)));  // second time in do-while condition, actualLength will be 0
    }

#ifdef TLSAPI_WITH_DROP_SUPPORT
    void
    dropTLSFailureEngineDropFailed(TLSEngineError errorToBeRet)
    {
        seeUserFd->m_droppable = true;

        EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DropTLS()).Times(2).WillRepeatedly(Return(errorToBeRet));

        // engine Receive(...) func returns RC_TLS_ENGINE_SUCCESSFUL and actualLength 0
        ReceiveCalledTwiceSuccess();

        EXPECT_EQ(seeUserFd->dropTLS(), vwg::tls::impl::EngineToTLSReturnCode(errorToBeRet));

        EXPECT_TRUE(seeUserFd->m_dropInitiated);
        EXPECT_FALSE(seeUserFd->m_dropSendCompleted);
        EXPECT_TRUE(seeUserFd->m_dropReceived);
    };

#endif

    virtual void
    TearDown()
    {
        EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Close()).Times(2);        // seeLocalFd + seeUserFd DTOR
        EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(false));  // seeLocalFd DTOR

        delete seeLocalFd;
        delete seeUserFd;
        delete PSKEngineUT::mMockPSKEngine;
    }
};

/**
 * @ingroup TLSSessionEndpoint_getSocketFD
 * @fn TEST_F(TLSSessionEndPointImplTest, getSocketFDSuccess)
 * @brief check getSocketFD function
 */
TEST_F(TLSSessionEndPointImplTest, getSocketFDSuccess)
{
    EXPECT_CALL(*m_stream.get(), GetFD()).Times(1).WillOnce(Return(5));
    EXPECT_EQ(seeUserFd->getSocketFD(), 5);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, sendSuccess)
 * @brief check send functions
 */
TEST_F(TLSSessionEndPointImplTest, sendSuccess)
{
    const Int32  len                  = 2;
    const UInt32 offset               = 1;
    Byte         buffer[len + offset] = {0};

    Int32 actualLengthToOutVal = len;

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Send(buffer + 0, len, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<2>(actualLengthToOutVal), Return(RC_TLS_ENGINE_SUCCESSFUL)));

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Send(buffer + offset, len, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<2>(actualLengthToOutVal), Return(RC_TLS_ENGINE_SUCCESSFUL)));

    EXPECT_EQ(seeUserFd->send(buffer, len), actualLengthToOutVal);
    EXPECT_EQ(seeUserFd->send(buffer, offset, len), actualLengthToOutVal);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, sendFailure)
 * @brief checks send function when it fails
 */
TEST_F(TLSSessionEndPointImplTest, sendFailure)
{
    const Int32  len                  = 2;
    const UInt32 offset               = 1;
    Byte         buffer[len + offset] = {0};

    Int32          actualLengthToOutVal = -1;
    TLSEngineError someError            = RC_TLS_ENGINE_UNKNOWN_ERROR;

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Send(buffer + 0, len, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<2>(actualLengthToOutVal), Return(someError)));

    EXPECT_EQ(seeUserFd->send(buffer, len), -1);
    EXPECT_EQ(seeUserFd->getPendingErrors(), EngineToTLSReturnCode(someError));
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, receiveSuccess)
 * @brief check receive functions
 */
TEST_F(TLSSessionEndPointImplTest, receiveSuccess)
{
    const Int32  len                  = 2;
    const UInt32 offset               = 1;
    Byte         buffer[len + offset] = {0};

    Int32 actualLengthToOutVal = len;

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Receive(buffer + 0, len, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<2>(actualLengthToOutVal), Return(RC_TLS_ENGINE_SUCCESSFUL)));

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Receive(buffer + offset, len, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<2>(actualLengthToOutVal), Return(RC_TLS_ENGINE_SUCCESSFUL)));

    EXPECT_EQ(seeUserFd->receive(buffer, len), actualLengthToOutVal);
    EXPECT_EQ(seeUserFd->receive(buffer, offset, len), actualLengthToOutVal);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, setBlockingSuccess)
 * @brief check setBlocking function
 */
TEST_F(TLSSessionEndPointImplTest, setBlockingSuccess)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, SetBlocking(false)).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));
    TLSReturnCodes res = seeUserFd->setBlocking(false);
    EXPECT_EQ(res, RC_TLS_SUCCESSFUL);

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, SetBlocking(true)).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));
    res = seeUserFd->setBlocking(true);
    EXPECT_EQ(res, RC_TLS_SUCCESSFUL);
}


/**
 * @fn TEST_F(TLSSessionEndPointImplTest, setBlockingFailure)
 * @brief check setBlocking function
 */
TEST_F(TLSSessionEndPointImplTest, setBlockingFailure)
{
    bool blocking = true;
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, SetBlocking(blocking))
        .Times(1)
        .WillOnce(Return(RC_TLS_ENGINE_SPECIFIC_ERROR));
    EXPECT_EQ(seeUserFd->setBlocking(blocking), RC_TLS_IO_ERROR);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, shutdownSuccess_localFd)
 * @brief check shutdown function
 */
TEST_F(TLSSessionEndPointImplTest, shutdownSuccess_localFd)
{
    TLSReturnCodes res;

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Shutdown()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Close()).Times(1);
    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*m_stream, close()).Times(1);

    res = seeLocalFd->shutdown();
    EXPECT_EQ(res, RC_TLS_SUCCESSFUL);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, shutdownSuccess_userFd)
 * @brief check shutdown function
 */
TEST_F(TLSSessionEndPointImplTest, shutdownSuccess_userFd)
{
    TLSReturnCodes res;

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Shutdown()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Close()).Times(1);

    res = seeUserFd->shutdown();
    EXPECT_EQ(res, RC_TLS_SUCCESSFUL);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, isOpen)
 * @brief check isOpen function
 */
TEST_F(TLSSessionEndPointImplTest, isOpen)
{
    bool res;

    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(true));
    res = seeUserFd->isOpen();
    EXPECT_EQ(res, true);

    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(false));
    res = seeUserFd->isOpen();
    EXPECT_EQ(res, false);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, isClosed)
 * @brief check isClosed function
 */
TEST_F(TLSSessionEndPointImplTest, isClosed)
{
    bool res;

    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(true));
    res = seeUserFd->isClosed();
    EXPECT_EQ(res, false);

    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(false));
    res = seeUserFd->isClosed();
    EXPECT_EQ(res, true);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getDropState)
 * @brief check getDropState function
 */
TEST_F(TLSSessionEndPointImplTest, getDropState)
{
    bool res = seeUserFd->getDropState();
    EXPECT_EQ(res, TLSDROP_DROPPED);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, isConnectionSocket)
 * @brief check isConnectionSocket function
 */
TEST_F(TLSSessionEndPointImplTest, isConnectionSocket)
{
    SocketType sockType = SOCKETTYPE_STREAM;
    EXPECT_CALL(*m_stream, GetConnectionType()).Times(1).WillOnce(Return(sockType));
    Boolean res = seeUserFd->isConnectionSocket();
    EXPECT_EQ(res, sockType);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, closeLocalFd)
 * @brief check close function
 */
TEST_F(TLSSessionEndPointImplTest, closeLocalFd)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Close()).Times(1);
    EXPECT_CALL(*m_stream, isOpen()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*m_stream, close()).Times(1);
    seeLocalFd->close();
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, closeUserFd)
 * @brief check close function
 */
TEST_F(TLSSessionEndPointImplTest, closeUserFd)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Close()).Times(1);
    seeUserFd->close();
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getLocalPort)
 * @brief check getLocalPort function
 */
TEST_F(TLSSessionEndPointImplTest, getLocalPort)
{
    uint16_t port = 8080;
    EXPECT_CALL(*m_stream, GetLocalPort()).Times(1).WillOnce(Return(port));
    uint16_t resPort = seeUserFd->getLocalPort();

    EXPECT_EQ(resPort, port);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getLocalInetAddress)
 * @brief check getLocalInetAddress function
 */
TEST_F(TLSSessionEndPointImplTest, getLocalInetAddress)
{
    std::string              stringAddress = "1:2:3:4:5:6:7:8";
    vwg::tls::SPIInetAddress address       = std::make_shared<IPInetAddressImpl>(stringAddress);

    EXPECT_CALL(*m_stream, GetLocalAddress()).Times(1).WillOnce(Return(address));
    vwg::tls::SPIInetAddress resAddress = seeUserFd->getLocalInetAddress();
    EXPECT_EQ(resAddress->toString(), stringAddress);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getRemoteDomainName)
 * @brief check getRemoteDomainName function
 */
TEST_F(TLSSessionEndPointImplTest, getRemoteDomainName)
{
    std::string domainName = "domain";

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, GetRemoteHintName()).Times(1).WillOnce(Return(domainName));
    std::string domainNameRes = seeUserFd->getRemoteDomainName();
    EXPECT_EQ(domainNameRes, domainName);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getLocalDomainName)
 * @brief check getLocalDomainName function
 */
TEST_F(TLSSessionEndPointImplTest, getLocalDomainName)
{
    std::string hintName = "hint";

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, GetHintName()).Times(1).WillOnce(Return(hintName));
    std::string domainNameRes = seeUserFd->getLocalDomainName();
    EXPECT_EQ(domainNameRes, hintName);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getRemotePort)
 * @brief check getRemotePort function
 */
TEST_F(TLSSessionEndPointImplTest, getRemotePort)
{
    UInt16 port = 8080;

    EXPECT_CALL(*m_stream, GetRemotePort()).Times(1).WillOnce(Return(port));
    UInt16 resPort = seeUserFd->getRemotePort();
    EXPECT_EQ(resPort, port);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getRemoteInetAddress)
 * @brief check getRemoteInetAddress function
 */
TEST_F(TLSSessionEndPointImplTest, getRemoteInetAddress)
{
    std::string              stringAddress = "1:2:3:4:5:6:7:8";
    vwg::tls::SPIInetAddress address       = std::make_shared<IPInetAddressImpl>(stringAddress);

    EXPECT_CALL(*m_stream, GetRemoteAddress()).Times(1).WillOnce(Return(address));
    vwg::tls::SPIInetAddress resAddress = seeUserFd->getRemoteInetAddress();
    EXPECT_EQ(resAddress->toString(), stringAddress);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getUsedAlpnMode)
 * @brief check getUsedAlpnMode function
 */
TEST_F(TLSSessionEndPointImplTest, getUsedAlpnMode)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, getUsedAlpnMode()).Times(1).WillOnce(ReturnRef(ALPN_HTTP2));

    AlpnMode res = seeUserFd->getUsedAlpnMode();
    EXPECT_EQ(res.userDefinedALPNisUsed(), ALPN_HTTP2.userDefinedALPNisUsed());
    EXPECT_EQ(res.getSupportedProtocols(), ALPN_HTTP2.getSupportedProtocols());
    EXPECT_EQ(res.getUserDefinedAlpnSetting(), ALPN_HTTP2.getUserDefinedAlpnSetting());
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, getUsedProtocol)
 * @brief check getUsedAlpnMode function
 */
TEST_F(TLSSessionEndPointImplTest, getUsedProtocol)
{
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, getUsedProtocol()).Times(1).WillOnce(Return(HTTP2));
    EXPECT_EQ(HTTP2, seeUserFd->getUsedProtocol());
}

#ifdef TLSAPI_WITH_DROP_SUPPORT

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, isDroppable)
 * @brief check isDroppable function
 */
TEST_F(TLSSessionEndPointImplTest, isDroppable)
{
    EXPECT_EQ(seeUserFd->isDroppable(), seeUserFd->m_droppable);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, dropTLSFailureNotDroppable)
 * @brief check dropTLS function when it got a failure when TLSSessionEndPointImpl is not droppable
 */
TEST_F(TLSSessionEndPointImplTest, dropTLSFailureNotDroppable)
{
    seeUserFd->m_droppable = false;
    EXPECT_EQ(seeUserFd->dropTLS(), RC_TLS_DROPPING_NOTSUPPORTED);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, dropTLSSuccess)
 * @brief check dropTLS function when it's called successfully
 */
TEST_F(TLSSessionEndPointImplTest, dropTLSSuccess)
{
    seeUserFd->m_droppable = true;

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DropTLS()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    // receive()
    ReceiveCalledTwiceSuccess();

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Close()).Times(1);

    EXPECT_EQ(seeUserFd->dropTLS(), RC_TLS_SUCCESSFUL);

    EXPECT_TRUE(seeUserFd->m_dropInitiated);
    EXPECT_TRUE(seeUserFd->m_dropSendCompleted);
    EXPECT_TRUE(seeUserFd->m_dropReceived);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, dropTLSFailureBlockRead)
 * @brief check dropTLS function when DropTLS engine func returns RC_TLS_ENGINE_WOULD_BLOCK_READ twice, in dropTLS and
 * also in the internal receive call
 */
TEST_F(TLSSessionEndPointImplTest, dropTLSFailureBlockRead)
{
    dropTLSFailureEngineDropFailed(RC_TLS_ENGINE_WOULD_BLOCK_READ);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, dropTLSFailureBlockWrite)
 * @brief check dropTLS function when DropTLS engine func returns RC_TLS_ENGINE_WOULD_BLOCK_WRITE twice, in dropTLS and
 * also in the internal receive call
 */
TEST_F(TLSSessionEndPointImplTest, dropTLSFailureBlockWrite)
{
    dropTLSFailureEngineDropFailed(RC_TLS_ENGINE_WOULD_BLOCK_WRITE);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, dropTLSFailureBlockWrite)
 * @brief check dropTLS function when DropTLS engine func returns some error which is not
 * RC_TLS_ENGINE_WOULD_BLOCK_WRITE or RC_TLS_ENGINE_WOULD_BLOCK_READ
 */
TEST_F(TLSSessionEndPointImplTest, dropTLSFailureSomeError)
{
    seeUserFd->m_droppable = true;

    TLSEngineError someError = RC_TLS_ENGINE_NOT_SUPPORTED;
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DropTLS()).Times(1).WillOnce(Return(someError));
    EXPECT_EQ(seeUserFd->dropTLS(), vwg::tls::impl::EngineToTLSReturnCode(someError));

    EXPECT_TRUE(seeUserFd->m_dropInitiated);
    EXPECT_FALSE(seeUserFd->m_dropSendCompleted);
    EXPECT_FALSE(seeUserFd->m_dropReceived);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, dropTLSReceiveFailed)
 * @brief check dropTLS function when DropTLS engine func succeeds but receive() function fails,
 * and it return some error
 */
TEST_F(TLSSessionEndPointImplTest, dropTLSReceiveFailed)
{
    seeUserFd->m_droppable = true;

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DropTLS()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    TLSEngineError someError = RC_TLS_ENGINE_UNKNOWN_ERROR;

    // receive()
    int32_t actualLengthOutVal = -1;
    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, Receive(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<2>(actualLengthOutVal),
                        Return(someError)));  // actualLength will be less than 0

    EXPECT_EQ(seeUserFd->dropTLS(), EngineToTLSReturnCode(someError));

    EXPECT_TRUE(seeUserFd->m_dropInitiated);
    EXPECT_TRUE(seeUserFd->m_dropSendCompleted);
    EXPECT_FALSE(seeUserFd->m_dropReceived);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, receiveNotDropSendCompleted)
 * @brief check receive function when m_dropSendCompleted is false
 */
TEST_F(TLSSessionEndPointImplTest, receiveNotDropSendCompleted)
{
    const Int32 len         = 2;
    Byte        buffer[len] = {0};

    seeUserFd->m_droppable         = true;
    seeUserFd->m_dropReceived      = true;
    seeUserFd->m_dropSendCompleted = false;

    EXPECT_CALL(*PSKEngineUT::mMockPSKEngine, DropTLS()).Times(1).WillOnce(Return(RC_TLS_ENGINE_SUCCESSFUL));

    EXPECT_EQ(seeUserFd->receive(buffer, len), 0);

    EXPECT_TRUE(seeUserFd->m_dropInitiated);
    EXPECT_TRUE(seeUserFd->m_dropSendCompleted);
}

/**
 * @fn TEST_F(TLSSessionEndPointImplTest, sendWithDropFailure)
 * @brief check send function when m_dropInitiated is true and it fails
 */
TEST_F(TLSSessionEndPointImplTest, sendWithDropFailure)
{
    const Int32  len                  = 2;
    const UInt32 offset               = 1;
    Byte         buffer[len + offset] = {0};

    seeUserFd->m_droppable     = true;
    seeUserFd->m_dropInitiated = true;

    EXPECT_EQ(seeUserFd->send(buffer, offset, len), -1);
    EXPECT_EQ(seeUserFd->getPendingErrors(), RC_TLS_IO_ERROR);
}

#endif  // TLSAPI_WITH_DROP_SUPPORT