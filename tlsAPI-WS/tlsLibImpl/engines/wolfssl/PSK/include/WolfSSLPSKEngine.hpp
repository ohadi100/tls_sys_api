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

#ifndef SACCESSLIB_WOLFSSLPSKENGINE_HPP
#define SACCESSLIB_WOLFSSLPSKENGINE_HPP

#include <functional>
#include <string>
#include <vector>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "IOStreamIf.hpp"
#include "TLSEngine.hpp"

namespace vwg
{
namespace tls
{
namespace impl
{

/**
* @class   WolfSSLEngine
* @brief   The WolfSSLEngine is the WolfSSL implementation of TLSEngine.
*/
class WolfSSLPSKEngine : public TLSEngine
{
public:

    /**
     * @brief   Constructor.
     * @param   stream - the underlying IOStreamIf used by the engine to perform actual input/output.
     * @param   context - the shared context for the engine.
     * @param   ssl - the ssl object for the engine.
     * @return  None.
     */
    WolfSSLPSKEngine(const std::shared_ptr<IOStreamIf> &stream, bool isServer, const std::string &hint, SecurityLevel confidentiality);

    /**
     * @brief   Destructor. Calls WolfSSLEngine::Close().
     * @param   None.
     * @return  None.
     */
    virtual ~WolfSSLPSKEngine();

    /**
     * @brief   Perform the TLS handshake, according to the arguments provided in the constructor. Also
     *          initializes some WolfSSL memory constructs.
     * @param   None.
     * @return  None.
     */
    virtual TLSEngineError DoSSLHandshake() override;

    /**
     * @brief   Send a buffer to the other side.
     * @param   buffer - an unencrypted buffer of size 'length', which will be encrypted and sent through the
     *          underlying (inheriting) TLS engine. This argument must be pre-allocated (either statically or
     *          dynamically) by the callee.
     * @param   bufLength - length of unencrypted buffer.
     * @param   actualLength - length of unencrypted buffer actually sent.
     * @return  True of successful, false otherwise.
     */
    virtual TLSEngineError Send(const uint8_t *data, int32_t bufLength, int32_t &actualLength) override;

    /**
     * @brief   Receive a buffer from the other side.
     * @param   buffer - a buffer of size 'bufLength' to receive the data. 'buffer' should be pre-allocated (either
     *          statically or dynamically) by the callee.
     * @param   bufLength - length of buffer.
     * @param   actualLength - length of unencrypted buffer actually read.
     * @return  True of successful, false otherwise.
     */
    virtual TLSEngineError Receive(uint8_t *buffer, int32_t bufLength, int32_t &actualLength) override;

    virtual TLSEngineError SetBlocking(bool blocking) override;

    virtual TLSEngineError Shutdown() override;

#ifdef TLSAPI_WITH_DROP_SUPPORT

    virtual TLSEngineError DropTLS() override;

#endif

    const std::string GetRemoteHintName() const override;

    const std::string GetHintName() const override;

    /**
     * @brief   Close the underlying TLS connection and release any resources that are used by WolfSSL.
     * @param   None.
     * @return  None.
     */
    virtual void Close() override;

    virtual const AlpnMode& getUsedAlpnMode() const  override;

    virtual IANAProtocol getUsedProtocol() const  override;
#ifndef UNIT_TEST
private:
#endif
    TLSEngineError WolfSSLToEngineError();
    TLSEngineError ctxInit();

    /** m_ctx and m_ssl cannot be unique_ptr because wolfssl does not allow direct access to the internal structures
     * and it must have access to the pointer
     */
    std::shared_ptr<WOLFSSL_CTX> m_ctx;
    std::shared_ptr<WOLFSSL> m_ssl;

    pskData m_keys;
    bool m_isServer;
    SecurityLevel m_confidentiality;
    bool m_isDropped;
 };

} // namespace impl
} // namespace tls
} // namespace vwg

#endif //SACCESSLIB_WOLFSSLPSKENGINE_HPP