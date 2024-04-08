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

#ifndef SRC_TLSRESULT_H_
#define SRC_TLSRESULT_H_

#include <TLSReturnCodes.h>
#include <memory>
#include <cassert>

#include "vwgtypes.h"


using namespace vwg::types;

namespace vwg
{
namespace tls
{
/**
 * \brief  This is a struct to return the return code or the value in case the operation is performed successful.
 * Basically it will take a payload or an return code. One can assume that the paylod is empty if the operation failed.
 * One have to use failed or succeeded first to check if the payload is set or not first.
 * Currently it is assumed that the access of a empty payload will fail and an error is raised.
 */
template <class T>
struct TLSResult {
    using TT = TLSResult<T>;

private:
    Boolean        m_isEmpty;
    TLSReturnCodes m_rc;
    T              m_payload;

public:
    TLSResult()
      : m_isEmpty(true)
      , m_rc(RC_TLS_PROGRAMMING_ERROR_RESULT){};

    TLSResult(TLSReturnCodes code)
      : m_isEmpty(true)
      , m_rc(code){};

    TLSResult(T payload)
      : m_isEmpty(false)
      , m_rc(RC_TLS_SUCCESSFUL)
      , m_payload(payload){

        };


    TT&
    operator=(const TT& other)
    {
        // check for self-assignment
        if (&other == this)
            return *this;

        this->m_isEmpty = other.m_isEmpty;
        this->m_rc      = other.m_rc;
        if (!m_isEmpty) {
            this->m_payload = other.m_payload;
        }
        return *this;
    }


    /**
     * \brief Checks if the operation failed.
     *
     * \return true if operation failed and the payload is empty.
     */
    inline bool
    failed()
    {
        return !succeeded();
    };

    /**
     * \brief Checks if the operation failed.
     *
     * \return true if operation failed and the payload is not empty.
     */
    inline bool
    succeeded()
    {
        return (m_rc == RC_TLS_SUCCESSFUL);
    }

    /**
     * \brief Gets the payload.
     * <b>Caution!</> this will raise an error if the payload is empty. please check the result with failed and
     * succeeded before hand.
     *
     * \return the payload.
     */
    T
    getPayload()
    {
        assert(!m_isEmpty);
        return m_payload;
    }

    /**
     * \brief Gets the error code.
     *
     * \return the error code.
     */
    TLSReturnCodes
    getErrorCode()
    {
        return m_rc;
    }
};


} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_TLSRESULT_H_ */
