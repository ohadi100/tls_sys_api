/**
 * @file TLSResult.h
 * @brief Defines a template struct for returning operation results in the TLS API.
 *
 * TLSResult is used across the TLS API to return operation results. It encapsulates either a payload on success
 * or an error code on failure, providing a mechanism to handle errors and successful outcomes uniformly.
 */

#ifndef SRC_TLSRESULT_H_
#define SRC_TLSRESULT_H_

#include "TLSReturnCodes.h"

namespace vwg {
namespace tls {

/**
 * @brief A template struct that encapsulates the result of an operation, including a return code and a payload.
 *
 * @tparam T The type of the payload contained in the result.
 */
template <class T>
struct TLSResult {
    using TT = TLSResult<T>;

private:
    Boolean        m_isEmpty;     ///< Indicates if the result contains a payload.
    TLSReturnCodes m_rc;          ///< The return code of the operation.
    T              m_payload;     ///< The payload of the operation, valid only if the operation succeeded.

public:
    /**
     * @brief Default constructor. Represents an empty result with an error code.
     */
    TLSResult()
      : m_isEmpty(true), m_rc(RC_TLS_PROGRAMMING_ERROR_RESULT) {};

    /**
     * @brief Constructs a result with an error code.
     * @param code The error code.
     */
    TLSResult(TLSReturnCodes code)
      : m_isEmpty(true), m_rc(code) {};

    /**
     * @brief Constructs a result with a payload.
     * @param payload The payload.
     */
    TLSResult(T payload)
      : m_isEmpty(false), m_rc(RC_TLS_SUCCESSFUL), m_payload(payload) {};

    /**
     * @brief Checks if the operation succeeded.
     * @return True if the operation was successful, otherwise false.
     */
    inline bool succeeded() {
        return (m_rc == RC_TLS_SUCCESSFUL);
    }

    /**
     * @brief Checks if the operation failed.
     * @return True if the operation failed, otherwise false.
     */
    inline bool failed() {
        return !succeeded();
    }

    /**
     * @brief Returns the payload of the operation.
     * @note This operation will assert if the payload is empty.
     * @return The payload.
     */
    T getPayload() {
        assert(!m_isEmpty);
        return m_payload;
    }

    /**
     * @brief Returns the error code of the operation.
     * @return The error code.
     */
    TLSReturnCodes getErrorCode() {
        return m_rc;
    }
};

} // namespace tls
} // namespace vwg

#endif /* SRC_TLSRESULT_H_ */
