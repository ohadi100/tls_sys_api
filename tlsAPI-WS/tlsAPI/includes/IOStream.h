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

#ifndef SRC_STREAM_H_
#define SRC_STREAM_H_

#include "vwgtypes.h"

namespace vwg
{
namespace tls
{
using vwg::types::UInt32;

/**
 * \brief Error values for receiving or sending data.
 */
typedef enum {
    RC_STREAM_WOULD_BLOCK = -1,
    RC_STREAM_IO_ERROR    = -2,
} StreamReturnCode;

/**
 * \brief Representation an interface of an I/O stream. Can read, write and close.
 */
class IOStream
{
public:
    IOStream()          = default;
    virtual ~IOStream() = default;

public:
    /**
     * \brief Reads from the stream, up to len bytes.
     * The method blocks until data are available, unless in non-blocking mode.
     *
     * \param[in] buf the buffer to read into
     * \param[in] len length of the buffer, in bytes
     *
     * \return the number of bytes received or the relevant StreamReturnCode error code
     */
    virtual int32_t receive(void* buf, uint32_t len) = 0;

    /**
     * \brief Writes into the stream.
     * The method blocks until data are sent, unless in non-blocking mode.
     *
     * \param[in] buf the buffer to write
     * \param[in] len length of the buffer, in bytes
     *
     * \return the number of bytes sent or the relevant StreamReturnCode error code
     */
    virtual int32_t send(const void* buf, uint32_t len) = 0;

    /**
     * \brief Closes the stream
     */
    virtual void close() = 0;

    /**
     * \brief Check whether the stream is open or not
     *
     * \return true if the stream is open, false otherwise
     */
    virtual bool isOpen() = 0;

    /**
     * \brief Check whether the stream is open or not
     *
     * \return true if the stream is closed, false otherwise
     */
    virtual bool isClosed() = 0;
};


} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_STREAM_H_ */
