/**
 * @file Stream.h
 * @brief Defines the IOStream interface for stream-based input and output operations.
 *
 * This header file provides the definition of the IOStream interface, which encapsulates
 * the basic functionalities required for stream-based I/O operations in TLS communications.
 * It includes methods for reading from and writing to the stream, as well as for closing the stream.
 *
 * @copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All the information and materials contained herein, including the
 * intellectual and technical concepts, are the property of CARIAD SE and may
 * be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * This notice does not evidence any actual or intended publication or disclosure
 * of this source code, which includes information that is confidential and/or proprietary
 * and considered trade secrets of CARIAD SE.
 *
 * Any reproduction, modification, distribution, or public display of this source code
 * without the prior written consent of CARIAD SE is strictly prohibited and in violation
 * of applicable laws.
 *
 * Possession of this source code does not convey any rights to reproduce, disclose,
 * or distribute its contents, or to manufacture, use, or sell anything it may describe,
 * in whole or in part.
 */

#ifndef SRC_STREAM_H_
#define SRC_STREAM_H_

#include "vwgtypes.h"

namespace vwg {
namespace tls {
using vwg::types::UInt32;

/**
 * @enum StreamReturnCode
 * @brief Error codes for stream operations.
 *
 * Defines return codes for errors that may occur during data transmission or reception
 * over an IOStream.
 */
typedef enum {
    RC_STREAM_WOULD_BLOCK = -1, /**< Operation would block */
    RC_STREAM_IO_ERROR    = -2, /**< Input/Output error occurred */
} StreamReturnCode;

/**
 * @class IOStream
 * @brief Interface representing an input/output stream.
 *
 * IOStream defines the interface for read, write, and close operations on a data stream.
 * It is typically implemented to handle network or file I/O within secure communication protocols.
 */
class IOStream
{
public:
    IOStream()          = default;
    virtual ~IOStream() = default;

    /**
     * @brief Reads data from the stream into a buffer.
     *
     * Blocks until either some data is available (unless the stream is in non-blocking mode) or
     * an error occurs.
     *
     * @param[out] buf The buffer to read data into.
     * @param[in] len The maximum number of bytes to read.
     * @return The number of bytes read or a StreamReturnCode indicating an error.
     */
    virtual int32_t receive(void* buf, uint32_t len) = 0;

    /**
     * @brief Writes data to the stream from a buffer.
     *
     * Blocks until either all data is sent (unless the stream is in non-blocking mode) or
     * an error occurs.
     *
     * @param[in] buf The buffer containing data to write.
     * @param[in] len The number of bytes to write.
     * @return The number of bytes written or a StreamReturnCode indicating an error.
     */
    virtual int32_t send(const void* buf, uint32_t len) = 0;

    /**
     * @brief Closes the stream, discontinuing any I/O operations.
     */
    virtual void close() = 0;

    /**
     * @brief Checks if the stream is currently open.
     *
     * @return True if the stream is open, false otherwise.
     */
    virtual bool isOpen() = 0;

    /**
     * @brief Checks if the stream is currently closed.
     *
     * @return True if the stream is closed, false otherwise.
     */
    virtual bool isClosed() = 0;
};

} /* namespace tls */
} /* namespace vwg */

#endif /* SRC_STREAM_H_ */
