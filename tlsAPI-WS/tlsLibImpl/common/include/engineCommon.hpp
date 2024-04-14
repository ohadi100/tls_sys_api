/**
 * @file    SetIntersection.hpp
 *
 * @brief   Checks for common elements between two sets.
 *
 * This header file contains a function to determine if there is at least one common element between two sets of characters.
 *
 * @version 1.0
 * 
 * \copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All the information and materials contained herein, including the intellectual and technical concepts,
 * are the property of CARIAD SE and may be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * The copyright notice above does not evidence any actual or intended publication or disclosure of this source code,
 * which includes information and materials that are confidential and/or proprietary and trade secrets of CARIAD SE.
 *
 * Any reproduction, dissemination, modification, distribution, public performance, public display of or any other use
 * of this source code and/or any other information and/or material contained herein without the prior written consent
 * of CARIAD SE is strictly prohibited and in violation of applicable laws.
 *
 * The receipt or possession of this source code and/or related information does not convey or imply any rights
 * to reproduce, disclose or distribute its contents or to manufacture, use or sell anything that it may describe
 * in whole or in part.
 */

#include <vector>

/**
 * @brief Checks if there is at least one common element between two sets.
 * 
 * This function iterates over two sets of vectors of characters and determines if they share at least one common member.
 * 
 * @param A The first set of elements (vector of vectors of chars).
 * @param B The second set of elements (vector of vectors of chars).
 * @return true if at least one common element is found, false otherwise.
 */
bool atLeastOneCommonMember(std::vector<std::vector<char>> const& A, std::vector<std::vector<char>> const& B);
