/**
 * @file Singleton.h
 * 
 * @brief Singleton pattern implementation which restricts class instantiation to a single object.
 * 
 * This design pattern ensures that a class has only one instance and provides a global point of access to it.
 * 
 * @version 1.0
 * 
 * \copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 * All the information and materials contained herein, including the intellectual and technical concepts,
 * are the property of CARIAD SE and may be covered by patents, patents in process, and are protected by
 * trade secret and/or copyright law.
 *
 * The copyright notice above does not evidence any actual or intended publication or disclosure of this
 * source code, which includes information and materials that are confidential and/or proprietary and trade
 * secrets of CARIAD SE.
 *
 * Any reproduction, dissemination, modification, distribution, public performance, public display of, or any
 * other use of this source code and/or any other information and/or material contained herein without the
 * prior written consent of CARIAD SE is strictly prohibited and in violation of applicable laws.
 *
 * The receipt or possession of this source code and/or related information does not convey or imply any rights
 * to reproduce, disclose, or distribute its contents, or to manufacture, use, or sell anything that it may
 * describe in whole or in part.
 */

#ifndef _SINGLETON_H_
#define _SINGLETON_H_

namespace common
{
    /**
     * @class Singleton
     * @brief Templated Singleton class to restrict a class instantiation to one object.
     * 
     * This template class manages the lifecycle of a single instance of a class which is accessed globally.
     * It is designed to be subclassed by classes that wish to implement the singleton pattern.
     * 
     * @tparam T The class type to apply the singleton pattern.
     */
    template<class T>
    class Singleton
    {
    public:
        /**
         * @brief Access the singleton instance of the class.
         * 
         * This function provides a global point of access to the instance of the type T.
         * 
         * @return Reference to the singleton instance of the class T.
         */
        static T& GetInstance();

    protected:
        /**
         * @brief Default constructor.
         * 
         * Protected constructor to prevent instantiation outside of the class itself.
         */
        Singleton() = default;

        /**
         * @brief Destructor.
         * 
         * Virtual destructor to support subclassing.
         */
        virtual ~Singleton() = default;

        /**
         * @brief Copy constructor.
         * 
         * Deleted to prevent copying of the singleton instance.
         */
        Singleton(const Singleton&) = delete;

        /**
         * @brief Copy assignment operator.
         * 
         * Deleted to prevent assignment of the singleton instance.
         */
        void operator=(const Singleton&) = delete;

        /**
         * @brief Static instance of the singleton.
         * 
         * This static member ensures that there is only one instance of T throughout the application.
         */
        static T& m_instance;
    };

    /**
     * @brief Template static member initialization.
     * 
     * Explicit instantiation of the static member variable to ensure it is created.
     */
    template<class T>
    T& Singleton<T>::m_instance = Singleton<T>::GetInstance();

    /**
     * @brief GetInstance function definition.
     * 
     * This function is defined outside the class to avoid linker errors.
     */
    template<class T>
    T& Singleton<T>::GetInstance()
    {
        static T instance;
        return instance;
    }

} // namespace common

#endif // _SINGLETON_H_
