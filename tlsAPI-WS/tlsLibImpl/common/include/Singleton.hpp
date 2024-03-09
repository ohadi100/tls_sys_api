/**
 * 
 * @file        Singelton.
 * 
 * @brief       This singleton pattern is a design pattern that restricts the instantiation of a class to one object.
 * 
 * @version     1.0
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


#ifndef _SINGLETON_H_
#define _SINGLETON_H_

namespace common
{

/**
 * This singleton pattern is a design pattern that restricts the instantiation of a class to one object.
 */

/**
 * @class   Singleton
 * @brief   Implementing a singleton interface class.
 *          A class that wants to implement the singleton interface needs to inherit from this class
 *          and make it a friend class.
 */
template<class T>
class Singleton
{
public:
    /**
     * @brief   Getter function to call whenever the user wants access to the 'T' object.
     * @param   none.
     * @return  A reference to the inner T object.
     */
    static T & GetInstance();

protected:
    /**
     * @brief   Deleted copy constructor.
     * @param   Other Singleton object to copy from
     * @return  none.
     */
    Singleton(const Singleton &) = delete;

    /**
     * @brief   Deleted assignment operator
     * @param   Other Singleton object to copy from.
     * @return  none.
     */
    void operator=(const Singleton &) = delete;

    /**
     * @brief   Deleted default constructor.
     * @param   none.
     * @return  none.
     */
    /**
     * A protected constructor ensures that the class will never be instantiated outside the class.
     * The 'T' object will be given to the user only by calling to 'GetInstance()'.
     */
    Singleton() = default;

    /**
     * @brief   Deleted destructor.
     * @param   none.
     * @return  none.
     */
    virtual ~Singleton() = default;

    /**
     * This 'm_instance' is used for explicit instantiation of 'T' object by calling to 'GetInstance()'
     * which instantiates 'static T t' once and only (due to the 'static' declaration).
     * This explicit instantiation at compile time is necessary to avoiding race conditions with the first
     * instantiation of 'static T t' inside 'GetInstance()'.
     * This object is 'protected' so it is never used by the user outside this class.
     */
    static T & m_instance;
};


/////////////////////////////////////////////////////////////////////////////////////
////////////////////////// Templates functions definitions //////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

template<class T>
// static
T & Singleton<T>::GetInstance()
{
    // Instantiate 'T' instance when the function is first called. Since 't' is static, there's only one occurence
    // of it.
    static T t;
    return static_cast<T &>(t);
}


// This explicit instantiation is used to instantiate the static 'T' object 't' inside 'GetInstance()'.
template<class T>
T & Singleton<T>::m_instance = Singleton<T>::GetInstance();

} // namespace common

#endif // _SINGLETON_H_
