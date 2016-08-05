#pragma once

#include <arpa/inet.h>

#include <functional>

using IpmiCleanupCallbackPtr_t = std::function<void (void)>;

/**
 * @brief Class Template SingletonHolder
 *
 * Provides Singleton amenities for a type T
 */
template <typename T>
class SingletonHolder : private T
{
    public:
        /**
         *  @brief Returns static singleton instance.
         *
         *  Only once the static instance is getting created and
         *  is in a thread-safe manner.
         *
         *  @return T&
         *      Static singleton instance (type T)
         *
         */
        static T& Instance()
        {
            static SingletonHolder<T> instance;
            return instance;
        }

    private:
        // Constructor disabled. There is no way to make an instance of a
        // SingletonHolder, the only public function is a static class function
        SingletonHolder() : T() {};
};

namespace endian
{
    namespace details
    {
        template <typename T>
        struct convert
        {
            static T to_ipmi(T) = delete;
            static T from_ipmi(T) = delete;
            static T to_network(T) = delete;
            static T from_network(T) = delete;
        };
        template<> uint16_t convert<uint16_t>::from_ipmi(uint16_t i);
        template<> uint16_t convert<uint16_t>::to_ipmi(uint16_t i);
        template<> uint16_t convert<uint16_t>::from_network(uint16_t i);
        template<> uint16_t convert<uint16_t>::to_network(uint16_t i);
        template<> uint32_t convert<uint32_t>::from_ipmi(uint32_t i);
        template<> uint32_t convert<uint32_t>::to_ipmi(uint32_t i);
        template<> uint32_t convert<uint32_t>::from_network(uint32_t i);
        template<> uint32_t convert<uint32_t>::to_network(uint32_t i);
    }

    template<typename T> T to_ipmi(T i)
    {
        return details::convert<T>::to_ipmi(i);
    }
    template<typename T> T from_ipmi(T i)
    {
        return details::convert<T>::from_ipmi(i);
    }
    template<typename T> T to_network(T i)
    {
        return details::convert<T>::to_network(i);
    }
    template<typename T> T from_network(T i)
    {
        return details::convert<T>::from_network(i);
    }
}

