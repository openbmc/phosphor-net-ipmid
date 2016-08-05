#ifndef IPMIAPPUTIL_H_
#define IPMIAPPUTIL_H_

#include <arpa/inet.h>

#include <functional>

using IpmiCleanupCallbackPtr_t = std::function<void (void)>;

enum ByteOrder
{
  IPMI,       //Little Endian
  HOST,       //Can be either Little Endian or Big Endian based on Service Processor
  NETWORK,    //Always Big Endian
};

class PacketField16_t {
 public:
  PacketField16_t();

  PacketField16_t(uint16_t i_val, ByteOrder i_byteOrder = HOST);

  ~PacketField16_t();

  uint16_t get(ByteOrder i_byteOrder = HOST);

  void set(uint16_t  i_val, ByteOrder i_byteOrder = HOST);

 private:
  uint16_t iv_var_;
};

class PacketField32_t {
 public:
  PacketField32_t();

  PacketField32_t(uint32_t  i_val, ByteOrder i_byteOrder = HOST);

  ~PacketField32_t();

  uint32_t get(ByteOrder i_byteOrder = HOST);

  void set(uint32_t  i_val, ByteOrder i_byteOrder = HOST);

 private:
  uint32_t iv_var_;
};

/**
 * @brief Class Template SingletonHolder
 *
 * Provides Singleton amenities for a type T
 */
template <typename T>
class SingletonHolder : private T {
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
  static T& Instance() {
    static SingletonHolder<T> instance;
    return instance;
  }

 private:
  // Constructor disabled. There is no way to make an instance of a
  // SingletonHolder, the only public function is a static class function
  SingletonHolder() : T() {};
};

/**
 * @brief Generate specified number of random bytes.
 */
void ipmiGenerateRandomBytes(uint8_t* i_buffer, uint32_t io_numBytes);

#endif /* IPMIAPPUTIL_H_ */
