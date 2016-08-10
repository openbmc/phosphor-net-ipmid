#ifndef IPMIMESSAGEPARSERS_H_
#define IPMIMESSAGEPARSERS_H_

#include <ipmiMessage.H>

class Ipmi15Parser : public IpmiMessageParser {
 public:

#pragma pack(1)
  struct SessionHeader_t {
    struct BasicHeader_t base;
    uint32_t sessSeqNum;
    uint32_t sessId;
    //<Optional Field: AuthCode>
    uint8_t payloadLength;
  };

  struct SessionTrailer_t {
    uint8_t legacyPad;
  };
#pragma pack()

  Ipmi15Parser();
  virtual ~Ipmi15Parser();

  virtual uint32_t getPacketSize(IpmiMessage* i_msg);

  virtual PacketField32_t getSessionID(IpmiMessage* i_msg);

  virtual bool unflatten(IpmiMessage* i_msg);

  virtual bool flatten(IpmiMessage* i_msg);
};

class Ipmi20Parser : public IpmiMessageParser {
 public:
  enum Ipmi20ParserDefines
  {
    MAX_INTEGRITY_DATA_LENGTH = 12,
    IPMI_SHA1_AUTHCODE_SIZE = 12,
    IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE = 0x10,
};

#pragma pack(1)
  struct SessionHeader_t
  {
    struct BasicHeader_t base;

    uint8_t payloadType;

    uint32_t sessId;
    uint32_t sessSeqNum;
    uint16_t payloadLength;
};

  struct SessionTrailer_t
  {
    //Integrity Pad
    uint8_t padLength;
    uint8_t nextHeader;
    uint8_t authCode[MAX_INTEGRITY_DATA_LENGTH];//AuthCode (Integrity Data)
  };
#pragma pack()

  Ipmi20Parser();
  virtual ~Ipmi20Parser();

  virtual uint32_t getPacketSize(IpmiMessage* i_msg);

  virtual PacketField32_t getSessionID(IpmiMessage* i_msg);

  virtual bool unflatten(IpmiMessage* i_msg);

  virtual bool flatten(IpmiMessage* i_msg);

 protected:
    //TRUE implies test passed .. FALSE implies contrary
    bool checkSlidingWindowFilter(IpmiMessage* i_msg);

    bool addSequenceNumber(IpmiMessage* i_msg);

    bool checkPacketIntegrity(IpmiMessage* i_msg);

    bool addIntegrityData(IpmiMessage* i_message);

    bool decryptPayload(IpmiMessage* i_msg);
    bool encryptPayload(IpmiMessage* i_msg);
};

#endif /* IPMIMESSAGEPARSERS_H_ */
