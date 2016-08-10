#include <ipmiMessageParsers.H>
#include <ipmiSessionsManager.H>
#include <memory>
#include <iostream>

IpmiMessageParser* IpmiMessageParser::getParser(uint8_t* i_pkt, uint32_t i_pktLen) {
  IpmiMessageParser* l_parser = nullptr;

  do {
    BasicHeader_t* l_pRmcppHeadersPtr = reinterpret_cast<BasicHeader_t*>(i_pkt);
    uint32_t l_packetLengthCheck = 0;

    //********************************************************************//
    // Verify that the RMCP Header is correct
    //********************************************************************//
    //Expect the packet to have atleast the RMCP header
    l_packetLengthCheck = sizeof(BasicHeader_t);
    if (i_pktLen < l_packetLengthCheck) {
      break;
    }

    //Verify if the fields in the RMCP header conforms to our expectations
    if ((l_pRmcppHeadersPtr->version != 0x06) ||
      (l_pRmcppHeadersPtr->rmcpSeqNum != 0xFF) ||
      (l_pRmcppHeadersPtr->classOfMsg != 0x07)) {
      break;
    }

    //********************************************************************//
    // Verify that length of IPMI Session Header is correct for given type
    //********************************************************************//

    //Read the Auth Type/Format field and check if the packet length is
    //correct.
    switch (l_pRmcppHeadersPtr->format.formatType) {
      case IPMI_AUTHTYPE_FORMAT_IPMI15_NONE: {
        l_parser = new Ipmi15Parser;
        break;
      }
      case IPMI_AUTHTYPE_FORMAT_IPMI20: {
        l_parser = new Ipmi20Parser;
        break;
      }
      default: {
        break;
      }
    }
  } while (0);

  return l_parser;
}

Ipmi15Parser::Ipmi15Parser() {}

Ipmi15Parser::~Ipmi15Parser() {}

uint32_t Ipmi15Parser::getPacketSize(IpmiMessage* i_msg) {
  uint32_t l_pktSize = 0;

  if (i_msg) {
    SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(i_msg->getPacket());
    l_pktSize += sizeof(SessionHeader_t);
    l_pktSize += l_hdr->payloadLength;
  }

  return l_pktSize;
}

PacketField32_t Ipmi15Parser::getSessionID(IpmiMessage* i_msg) {
  PacketField32_t l_sessionID;

  if (i_msg) {
    SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(i_msg->getPacket());
    l_sessionID.set(l_hdr->sessId,IPMI);
  }

  return l_sessionID;
}

bool Ipmi15Parser::unflatten(IpmiMessage* i_msg) {
  if (i_msg) {
    SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(i_msg->getPacket());

    i_msg->setPayloadType(IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI);
    PacketField32_t l_var(l_hdr->sessId,IPMI);
    i_msg->setSessionId(l_var);
    l_var.set(l_hdr->sessSeqNum,IPMI);
    i_msg->setSessionSeqNum(l_var);
    i_msg->setIsPacketEncrypted(false);
    i_msg->setIsPacketAuthenticated(false);
    i_msg->setPayload((i_msg->getPacket())+sizeof(SessionHeader_t),false);
    PacketField16_t l_payloadLen(l_hdr->payloadLength); //Deliberately not
                             //adding in IPMI order because here its just a byte
    i_msg->setPayloadLength(l_payloadLen);
    i_msg->setIntegrityData(nullptr,false); //No integrity data handled for IPMI1.5
    i_msg->setIntegrityDataLength(0);
    }

  return true;
}

bool Ipmi15Parser::flatten(IpmiMessage* i_msg) {
  if (i_msg) {
    //Allocate memory to read the packet into
    uint8_t* l_pkt = new uint8_t[IpmiMessage::IPMI_MESSAGE_MAX_PACKET_LENGTH];
    uint32_t l_pktLength = 0;

    SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(l_pkt);
    l_hdr->base.version = 0x06;
    l_hdr->base.reserved = 0x00;
    l_hdr->base.rmcpSeqNum = 0xFF;
    l_hdr->base.classOfMsg = 0x07;
    l_hdr->base.format.formatType = static_cast<uint8_t>(IPMI_AUTHTYPE_FORMAT_IPMI15_NONE);

    l_hdr->sessSeqNum = 0;
    l_hdr->sessId = i_msg->getSessionId().get(IPMI);
    l_hdr->payloadLength = static_cast<uint8_t>(i_msg->getPayloadLength().get());

    l_pktLength += sizeof(SessionHeader_t);
    memcpy(l_pkt+l_pktLength,i_msg->getPayload(),l_hdr->payloadLength);
    l_pktLength += l_hdr->payloadLength;
    (reinterpret_cast<SessionTrailer_t*>(l_pkt+l_pktLength))->legacyPad = 0x00;
    l_pktLength += sizeof(SessionTrailer_t);

    i_msg->setPacket(l_pkt,true);
    i_msg->setPacketLength(l_pktLength);

    std::cout<<"I> Ipmi15Parser::flatten i_msg->getPacketLength "<<i_msg->getPacketLength()
                                                                <<std::endl;
  }

  return true;
}

Ipmi20Parser::Ipmi20Parser() {}

Ipmi20Parser::~Ipmi20Parser() {}

uint32_t Ipmi20Parser::getPacketSize(IpmiMessage* i_msg) {
  enum
  {
    SIZEOF_RMCP_HEADER = 4,
    SIZEOF_SESS_TRLR_USED_IN_INTG_CHECK = 2,
  };

  uint32_t l_pktSize = 0;

  if (i_msg) {
    uint8_t* l_packet = i_msg->getPacket();
    SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(l_packet);

    l_pktSize += sizeof(SessionHeader_t);

    PacketField16_t l_payload(l_hdr->payloadLength,IPMI);
    l_pktSize += l_payload.get();

    if (l_hdr->payloadType & 0x40) {
      //If packet is authenticated, check for Integrity Pad .. which can be utmost 3 bytes
      uint32_t l_intgPad = ((4 - ((l_payload.get()+2)%4))%4);

      l_pktSize += l_intgPad;
      l_pktSize += sizeof(SessionTrailer_t);
    }
  }

  return l_pktSize;
}

PacketField32_t Ipmi20Parser::getSessionID(IpmiMessage* i_msg) {
  PacketField32_t l_sessionID = 0;

  if (i_msg) {
    SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(i_msg->getPacket());
    l_sessionID.set(l_hdr->sessId,IPMI);
  }

  return l_sessionID;
}

bool Ipmi20Parser::unflatten(IpmiMessage* i_msg) {
  bool l_ret = false;

  do {
    if (i_msg) {
      //************************************************************//
      //Actual unflatten
      //************************************************************//
      uint8_t* l_packet = i_msg->getPacket();
      SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(l_packet);

      i_msg->setPayloadType((l_hdr->payloadType & 0x3F));
      PacketField32_t l_var(l_hdr->sessId,IPMI);
      i_msg->setSessionId(l_var);
      l_var.set(l_hdr->sessSeqNum,IPMI);
      i_msg->setSessionSeqNum(l_var);
      i_msg->setIsPacketEncrypted( (l_hdr->payloadType & 0x80)? true:false);
      i_msg->setIsPacketAuthenticated( (l_hdr->payloadType & 0x40)? true:false);
      i_msg->setPayload((i_msg->getPacket())+sizeof(SessionHeader_t),false);
      PacketField16_t l_payload(l_hdr->payloadLength,IPMI);
      i_msg->setPayloadLength(l_payload);
      l_packet += sizeof(SessionHeader_t) + l_payload.get();

      //If packet is authenticated, check for Integrity Pad .. which
      //can be utmost 3 bytes
      uint8_t l_padLen = 0;
      if (l_hdr->payloadType & 0x40) {
        l_padLen = (4 - ((l_payload.get()+2)%4))%4;
      }

      l_packet += l_padLen;

      SessionTrailer_t* l_trl = reinterpret_cast<SessionTrailer_t*>(l_packet);
      i_msg->setIntegrityData(l_trl->authCode,false);
      i_msg->setIntegrityDataLength(MAX_INTEGRITY_DATA_LENGTH);

      //************************************************************//
      //Check if packet passes through sliding window filter
      //************************************************************//
      l_ret = checkSlidingWindowFilter(i_msg);
      if (l_ret == false) {
        //Message fails the sliding window check
        break;
      }

      //************************************************************//
      //Check if packet passes the integrity check filter
      //************************************************************//
      l_ret = checkPacketIntegrity(i_msg);
      if (l_ret == false) {
        //Message fails the integrity check
        break;
      }

      //************************************************************//
      //Decrypt the payload
      //************************************************************//
      l_ret = decryptPayload(i_msg);
      if (l_ret == false) {
        //Message decryption fails
        break;
      }
    }
  } while(0);

  return l_ret;
}

bool Ipmi20Parser::flatten(IpmiMessage* i_msg) {
  std::cout<<">> Ipmi20Parser::flatten "<<std::endl;
  bool l_ret = false;

  if (i_msg)
    do {
      //Allocate memory to read the packet into.
      uint8_t* l_pkt = new uint8_t[IpmiMessage::IPMI_MESSAGE_MAX_PACKET_LENGTH];
      uint32_t l_pktLength = 0;
      i_msg->setPacket(l_pkt,true);
      i_msg->setPacketLength(l_pktLength);

      SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(l_pkt);
      l_hdr->base.version = 0x06;
      l_hdr->base.reserved = 0x00;
      l_hdr->base.rmcpSeqNum = 0xFF;
      l_hdr->base.classOfMsg = 0x07;
      l_hdr->base.format.formatType = static_cast<uint8_t>(IPMI_AUTHTYPE_FORMAT_IPMI20);
      l_hdr->payloadType = i_msg->getPayloadType();
      l_hdr->sessId = i_msg->getSessionId().get(IPMI);

      //************************************************************//
      //Add session sequence number
      //************************************************************//
      l_ret = addSequenceNumber(i_msg);
      if (l_ret == false) {
        // fails
        break;
      }

      l_hdr->payloadLength = i_msg->getPayloadLength().get(IPMI);
      l_pktLength += sizeof(SessionHeader_t);
      i_msg->setPacketLength(l_pktLength);

      //************************************************************//
      //Encrypt the Payload
      //************************************************************//
      l_ret = encryptPayload(i_msg);
      if (l_ret == false) {
        //Message encryption fails
        break;
      }

      //Payload length changes if the packet was encrypted
      l_hdr->payloadLength = i_msg->getPayloadLength().get(IPMI);
      memcpy(l_pkt+l_pktLength,i_msg->getPayload(),i_msg->getPayloadLength().get());
      l_pktLength += i_msg->getPayloadLength().get();

      //************************************************************//
      //Add integrity data
      //************************************************************//
      //Padding aligned for 4 byte boundary & 2 is size of trailer minus
      //authCode
      uint32_t l_intgPadCount = (4 - ((i_msg->getPayloadLength().get()+2)%4))%4;

      for (uint32_t l_itor = 0; l_itor < l_intgPadCount ; ++l_itor,++l_pktLength) {
      *(l_pkt+l_pktLength) = 0xFF;
      }

      SessionTrailer_t* l_trl = reinterpret_cast<SessionTrailer_t*>(l_pkt+l_pktLength);
      l_trl->padLength = l_intgPadCount;
      l_trl->nextHeader = 0x07;
      l_pktLength += 2;

      i_msg->setPacketLength(l_pktLength);

      l_ret = addIntegrityData(i_msg);
      if (l_ret == false) {
        //fails
        break;
      }

      memcpy(l_pkt+l_pktLength,i_msg->getIntegrityData(),i_msg->getIntegrityDataLength());
      l_pktLength += i_msg->getIntegrityDataLength();
      i_msg->setPacketLength(l_pktLength);

      std::cout<<"I> Ipmi20Parser::flatten i_msg->getPacketLength "<<i_msg->getPacketLength()
                                                                   <<std::endl;
    } while (0);

  std::cout<<"<< Ipmi20Parser::flatten "<<std::endl;
  return l_ret;
}


//TRUE implies test passed .. FALSE implies contrary
bool Ipmi20Parser::checkSlidingWindowFilter(IpmiMessage* i_msg) {
  return true;
}

bool Ipmi20Parser::addSequenceNumber(IpmiMessage* i_msg) {
  bool l_retVal = true;

  SessionHeader_t* l_hdr = reinterpret_cast<SessionHeader_t*>(i_msg->getPacket());

  if(l_hdr->sessId == 0x00) {
    l_hdr->sessSeqNum = 0x00;
  } else {
    std::shared_ptr<IpmiSession> l_pSess = IpmiSessionsManager::getInstance().getSession(
                                i_msg->getSessionId().get(),
                                IpmiSessionsManager
                                  ::IPMI_SESSION_RETRIEVE_OPTION_RC_SESSION_ID );

    if(l_pSess.get()) {
      bool l_authenticated = false;

      if (l_pSess->getSessionCipherSuite().getIntegrityCipher()
         &&(l_pSess->getSessionCipherSuite().getIntegrityCipher()->getState())
         &&(l_pSess->getSessionCipherSuite().getIntegrityCipher()->getApplied() > 0)) {
        l_authenticated = true;
      } else {
        l_authenticated = false;
      }

      PacketField32_t l_seqNum(l_pSess->getSessionState().incrementSequenceNumber(l_authenticated));
      l_hdr->sessSeqNum = l_seqNum.get(IPMI);
    } else {
      l_retVal = false;
    }
  }
  return l_retVal;
}

bool Ipmi20Parser::checkPacketIntegrity(IpmiMessage* i_msg) {
  bool l_ret = false;

  std::shared_ptr<IpmiSession> l_pSession = IpmiSessionsManager::getInstance().getSession
                                                            (i_msg->getSessionId().get());

  if (!l_pSession) {
    l_ret = false;
  } else {
    if(i_msg->getIsPacketAuthenticated()) {
      IpmiSessionKeys* l_keys = &(l_pSession->getSessionCipherSuite().getSessionKeys());
      l_ret = l_pSession->getSessionCipherSuite().getIntegrityCipher()->verifyIntegrityData
                                                                            (l_keys,i_msg);
    } else {
      l_ret = true;
    }
  }

  return l_ret;
}

bool Ipmi20Parser::addIntegrityData(IpmiMessage* i_message) {
  bool l_ret = true;

  std::shared_ptr<IpmiSession> l_pSession = IpmiSessionsManager::getInstance().getSession(
          i_message->getBmcSessionId().get(),
          IpmiSessionsManager::IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID);

  if (l_pSession == nullptr) {
    //If there is no session
    l_ret = false;
  } else {
    l_ret = true;
    if (i_message->getSessionId().get() == 0x00) {
      //If we are on session 0
    } else if (!l_pSession->getSessionCipherSuite().getIntegrityCipher()->getState()) {
      //If the Integrity cipher for this session is not ON
    } else {
      IpmiSessionKeys* l_keys = &(l_pSession->getSessionCipherSuite().getSessionKeys());
      l_pSession->getSessionCipherSuite().getIntegrityCipher()->generateIntegrityData
                                                                (l_keys,i_message);
    }
  }

  return l_ret;
}

bool Ipmi20Parser::decryptPayload(IpmiMessage* i_msg) {
  bool l_ret = false;

  std::shared_ptr<IpmiSession> l_pSession = IpmiSessionsManager::getInstance().getSession
                                                            (i_msg->getSessionId().get());

  if (l_pSession == nullptr) {
    l_ret = false;
  } else {
    l_ret = true;
    if (i_msg->getIsPacketEncrypted()) {
      IpmiSessionKeys* l_keys = &(l_pSession->getSessionCipherSuite().getSessionKeys());
      l_pSession->getSessionCipherSuite().getConfidentialityCipher()->decryptData(l_keys,i_msg);
    }
  }

  return l_ret;
}

bool Ipmi20Parser::encryptPayload(IpmiMessage* i_msg) {
  bool l_ret = true;

  std::shared_ptr<IpmiSession> l_pSession = IpmiSessionsManager::getInstance().getSession(
          i_msg->getBmcSessionId().get(),
          IpmiSessionsManager::IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID);

  if (l_pSession == nullptr) {
    //If there is no session
    l_ret = false;
  } else {
    l_ret = true;
    if (i_msg->getSessionId().get() == 0x00) {
      //If we are on session 0
    } else if ( !l_pSession->getSessionCipherSuite().getConfidentialityCipher()->getState()) {
      //If the Confidentiality cipher for this session is not ON
    } else {
      IpmiSessionKeys* l_keys = &(l_pSession->getSessionCipherSuite().getSessionKeys());
      l_pSession->getSessionCipherSuite().getConfidentialityCipher()->encryptData(l_keys,i_msg);
    }
  }

  return l_ret;
}

