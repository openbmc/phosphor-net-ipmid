#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ipmiCiphers.H>
#include <ipmiMessageParsers.H>
#include <ipmiAppUtil.H>
#include <ipmiSession.H>
#include <iostream>
#include <string>

IpmiAuthenticationAlgoNone::IpmiAuthenticationAlgoNone()
{
}

IpmiAuthenticationAlgoNone::~IpmiAuthenticationAlgoNone()
{
}


void IpmiAuthenticationAlgoNone::generateKeyExchangeAuthCode_RAKP2(
                                               IpmiSessionKeys* i_sessionSlot,
                                               const uint8_t*   i_input,
                                               uint32_t         i_inputLength,
                                               uint8_t*         o_key,
                                               uint32_t&        o_keyLength)
{
    uint8_t l_key[20] = {};
    uint32_t l_keyLength = 20;
    i_sessionSlot->getUserKey(l_key,l_keyLength);

    HMAC(EVP_sha1(),l_key,l_keyLength,i_input,i_inputLength, o_key,&o_keyLength);
}

//Returns False if verification fails
bool IpmiAuthenticationAlgoNone::verifyKeyExchangeAuthCode_RAKP3(
                                                IpmiSessionKeys* i_sessionKeys,
                                                uint8_t* i_key,
                                                uint32_t i_keyLength)
{    return true;
}

void IpmiAuthenticationAlgoNone::generateSessionIntegrityKey_RAKP3(
                                                IpmiSessionKeys* i_sessionSlot)
{

}

void IpmiAuthenticationAlgoNone::generateIntegrityCheckValue_RAKP4(
                                               IpmiSessionKeys* i_sessionSlot,
                                               uint8_t*& o_key,
                                               uint32_t& o_keyLength)
{

}


IpmiIntegrityAlgoNone::IpmiIntegrityAlgoNone()
{

}

IpmiIntegrityAlgoNone::~IpmiIntegrityAlgoNone()
{

}

void IpmiIntegrityAlgoNone::generateIntegrityData(IpmiSessionKeys* i_sessionSlot,
                                                  IpmiMessage* i_message)
{

}

bool IpmiIntegrityAlgoNone::verifyIntegrityData(IpmiSessionKeys* i_sessionSlot,
                                                IpmiMessage* i_message)
{
    return true;
}

IpmiIntegrityAlgoHmacSha1_96::IpmiIntegrityAlgoHmacSha1_96()
{

}

IpmiIntegrityAlgoHmacSha1_96::~IpmiIntegrityAlgoHmacSha1_96()
{

}

void Ipmi_GenerateIntegrityCode(uint8_t* i_buffer,
                                 uint16_t i_len,
                                 uint8_t* o_buffer,
                                 uint32_t &o_len,
                                 IpmiSessionKeys* i_sessionSlot)
{
    if(!i_sessionSlot || i_buffer == nullptr ) return;

    uint8_t k1_buffer[SHA_DIGEST_LENGTH];
    uint32_t k1_length = 0;
    uint32_t gen_len = 0;

    uint8_t l_sik_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_sik_hmacBuflen = sizeof(l_sik_hmacBuffer);

    i_sessionSlot->getSIK(l_sik_hmacBuffer,l_sik_hmacBuflen);

    uint8_t CONST_1[] =  {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    HMAC(EVP_sha1(), l_sik_hmacBuffer, l_sik_hmacBuflen, CONST_1, 20, k1_buffer, &k1_length);

    HMAC(EVP_sha1(), k1_buffer, k1_length, i_buffer, i_len, o_buffer, &gen_len);

    o_len = gen_len;

}

void IpmiIntegrityAlgoHmacSha1_96::generateIntegrityData(IpmiSessionKeys* i_sessionSlot,
                                                  IpmiMessage* i_message)
{
    Ipmi20Parser::SessionHeader_t* l_hdr = reinterpret_cast<Ipmi20Parser::SessionHeader_t*>(i_message->getPacket());
    l_hdr->payloadType = (l_hdr->payloadType | 0x40);

    uint8_t* l_pOutgoingPacket = i_message->getPacket();
    uint32_t l_lanMsgLength = i_message->getPacketLength();

    uint8_t generated_authcode[SHA_DIGEST_LENGTH] = {};
    uint32_t gen_auth_len = 0;

    Ipmi_GenerateIntegrityCode(l_pOutgoingPacket + 4,  //Skip RMCP Hdr
                               l_lanMsgLength - 4,
                               generated_authcode,
                               gen_auth_len,
                               i_sessionSlot);

    uint8_t* l_intgData = new uint8_t[gen_auth_len];
    memcpy(l_intgData,generated_authcode,gen_auth_len);
    i_message->setIntegrityData(l_intgData,true);
    i_message->setIntegrityDataLength(12);
    return;
}

bool IpmiIntegrityAlgoHmacSha1_96::verifyIntegrityData(IpmiSessionKeys* i_sessionSlot,
                                                IpmiMessage* i_message)
{
    if( ! i_message->getIsPacketAuthenticated() )
    {
        return true;
    }

    const uint32_t IPMI_SESSION_HEADER_AUTH_TYPE_OFFSET = 4;
    const uint32_t IPMI_SESSION_TRAILER_SIZE=2;
    const uint32_t IPMI_SESSION_HEADER_SIZE=12;

    bool l_valid = false;

    uint8_t generated_authcode[SHA_DIGEST_LENGTH] = {};
    uint32_t gen_auth_len= 0;

    uint8_t* l_pReceivedMsg = i_message->getPacket();

    uint32_t l_RcvMsgLength = i_message->getPayloadLength().get();
    l_RcvMsgLength += IPMI_SESSION_HEADER_SIZE;
    l_RcvMsgLength += (4 - ((i_message->getPayloadLength().get()+2)%4)); //Pad bytes
    l_RcvMsgLength += IPMI_SESSION_TRAILER_SIZE;

    Ipmi_GenerateIntegrityCode(l_pReceivedMsg + IPMI_SESSION_HEADER_AUTH_TYPE_OFFSET,
                               l_RcvMsgLength ,
                               generated_authcode,
                               gen_auth_len,
                               i_sessionSlot);

    uint8_t * bmc_authcode = i_message->getIntegrityData();

    int value = memcmp(bmc_authcode, generated_authcode, 12);
    if (value == 0)
        l_valid = true;
    else
    {
        std::cerr<<"E> IPMI Packet Integrity Verification failed"<<std::endl;
        l_valid = false;
    }

    return l_valid;
}

IpmiConfidentialityAlgoNone::IpmiConfidentialityAlgoNone()
{
}

IpmiConfidentialityAlgoNone::~IpmiConfidentialityAlgoNone()
{

}

void IpmiConfidentialityAlgoNone::encryptData(IpmiSessionKeys* i_sessionSlot,
                                            IpmiMessage* i_message)
{

}

void IpmiConfidentialityAlgoNone::decryptData(IpmiSessionKeys* i_sessionSlot,
                                            IpmiMessage* i_message)
{

}

IpmiConfidentialityAlgoAesCbc128::IpmiConfidentialityAlgoAesCbc128()
{
}

IpmiConfidentialityAlgoAesCbc128::~IpmiConfidentialityAlgoAesCbc128()
{

}

void ipmi_encrypt_aes_cbc_128(const uint8_t * iv,
                                               const uint8_t * key,
                                               const uint8_t * input,
                                               uint32_t input_length,
                                               uint8_t * output,
                                               uint32_t * bytes_written)
{
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);


    *bytes_written = 0;

    if (input_length == 0)
        return;

//    assert((input_length % IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE) == 0);

    if(!EVP_EncryptUpdate(&ctx, output, (int *)bytes_written, input, input_length))
    {
        /* Error */
        *bytes_written = 0;
        return;
    }
    else
    {
        unsigned int tmplen;

        if(!EVP_EncryptFinal_ex(&ctx, output + (*bytes_written), (int *)&tmplen))
        {
            //printf ("Failure\n");
            *bytes_written = 0;
            return; /* Error */
        }
        else
        {
            /* Success */
            *bytes_written += tmplen;
            EVP_CIPHER_CTX_cleanup(&ctx);
        }
    }
}

int ipmi_decrypt_aes_cbc_128 (const uint8_t * iv,
                               const uint8_t * key,
                               const uint8_t * input,
                               uint32_t input_length,
                               uint8_t * output,
                               uint32_t * bytes_written)

{
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);


    *bytes_written = 0;

    if (input_length == 0)
        return -1;


    if (!EVP_DecryptUpdate(&ctx, output, (int *)bytes_written, input, input_length))
    {
        /* Error */
        *bytes_written = 0;
        return -1;
    }
    else
    {
        unsigned int tmplen;

        if (!EVP_DecryptFinal_ex(&ctx, output + (*bytes_written), (int *)&tmplen))
        {

            //printf ("EVP_DecryptFinal_ex failed\n");
            *bytes_written = 0;
            return -1; /* Error */
        }
        else
        {
            /* Success */
            *bytes_written += tmplen;
            EVP_CIPHER_CTX_cleanup(&ctx);
        }
    }

    return 0;

}

void IpmiConfidentialityAlgoAesCbc128::encryptData(IpmiSessionKeys* i_sessionSlot,
                                            IpmiMessage* i_message)
{
#define IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE 0x10
    Ipmi20Parser::SessionHeader_t* l_hdr = reinterpret_cast<Ipmi20Parser::SessionHeader_t*>(i_message->getPacket());
    l_hdr->payloadType = (l_hdr->payloadType | 0x80);

    uint8_t* i_buffer = i_message->getPayload();
    uint16_t i_PayloadLen = i_message->getPayloadLength().get();
    uint8_t* o_buffer = new uint8_t[IpmiMessage::IPMI_MESSAGE_MAX_PACKET_LENGTH];
    uint16_t o_PayloadLength = 0;

    uint8_t * padded_input;
    uint32_t    mod, i, bytes_encrypted;
    uint8_t   pad_length = 0;

    uint8_t input_length = 0;

    uint8_t l_sik_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_sik_hmacBuflen = sizeof(l_sik_hmacBuffer);

    i_sessionSlot->getSIK(l_sik_hmacBuffer,l_sik_hmacBuflen);

    if (1)
    {
        // data length + payload length (1byte)
        mod = (i_PayloadLen + 1) % IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE;
        if (mod)
            pad_length = IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE - mod;

        padded_input = (uint8_t*)malloc(i_PayloadLen + pad_length + 1);
        if (padded_input == nullptr) {
            return;
        }

        memcpy(padded_input, i_buffer, i_PayloadLen);
        /* add the pad */
        for (i = 0; i < pad_length; ++i)
            padded_input[i_PayloadLen + i] = i + 1;

        /* add the pad length */
        padded_input[i_PayloadLen + pad_length] = pad_length;

        input_length = i_PayloadLen + pad_length +1;

    }

    /* Generate an initialization vector, IV, for the encryption process */
    if (! RAND_bytes(o_buffer, IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE))
    {
        free(padded_input);
        padded_input = nullptr;
        return;
    }
    uint8_t k2_buffer[SHA_DIGEST_LENGTH];
    uint32_t k2_length = 0;

    uint8_t CONST_K2[] =  {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                           0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};

    HMAC(EVP_sha1(), l_sik_hmacBuffer, l_sik_hmacBuflen, CONST_K2, 20, k2_buffer, &k2_length);


    ipmi_encrypt_aes_cbc_128(o_buffer,                                     /* IV              */
                            k2_buffer,                                        /* K2              */
                            padded_input,                               /* Data to encrypt */
                            input_length,              /* Input length    */
                            o_buffer + IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE, /* output          */
                            &bytes_encrypted);                          /* bytes written   */

     o_PayloadLength = IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE + bytes_encrypted;


    free(padded_input);

    delete[] static_cast<uint8_t*>(i_message->getPayload());
    i_message->setPayload(o_buffer,true);
    PacketField16_t l_len(o_PayloadLength);
    i_message->setPayloadLength(l_len);

    return;

}

void IpmiConfidentialityAlgoAesCbc128::decryptData(IpmiSessionKeys* i_sessionSlot,
                                            IpmiMessage* i_message)
{
    uint8_t * input = i_message->getPayload();
    uint16_t  input_length = i_message->getPayloadLength().get();
    uint8_t*  output = new uint8_t[IpmiMessage::IPMI_MESSAGE_MAX_PACKET_LENGTH];
    uint16_t  payload_size = 0 ;

    uint8_t * decrypted_payload;
    uint32_t    bytes_decrypted;

    uint8_t l_sik_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_sik_hmacBuflen = sizeof(l_sik_hmacBuffer);

    i_sessionSlot->getSIK(l_sik_hmacBuffer,l_sik_hmacBuflen);

    decrypted_payload = (uint8_t*)malloc(input_length);
    if (decrypted_payload == nullptr) {
        return ;
    }

    uint8_t k2_buffer[SHA_DIGEST_LENGTH];
    uint32_t k2_length = 0;

    uint8_t CONST_K2[] =  {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                           0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};

    HMAC(EVP_sha1(), l_sik_hmacBuffer, l_sik_hmacBuflen, CONST_K2, 20, k2_buffer, &k2_length);

    int x =ipmi_decrypt_aes_cbc_128(input,                                /* IV              */
                                k2_buffer,                                  /* Key             */
                                input + IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE,    /* Data to decrypt */
                                input_length - IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE,    /* Input length    */
                                decrypted_payload,                    /* output          */
                                &bytes_decrypted);                    /* bytes written   */

    if (x == -1)
    {
        //printf ("decrypted error\n");
        delete[] output;
        return ;
    }


    if (bytes_decrypted != 0)
    {
        /* Success */
        uint8_t conf_pad_length;
        int i;

        memcpy(output,
                decrypted_payload,
                bytes_decrypted);

        /*
         * We have to determine the payload size, by substracting the padding, etc.
         * The last byte of the decrypted payload is the confidentiality pad length.
         */

        conf_pad_length = decrypted_payload[bytes_decrypted - 1];
        payload_size = bytes_decrypted - conf_pad_length - 1;

        /*
         * Extra test to make sure that the padding looks like it should (should start
         * with 0x01, 0x02, 0x03, etc...
         */
        for (i = 0; i < conf_pad_length; ++i)
        {
            if (decrypted_payload[payload_size + i] == (i + 1))
            {
    //               printf ("Confidentiality padding is correct\n");
            }
            else ;
    //             printf ("Confidentiality padding is not correct\n");
        }

    }
    else
    {
        //printf("ERROR: decryptd 0 bytes");
        delete[] output;
        return;
    }

    free(decrypted_payload);

    //@TODO: not required but can make some clean intf to remove existing payload
    //delete[] static_cast<uint8_t*>(i_message->getPayload());
    i_message->setPayload(output,true);
    PacketField16_t l_len(payload_size);
    i_message->setPayloadLength(l_len);

    return ;
}

IpmiUnsupportedPasswordAuthentication::IpmiUnsupportedPasswordAuthentication()
:IpmiUserAuthenticationInterface(IpmiUserAuthenticationInterface::IPMI_AUTH_METHOD_UNSUPPORTED)
{

}

IpmiUnsupportedPasswordAuthentication::~IpmiUnsupportedPasswordAuthentication()
{

}

bool IpmiUnsupportedPasswordAuthentication::AuthenticateUser(
                                uint8_t*  i_userName, uint32_t  i_userNameLen,
                                uint8_t*  o_key,      uint32_t& o_keyLen,
                                uint8_t&  io_privilegeLevel )
{
    bool l_userValid = false;
    o_keyLen = 0;
    return l_userValid;
}
IpmiStaticPasswordAuthentication::IpmiStaticPasswordAuthentication()
:IpmiUserAuthenticationInterface(IpmiUserAuthenticationInterface::IPMI_AUTH_METHOD_STATIC_PASS_KEY)
{

}

IpmiStaticPasswordAuthentication::~IpmiStaticPasswordAuthentication()
{

}

bool IpmiStaticPasswordAuthentication::AuthenticateUser(
                                uint8_t*  i_userName, uint32_t  i_userNameLen,
                                uint8_t*  o_key,      uint32_t& o_keyLen,
                                uint8_t&  io_privilegeLevel )
{
    bool l_userValid = false;

    if(o_key)
    {
        //l_sessKeys.getUserName will give us the user name
        //i_pSession->getSessionState().getPrevilegeLevel() will give us the
        //  requested prv level.
        //{'P','A','S','S','W','0','R','D', 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0  };
        //@TODO: Do this dynamically
        uint8_t l_userKey[20] = {'o','k',0,0,0,0,0,0,0,0,
                                  0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0  };
        uint32_t l_userKeyLength = sizeof(l_userKey);
        l_userValid = true;

        o_keyLen = o_keyLen>l_userKeyLength?l_userKeyLength:o_keyLen;
        memcpy(o_key,l_userKey,o_keyLen);
    }

    return l_userValid;
}

IpmiPasswordFileAuthentication::IpmiPasswordFileAuthentication()
:IpmiUserAuthenticationInterface(IpmiUserAuthenticationInterface::IPMI_AUTH_METHOD_PASSWORD_FILE)
{

}

IpmiPasswordFileAuthentication::~IpmiPasswordFileAuthentication()
{

}

bool IpmiPasswordFileAuthentication::AuthenticateUser(
                                uint8_t*  i_userName, uint32_t  i_userNameLen,
                                uint8_t*  o_key,      uint32_t& io_keyLen,
                                uint8_t&  io_privilegeLevel )
{
    // Read the User Account that matches with the requested username and privilege level
	// If the user account is valid return the User Password, Length and the allowed
	// privilege level.

    return true;
}

