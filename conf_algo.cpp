#include "conf_algo.hpp"

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>

#include "message.hpp"
#include "message_parsers.hpp"

namespace cipher
{
namespace conf
{
void AlgoNone::encryptData(Keys* i_sessionSlot, IpmiMessage* i_message) {}

void AlgoNone::decryptData(Keys* i_sessionSlot, IpmiMessage* i_message) {}

void ipmi_encrypt_aes_cbc_128(const uint8_t* iv, const uint8_t* key,
                              const uint8_t* input,
                              uint32_t input_length, uint8_t* output, uint32_t* bytes_written)
{
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    *bytes_written = 0;

    if (input_length == 0)
    {
        return;
    }

    if (!EVP_EncryptUpdate(&ctx, output, (int*)bytes_written, input, input_length))
    {
        /* Error */
        *bytes_written = 0;
        return;
    }
    else
    {
        unsigned int tmplen;

        if (!EVP_EncryptFinal_ex(&ctx, output + (*bytes_written), (int*)&tmplen))
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

int ipmi_decrypt_aes_cbc_128(const uint8_t* iv, const uint8_t* key,
                             const uint8_t* input,
                             uint32_t input_length, uint8_t* output, uint32_t* bytes_written)
{
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    *bytes_written = 0;

    if (input_length == 0)
    {
        return -1;
    }

    if (!EVP_DecryptUpdate(&ctx, output, (int*)bytes_written, input, input_length))
    {
        /* Error */
        *bytes_written = 0;
        return -1;
    }
    else
    {
        unsigned int tmplen;

        if (!EVP_DecryptFinal_ex(&ctx, output + (*bytes_written), (int*)&tmplen))
        {
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

void AlgoAesCbc128::encryptData(Keys*
                                i_sessionSlot,
                                IpmiMessage* i_message)
{
#define IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE 0x10
    Ipmi20Parser::SessionHeader_t* l_hdr =
        reinterpret_cast<Ipmi20Parser::SessionHeader_t*>(i_message->getPacket());
    l_hdr->payloadType = (l_hdr->payloadType | 0x80);

    uint8_t* i_buffer = i_message->getPayload();
    uint16_t i_PayloadLen = i_message->getPayloadLength();
    uint8_t* o_buffer = new uint8_t[IpmiMessage::IPMI_MESSAGE_MAX_PACKET_LENGTH];
    uint16_t o_PayloadLength = 0;

    uint8_t* padded_input;
    uint32_t mod, i, bytes_encrypted;
    uint8_t pad_length = 0;

    uint8_t input_length = 0;

    uint8_t l_sik_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_sik_hmacBuflen = sizeof(l_sik_hmacBuffer);

    std::copy(i_sessionSlot->sessionIntegrityKey.begin(),
              i_sessionSlot->sessionIntegrityKey.end(), l_sik_hmacBuffer);

    if (1)
    {
        // data length + payload length (1byte)
        mod = (i_PayloadLen + 1) % IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE;
        if (mod)
        {
            pad_length = IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE - mod;
        }

        padded_input = (uint8_t*)malloc(i_PayloadLen + pad_length + 1);
        if (padded_input == nullptr)
        {
            return;
        }

        memcpy(padded_input, i_buffer, i_PayloadLen);
        /* add the pad */
        for (i = 0; i < pad_length; ++i)
        {
            padded_input[i_PayloadLen + i] = i + 1;
        }

        /* add the pad length */
        padded_input[i_PayloadLen + pad_length] = pad_length;

        input_length = i_PayloadLen + pad_length + 1;
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

    uint8_t CONST_K2[] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
                         };

    HMAC(EVP_sha1(), l_sik_hmacBuffer, l_sik_hmacBuflen, CONST_K2, 20, k2_buffer,
         &k2_length);


    ipmi_encrypt_aes_cbc_128(
        o_buffer,                                   /* IV              */
        k2_buffer,                                   /* K2              */
        padded_input,                                /* Data to encrypt */
        input_length,                                /* Input length    */
        o_buffer + IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE,/* output          */
        &bytes_encrypted);                           /* bytes written   */

    o_PayloadLength = IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE + bytes_encrypted;

    free(padded_input);

    delete[] static_cast<uint8_t*>(i_message->getPayload());
    i_message->setPayload(o_buffer, true);
    uint16_t l_len = o_PayloadLength;
    i_message->setPayloadLength(l_len);

    return;
}

void AlgoAesCbc128::decryptData(Keys*
                                i_sessionSlot,
                                IpmiMessage* i_message)

{
    uint8_t* input = i_message->getPayload();
    uint16_t input_length = i_message->getPayloadLength();
    uint8_t* output = new uint8_t[IpmiMessage::IPMI_MESSAGE_MAX_PACKET_LENGTH];
    uint16_t payload_size = 0 ;

    uint8_t* decrypted_payload;
    uint32_t bytes_decrypted;

    uint8_t l_sik_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    auto l_sik_hmacBuflen = sizeof(l_sik_hmacBuffer);

    std::copy(i_sessionSlot->sessionIntegrityKey.begin(),
              i_sessionSlot->sessionIntegrityKey.end(), l_sik_hmacBuffer);

    decrypted_payload = (uint8_t*)malloc(input_length);
    if (decrypted_payload == nullptr)
    {
        return ;
    }

    uint8_t k2_buffer[SHA_DIGEST_LENGTH];
    uint32_t k2_length = 0;

    uint8_t CONST_K2[] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
                         };

    HMAC(EVP_sha1(), l_sik_hmacBuffer, l_sik_hmacBuflen, CONST_K2, 20, k2_buffer,
         &k2_length);

    int x = ipmi_decrypt_aes_cbc_128(
                input,                                      /* IV              */
                k2_buffer,                                       /* Key             */
                input + IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE,       /* Data to decrypt */
                input_length - IPMI_CRYPT_AES_CBC_128_BLOCK_SIZE,/* Input length    */
                decrypted_payload,                               /* output          */
                &bytes_decrypted);                               /* Bytes written   */

    if (x == -1)
    {
        std::cerr << "E> Error in encryption\n";
        delete[] output;
        return ;
    }

    if (bytes_decrypted != 0)
    {
        /* Success */
        uint8_t conf_pad_length;
        int i;

        memcpy(output, decrypted_payload, bytes_decrypted);

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
            }
        }
    }
    else
    {
        delete[] output;
        return;
    }

    free(decrypted_payload);

    //@TODO: not required but can make some clean intf to remove existing payload
    //delete[] static_cast<uint8_t*>(i_message->getPayload());
    i_message->setPayload(output, true);
    uint16_t l_len = payload_size;
    i_message->setPayloadLength(l_len);

    return ;
}

} // namespace conf

} // namespace cipher
