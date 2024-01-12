/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "crypto.h"

#include "coin.h"
#include "crypto_helper.h"
#include "cx.h"
#include "tx.h"
#include "zxformat.h"
#include "zxmacros.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];
uint32_t hdPath_len;
uint8_t change_address[20];
#include <bech32.h>

#define MAX_DER_SIGNATURE_LEN 73

zxerr_t crypto_extractUncompressedPublicKey(uint8_t *pubKey, uint16_t pubKeyLen, uint8_t *chainCode) {
    if (pubKey == NULL || pubKeyLen < PK_LEN_SECP256K1_UNCOMPRESSED) {
        return zxerr_invalid_crypto_settings;
    }
    cx_ecfp_public_key_t cx_publicKey = {0};
    cx_ecfp_private_key_t cx_privateKey = {0};
    uint8_t privateKeyData[64] = {0};

    zxerr_t error = zxerr_unknown;

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_256K1, hdPath, hdPath_len, privateKeyData,
                                                     chainCode, NULL, 0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1));
    memcpy(pubKey, cx_publicKey.W, PK_LEN_SECP256K1_UNCOMPRESSED);
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }

    return error;
}

__Z_INLINE zxerr_t compressPubkey(const uint8_t *pubkey, uint16_t pubkeyLen, uint8_t *output, uint16_t outputLen) {
    if (pubkey == NULL || output == NULL || pubkeyLen != PK_LEN_SECP256K1_UNCOMPRESSED || outputLen < PK_LEN_SECP256K1) {
        return zxerr_invalid_crypto_settings;
    }

    MEMCPY(output, pubkey, PK_LEN_SECP256K1);
    output[0] = pubkey[64] & 1 ? 0x03 : 0x02;  // "Compress" public key in place
    return zxerr_ok;
}

zxerr_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen, uint16_t *sigSize, bool hash) {
    if (signature == NULL || sigSize == NULL) {
        return zxerr_invalid_crypto_settings;
    }
    uint8_t messageDigest[CX_SHA256_SIZE] = {0};
    MEMZERO(messageDigest, sizeof(messageDigest));

    // Hash it
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLen = tx_get_buffer_length();
    if (!hash) {
        crypto_sha256(message, messageLen, messageDigest, CX_SHA256_SIZE);
    } else {
        MEMCPY(messageDigest, message, messageLen);
    }

    cx_ecfp_private_key_t cx_privateKey = {0};
    uint8_t privateKeyData[64] = {0};
    unsigned int info = 0;
    size_t signatureLength = MAX_DER_SIGNATURE_LEN;
    zxerr_t error = zxerr_unknown;

    // Generate keys
    CATCH_CXERROR(
        os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_256K1, hdPath, hdPath_len, privateKeyData, NULL, NULL, 0));
    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));

    // Sign
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256, messageDigest, CX_SHA256_SIZE,
                                         signature, &signatureLength, &info));

    *sigSize = signatureLength;
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(signature, signatureMaxlen);
    }

    return error;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

zxerr_t _sign(uint8_t *output, uint16_t outputLen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize,
              unsigned int *info) {
    if (output == NULL || message == NULL || sigSize == NULL || outputLen < sizeof(signature_t) ||
        messageLen != CX_SHA256_SIZE) {
        return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SECP256K1_SK_LEN] = {0};
    size_t signatureLength = sizeof_field(signature_t, der_signature);
    uint32_t tmpInfo = 0;
    *sigSize = 0;

    signature_t *const signature = (signature_t *)output;
    zxerr_t error = zxerr_unknown;

    CATCH_CXERROR(
        os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_256K1, hdPath, hdPath_len, privateKeyData, NULL, NULL, 0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256, message, messageLen,
                                         signature->der_signature, &signatureLength, &tmpInfo));

    const err_convert_e err_c =
        convertDERtoRSV(signature->der_signature, tmpInfo, signature->r, signature->s, &signature->v);
    if (err_c == no_error) {
        *sigSize =
            sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;
        if (info != NULL) {
            *info = tmpInfo;
        }
        error = zxerr_ok;
    }

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}

// Sign an ethereum related transaction
zxerr_t crypto_sign_eth(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                        uint16_t *sigSize) {
    if (buffer == NULL || message == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t message_digest[KECCAK_256_SIZE] = {0};
    CHECK_ZXERR(keccak_digest(message, messageLen, message_digest, KECCAK_256_SIZE))

    unsigned int info = 0;
    zxerr_t error = _sign(buffer, signatureMaxlen, message_digest, KECCAK_256_SIZE, sigSize, &info);
    if (error != zxerr_ok) {
        return zxerr_invalid_crypto_settings;
    }

    // we need to fix V
    uint8_t v = 0;
    error = tx_compute_eth_v(info, &v);

    if (error != zxerr_ok) return zxerr_invalid_crypto_settings;

    // need to reorder signature as hw-eth-app expects v at the beginning.
    // so rsv -> vrs
    uint8_t rs_size = sizeof_field(signature_t, r) + sizeof_field(signature_t, s);
    memmove(buffer + 1, buffer, rs_size);
    buffer[0] = v;

    return error;
}

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen) {
    zemu_log("crypto_fillAddress");
    if (bufferLen < PK_LEN_SECP256K1 + 50) {
        return zxerr_unknown;
    }

    char *addr = (char *)(buffer + PK_LEN_SECP256K1);
    uint8_t uncompressedPubkey[PK_LEN_SECP256K1_UNCOMPRESSED] = {0};
    CHECK_ZXERR(crypto_extractUncompressedPublicKey(uncompressedPubkey, sizeof(uncompressedPubkey), NULL));
    CHECK_ZXERR(compressPubkey(uncompressedPubkey, sizeof(uncompressedPubkey), buffer, bufferLen));

    const uint8_t outLen = crypto_encodePubkey(buffer, addr, bufferLen - PK_LEN_SECP256K1);

    if (outLen == 0) {
        MEMZERO(buffer, bufferLen);
        return zxerr_encoding_failed;
    }

    *addrResponseLen = PK_LEN_SECP256K1 + outLen;
    return zxerr_ok;
}

zxerr_t crypto_get_address(void) {
    uint8_t uncompressedPubkey[PK_LEN_SECP256K1_UNCOMPRESSED] = {0};
    uint8_t compressedPubkey[PK_LEN_SECP256K1] = {0};
    CHECK_ZXERR(crypto_extractUncompressedPublicKey(uncompressedPubkey, sizeof(uncompressedPubkey), NULL));
    CHECK_ZXERR(compressPubkey(uncompressedPubkey, sizeof(uncompressedPubkey), compressedPubkey, sizeof(compressedPubkey)));

    // Hash it
    uint8_t hashed1_pk[CX_SHA256_SIZE] = {0};
    crypto_sha256(compressedPubkey, PK_LEN_SECP256K1, hashed1_pk, CX_SHA256_SIZE);

    CHECK_ZXERR(ripemd160_32(change_address, hashed1_pk))

    return zxerr_ok;
}

typedef struct {
    // plus 1-bytes to write pubkey len
    uint8_t publicKey[SECP256K1_PK_LEN + 1];
    // hex of the ethereum address plus 1-bytes
    // to write the address len
    uint8_t address[(ETH_ADDR_LEN * 2) + 1];
    // place holder for further dev
    uint8_t chainCode[32];

} __attribute__((packed)) answer_eth_t;

zxerr_t crypto_fillEthAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    if (buffer == NULL || buffer_len < sizeof(answer_eth_t) || addrLen == NULL) {
        return zxerr_no_data;
    }
    MEMZERO(buffer, buffer_len);
    answer_eth_t *const answer = (answer_eth_t *)buffer;

    CHECK_ZXERR(crypto_extractUncompressedPublicKey(&answer->publicKey[1], sizeof_field(answer_eth_t, publicKey) - 1,
                                                    &flr_chain_code))

    answer->publicKey[0] = SECP256K1_PK_LEN;

    uint8_t hash[KECCAK_256_SIZE] = {0};

    CHECK_ZXERR(keccak_digest(&answer->publicKey[2], SECP256K1_PK_LEN - 1, hash, KECCAK_256_SIZE))

    answer->address[0] = ETH_ADDR_LEN * 2;

    // get hex of the eth address(last 20 bytes of pubkey hash)
    char str[41] = {0};

    // take the last 20-bytes of the hash, they are the ethereum address
    array_to_hexstr(str, 41, hash + 12, ETH_ADDR_LEN);
    MEMCPY(answer->address + 1, str, 40);

    *addrLen = sizeof_field(answer_eth_t, publicKey) + sizeof_field(answer_eth_t, address);

    return zxerr_ok;
}
