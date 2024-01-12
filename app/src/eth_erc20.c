/*******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
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

#include "eth_erc20.h"

#include "zxformat.h"

// Prefix is calculated as: keccak256("transfer(address,uint256)") = 0xa9059cbb
const uint8_t ERC20_TRANSFER_PREFIX[] = {0xa9, 0x05, 0x9c, 0xbb};
#define ERC20_DATA_LENGTH 68  // 4 + 32 + 32
#define ADDRESS_CONTRACT_LENGTH 20
#define DECIMAL_BASE 10
const erc20_tokens_t supportedTokens[] = {
    {{0x1D, 0x80, 0xc4, 0x9B, 0xbB, 0xCd, 0x1C, 0x09, 0x11, 0x34,
      0x66, 0x56, 0xB5, 0x29, 0xDF, 0x9E, 0x5c, 0x2F, 0x78, 0x3d},
     "WFLR ",
     18},
};

parser_error_t getERC20Token(const rlp_t *data, char tokenSymbol[MAX_SYMBOL_LEN], uint8_t *decimals) {
    if (data == NULL || tokenSymbol == NULL || decimals == NULL || data->rlpLen != ERC20_DATA_LENGTH ||
        memcmp(data->ptr, ERC20_TRANSFER_PREFIX, 4) != 0) {
        return parser_unexpected_value;
    }

    // Verify address contract: first 12 bytes must be 0
    const uint8_t *addressPtr = data->ptr + 4;
    for (uint8_t i = 0; i < 12; i++) {
        if (*(addressPtr++) != 0) {
            return parser_unexpected_value;
        }
    }

    // Check if token is in the list
    const uint8_t supportedTokensSize = sizeof(supportedTokens) / sizeof(supportedTokens[0]);
    for (uint8_t i = 0; i < supportedTokensSize; i++) {
        if (memcmp(addressPtr, supportedTokens[i].address, ADDRESS_CONTRACT_LENGTH) == 0) {
            // Set symbol and decimals
            snprintf(tokenSymbol, 10, "%s", (char *)PIC(supportedTokens[i].symbol));
            *decimals = supportedTokens[i].decimals;
            return parser_ok;
        }
    }

    // Unknonw token
    snprintf(tokenSymbol, 10, "?? ");
    *decimals = 0;
    return parser_ok;
}
parser_error_t printERC20Value(const rlp_t *data, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (data == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    // [identifier (4) | token contract (12 + 20) | value (32)]
    char tokenSymbol[10] = {0};
    uint8_t decimals = 0;
    CHECK_ERROR(getERC20Token(data, tokenSymbol, &decimals))

    uint256_t value = {0};
    const uint8_t *valuePtr = data->ptr + 4 + 12 + ADDRESS_CONTRACT_LENGTH;
    parser_context_t tmpCtx = {.buffer = valuePtr, .bufferLen = 32, .offset = 0, .tx_type = eth_tx};
    CHECK_ERROR(readu256BE(&tmpCtx, &value));

    char bufferUI[100] = {0};
    if (!tostring256(&value, DECIMAL_BASE, bufferUI, sizeof(bufferUI))) {
        return parser_unexpected_error;
    }

    // Add symbol, add decimals, page number
    if (intstr_to_fpstr_inplace(bufferUI, sizeof(bufferUI), decimals) == 0) {
        return parser_unexpected_value;
    }

    if (z_str3join(bufferUI, sizeof(bufferUI), tokenSymbol, NULL) != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    number_inplace_trimming(bufferUI, 1);
    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);

    return parser_ok;
}

bool validateERC20(rlp_t data) {
    // Check that data start with ERC20 prefix
    if (data.rlpLen != ERC20_DATA_LENGTH || memcmp(data.ptr, ERC20_TRANSFER_PREFIX, 4) != 0) {
        return false;
    }

    return true;
}
