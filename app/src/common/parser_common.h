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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "parser_txdef.h"

#define CHECK_ERROR(__CALL)                   \
    {                                         \
        parser_error_t __err = __CALL;        \
        CHECK_APP_CANARY()                    \
        if (__err != parser_ok) return __err; \
    }

typedef enum {
    // Generic errors
    parser_ok = 0,
    parser_no_data,
    parser_init_context_empty,
    parser_display_idx_out_of_range,
    parser_display_page_out_of_range,
    parser_unexpected_error,

    // Coin generic
    parser_unexpected_type,
    parser_unexpected_method,
    parser_unexpected_buffer_end,
    parser_unexpected_value,
    parser_unexpected_number_items,
    parser_unexpected_version,
    parser_unexpected_characters,
    parser_unexpected_field,
    parser_duplicated_field,
    parser_value_out_of_range,
    parser_invalid_address,
    parser_unexpected_chain,
    parser_missing_field,
    parser_unknown_transaction,

    // utils specific
    parser_unexpected_data_len,
    parser_invalid_codec,
    parser_unexpected_network,
    parser_unexpected_type_id,
    parser_unexpected_threshold,
    parser_unexpected_n_address_zero,
    parser_unexpected_unparsed_bytes,
    parser_invalid_time_stamp,
    parser_invalid_stake_amount,
    parser_unexpected_output_locked,
    parser_unsupported_tx,
    parser_blindsign_mode_required,

    parser_invalid_rs_values,
    parser_invalid_chain_id,
} parser_error_t;

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    parser_tx_t *tx_obj;
} parser_context_t;

#ifdef __cplusplus
}
#endif
