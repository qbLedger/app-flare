/*******************************************************************************
 *  (c) 2018 - 2022 Zondax AG
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
#include "parser_common.h"
#include "stdbool.h"

#ifdef __cplusplus
extern "C" {
#endif
parser_error_t read_u16(parser_context_t *ctx, uint16_t *result);
parser_error_t read_u8(parser_context_t *ctx, uint8_t *result);
parser_error_t read_u32(parser_context_t *ctx, uint32_t *result);
parser_error_t read_u64(parser_context_t *ctx, uint64_t *result);
parser_error_t verifyBytes(parser_context_t *ctx, uint16_t buffLen);
parser_error_t readBytes(parser_context_t *ctx, uint8_t *buff, uint16_t buffLen);
parser_error_t checkAvailableBytes(parser_context_t *ctx, uint16_t buffLen);
parser_error_t verifyContext(parser_context_t *ctx);

parser_error_t parser_get_chain_id(parser_context_t *c, parser_tx_t *v);
parser_error_t parser_get_chain_alias(const uint8_t *blockchain_id, char *chain);
parser_error_t parser_go_to_next_transferable_output(parser_context_t *c);

parser_error_t parse_evm_inputs(parser_context_t *c, evm_inputs_t *evm);
parser_error_t parse_transferable_secp_output(parser_context_t *c, transferable_out_secp_t *outputs, bool verify_locktime);
parser_error_t parse_transferable_secp_input(parser_context_t *c, transferable_in_secp_t *outputs);
parser_error_t parse_secp_owners_output(parser_context_t *c, secp_owners_out_t *outputs);
parser_error_t parse_evm_output(parser_context_t *c, evm_outs_t *outputs);

parser_error_t parser_get_secp_output_for_index(parser_context_t *out_ctx, transferable_out_secp_t secp_outs,
                                                uint8_t inner_displayIdx, uint64_t *amount, uint8_t *address,
                                                uint8_t *element_idx);

parser_error_t parser_get_evm_output_index(parser_context_t *out_ctx, evm_outs_t evm_outs, uint8_t out_index,
                                           uint64_t *amount, uint8_t *address);

int parser_get_renderable_outputs_number(uint64_t mask);
#ifdef __cplusplus
}

#endif
