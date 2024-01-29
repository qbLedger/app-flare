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
#include "tx_pchain.h"

#include "app_mode.h"
#include "parser_impl_common.h"
#include "parser_print_common.h"
#include "zxformat.h"
#include "zxmacros.h"

static parser_error_t parser_base_tx(parser_context_t *c, transferable_in_secp_t *inputs, transferable_out_secp_t *outputs) {
    // Get outputs
    CHECK_ERROR(read_u32(c, &outputs->n_outs));
    if (outputs->n_outs > MAX_OUTPUTS) {
        return parser_unexpected_number_items;
    }

    // Pointer to outputs
    if (outputs->n_outs > 0) {
        CHECK_ERROR(verifyContext(c));
        outputs->outs = c->buffer + c->offset;
        CHECK_ERROR(parse_transferable_secp_output(c, outputs, true));
    }

    // Get inputs
    CHECK_ERROR(read_u32(c, &inputs->n_ins));

    // Pointer to inputs
    if (inputs->n_ins > 0) {
        CHECK_ERROR(verifyContext(c));
        inputs->ins = c->buffer + c->offset;
        CHECK_ERROR(parse_transferable_secp_input(c, inputs));
    }

    // Get Memo Len
    uint32_t memoLen = 0;
    CHECK_ERROR(read_u32(c, &memoLen));
    if (memoLen > MAX_MEMO_LEN) {
        return parser_unexpected_number_items;
    }

    return parser_ok;
}

parser_error_t parser_handle_p_export_tx(parser_context_t *c, parser_tx_t *v) {
    // Parse base tx
    CHECK_ERROR(parser_base_tx(c, &v->tx.p_export_tx.base_secp_ins, &v->tx.p_export_tx.base_secp_outs));

    // Get destination chain
    CHECK_ERROR(checkAvailableBytes(c, BLOCKCHAIN_ID_LEN));
    v->tx.p_export_tx.destination_chain = c->buffer + c->offset;
    if (!MEMCMP(PIC(v->tx.p_export_tx.destination_chain), v->blockchain_id, BLOCKCHAIN_ID_LEN)) {
        return parser_unexpected_chain;
    }
    CHECK_ERROR(verifyBytes(c, BLOCKCHAIN_ID_LEN));

    // Get number of outputs
    CHECK_ERROR(read_u32(c, &v->tx.p_export_tx.secp_outs.n_outs));
    if (v->tx.p_export_tx.secp_outs.n_outs > MAX_OUTPUTS) {
        return parser_unexpected_number_items;
    }

    // Pointer to outputs
    CHECK_ERROR(verifyContext(c));
    v->tx.p_export_tx.secp_outs.outs = c->buffer + c->offset;
    v->tx.p_export_tx.secp_outs.outs_offset = c->offset;
    CHECK_ERROR(parse_transferable_secp_output(c, &v->tx.p_export_tx.secp_outs, true));

    return parser_ok;
}

parser_error_t parser_handle_p_import_tx(parser_context_t *c, parser_tx_t *v) {
    // Parse base tx
    CHECK_ERROR(parser_base_tx(c, &v->tx.p_import_tx.base_secp_ins, &v->tx.p_import_tx.base_secp_outs));

    // Get source chain
    CHECK_ERROR(checkAvailableBytes(c, BLOCKCHAIN_ID_LEN));
    v->tx.p_import_tx.source_chain = c->buffer + c->offset;
    if (!MEMCMP(v->tx.p_import_tx.source_chain, v->blockchain_id, BLOCKCHAIN_ID_LEN)) {
        return parser_unexpected_chain;
    }
    CHECK_ERROR(verifyBytes(c, BLOCKCHAIN_ID_LEN));

    // Get number of inputs
    CHECK_ERROR(read_u32(c, &v->tx.p_import_tx.secp_ins.n_ins));
    if (v->tx.p_import_tx.secp_ins.n_ins > MAX_INPUTS) {
        return parser_unexpected_number_items;
    }

    // Pointer to inputs
    CHECK_ERROR(verifyContext(c));
    v->tx.p_import_tx.secp_ins.ins = c->buffer + c->offset;
    v->tx.p_import_tx.secp_ins.ins_offset = c->offset;
    CHECK_ERROR(parse_transferable_secp_input(c, &v->tx.p_import_tx.secp_ins));

    return parser_ok;
}

parser_error_t parser_handle_add_delegator_validator(parser_context_t *c, parser_tx_t *v) {
    // Parse base tx
    CHECK_ERROR(parser_base_tx(c, &v->tx.add_del_val_tx.base_secp_ins, &v->tx.add_del_val_tx.base_secp_outs));

    // Node ID
    CHECK_ERROR(verifyContext(c));
    v->tx.add_del_val_tx.node_id = c->buffer + c->offset;
    CHECK_ERROR(verifyBytes(c, NODE_ID_LEN));

    // Get Start Time
    CHECK_ERROR(read_u64(c, &v->tx.add_del_val_tx.start_time));

    // Get End Time
    CHECK_ERROR(read_u64(c, &v->tx.add_del_val_tx.end_time));

    if (v->tx.add_del_val_tx.end_time <= v->tx.add_del_val_tx.start_time) {
        return parser_invalid_time_stamp;
    }

    // Get weight
    CHECK_ERROR(read_u64(c, &v->tx.add_del_val_tx.weigth));

    // Get number of outputs
    CHECK_ERROR(read_u32(c, &v->tx.add_del_val_tx.staked_outs.n_outs));
    if (v->tx.add_del_val_tx.staked_outs.n_outs > MAX_OUTPUTS) {
        return parser_unexpected_number_items;
    }

    // Pointer to outputs
    CHECK_ERROR(verifyContext(c));
    v->tx.add_del_val_tx.staked_outs.outs = c->buffer + c->offset;
    CHECK_ERROR(parse_transferable_secp_output(c, &v->tx.add_del_val_tx.staked_outs, false));

    if (v->tx.add_del_val_tx.weigth != v->tx.add_del_val_tx.staked_outs.out_sum) {
        return parser_invalid_stake_amount;
    }

    // Pointer to owners output
    CHECK_ERROR(verifyContext(c));
    v->tx.add_del_val_tx.owners_out.outs = c->buffer + c->offset;
    v->tx.add_del_val_tx.owners_out.n_outs = 1;
    CHECK_ERROR(parse_secp_owners_output(c, &v->tx.add_del_val_tx.owners_out));

    if (v->tx_type == add_validator_tx) {
        // Get shares
        CHECK_ERROR(read_u32(c, &v->tx.add_del_val_tx.shares));
    }
    return parser_ok;
}

parser_error_t parser_pchain(parser_context_t *c, parser_tx_t *v) {
    switch (v->tx_type) {
        case p_export_tx:
            return parser_handle_p_export_tx(c, v);
            break;
        case p_import_tx:
            return parser_handle_p_import_tx(c, v);
            break;
        case add_delegator_tx:
        case add_validator_tx:
            return parser_handle_add_delegator_validator(c, v);
            break;
        default:
            return parser_unexpected_type;
            break;
    }

    return parser_ok;
}

parser_error_t print_add_del_val_tx(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (ctx->tx_obj->tx_type == add_delegator_tx && displayIdx >= 5) {
        displayIdx += 1;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printNodeId(ctx->tx_obj->tx.add_del_val_tx.node_id, outVal, outValLen, pageIdx, pageCount));
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Start time");
            CHECK_ERROR(printTimestamp(ctx->tx_obj->tx.add_del_val_tx.start_time, outVal, outValLen, pageIdx, pageCount));
            break;
        case 2:
            snprintf(outKey, outKeyLen, "End time");
            CHECK_ERROR(printTimestamp(ctx->tx_obj->tx.add_del_val_tx.end_time, outVal, outValLen, pageIdx, pageCount));
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Total stake");
            CHECK_ERROR(printAmount64(ctx->tx_obj->tx.add_del_val_tx.staked_outs.out_sum, AMOUNT_DECIMAL_PLACES,
                                      ctx->tx_obj->network_id, outVal, outValLen, pageIdx, pageCount));
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Rewards to");
            CHECK_ERROR(printAddress(ctx->tx_obj->tx.add_del_val_tx.owners_out.addr, ctx->tx_obj->network_id, outVal,
                                     outValLen, pageIdx, pageCount));
            break;
        case 5:
            snprintf(outKey, outKeyLen, "Delegate fee");
            char tmp[ADDRESS_LEN] = {0};
            snprintf(tmp, ADDRESS_LEN, "%d %%", ctx->tx_obj->tx.add_del_val_tx.shares / SHARES_DIVISON_BASE);
            pageString(outVal, outValLen, (const char *)&tmp, pageIdx, pageCount);
            break;
        case 6:
            snprintf(outKey, outKeyLen, "Fee");
            uint64_t fee =
                ctx->tx_obj->tx.add_del_val_tx.base_secp_ins.in_sum -
                (ctx->tx_obj->tx.add_del_val_tx.base_secp_outs.out_sum + ctx->tx_obj->tx.add_del_val_tx.staked_outs.out_sum);
            CHECK_ERROR(
                printAmount64(fee, AMOUNT_DECIMAL_PLACES, ctx->tx_obj->network_id, outVal, outValLen, pageIdx, pageCount));
            break;
        default:
            if (app_mode_expert() && displayIdx == 7) {
                snprintf(outKey, outKeyLen, "Hash");
                printHash(ctx, outVal, outValLen, pageIdx, pageCount);
                return parser_ok;
            }
            return parser_display_idx_out_of_range;
    }

    return parser_ok;
}

parser_error_t print_p_export_tx(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                 char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Export");

        char chain = 0;
        CHECK_ERROR(parser_get_chain_alias(ctx->tx_obj->tx.p_export_tx.destination_chain, &chain));
        snprintf(outVal, outValLen, "P to %c chain", chain);
        return parser_ok;
    }

    // print ampount and addresses
    if (displayIdx <= ctx->tx_obj->tx.p_export_tx.secp_outs.n_addrs + ctx->tx_obj->tx.p_export_tx.secp_outs.n_outs) {
        // Create new context parser for outputs
        parser_context_t output_ctx = {.buffer = ctx->tx_obj->tx.p_export_tx.secp_outs.outs,
                                       .bufferLen = ctx->bufferLen - ctx->tx_obj->tx.p_export_tx.secp_outs.outs_offset + 1,
                                       .offset = 0,
                                       .tx_obj = NULL};

        uint8_t inner_displayIdx = displayIdx - 1;
        uint8_t element_idx = 0;
        uint64_t amount = 0;
        uint8_t address[ADDRESS_LEN] = {0};

        // check which output cointains the displayIdx we want
        CHECK_ERROR(parser_get_secp_output_for_index(&output_ctx, ctx->tx_obj->tx.p_export_tx.secp_outs, inner_displayIdx,
                                                     &amount, address, &element_idx));
        if (!element_idx) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount64(amount, AMOUNT_DECIMAL_PLACES, ctx->tx_obj->network_id, outVal, outValLen, pageIdx,
                                      pageCount));
        } else {
            snprintf(outKey, outKeyLen, "Address");
            CHECK_ERROR(printAddress(address, ctx->tx_obj->network_id, outVal, outValLen, pageIdx, pageCount));
        }
        return parser_ok;
    }

    if (displayIdx == ctx->tx_obj->tx.p_export_tx.secp_outs.n_addrs + ctx->tx_obj->tx.p_export_tx.secp_outs.n_outs + 1) {
        snprintf(outKey, outKeyLen, "Fee");
        uint64_t fee = ctx->tx_obj->tx.p_export_tx.base_secp_ins.in_sum -
                       (ctx->tx_obj->tx.p_export_tx.base_secp_outs.out_sum + ctx->tx_obj->tx.p_export_tx.secp_outs.out_sum);
        CHECK_ERROR(
            printAmount64(fee, AMOUNT_DECIMAL_PLACES, ctx->tx_obj->network_id, outVal, outValLen, pageIdx, pageCount));
        return parser_ok;
    }

    if (displayIdx == ctx->tx_obj->tx.p_export_tx.secp_outs.n_addrs + ctx->tx_obj->tx.p_export_tx.secp_outs.n_outs + 1 + 1) {
        snprintf(outKey, outKeyLen, "Hash");
        printHash(ctx, outVal, outValLen, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_display_idx_out_of_range;
}

parser_error_t print_p_import_tx(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                 char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Import");

        char chain = 0;
        CHECK_ERROR(parser_get_chain_alias(ctx->tx_obj->tx.p_import_tx.source_chain, &chain));
        snprintf(outVal, outValLen, "P from %c chain", chain);
        return parser_ok;
    }

    // print ampount and addresses
    if (displayIdx <=
        ctx->tx_obj->tx.p_import_tx.base_secp_outs.n_addrs + ctx->tx_obj->tx.p_import_tx.base_secp_outs.n_outs) {
        // Create new context parser for outputs
        parser_context_t output_ctx = {
            .buffer = ctx->tx_obj->tx.p_import_tx.base_secp_outs.outs,
            .bufferLen = ctx->bufferLen - ctx->tx_obj->tx.p_import_tx.base_secp_outs.outs_offset + 1,
            .offset = 0,
            .tx_obj = NULL};

        uint8_t inner_displayIdx = displayIdx - 1;
        uint8_t element_idx = 0;
        uint64_t amount = 0;
        uint8_t address[ADDRESS_LEN] = {0};

        // check which output cointains the displayIdx we want
        CHECK_ERROR(parser_get_secp_output_for_index(&output_ctx, ctx->tx_obj->tx.p_export_tx.base_secp_outs,
                                                     inner_displayIdx, &amount, address, &element_idx));
        if (!element_idx) {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount64(amount, AMOUNT_DECIMAL_PLACES, ctx->tx_obj->network_id, outVal, outValLen, pageIdx,
                                      pageCount));
        } else {
            snprintf(outKey, outKeyLen, "Address");
            CHECK_ERROR(printAddress(address, ctx->tx_obj->network_id, outVal, outValLen, pageIdx, pageCount));
        }
        return parser_ok;
    }

    if (displayIdx ==
        ctx->tx_obj->tx.p_import_tx.base_secp_outs.n_addrs + ctx->tx_obj->tx.p_import_tx.base_secp_outs.n_outs + 1) {
        snprintf(outKey, outKeyLen, "Fee");
        uint64_t fee = (ctx->tx_obj->tx.p_import_tx.base_secp_ins.in_sum + ctx->tx_obj->tx.p_import_tx.secp_ins.in_sum) -
                       ctx->tx_obj->tx.p_import_tx.base_secp_outs.out_sum;
        CHECK_ERROR(
            printAmount64(fee, AMOUNT_DECIMAL_PLACES, ctx->tx_obj->network_id, outVal, outValLen, pageIdx, pageCount));
        return parser_ok;
    }

    if (displayIdx ==
        ctx->tx_obj->tx.p_import_tx.base_secp_outs.n_addrs + ctx->tx_obj->tx.p_import_tx.base_secp_outs.n_outs + 1 + 1) {
        snprintf(outKey, outKeyLen, "Hash");
        printHash(ctx, outVal, outValLen, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_display_idx_out_of_range;
}
