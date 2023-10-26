import { INSGeneric, ResponseBase } from "@zondax/ledger-js";

export interface FlareIns extends INSGeneric {
  GET_VERSION: 0x00;
  GET_ADDR: 0x01;
  SIGN: 0x02;
}

export interface ResponseAddress extends ResponseBase {
  bech32_address?: string;
  compressed_pk?: Buffer;
}

export interface ResponseSign extends ResponseBase {
  signature?: Buffer;
}
