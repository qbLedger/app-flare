import { errorCodeToString } from "@zondax/ledger-js";
import { PKLEN } from "./consts";
import { ResponseAddress } from "./types";

export function serializeHrp(hrp?: string): Buffer {
  if (hrp) {
    const bufHrp = Buffer.from(hrp, "ascii");
    return Buffer.concat([Buffer.alloc(1, bufHrp.length), bufHrp]);
  } else {
    return Buffer.alloc(1, 0);
  }
}

export function processGetAddrResponse(response: Buffer): ResponseAddress {
  const errorCodeData = response.subarray(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const compressed_pk = Buffer.from(response.subarray(0, PKLEN));
  const bech32_address = Buffer.from(response.subarray(PKLEN, -2)).toString();

  return {
    compressed_pk,
    bech32_address,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}
