/** ******************************************************************************
 *  (c) 2019-2020 Zondax GmbH
 *  (c) 2016-2017 Ledger
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
 ******************************************************************************* */
import { HASH_LEN, INS, P2_VALUES } from "./consts";
import { ResponseAddress, ResponseSign, FlareIns } from "./types";

import GenericApp, {
  ConstructorParams,
  errorCodeToString,
  LedgerError,
  PAYLOAD_TYPE,
  processErrorResponse,
  Transport,
} from "@zondax/ledger-js";
import { processGetAddrResponse, serializeHrp } from "./helper";

export * from "./types";

export default class FlareApp extends GenericApp {
  constructor(transport: Transport) {
    if (transport == null) throw new Error("Transport has not been defined");

    const params: ConstructorParams = {
      cla: 0x58,
      ins: {
        GET_VERSION: 0x00,
        GET_ADDR: 0x01,
        SIGN: 0x02,
        SIGN_HASH: 0x03,
      },
      p1Values: {
        ONLY_RETRIEVE: 0x00,
        SHOW_ADDRESS_IN_DEVICE: 0x01,
      },
      acceptedPathLengths: [4, 5, 6],
      chunkSize: 250,
    };
    super(transport, params);
  }

  async _pubkey(path: string, show = true, hrp?: string): Promise<ResponseAddress> {
    const p1 = show ? this.P1_VALUES.SHOW_ADDRESS_IN_DEVICE : this.P1_VALUES.ONLY_RETRIEVE;
    const serializedPath = this.serializePath(path);
    const serializedHrp = serializeHrp(hrp);

    return this.transport
      .send(this.CLA, this.INS.GET_ADDR, p1, P2_VALUES.DEFAULT, Buffer.concat([serializedHrp, serializedPath]), [
        LedgerError.NoErrors,
      ])
      .then(processGetAddrResponse, processErrorResponse);
  }

  async getAddressAndPubKey(path: string, hrp = "flare"): Promise<ResponseAddress> {
    return this._pubkey(path, false, hrp);
  }

  async showAddressAndPubKey(path: string, hrp = "flare"): Promise<ResponseAddress> {
    return this._pubkey(path, true, hrp);
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, ins: INS): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD;
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT;
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST;
    }

    return await this.transport
      .send(this.CLA, ins, payloadType, 0, chunk, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.subarray(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);

        let signature = Buffer.alloc(0);

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response.subarray(0, response.length - 2).toString("ascii")}`;
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          signature = response.slice(0, response.length - 2);
          return {
            signature,
            returnCode,
            errorMessage,
          };
        }

        return {
          returnCode,
          errorMessage,
        };
      }, processErrorResponse);
  }

  async sign(path: string, message: Buffer): Promise<ResponseSign> {
    const chunks = this.prepareChunks(path, message);
    return await this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN).then(async (response) => {
      let result: ResponseSign = {
        returnCode: response.returnCode,
        errorMessage: response.errorMessage,
      };

      for (let i = 1; i < chunks.length; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN);
        if (result.returnCode !== LedgerError.NoErrors) {
          break;
        }
      }
      return result;
    }, processErrorResponse);
  }

  async signHash(path: string, hash: Buffer): Promise<ResponseSign> {
    if (hash.length !== HASH_LEN) {
      throw new Error("Invalid hash length");
    }

    const chunks = this.prepareChunks(path, hash);
    return await this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_HASH).then(async (response) => {
      let result: ResponseSign = {
        returnCode: response.returnCode,
        errorMessage: response.errorMessage,
      };

      for (let i = 1; i < chunks.length; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_HASH);
        if (result.returnCode !== LedgerError.NoErrors) {
          break;
        }
      }
      return result;
    }, processErrorResponse);
  }
}
