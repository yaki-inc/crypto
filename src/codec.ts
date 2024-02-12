import { Range } from "semver";
import { DatagramCodec, DatagramMetadata, SymmetricKey, bytesToUtf8String, utf8StringToBytes } from "./crypto";
import { SuperJSON } from "superjson";

export type StringDatagramMetadata = {
  type: 'datagram://string',
  version: '0.1.0'
};

export const StringDatagramCodec: DatagramCodec<string, StringDatagramMetadata> = {
  metadata: { type: 'datagram://string', version: '0.1.0'},
  versionRange: new Range('^0.1.0'),
  serialize: utf8StringToBytes,
  deserialize: bytesToUtf8String
}

export type NumberDatagramMetadata = {
  type: 'datagram://number',
  version: '0.1.0'
}

export const NumberDatagramCodec: DatagramCodec<number, NumberDatagramMetadata> = {
  metadata: { type: 'datagram://number', version: '0.1.0'},
  versionRange: new Range('^0.1.0'),
  serialize: n => utf8StringToBytes(''+n),
  deserialize: b => Number(bytesToUtf8String(b))
}

export type SymmetricKeyDatagramMetadata = {
  type: 'datagram://symmetric',
  version: '0.1.0'
}

export const SymmetricKeyDatagramCodec: DatagramCodec<SymmetricKey, SymmetricKeyDatagramMetadata> = {
  metadata: { type: 'datagram://symmetric', version: '0.1.0'},
  versionRange: new Range('^0.1.0'),
  serialize: k => k,
  deserialize: k => k
}

export const createJsonDatagramCodec = <T, M extends DatagramMetadata>(metadata: M, versionRange: Range = new Range('0.1.*')): DatagramCodec<T, M> => {
  if (!versionRange.test(metadata.version)) {
    throw RangeError(`version does not match provided range ${versionRange.range}`);
  }
  return {
    metadata,
    versionRange,
    serialize: (data: T) => {
      return utf8StringToBytes(SuperJSON.stringify(data));
    },
    deserialize: (bytes: Uint8Array) => {
      return SuperJSON.parse(bytesToUtf8String(bytes)) as T;
    }
  }
}

function integerToUint8Array(num: number): Uint8Array {
  let arr = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    arr[i] = num % 256;
    num = Math.floor(num / 256);
  }
  return arr;
}

function uint8ArrayToInteger(arr: Uint8Array): number {
  let num = 0;
  for (let i = 7; i >= 0; i--) {
    num = num * 256 + arr[i];
  }
  return num;
}
