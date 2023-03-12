/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { Buffer } from 'buffer';
import * as secp from '@noble/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as sha256x } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';

export const uint8ArrayFromBuffer = (data: Buffer) => {
    const u8a = new Uint8Array(data.length);
    data.forEach((d, i) => { u8a[i] = d });
    return u8a;
}

export function hmacSha512(key: Buffer, data: Buffer): Buffer {
    return Buffer.from(hmac.create(sha512, uint8ArrayFromBuffer(key)).update(uint8ArrayFromBuffer(data)).digest());
}

export function sha256(data: Buffer): Buffer {
    return Buffer.from(sha256x.create().update(uint8ArrayFromBuffer(data)).digest());
}

export function hash160(data: Buffer): Buffer {
    const d1 = sha256x.create().update(uint8ArrayFromBuffer(data)).digest();
    return Buffer.from(ripemd160.create().update(d1).digest());
}

secp.utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
    return Buffer.from(hmac.create(sha256x, key).update(secp.utils.concatBytes(...messages)).digest())
};
 