/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as secp from '@noble/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as sha256x } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';

export function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
    return hmac.create(sha512, new Uint8Array(key)).update(new Uint8Array(data)).digest();
}

export function sha256(data: Uint8Array): Uint8Array {
    return sha256x.create().update(new Uint8Array(data)).digest();
}

export function hash160(data: Uint8Array): Uint8Array {
    const d1 = sha256x.create().update(new Uint8Array(data)).digest();
    return ripemd160.create().update(d1).digest();
}

secp.utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
    return hmac.create(sha256x, key).update(secp.utils.concatBytes(...messages)).digest();
};
 