/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import * as secp from '@noble/secp256k1';

export function hmacSha512(key: Buffer, data: Buffer): Buffer {
    return crypto.createHmac('sha512', key).update(data).digest();
}

export function sha256(data: any): Buffer {
    return crypto.createHash('sha256').update(data).digest();
}

export function hash160(data: Buffer): Buffer {
    const d = crypto.createHash('sha256').update(data).digest();
    return crypto.createHash('rmd160').update(d).digest();
}

secp.utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
    const a = Buffer.from(key);
    const args = secp.utils.concatBytes(...messages);
    const bufArgs = Buffer.from(args);
    return crypto.createHmac('sha256', a).update(bufArgs).digest();
};