/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { Buffer } from 'buffer';
import * as crypto from 'crypto';

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
