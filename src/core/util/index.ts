/*
 * Copyright Kepler Group, Inc. - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * The contents of this file are considered proprietary and confidential.
 * Written by Dave Krause <dkrause@keplergroupsystems.com>, February 2019
 */
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
