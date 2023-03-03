/*
 * Copyright Kepler Group, Inc. - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * The contents of this file are considered proprietary and confidential.
 * Written by Dave Krause <dkrause@keplergroupsystems.com>, February 2019
 */
import * as Base58 from 'bs58';
import { Buffer } from 'buffer';
import { hmacSha512, sha256, hash160 } from '../util';
import { Versions, Bip32NetworkInfo } from './Versions';
import * as secp from '@noble/secp256k1';

// tslint:disable: quotemark max-line-length
const HARDENED_KEY_OFFSET = 0x80000000;

interface HDKeyConstructorParams {
    privateKey?: Buffer;
    publicKey?: Buffer;
    chainCode?: Buffer;
    index?: number;
    depth?: number;
    parentFingerprint?: Buffer;
    version?: Bip32NetworkInfo;
}
export class HDKey {
    static readonly hardenedKeyOffset: number = HARDENED_KEY_OFFSET;
    _privateKey!: Buffer;
    _publicKey!: Buffer;
    _chainCode!: Buffer;
    _depth: number;
    _index: number;
    _parentFingerprint!: Buffer;
    _keyIdentifier: Buffer;
    _version: Bip32NetworkInfo;
    constructor(params: HDKeyConstructorParams) {
        if (!params.privateKey && !params.publicKey) {
            throw new Error('either private key or public key must be provided');
        }
        if (params.privateKey) {
            this._privateKey = params.privateKey;
            this._publicKey = Buffer.from(secp.schnorr.getPublicKey(params.privateKey));
            // const ecdh = crypto.createECDH('secp256k1');
            // if (ecdh['curve'] && ecdh['curve']['keyFromPrivate']) {
            //     // ECDH is not native, fallback to pure-JS elliptic lib
            //     this._publicKey = Buffer.from(secp256k1.keyFromPrivate(params.privateKey).getPublic(true, 'hex'), 'hex');
            // } else {
            //     ecdh.setPrivateKey(params.privateKey);
            //     this._publicKey = Buffer.from(ecdh.getPublicKey('latin1', 'compressed'), 'latin1');
            // }
        } else if (params.publicKey) {
            this._publicKey = params.publicKey;
        }
        if (params.chainCode) this._chainCode = params.chainCode;
        this._depth = params.depth || 0;
        this._index = params.index || 0;
        if (params.parentFingerprint) this._parentFingerprint = params.parentFingerprint;
        this._keyIdentifier = hash160(this._publicKey);
        this._version = params.version || Versions.bitcoinMain;
    }
    static parseMasterSeed(seed: Uint32Array, version: Bip32NetworkInfo): HDKey {
        const i = hmacSha512(Buffer.from('Bitcoin seed'), Buffer.from(seed));
        const iL = i.slice(0, 32);
        const iR = i.slice(32);
        return new HDKey({ privateKey: iL, chainCode: iR, version: version });
    }
    static parseExtendedKey(key: string): HDKey {
        // version_bytes[4] || depth[1] || parent_fingerprint[4] || index[4] || chain_code[32] || key_data[33] || checksum[4]
        const decoded = Buffer.from(Base58.decode(key));
        if (decoded.length > 112) {
            throw new Error('invalid extended key');
        }
        const version = key.length === 99 ? Versions.animiqAPI3 : Versions.animiqAPI2;
        const checksum = decoded.slice(-4);
        const buf = decoded.slice(0, -4);
        if (!sha256(sha256(buf)).slice(0, 4).equals(checksum)) {
            throw new Error('invalid checksum');
        }
        let o = 0;

        const versionRead = buf.readUInt32BE(o);
        let depth: number, index: number, parentFingerprint: Buffer | undefined;
        o += 4;
        if (!version.cloaked) {
            depth = buf.readUInt8(o);
            o += 1;
            parentFingerprint = buf.slice(o, o += 4);
            if (parentFingerprint.readUInt32BE(0) === 0) {
                parentFingerprint = undefined;
            }
            index = buf.readUInt32BE(o);
            o += 4;
        } else {
            depth = undefined as any as number;
            index = undefined as any as number;
        }
        const chainCode = buf.slice(o, o += 32);
        const keyData = buf.slice(o);
        const privateKey = keyData[0] === 0 ? keyData.slice(1) : undefined;
        const publicKey = keyData[0] !== 0 ? keyData : undefined;
        if (privateKey && versionRead !== version.bip32.private || publicKey && versionRead !== version.bip32.public) {
            throw new Error('invalid version bytes');
        }
        return new HDKey({
            privateKey,
            publicKey,
            chainCode,
            index,
            depth,
            parentFingerprint,
            version
        });
    }
    static concatPublicKeys(...keys: HDKey[]): Buffer {
        const buf = Buffer.alloc(65 * keys.length);
        let o = 0;
        keys.forEach(k => {
            o += k.chainCode.copy(buf, o);
            o += k.publicKey.copy(buf, o);
        });
        return buf;
    }
    static deconcatPublicKeys(buf: Buffer): HDKey[] {
        const numKeys = buf.length / 65;
        const keys: HDKey[] = [];
        let o = 0;
        for (let i = 0; i < numKeys; i++) {
            const chainCode = buf.slice(o, o += 32);
            const publicKey = buf.slice(o, o += 33);
            const k = new HDKey({ publicKey, chainCode, version: Versions.animiqAPI3 });
            keys.push(k);
        }
        return keys;
    }
    serialize(prefix: number, key: Buffer): string {
        // version_bytes[4] || depth[1] || parent_fingerprint[4] || index[4] || chain_code[32] || key_data[33] || checksum[4]
        const buf = Buffer.alloc(!this.version.cloaked ? 78 : 69);
        let o = buf.writeUInt32BE(prefix, 0);
        if (!this.version.cloaked) {
            o = buf.writeUInt8(this.depth, o);
            o += this.parentFingerprint ? this.parentFingerprint.copy(buf, o) : 4;
            o = buf.writeUInt32BE(this.index, o);
        }
        o += this.chainCode.copy(buf, o);
        o += 33 - key.length;
        key.copy(buf, o);
        const checksum = sha256(sha256(buf)).slice(0, 4);
        return Base58.encode(Buffer.concat([buf, checksum]));
    }
    get privateKey(): Buffer {
        return this._privateKey || null;
    }
    get publicKey(): Buffer {
        return this._publicKey;
    }
    get chainCode(): Buffer {
        return this._chainCode;
    }
    get depth(): number {
        return this._depth;
    }
    get parentFingerprint(): Buffer {
        return this._parentFingerprint || null;
    }
    get index(): number {
        return this._index;
    }
    get keyIdentifier(): Buffer {
        return this._keyIdentifier;
    }
    get fingerprint(): Buffer {
        return this._keyIdentifier.slice(0, 4);
    }
    get version() {
        return this._version;
    }
    get extendedPrivateKey(): string | null {
        return this._privateKey ? this.serialize(this._version.bip32.private, this._privateKey) : null;
    }
    get extendedPublicKey(): string {
        return this.serialize(this._version.bip32.public, this._publicKey);
    }
    get publicKeyString(): string {
        return this._publicKey.toString('base64');
    }
    get extendedPublicKeyHash(): string {
        return Base58.encode(sha256(this.serialize(this._version.bip32.public, this._publicKey)));
    }
    derive(chain: string): HDKey {
        const c = chain.toLowerCase();
        let childKey = this as HDKey;
        c.split('/').forEach(path => {
            const p = path.trim();
            if (p === 'm' || p === "m'" || p === '') {
                return;
            }
            const index = Number.parseInt(p, 10);
            if (Number.isNaN(index)) {
                throw new Error('invalid child key derivation chain');
            }
            const hardened = p.slice(-1) === "'";
            childKey = childKey.deriveChildKey(index, hardened);
        });
        return childKey;
    }
    deriveChildKey(childIndex: number, hardened = false): HDKey {
        if (childIndex >= HARDENED_KEY_OFFSET) {
            throw new Error('invalid index');
        }
        if (!this.privateKey && !this.publicKey) {
            throw new Error('either private key or public key must be provided');
        }
        // if (!secp256k1.n) {
        //     throw new Error('secp256k1.n required');
        // }
        let index = childIndex;

        const data = Buffer.alloc(37);
        let o = 0;
        if (hardened) {
            if (!this.privateKey) {
                throw new Error('cannot derive a hardened child key from a public key');
            }
            // 0x00 || ser256(kpar) || ser32(i)
            // 0x00[1] || parent_private_key[32] || child_index[4]
            index += HARDENED_KEY_OFFSET;
            o += 1;
            o += this.privateKey.copy(data, o);
        } else {
            // serP(point(kpar)) || ser32(i)
            // compressed_parent_public_key[33] || child_index[4]
            o += this.publicKey.copy(data, o);
        }

        o += data.writeUInt32BE(index, o);
        const i = hmacSha512(this.chainCode, data);
        // const iL = new BigNumber(i.slice(0, 32));
        const iL2 = BigInt('0x' + i.slice(0, 32).toString('hex'));
        const iR = i.slice(32);
        // if parse256(IL) >= n, the resulting key is invalid; proceed with the next value for i
        // if (iL.cmp(secp256k1.n) >= 0) {
        if (iL2 >= secp.CURVE.n) {
            return this.deriveChildKey(childIndex + 1, hardened);
        }
        if (this.privateKey) {
            // ki is parse256(IL) + kpar (mod n)
            // const childKey = iL.add(new BigNumber.BN(this.privateKey)).mod(secp256k1.n);
            const childKey2 = secp.utils.mod(iL2 + BigInt('0x' + this.privateKey.toString('hex')), secp.CURVE.n);
            // if ki = 0, the resulting key is invalid; proceed with the next value for i
            // if (childKey.cmp(new BigNumber.BN(0)) === 0) {
            if (childKey2 === 0n) {
                return this.deriveChildKey(childIndex + 1, hardened);
            }
            // const data1 = childKey.toArrayLike(Buffer, 'be', 32)
            // const data2 = secp.utils._bigintTo32Bytes(childKey2)
            return new HDKey({
                depth: this.depth + 1,
                // privateKey: childKey.toArrayLike(Buffer, 'be', 32),
                privateKey: Buffer.from(secp.utils._bigintTo32Bytes(childKey2)),
                chainCode: iR,
                parentFingerprint: this.fingerprint,
                index,
                version: this.version
            });
        } else {
            // Ki is point(parse256(IL)) + Kpar = G * IL + Kpar
            // const parentKey = secp256k1.keyFromPublic(Buffer.concat([Buffer.from([0x02]),this.publicKey])).getPublic();
            // const childKey = secp256k1.g.mul(iL).add(parentKey);
            
            const parentKey2 = secp.Point.fromHex(this.publicKey.toString('hex'));
            const childKey2 = secp.Point.BASE.multiply(iL2).add(parentKey2);          
            
            // if Ki is the point at infinity, the resulting key is invalid; proceed with the next value for i
            // if (childKey.isInfinity()) {
            //     return this.deriveChildKey(childIndex + 1, false);
            // }
            try {
                childKey2.assertValidity();
            } catch (error) {
                return this.deriveChildKey(childIndex + 1, false);
            }
            // const compressedChildKey = Buffer.from(childKey.encode(null, true));
            return new HDKey({
                depth: this.depth + 1,
                // publicKey: compressedChildKey.slice(1),
                publicKey: Buffer.from(childKey2.toRawX()),
                chainCode: iR,
                parentFingerprint: this.fingerprint,
                index,
                version: this.version
            });
        }
    }
    createIndexesFromWord(word: string, length = 16): Int32Array {
        const hash = hmacSha512(this.chainCode, sha256(word));
        const hash1 = hmacSha512(this.privateKey, hash);
        const hash2 = sha256(hash1);
        const r2 = new Int32Array(20);
        for (let i = 0; i < length; i++) {
            const value = i < 8 ? Math.abs(hash.readInt32BE(i * 8)) : Math.abs(hash1.readInt32BE((i - 8) * 8));
            r2[i] = value;
        }
        r2[16] = Math.abs(hash2.readInt32BE(0));
        r2[17] = Math.abs(hash2.readInt32BE(8));
        r2[18] = Math.abs(hash2.readInt32BE(16));
        r2[19] = Math.abs(hash2.readInt32BE(24));
        return r2;
    }
}
