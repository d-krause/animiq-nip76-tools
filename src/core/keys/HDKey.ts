/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
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
        } else if (params.privateKey && params.privateKey.length !== 32) {
            throw new Error('private key must be 32 bytes');
        } else if (params.publicKey && (params.publicKey.length !== 33 && params.publicKey.length !== 65)) {
            throw new Error('private key must be 33 or 65 bytes');
        }
        if (params.privateKey) {
            this._privateKey = params.privateKey;
            this._publicKey = Buffer.from(secp.getPublicKey(params.privateKey, true));
        } else if (params.publicKey) {
            this._publicKey = Buffer.from(secp.Point.fromHex(params.publicKey).toRawBytes(true));
        }
        if (params.chainCode) this._chainCode = params.chainCode;
        this._depth = params.depth || 0;
        this._index = params.index || 0;
        if (params.parentFingerprint) this._parentFingerprint = params.parentFingerprint;
        if (!this.depth) {
            if (this.parentFingerprint || this.index) {
              throw new Error('HDKey: zero depth with non-zero index/parent fingerprint');
            }
          }
        this._keyIdentifier = hash160(this._publicKey);
        this._version = params.version || Versions.bitcoinMain;
    }
    static parseMasterSeed(seed: Buffer, version: Bip32NetworkInfo): HDKey {
        const i = hmacSha512(Buffer.from('Bitcoin seed'), seed);
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
        const version = key.length === 99 ? Versions.nip76API1 : Versions.bitcoinMain;
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
    static fromJSON(json: { xpriv: string }): HDKey {
        return HDKey.parseExtendedKey(json.xpriv);
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
        return this._privateKey;
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
    get nostrPubKey(): string {
        return this._publicKey.slice(1).toString('hex');
    }
    derive(chain: string): HDKey {
        if (!/^[mM]'?/.test(chain)) {
          throw new Error('Path must start with "m" or "M"');
        }
        if (/^[mM]'?$/.test(chain)) {
          return this;
        }
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
        let index = childIndex;
        const data = Buffer.alloc(37);
        let o = 0;
        if (hardened) {
            if (!this.privateKey) {
                throw new Error('cannot derive a hardened child key from a public key');
            }
            index += HARDENED_KEY_OFFSET;
            o += 1;
            o += this.privateKey.copy(data, o);
        } else {
            o += this.publicKey.copy(data, o);
        }

        o += data.writeUInt32BE(index, o);
        const i = hmacSha512(this.chainCode, data);
        const iL = BigInt('0x' + i.slice(0, 32).toString('hex'));
        const iR = i.slice(32);
        if (iL >= secp.CURVE.n) {
            return this.deriveChildKey(childIndex + 1, hardened);
        }
        if (this.privateKey) {
            const childKey = secp.utils.mod(iL + BigInt('0x' + this.privateKey.toString('hex')), secp.CURVE.n);
            if (childKey === 0n) {
                return this.deriveChildKey(childIndex + 1, hardened);
            }
            return new HDKey({
                depth: this.depth + 1,
                privateKey: Buffer.from(secp.utils._bigintTo32Bytes(childKey)),
                chainCode: iR,
                parentFingerprint: this.fingerprint,
                index,
                version: this.version
            });
        } else {
            const parentKey = secp.Point.fromHex(this.publicKey);
            const childKey = parentKey.add(secp.Point.fromPrivateKey(iL));
            try {
                childKey.assertValidity();
            } catch (error) {
                return this.deriveChildKey(childIndex + 1, false);
            }
            return new HDKey({
                depth: this.depth + 1,
                publicKey: Buffer.from(childKey.toRawBytes(true)),
                chainCode: iR,
                parentFingerprint: this.fingerprint,
                index,
                version: this.version
            });
        }
    }
    wipePrivateData() {
        if (this._privateKey) {
            this._privateKey.fill(0);
            this._privateKey = null as unknown as Buffer;
        }
        return this;
    }
    sign(hash: Uint8Array): Buffer {
        if (!this._privateKey) {
            throw new Error('No privateKey set!');
        }
        if (hash.length !== 32) throw new Error('message length is invalid');
        return Buffer.from(secp.signSync(hash, this._privateKey!, {
            canonical: true,
            der: false,
        }));
    }
    verify(hash: Buffer, signature: Buffer): boolean {
        if (hash.length !== 32) throw new Error('message length is invalid');
        if (signature.length !== 64) throw new Error('signature length is invalid');
        if (!this._publicKey) {
            throw new Error('No publicKey set!');
        }
        let sig;
        try {
            sig = secp.Signature.fromCompact(signature);
        } catch (error) {
            return false;
        }
        return secp.verify(sig, hash, this.publicKey);
    }
    toJSON(): { xpriv: string; xpub: string } {
        return {
            xpriv: this.extendedPrivateKey!,
            xpub: this.extendedPublicKey,
        };
    }
    createIndexesFromWord(word: string, length = 16): Int32Array {
        const hash0 = sha256(Buffer.from(word));
        const hash1 = hmacSha512(this.privateKey, hash0);
        const hash2 = hmacSha512(this.chainCode, hash0);
        const r2 = new Int32Array(20);
        for (let i = 0; i < length; i++) {
            const value = i < 8 ? Math.abs(hash1.readInt32BE(i * 8)) : Math.abs(hash2.readInt32BE((i - 8) * 8));
            r2[i] = value;
        }
        r2[16] = Math.abs(hash0.readInt32BE(0));
        r2[17] = Math.abs(hash0.readInt32BE(8));
        r2[18] = Math.abs(hash0.readInt32BE(16));
        r2[19] = Math.abs(hash0.readInt32BE(24));
        return r2;
    }
    deriveNewMasterKey(): HDKey {
        const i = hmacSha512(this.publicKey, this.chainCode);
        const iL = i.slice(0, 32);
        const iR = i.slice(32);
        return new HDKey({ privateKey: iL, chainCode: iR, version: this.version });
    }
}
