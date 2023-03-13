/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as Base58 from 'bs58';
import { hmacSha512, sha256, hash160 } from '../util';
import { Versions, Bip32NetworkInfo } from './Versions';
import * as secp from '@noble/secp256k1';
import { assertBytes, bytesToHex, concatBytes, createView, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
// tslint:disable: quotemark max-line-length
const HARDENED_KEY_OFFSET = 0x80000000;

function bytesToNumber(bytes: Uint8Array): bigint {
    return BigInt(`0x${bytesToHex(bytes)}`);
}

function numberToBytes(num: bigint): Uint8Array {
    return hexToBytes(num.toString(16).padStart(64, '0'));
}
const fromU32 = (data: Uint8Array) => createView(data).getUint32(0, false);
const toU32 = (n: number) => {
    if (!Number.isSafeInteger(n) || n < 0 || n > 2 ** 32 - 1) {
        throw new Error(`Invalid number=${n}. Should be from 0 to 2 ** 32 - 1`);
    }
    const buf = new Uint8Array(4);
    createView(buf).setUint32(0, n, false);
    return buf;
};

interface HDKeyConstructorParams {
    privateKey?: Uint8Array;
    publicKey?: Uint8Array;
    chainCode?: Uint8Array;
    index?: number;
    depth?: number;
    parentFingerprint?: number;
    version?: Bip32NetworkInfo;
}
export class HDKey {
    static readonly hardenedKeyOffset: number = HARDENED_KEY_OFFSET;
    _privateKey!: Uint8Array;
    _publicKey!: Uint8Array;
    _chainCode!: Uint8Array;
    _depth: number;
    _index: number;
    _parentFingerprint!: number;
    _keyIdentifier: Uint8Array;
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
            this._publicKey = secp.getPublicKey(params.privateKey, true);
        } else if (params.publicKey) {
            this._publicKey = secp.Point.fromHex(params.publicKey).toRawBytes(true);
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
    static parseMasterSeed(seed: Uint8Array, version: Bip32NetworkInfo): HDKey {
        const i = hmacSha512(utf8ToBytes('Bitcoin seed'), seed);
        const iL = i.slice(0, 32);
        const iR = i.slice(32);
        return new HDKey({ privateKey: iL, chainCode: iR, version: version });
    }
    static parseExtendedKey(key: string): HDKey {
        // version_bytes[4] || depth[1] || parent_fingerprint[4] || index[4] || chain_code[32] || key_data[33] || checksum[4]
        const decoded = Base58.decode(key);
        if (decoded.length > 112) {
            throw new Error('invalid extended key');
        }
        const version = key.length === 99 ? Versions.nip76API1 : Versions.bitcoinMain;
        const checksum = fromU32(decoded.slice(-4));
        const buf = decoded.slice(0, -4);
        const foo = fromU32(sha256(sha256(buf)).slice(0, 4));
        if (foo != checksum) {
            throw new Error('invalid checksum');
        }
        let o = 0;
        const keyView = createView(buf);
        const versionRead = keyView.getUint32(o);
        let depth: number, index: number, parentFingerprint: number | undefined;
        o += 4;
        if (!version.cloaked) {
            depth = decoded[4];
            o += 1;
            parentFingerprint = keyView.getUint32(o);
            o += 4;
            if (parentFingerprint === 0) {
                parentFingerprint = undefined;
            }
            index = keyView.getUint32(o);
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
    serialize(prefix: number, key: Uint8Array): string {
        // version_bytes[4] || depth[1] || parent_fingerprint[4] || index[4] || chain_code[32] || key_data[33] || checksum[4]
        const bytes = secp.utils.concatBytes(
            toU32(prefix),
            this.version.cloaked ? new Uint8Array([]) : new Uint8Array([this.depth]),
            this.version.cloaked ? new Uint8Array([]) : toU32(this.parentFingerprint || 0),
            this.version.cloaked ? new Uint8Array([]) : toU32(this.index),
            this.chainCode,
            key.length === 32 ? new Uint8Array([0]) : new Uint8Array([]),
            key,
        );
        const checksum = sha256(sha256(bytes)).slice(0, 4);
        return Base58.encode(secp.utils.concatBytes(bytes, checksum));
    }
    get privateKey(): Uint8Array {
        return this._privateKey;
    }
    get publicKey(): Uint8Array {
        return this._publicKey;
    }
    get chainCode(): Uint8Array {
        return this._chainCode;
    }
    get depth(): number {
        return this._depth;
    }
    get parentFingerprint(): number | undefined {
        return this._parentFingerprint || undefined;
    }
    get index(): number {
        return this._index;
    }
    get keyIdentifier(): Uint8Array {
        return this._keyIdentifier;
    }
    get fingerprint(): number {
        return fromU32(this._keyIdentifier.slice(0, 4));
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
        return secp.utils.bytesToHex(this._publicKey.slice(1));
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
    public deriveChildKey(index: number, hardened = false): HDKey {
        if (!this.publicKey || !this.chainCode) {
            throw new Error('No publicKey or chainCode set');
        }
        let data: Uint8Array;
        if (hardened) {
            const priv = this.privateKey;
            if (!priv) {
                throw new Error('Could not derive hardened child key');
            }
            index += HARDENED_KEY_OFFSET;
            // Hardened child: 0x00 || ser256(kpar) || ser32(index)
            data = toU32(index);
            data = concatBytes(new Uint8Array([0]), priv, data);
        } else {
            // Normal child: serP(point(kpar)) || ser32(index)
            data = toU32(index);
            data = concatBytes(this.publicKey, data);
        }
        const I = hmac(sha512, this.chainCode, data);
        const childTweak = bytesToNumber(I.slice(0, 32));
        const chainCode = I.slice(32);
        if (!secp.utils.isValidPrivateKey(childTweak)) {
            throw new Error('Tweak bigger than curve order');
        }
        const opt = {
            version: this.version,
            chainCode,
            depth: this.depth + 1,
            parentFingerprint: this.fingerprint,
            index
        } as HDKeyConstructorParams;
        try {
            // Private parent key -> private child key
            if (this.privateKey) {
                const privKey = bytesToNumber(this.privateKey);
                const added = secp.utils.mod(privKey! + childTweak, secp.CURVE.n);
                if (!secp.utils.isValidPrivateKey(added)) {
                    throw new Error('The tweak was out of range or the resulted private key is invalid');
                }
                opt.privateKey = numberToBytes(added);
            } else {
                const added = secp.Point.fromHex(this.publicKey).add(secp.Point.fromPrivateKey(childTweak));
                // Cryptographically impossible: hmac-sha512 preimage would need to be found
                if (added.equals(secp.Point.ZERO)) {
                    throw new Error('The tweak was equal to negative P, which made the result key invalid');
                }
                opt.publicKey = added.toRawBytes(true);
            }
            return new HDKey(opt);
        } catch (err) {
            return this.deriveChildKey(index + 1, hardened);
        }
    }
    wipePrivateData() {
        if (this._privateKey) {
            this._privateKey.fill(0);
            this._privateKey = null as unknown as Uint8Array;
        }
        return this;
    }
    sign(hash: Uint8Array): Uint8Array {
        if (!this.privateKey) {
            throw new Error('No privateKey set!');
        }
        assertBytes(hash, 32);
        return secp.signSync(hash, this.privateKey!, {
            canonical: true,
            der: false,
        });
    }
    verify(hash: Uint8Array, signature: Uint8Array): boolean {
        assertBytes(hash, 32);
        assertBytes(signature, 64);
        if (!this.publicKey) {
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
        const hash = sha256(new TextEncoder().encode(word));
        const hash0 = createView(hash);
        const hash1 = createView(hmacSha512(this.privateKey, hash));
        const hash2 = createView(hmacSha512(this.chainCode, hash));
        const r2 = new Int32Array(20);
        for (let i = 0; i < length; i++) {
            const value = i < 8 ? Math.abs(hash1.getInt32(i * 8)) : Math.abs(hash2.getInt32((i - 8) * 8));
            r2[i] = value;
        }
        r2[16] = Math.abs(hash0.getInt32(0));
        r2[17] = Math.abs(hash0.getInt32(8));
        r2[18] = Math.abs(hash0.getInt32(16));
        r2[19] = Math.abs(hash0.getInt32(24));
        return r2;
    }
    deriveNewMasterKey(): HDKey {
        const i = hmacSha512(this.publicKey, this.chainCode);
        const iL = i.slice(0, 32);
        const iR = i.slice(32);
        return new HDKey({ privateKey: iL, chainCode: iR, version: this.version });
    }
}
