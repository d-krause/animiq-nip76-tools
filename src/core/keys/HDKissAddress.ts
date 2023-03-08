/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as crypto from 'crypto';
import { Buffer } from 'buffer';
import { sha256, hash160 } from '../util';
import { Bip32NetworkInfo, Versions } from './Versions';
import { HDKissDocumentType } from './HDKissDocumentType';
import * as secp from '@noble/secp256k1';
import { bytesToString } from '@scure/base'

export interface HDKissAddressConstructorParams {
    publicKey: Buffer;
    type: HDKissDocumentType;
    version: Bip32NetworkInfo;
}

export class HDKissAddress {

    _publicKey: Buffer;
    _version: Bip32NetworkInfo;
    _type: HDKissDocumentType;
    _rawAddress!: Buffer;
    _addressValue!: string;
    _formatted!: string;
    _display!: string;

    constructor(params: HDKissAddressConstructorParams) {
        const length = params.publicKey.length;
        const firstByte = params.publicKey[0];
        //SECP if (length !== 33 && length !== 65 || firstByte < 2 || firstByte > 4) {
        if (length !== 33 && length !== 64) {
            throw new Error('invalid public key');
        }
        this._publicKey = params.publicKey;
        this._version = params.version;
        this._type = params.type;
    }

    static from(publicKey: Buffer, type: HDKissDocumentType, version: Bip32NetworkInfo): HDKissAddress {
        return new HDKissAddress({ publicKey, version, type });
    }

    static isValid(_address: string, version: Bip32NetworkInfo): boolean {
        if (_address.length !== 36) {
            return false;
        }
        try {
            const type = _address.slice(0, 2);
            const check = parseInt(_address.slice(2, 4), 10);
            const base32 = _address.slice(-32);
            if (version === Versions.animiqAPI3) {
                const iban = (98 - HDKissAddress._ibanCheck(base32 + type + version.networkId + '00'));
                return iban === check;
            } else {
                const iban = (98 - HDKissAddress._ibanCheck(base32 + type + '00'));
                return iban === check;
            }
        } catch (_err) {
            return false;
        }
    }

    static _ibanCheck(str: string): number {
        const num = str.split('').map((c) => {
            const code = c.toUpperCase().charCodeAt(0);
            return code >= 48 && code <= 57 ? c : (code - 55).toString();
        }).join('');
        let tmp = '';

        for (let i = 0; i < Math.ceil(num.length / 6); i++) {
            tmp = (parseInt(tmp + num.substr(i * 6, 6), 10) % 97).toString();
        }

        return parseInt(tmp, 10);
    }

    static formatAddress(addr: string, minified: boolean = false): string {
        const formatted = addr.replace(/.{4}/g, '$& ').trim().toUpperCase();
        if (minified) {
            const parts = formatted.split(' ');
            return parts[0] + '...' + parts[8];
        } else {
            return formatted;
        }
    }

    static hashData(data: any) {
        const sdata = typeof data === 'string' ? data : JSON.stringify(data || {});
        return crypto.createHash('rmd160').update(sdata).digest().toString('base64');
    }

    static createNonce(): Buffer {
        return crypto.randomBytes(16);
    }

    static sign(data: string, privateKey: Buffer, version: number) {

        try {
            // const ecdhA = crypto.createECDH('secp256k1');

            // const kp = ecdhA['curve'] && ecdhA['curve']['keyFromPrivate']
            //     ? secp256k1.keyFromPrivate(privateKey)
            //     : ecdhA.setPrivateKey(privateKey);

            const msgHash = sha256(data);
            const signature = secp.schnorr.signSync(msgHash, privateKey);
            const signatureB64 = Buffer.from(signature).toString('base64');
            return signatureB64;
        } catch (ex) {
            console.error('Address.sign', ex);
            return 'FIXME!';
        }
    }

    static verify(data: string, signature: string, publicKey: Buffer, version: number) {

        try {
            return secp.schnorr.verifySync(signature, data, publicKey);
            // const ecdhA = crypto.createECDH('secp256k1');
            // const kp = secp256k1.keyFromPublic(publicKey);
            // const derSign = Buffer.from(signature, 'base64');
            // const msgHash = sha256(data);
            // const ret = kp.verify(msgHash, derSign);
            // return ret;
        } catch (ex) {
            console.error('Address.verify', ex);
            return false;
        }
    }

    encrypt(data: string, key: Buffer, version: number): string {

        const iv = sha256(this.publicKey).slice(0, 16);
        const secret = key.slice(0, 32);
        const cipher = crypto.createCipheriv('aes-256-gcm', secret, iv);
        const crypted = cipher.update(data, 'utf8');
        const final = cipher.final();
        const out = Buffer.concat([cipher.getAuthTag(), crypted, final]);
        return out.toString('base64');
    }

    decrypt(data: string, key: Buffer, version: number): string {

        try {
            const buf = Buffer.from(data, 'base64');
            const bdata = buf.slice(16) as any;
            const auth = buf.slice(0, 16);
            const iv = sha256(this.publicKey).slice(0, 16);
            const secret = key.slice(0, 32);
            const cipher = crypto.createDecipheriv('aes-256-gcm', secret, iv);
            cipher.setAuthTag(auth);
            const crypted = cipher.update(bdata, 'utf8');
            const final = cipher.final();
            const out = Buffer.concat([crypted, final]);
            if (out[0] == 123 && out[out.length - 1] == 125) {
                return out.toString('utf8');
            } else {
                return `{ "imageUrl": "${window.URL.createObjectURL(new Blob([out], { type: 'image/png' }))}" }`
            }

        } catch (e) {
            console.log('Address.decrypt error' + e);
            return null as any as string;
        }
    }

    encryptAS(data: Buffer, senderPrivateKey: Buffer, receiverPublicKey: Buffer): string {
        const secret = secp.getSharedSecret(senderPrivateKey, receiverPublicKey);
        const iv = sha256(this.publicKey).slice(0, 16);
        const cipher = crypto.createCipheriv('aes-256-gcm', secret, iv);
        const crypted = cipher.update(data);
        const final = cipher.final();
        const out = Buffer.concat([cipher.getAuthTag(), crypted, final]);
        return out.toString('base64');
    }

    decryptAS(data: string, senderPublicKey: Buffer, receiverPrivateKey: Buffer): Buffer {
        const secret = secp.getSharedSecret(receiverPrivateKey, senderPublicKey);
        const buf = Buffer.from(data, 'base64');
        const bdata = buf.slice(16) as any;
        const auth = buf.slice(0, 16);
        const iv = sha256(this.publicKey).slice(0, 16);
        const cipher = crypto.createDecipheriv('aes-256-gcm', secret, iv);
        cipher.setAuthTag(auth);
        const crypted = cipher.update(bdata, 'utf8');
        const final = cipher.final();
        const out = Buffer.concat([crypted, final]);
        return out;
    }

    get publicKey(): Buffer {
        return this._publicKey;
    }

    get rawAddress(): Buffer {
        if (!this._rawAddress) {
            const hash = hash160(this._publicKey);
            const prefixedHash = Buffer.alloc(1 + hash.length);
            prefixedHash.writeUInt8(this._version.networkId, 0);
            hash.copy(prefixedHash, 1);
            // const checksum = sha256(sha256(prefixedHash)).slice(0, 4);
            // this._rawAddress = Buffer.concat([prefixedHash, checksum]);
            this._rawAddress = prefixedHash;
        }
        return this._rawAddress;
    }

    /**
     * An address is 36 characters long, but the 1st two are type, 2nd two are checksum (00-99).  The last 32 are the
     * networkId plus base32 encoding of the double hash of the public key.  This means the number of addresses for a
     * given network and type is = 256^20. Or
     * 1,461,501,637,330,902,918,203,684,832,716,283,019,655,932,542,976
     * Or 1.46 Quindecillion (or 1.46 Trillion Undecillion) [49 digits]
     */
    get value(): string {
        if (!this._addressValue) {
            const base32 = bytesToString('base32',this.rawAddress.slice(1, 21))
            const check = ('00' + (98 - HDKissAddress._ibanCheck(base32 + this._type + this._version.networkId + '00'))).slice(-2);
            this._addressValue = this._type + check + base32;
        }
        return this._addressValue;
    }

    get formatted(): string {
        if (!this._formatted) {
            this._formatted = HDKissAddress.formatAddress(this.value);
        }
        return this._formatted;
    }

    get display(): string {
        if (!this._display) {
            this._display = HDKissAddress.formatAddress(this.value, true);
        }
        return this._display;
    }

}
