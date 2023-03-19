/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, createView } from '@noble/hashes/utils';
import { bytesToString } from '@scure/base';
import { HDKissDocumentType } from './HDKissDocumentType';
import { Bip32NetworkInfo, Versions } from './Versions';

export interface HDKissAddressConstructorParams {
    publicKey: Uint8Array;
    type: HDKissDocumentType;
    version: Bip32NetworkInfo;
}

export class HDKissAddress {

    _publicKey: Uint8Array;
    _version: Bip32NetworkInfo;
    _type: HDKissDocumentType;
    _rawAddress!: Uint8Array;
    _addressValue!: string;
    _formatted!: string;
    _display!: string;

    constructor(params: HDKissAddressConstructorParams) {
        const length = params.publicKey.length;
        if (length !== 33 && length !== 64) {
            throw new Error('invalid public key');
        }
        this._publicKey = params.publicKey;
        this._version = params.version;
        this._type = params.type;
    }

    static from(publicKey: Uint8Array, type: HDKissDocumentType, version: Bip32NetworkInfo): HDKissAddress {
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
            if (version === Versions.nip76API1) {
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

    get publicKey(): Uint8Array {
        return this._publicKey;
    }

    get rawAddress(): Uint8Array {
        if (!this._rawAddress) {
            const hash = ripemd160(sha256((this._publicKey)));
            const prefixedHash = new Uint8Array(1);
            const phv = createView(prefixedHash);
            phv.setUint8(0,this._version.networkId);
            this._rawAddress = concatBytes(prefixedHash, hash);
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
            const base32 = bytesToString('base32', this.rawAddress.slice(1, 21))
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
