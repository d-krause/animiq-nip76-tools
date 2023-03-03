/*
 * Copyright Kepler Group, Inc. - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * The contents of this file are considered proprietary and confidential.
 * Written by Dave Krause <dkrause@keplergroupsystems.com>, February 2019
 */
import { Buffer } from 'buffer';
declare var require: any; // needed for browser
const crypto = require('crypto');
// import * as crypto from 'crypto-browserify';
import { sha256 } from '../util';
import { HDKey, Versions } from '../keys';
import { ProfileDocument, ProfileKeySet } from '../content';

interface WalletCostructorParams {
    randoms?: Uint32Array;
    storage?: WalletStorage;
}

export class Wallet {

    private master!: HDKey;
    private aqroot!: HDKey;
    private pproot!: HDKey;
    private aproot!: HDKey;
    private sproot!: HDKey;
    private password = '';
    private lockword = '';
    private locknums!: Int32Array;
    profiles: ProfileDocument[] = [];
    isGuest = false;
    isInSession = false;
    sessionValid = false;
    requiresLogin = false;

    constructor() {
        const storedWallet = window.localStorage.getItem(WalletStorage.backupKey);
        const sessionWallet = window.localStorage.getItem(WalletStorage.sessionKey);
        const legacyStoredWallet = window.localStorage.getItem(WalletStorage.legacyWalletKey);

        if (!storedWallet && legacyStoredWallet != null) {
            const val = JSON.parse(legacyStoredWallet) as WalletStorage;
            this.init({ storage: val });
        } else {
            if (sessionWallet) {
                this.isInSession = true;
            } else if (storedWallet) {
                this.requiresLogin = !this.lockword || !this.password;
            } else {
                this.isGuest = true;
                this.reKey();
            }
            this.isGuest = true;
        }
    }

    private init(params: WalletCostructorParams): void {
        if (params.randoms) {
            this.master = HDKey.parseMasterSeed(params.randoms, Versions.animiqAPI3);
            this.setLockword('');
        } else if (params.storage) {
            this.master = HDKey.parseExtendedKey(params.storage.k);
            this.setLockword(params.storage.l || '');
        }
    }

    static getInstance() {
        return new Wallet();
    }

    reKey(): void {
        if (!this.isGuest) {
            throw new Error('Existing Wallet cannot be rekeyed.');
        }
        const randoms = new Uint32Array(66);
        window.crypto.getRandomValues(randoms);
        this.init({ randoms: randoms });
    }

    restoreFromKey(extendedPrivateKey: string): boolean {
        const ws = new WalletStorage();
        ws.k = extendedPrivateKey;
        ws.v = 3;
        // const rtn = new Wallet(this.contentService);
        this.init({ storage: ws });
        this.isGuest = false;
        return true;
    }

    saveKey(secret: string, saveType: 'backup' | 'session', includeLocknums: boolean): string {

        if (!this.master || !this.pproot || !this.locknums) {
            throw new Error('Master private, PP Root public, and Lock Numbers key needed before save().');
        }
        const keyBuffer = Buffer.alloc(65);
        let o = 0;
        o += this.master.chainCode.copy(keyBuffer, o);
        o += 33 - this.master.privateKey.length;
        this.master.privateKey.copy(keyBuffer, o);

        const cryptoBuffer = includeLocknums
            ? Buffer.concat([keyBuffer, Buffer.from(this.locknums.buffer)])
            : keyBuffer;

        const iv = crypto.randomBytes(16);
        const salt = crypto.randomBytes(64);
        const checksum = sha256(sha256(this.pproot.publicKey)).slice(0, 16);
        const secretKey = Buffer.from(secret, saveType === 'session' ? 'base64' : 'utf-8');
        const cryptoKey = crypto.pbkdf2Sync(secretKey, salt, 2145, 32, 'sha512');

        const cipher = crypto.createCipheriv('aes-256-gcm', cryptoKey, iv);
        const cryptUpdate = cipher.update(cryptoBuffer);
        const cryptFinal = cipher.final();
        const authTag = cipher.getAuthTag();

        const encrypted = Buffer.concat([salt, iv, authTag, checksum, cryptUpdate, cryptFinal]);

        console.log('saveKey() out', Array.prototype.slice.call(encrypted, 0));
        const stored = encrypted.toString('base64');
        if (saveType === 'session') {
            window.localStorage.setItem(WalletStorage.sessionKey, stored);
        } else {
            window.localStorage.setItem(WalletStorage.backupKey, stored);
        }
        return stored;
    }

    readKey(secret: string, saveType: 'backup' | 'session', lockword: string | null): boolean {
        let success = false;
        try {
            const stored = (saveType === 'session')
                ? window.localStorage.getItem(WalletStorage.sessionKey)
                : window.localStorage.getItem(WalletStorage.backupKey);
            if (!stored) {
                throw new Error('Stored value required to().');
            }
            const encrypted = Buffer.from(stored, 'base64');
            const salt = encrypted.slice(0, 64);
            const iv = encrypted.slice(64, 80);
            const authTag = encrypted.slice(80, 96);
            const checksum = encrypted.slice(96, 112);
            const cryptoBuffer = encrypted.slice(112);

            const secretKey = Buffer.from(secret, saveType === 'session' ? 'base64' : 'utf-8');
            const cryptoKey = crypto.pbkdf2Sync(secretKey, salt, 2145, 32, 'sha512');

            const decipher = crypto.createDecipheriv('aes-256-gcm', cryptoKey, iv);
            decipher.setAuthTag(authTag);
            let decrypted = decipher.update(cryptoBuffer);
            decrypted = Buffer.concat([decrypted, decipher.final()]);

            const keyParams = {
                chainCode: decrypted.slice(0, 32),
                privateKey: decrypted.slice(33, 65),
                version: Versions.animiqAPI3
            };

            this.master = new HDKey(keyParams);
            this.isGuest = false;
            if (lockword) {
                this.setLockword(lockword);
            } else {
                this.locknums = new Int32Array(this.toArrayBuffer(decrypted.slice(65)));
                this.setLockword(null as any as string, true);
            }

            const checksumVerify = sha256(sha256(this.pproot?.publicKey)).slice(0, 16);
            success = checksum.equals(checksumVerify);

        } catch (ex) {
            console.error('Wallet.readKey() ex=', ex);
        }
        return success;
    }

    toArrayBuffer(buf: Buffer) {
        const ab = new ArrayBuffer(buf.length);
        const view = new Uint8Array(ab);
        for (let i = 0; i < buf.length; ++i) {
            view[i] = buf[i];
        }
        return ab;
    }

    setLockword(word: string, numsOnly = false) {
        if (!this.master) {
            throw new Error('Master private key needed before setLockword().');
        }
        this.lockword = word;
        this.aqroot = this.master.derive(`m/1776'/07'/04'`);
        this.aqroot = this.aqroot.derive(`${this.locknums[19]}'/${this.locknums[15]}'/${this.locknums[11]}'/${this.locknums[7]}'`);
        this.pproot = this.aqroot.derive(`${this.locknums[18]}'/${this.locknums[14]}'/${this.locknums[10]}'/${this.locknums[6]}'`);
        this.aproot = this.aqroot.derive(`${this.locknums[17]}'/${this.locknums[13]}'/${this.locknums[9]}'/${this.locknums[5]}'`);
        this.sproot = this.aqroot.derive(`${this.locknums[16]}'/${this.locknums[12]}'/${this.locknums[8]}'/${this.locknums[4]}'`);
        this.profiles = [] as ProfileDocument[];
        this.getProfile(0);
    }

    save(): string {
        if (!this.master) {
            throw new Error('Master private key needed before save().');
        }
        if (!this.isGuest) {
            if (this.password) {
                return this.saveKey(this.password, 'backup', false);
            } else {
                return undefined as any as string;
            }
        } else {
            return undefined as any as string;
        }
    }

    clearSession(newBackup = '') {
        if (newBackup) {
            window.localStorage.setItem(WalletStorage.backupKey, newBackup);
        }
        window.localStorage.removeItem(WalletStorage.sessionKey);
        window.localStorage.removeItem(WalletStorage.legacyWalletKey);
    }

    private createProfile(keyset: ProfileKeySet, version = 3, isGuest = false): ProfileDocument {
        const profile = Object.assign(ProfileDocument.default, ProfileDocument.emptyProfile);
        profile.v = version;
        profile.isGuest = isGuest || false;
        profile.p.name = isGuest ? 'Guest User' : 'Loading ...';
        profile.setProfileKey(keyset.pp);
        profile.setKeys(keyset.ap, keyset.sp);
        return profile;
    }


    /**
     * v3 notes
     * a lockword is used to determine the child key indexes so that if a wallet master key is compromised an attacker
     * would still have a lot of work remaining to determine the wallet profile keys. Here is how much work.
     *
     * master.createIndexesFromWord() returns 20  2^31 useable index integers.
     *      20 of 2,147,483,648 (~2.1 Billion) possibles
     *
     * aqroot is a derived 4 deep of the default aqRoot:
     *      2^31^4 = 45,671,926,166,590,716,193,865,151,022,383,844,364,247,891,968 (~ 46 Quattuordecillion) [47 digits]
     *
     * pproot (and aproot,sproot) is derived from another 4 from aqroot, making it 8 levels deep:
     *      2^31^8 = 452,312,848,583,266,388,373,324,160,190,187,140,051,835,877,600,158,453,279,131,187,530,910,662,656
     *      (~ 452 Trillion Vigintillion) [75 digits]
     *
     * ppOffset (and apOffset, spOffset) are 2^31:
     *      2,147,483,648 (~2.1 Billion) possibles
     *
     * therefore, given an attacker succeeds in acquiring the master private key (which is protected by another password)
     *
     * (A) for him to determine a profile signing private key, a brute force attack could need to perform this many calculations:
     *      2^31^9 =
     *      971,334,446,112,864,535,459,730,953,411,759,453,321,203,419,526,069,760,625,906,204,869,452,142,602,604,249,088
     *      971 Sextiliion Vigintillion [84 digits]
     *
     * (B) from there to determine the addressing key and secret key, additional calculations needed off the discovered aqroot for each:
     *      2^31^5 = 45,671,926,166,590,716,193,865,151,022,383,844,364,247,891,968 (~45.6 Quattuordecillion) [47 digits]
     *
     * thus, in order to fully use a compromised wallet private key, the attacker could need to perform A + B + B calculations:
     *      971,334,446,112,864,535,459,730,953,411,759,453,412,547,271,859,251,193,013,636,506,914,219,831,331,100,033,024
     *      971 Sextiliion Vigintillion (and a few more :-) [84 digits]
     *
     * @param index array like 0 based profile number
     */
    getProfile(index: number): ProfileDocument {
        if (!this.pproot || !this.aproot || !this.sproot) {
            throw new Error('PP Root public, AP Root, and SP Root keys needed before getProfile().');
        }
        if (!this.profiles[index]) {
            let keyset: ProfileKeySet;
            const ppOffset = ((index + 1) * this.locknums[3]) % HDKey.hardenedKeyOffset;
            const apOffset = ((index + 1) * this.locknums[2]) % HDKey.hardenedKeyOffset;
            const spOffset = ((index + 1) * this.locknums[1]) % HDKey.hardenedKeyOffset;
            const pp = this.pproot.deriveChildKey(ppOffset, true);
            const ap = this.aproot.deriveChildKey(apOffset, true);
            const sp = this.sproot.deriveChildKey(spOffset, true);
            keyset = { pp: pp, ap: ap, sp: sp, ver: Versions.animiqAPI3 };
            this.profiles[index] = this.createProfile(keyset, 3, this.isGuest);
        }
        return this.profiles[index];
    }

    findProfile(address: string) {
        return this.profiles.find(p => p.a === address);
    }
}

export class WalletStorage {
    static readonly legacyWalletKey = '_animiq_wallet_';
    static readonly backupKey = 'aqbkpv3';
    static readonly sessionKey = 'aqsesv3';
    v!: number;
    k!: string;
    l!: string;
    toString = (): string => {
        return JSON.stringify(this);
    }
}
