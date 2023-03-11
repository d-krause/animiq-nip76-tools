/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import { sha256 } from '../util';
import { HDKey, Versions } from '../keys';
import { PrivateThread, ThreadKeySet } from '../content';

interface WalletCostructorParams {
    randoms?: Uint32Array;
    storage?: WalletStorage;
}

function getCookie(name: string) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift();
}

export class Wallet {
    readonly version = 3;
    ownerPubKey!: string;

    private master!: HDKey;
    nip76root!: HDKey;
    private aqroot!: HDKey;
    private pproot!: HDKey;
    private aproot!: HDKey;
    private sproot!: HDKey;
    private password = '';
    private lockword = '';
    private locknums!: Int32Array;

    threads: PrivateThread[] = [];
    following: PrivateThread[] = [];
    isGuest = false;
    isInSession = false;
    requiresLogin = false;
    sessionExpireMinutes = 15;

    constructor() {
        const storedWallet = window.localStorage.getItem(WalletStorage.backupKey);
        const sessionWallet = window.sessionStorage.getItem(WalletStorage.sessionKey);
        const sessionKey = getCookie(WalletStorage.sessionIdName);
        if (sessionWallet && sessionKey && this.readKey(sessionKey, 'session', null)) {
            this.saveWallet();
            this.isInSession = true;
        } else if (storedWallet) {
            this.requiresLogin = !this.lockword || !this.password;
        } else {
            this.isGuest = true;
            this.reKey();
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

    saveWallet(privateKey: string | undefined = undefined) {
        if(privateKey){
            this.saveKey(privateKey, 'backup');;
        }
        if (this.sessionExpireMinutes) {
            const sessionKey = Buffer.from(window.crypto.getRandomValues(new Uint8Array(32))).toString('hex');
            const expires = (new Date(Date.now() + this.sessionExpireMinutes * 60000)).toUTCString();
            document.cookie = `${WalletStorage.sessionIdName}=${sessionKey}; expires=${expires}; path=/;`
            const sessionWallet = this.saveKey(sessionKey, 'session');
            window.sessionStorage.setItem(WalletStorage.sessionKey, sessionWallet);
            this.isInSession = true;
        } else {
            this.clearSession();
        }
    }

    clearSession() {
        window.sessionStorage.removeItem(WalletStorage.sessionKey);
        document.cookie = `${WalletStorage.sessionIdName}=1; expires=1; path=/;`
    }

    reKey(): HDKey {
        if (!this.isGuest) {
            throw new Error('Existing Wallet cannot be rekeyed.');
        }
        const randoms = new Uint32Array(66);
        window.crypto.getRandomValues(randoms);
        this.init({ randoms: randoms });
        return this.master;
    }

    restoreFromKey(extendedPrivateKey: string): boolean {
        const ws = new WalletStorage();
        ws.k = extendedPrivateKey;
        ws.v = this.version;
        this.init({ storage: ws });
        this.isGuest = false;
        return true;
    }

    saveKey(secret: string, saveType: 'backup' | 'session'): string {

        if (!this.master || !this.pproot || !this.locknums) {
            throw new Error('Master private, PP Root public, and Lock Numbers key needed before save().');
        }
        const keyBuffer = Buffer.alloc(65);
        let o = 0;
        o += this.master.chainCode.copy(keyBuffer, o);
        o += 33 - this.master.privateKey.length;
        this.master.privateKey.copy(keyBuffer, o);

        const cryptoBuffer = saveType === 'session'
            ? Buffer.concat([keyBuffer, Buffer.from(this.locknums.buffer)])
            : keyBuffer;

        const iv = crypto.randomBytes(16);
        const salt = crypto.randomBytes(64);
        const checksum = sha256(sha256(this.pproot.publicKey)).slice(0, 16);
        const secretKey = Buffer.from(secret, 'hex');
        const cryptoKey = crypto.pbkdf2Sync(secretKey, salt, 2145, 32, 'sha512');

        const cipher = crypto.createCipheriv('aes-256-gcm', cryptoKey, iv);
        const cryptUpdate = cipher.update(Buffer.from(cryptoBuffer));
        const cryptFinal = cipher.final();
        const authTag = cipher.getAuthTag();

        const encrypted = Buffer.concat([salt, iv, authTag, checksum, cryptUpdate, cryptFinal]);

        console.log('saveKey() out', Array.prototype.slice.call(encrypted, 0));
        const stored = encrypted.toString('base64');
        if (saveType === 'session') {
            window.sessionStorage.setItem(WalletStorage.sessionKey, stored);
        } else {
            window.localStorage.setItem(WalletStorage.backupKey, stored);
        }
        return stored;
    }

    readKey(secret: string, saveType: 'backup' | 'session', lockword: string | null): boolean {
        let success = false;
        try {
            const stored = (saveType === 'session')
                ? window.sessionStorage.getItem(WalletStorage.sessionKey)
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

            const secretKey = Buffer.from(secret, 'hex');
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
            if (lockword !== null) {
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
        this.nip76root = this.master.derive(`m/44'/1237'/0'`);
        if (!numsOnly) { this.locknums = this.nip76root.createIndexesFromWord(this.lockword); }
        this.aqroot = this.nip76root.derive(`${this.locknums[19]}'/${this.locknums[15]}'/${this.locknums[11]}'/${this.locknums[7]}'`);
        this.pproot = this.aqroot.derive(`${this.locknums[18]}'/${this.locknums[14]}'/${this.locknums[10]}'/${this.locknums[6]}'`);
        this.aproot = this.aqroot.derive(`${this.locknums[17]}'/${this.locknums[13]}'/${this.locknums[9]}'/${this.locknums[5]}'`);
        this.sproot = this.aqroot.derive(`${this.locknums[16]}'/${this.locknums[12]}'/${this.locknums[8]}'/${this.locknums[4]}'`);
        this.threads = [] as PrivateThread[];
        this.getThread(0);

    }

    private createThread(keyset: ThreadKeySet): PrivateThread {
        const thread = PrivateThread.default;
        thread.v = 3;
        thread.p = {
            name: 'Loading Thread Info ...',
            last_known_index: 0
        };
        thread.pp = keyset.pp;
        thread.setKeys(keyset.ap, keyset.sp);
        thread.ownerPubKey = this.ownerPubKey;
        return thread;
    }

    getThread(index: number): PrivateThread {
        if (!this.pproot || !this.aproot || !this.sproot) {
            throw new Error('PP Root public, AP Root, and SP Root keys needed before getThread().');
        }
        if (!this.threads[index]) {
            let keyset: ThreadKeySet;
            const ppOffset = ((index + 1) * this.locknums[3]) % HDKey.hardenedKeyOffset;
            const apOffset = ((index + 1) * this.locknums[2]) % HDKey.hardenedKeyOffset;
            const spOffset = ((index + 1) * this.locknums[1]) % HDKey.hardenedKeyOffset;
            const pp = this.pproot.deriveChildKey(ppOffset, true);
            const ap = this.aproot.deriveChildKey(apOffset, true);
            const sp = this.sproot.deriveChildKey(spOffset, true);
            keyset = { pp: pp, ap: ap, sp: sp, ver: Versions.animiqAPI3 };
            this.threads = [...this.threads, this.createThread(keyset)];
        }
        this.threads[index].ownerPubKey = this.ownerPubKey;
        return this.threads[index];
    }
}

export class WalletStorage {
    static readonly backupKey = 'nip76-wallet';
    static readonly sessionKey = 'nip76-session';
    static readonly sessionIdName = 'nip76-session-id';
    v!: number;
    k!: string;
    l!: string;
    toString = (): string => {
        return JSON.stringify(this);
    }
}
