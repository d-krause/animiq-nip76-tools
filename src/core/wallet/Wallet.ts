/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as nostrTools from 'nostr-tools';
import { base64 } from '@scure/base';
import * as secp from '@noble/secp256k1';
import { sha256 as sha256x } from '@noble/hashes/sha256';
import { HDKey, Versions } from '../keys';
import { PrivateThread, ThreadKeySet } from '../content';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';

interface WalletCostructorParams {
    randoms?: Uint8Array;
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
    // private pproot!: HDKey;
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

    private constructor() { }

    static create() {
        const wallet = new Wallet();
        wallet.isGuest = true;
        wallet.reKey();
        return wallet;
    }

    static async fromStorage() {
        const wallet = new Wallet();
        const storedWallet = window.localStorage.getItem(WalletStorage.backupKey);
        const sessionWallet = window.sessionStorage.getItem(WalletStorage.sessionKey);
        const sessionKey = getCookie(WalletStorage.sessionIdName);
        if (sessionWallet && sessionKey && await wallet.readKey(sessionKey, 'session', null)) {
            wallet.saveWallet();
            wallet.isInSession = true;
        } else if (storedWallet) {
            wallet.requiresLogin = !wallet.lockword || !wallet.password;
        } else {
            wallet.isGuest = true;
            wallet.reKey();
        }
        return wallet;
    }

    private init(params: WalletCostructorParams): void {
        if (params.randoms) {
            this.master = HDKey.parseMasterSeed(params.randoms, Versions.nip76API1);
            this.setLockword('');
        } else if (params.storage) {
            this.master = HDKey.parseExtendedKey(params.storage.k);
            this.setLockword(params.storage.l || '');
        }
    }

    async saveWallet(privateKey: string | undefined = undefined) {
        if (privateKey) {
            await this.saveKey(privateKey, 'backup');
        }
        if (this.sessionExpireMinutes) {
            const sessionKey = bytesToHex(window.crypto.getRandomValues(new Uint8Array(32)));
            const expires = (new Date(Date.now() + this.sessionExpireMinutes * 60000)).toUTCString();
            document.cookie = `${WalletStorage.sessionIdName}=${sessionKey}; expires=${expires}; path=/;`
            this.isInSession = await this.saveKey(sessionKey, 'session');
        } else {
            await this.clearSession();
        }
    }

    async clearSession() {
        window.sessionStorage.removeItem(WalletStorage.sessionKey);
        document.cookie = `${WalletStorage.sessionIdName}=1; expires=1; path=/;`
    }

    reKey(): HDKey {
        if (!this.isGuest) {
            throw new Error('Existing Wallet cannot be rekeyed.');
        }
        const randoms = new Uint8Array(256);
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

    async saveKey(secret: string, saveType: 'backup' | 'session'): Promise<boolean> {
        if (!this.master || !this.locknums) {
            throw new Error('Master private and Lock Numbers key needed before save().');
        }
        const keyBuffer = secp.utils.concatBytes(this.master.chainCode, this.master.privateKey);
        const cryptoBuffer = saveType === 'session'
            ? concatBytes(keyBuffer, new Uint8Array(this.locknums.buffer))
            : keyBuffer;
        const iv = window.crypto.getRandomValues(new Uint8Array(16));
        const secretBytes = secp.utils.hexToBytes(secret);
        const secretHash = sha256x.create().update(secretBytes).digest();
        const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
        const secretKey = await window.crypto.subtle.importKey('raw', secretHash, alg, false, ['encrypt']);
        const encrypted = await window.crypto.subtle.encrypt(alg, secretKey, cryptoBuffer);
        const stored = base64.encode(secp.utils.concatBytes(iv, new Uint8Array(encrypted)));
        if (saveType === 'session') {
            window.sessionStorage.setItem(WalletStorage.sessionKey, stored);
        } else {
            window.localStorage.setItem(WalletStorage.backupKey, stored);
        }
        return true;
    }

    async readKey(secret: string, saveType: 'backup' | 'session', lockword: string | null): Promise<boolean> {
        let success = false;
        try {
            const stored = (saveType === 'session')
                ? window.sessionStorage.getItem(WalletStorage.sessionKey)
                : window.localStorage.getItem(WalletStorage.backupKey);
            if (!stored) {
                throw new Error('Stored value required to().');
            }

            const encrypted = base64.decode(stored);
            const iv = encrypted.slice(0, 16);
            const data = encrypted.slice(16);
            const secretBytes = secp.utils.hexToBytes(secret);
            const secretHash = sha256x.create().update(secretBytes).digest();
            const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
            const secretKey = await window.crypto.subtle.importKey('raw', secretHash, alg, false, ['decrypt']);
            const decrypted = new Uint8Array(await window.crypto.subtle.decrypt(alg, secretKey, data));

            const keyParams = {
                chainCode: decrypted.slice(0, 32),
                privateKey: decrypted.slice(32, 64),
                version: Versions.nip76API1
            };

            this.master = new HDKey(keyParams);
            this.isGuest = false;

            if (lockword !== null) {
                this.setLockword(lockword);
            } else {
                this.locknums = new Int32Array(decrypted.slice(64).buffer);
                this.setLockword(null as any as string, true);
            }
            success = true;
        } catch (ex) {
            console.error('Wallet.readKey() ex=', ex);
        }
        return success;
    }

    setLockword(word: string, numsOnly = false) {
        if (!this.master) {
            throw new Error('Master private key needed before setLockword().');
        }
        this.lockword = word;
        this.nip76root = this.master.derive(`m/44'/1237'/0'`);
        if (!numsOnly) { this.locknums = this.nip76root.createIndexesFromWord(this.lockword); }
        this.aqroot = this.nip76root.derive(`m/${this.locknums[19]}'/${this.locknums[15]}'/${this.locknums[11]}'/${this.locknums[7]}'`);
        this.aproot = this.aqroot.derive(`m/${this.locknums[17]}'/${this.locknums[13]}'/${this.locknums[9]}'/${this.locknums[5]}'`);
        // this.pproot = this.aqroot.derive(`m/${this.locknums[18]}'/${this.locknums[14]}'/${this.locknums[10]}'/${this.locknums[6]}'`);
        this.sproot = this.aqroot.derive(`m/${this.locknums[16]}'/${this.locknums[12]}'/${this.locknums[8]}'/${this.locknums[4]}'`);
        this.threads = [] as PrivateThread[];
        this.getThread(0);

    }

    private createThread(keyset: ThreadKeySet): PrivateThread {
        const thread = new PrivateThread();
        thread.content = {
            kind: nostrTools.Kind.ChannelMetadata,
            name: 'Loading Thread Info ...',
            pubkey: this.ownerPubKey,
            sig: '',
            tags: [],
            last_known_index: 0
        };
        thread.setOwnerKeys(keyset.ap, keyset.sp);
        thread.ownerPubKey = this.ownerPubKey;
        return thread;
    }

    getThread(index: number): PrivateThread {
        if (!this.aproot || !this.sproot) {
            throw new Error('AP Root and SP Root keys needed before getThread().');
        }
        if (!this.threads[index]) {
            let keyset: ThreadKeySet;
            // const ppOffset = ((index + 1) * this.locknums[3]) % HDKey.hardenedKeyOffset;
            const apOffset = ((index + 1) * this.locknums[2]) % HDKey.hardenedKeyOffset;
            const spOffset = ((index + 1) * this.locknums[1]) % HDKey.hardenedKeyOffset;
            // const pp = this.pproot.deriveChildKey(ppOffset, true);
            const ap = this.aproot.deriveChildKey(apOffset, true);
            const sp = this.sproot.deriveChildKey(spOffset, true);
            keyset = { ap: ap, sp: sp, ver: Versions.nip76API1 };
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
