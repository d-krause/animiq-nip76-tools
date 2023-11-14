/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { getPublicKey } from 'nostr-tools';
import { HDKey, HDKIndex, HDKIndexType, Versions } from '../keys';
import { getReducedKey } from '../util';
import { KeyStore, keyStoreRsvpDocumentsOffset } from '../wallet/Wallet';
import { KeyStoreStorage, KeyStoreStorageArgs, KeyStoreConstructorArgs } from './interfaces';

function getCookie(name: string) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift();
}

export class KeyStoreWebStorage implements KeyStoreStorage {

    static backupKey = 'defy-backup';
    static sessionKey = 'defy-session';
    static sessionIdName = 'defy-session-id';
    static sessionExpireMinutes = 15;

    static async fromStorage(storageArgs: { publicKey?: string, privateKey?: string }) {
        if (!storageArgs.publicKey && !storageArgs.privateKey) {
            throw new Error('A public or private hex key is needed to load a wallet.');
        }
        if (storageArgs.privateKey) {
            storageArgs.publicKey = getPublicKey(storageArgs.privateKey);
        }
        const storage = new KeyStoreWebStorage();
        const constructorArgs = await storage.load(storageArgs.publicKey!, storageArgs.privateKey);
        const wallet = new KeyStore(constructorArgs);
        wallet.documentsIndex = storage.getDocumentsIndex(constructorArgs)!;
        return wallet;
    }

    get isGuest() {
        return !globalThis.localStorage.getItem(KeyStoreWebStorage.backupKey);
    }

    async save(args: KeyStoreStorageArgs): Promise<boolean> {
        const isSession = !args.privateKey && !!KeyStoreWebStorage.sessionExpireMinutes;
        if (!args.masterKey || (isSession && !args.masterKey && !args.wordset)) {
            throw new Error('HD privateKey key needed for KeyStoreWebStorage.save(). lockwords required for sessions.');
        }
        if (isSession && !KeyStoreWebStorage.sessionExpireMinutes) {
            throw new Error('Sessions have been disabled in KeyStoreWebStorage.  To enable set sessionExpireMinutes to a non-zero value.');
        }
        let storeSecret = isSession ? hexToBytes(this.createSession()) : sha256(hexToBytes(args.privateKey!));
        if (storeSecret) {
            const keyBuffer = concatBytes(args.masterKey.chainCode, args.masterKey.privateKey);
            const cryptoBuffer = isSession
                ? concatBytes(keyBuffer, new Uint8Array(args.wordset!.buffer))
                : keyBuffer;
            const iv = window.crypto.getRandomValues(new Uint8Array(16));
            const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
            const secretKey = await window.crypto.subtle.importKey('raw', storeSecret, alg, false, ['encrypt']);
            const encrypted = await window.crypto.subtle.encrypt(alg, secretKey, cryptoBuffer);
            const stored = base64.encode(concatBytes(iv, new Uint8Array(encrypted)));
            if (isSession) {
                window.sessionStorage.setItem(KeyStoreWebStorage.sessionKey, stored);
            } else {
                window.localStorage.setItem(KeyStoreWebStorage.backupKey, stored);
            }
            return true;
        } else {
            return false;
        }
    }

    async load(publicKey: string, privateKey?: string): Promise<KeyStoreConstructorArgs> {
        const rtn: KeyStoreConstructorArgs = {
            publicKey,
            privateKey,
            store: this,
        };
        if (!this.isGuest) {
            try {
                let storeData: string | null = null;
                let storeSecret: Uint8Array | null = null;
                if (privateKey) {
                    storeData = window.localStorage.getItem(KeyStoreWebStorage.backupKey);
                    storeSecret = sha256(hexToBytes(privateKey!));
                } else {
                    const cookie = getCookie(KeyStoreWebStorage.sessionIdName);
                    storeData = window.sessionStorage.getItem(KeyStoreWebStorage.sessionKey);
                    if (cookie && cookie.match(/^[a-f0-9]{64}$/i)) {
                        storeSecret = hexToBytes(cookie);
                    } else if (storeData) {
                        console.log('KeyStoreWebStorage.load(): cleaning out old session')
                        window.sessionStorage.removeItem(KeyStoreWebStorage.sessionKey);
                    }
                }
                if (storeData && storeSecret) {
                    const encrypted = base64.decode(storeData);
                    const iv = encrypted.slice(0, 16);
                    const data = encrypted.slice(16);
                    const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
                    const secretKey = await window.crypto.subtle.importKey('raw', storeSecret, alg, false, ['decrypt']);
                    const decrypted = new Uint8Array(await window.crypto.subtle.decrypt(alg, secretKey, data));
                    rtn.masterKey = new HDKey({
                        chainCode: decrypted.slice(0, 32),
                        privateKey: decrypted.slice(32, 64),
                        version: Versions.nip76API1
                    });
                    rtn.wordset = new Uint32Array(decrypted.slice(64).buffer);
                }
            } catch (ex) {
                console.error('KeyStoreWebStorage.readKey() ex=', ex);
            }
        }
        return rtn;
    }

    getDocumentsIndex(args: KeyStoreConstructorArgs): HDKIndex {
        if (this.isGuest) {
            const randoms = new Uint8Array(256);
            window.crypto.getRandomValues(randoms);
            args.masterKey = HDKey.parseMasterSeed(randoms, Versions.nip76API1);
            args.rootKey = args.masterKey.derive(`m/44'/1237'/0'/1776'`);
            args.wordset = this.setLockWords({ secret: args.privateKey || ' ' });
        } else if (args.masterKey) {
            args.rootKey = args.masterKey.derive(`m/44'/1237'/0'/1776'`);
            if (args.privateKey || args.wordset) {
                args.wordset = this.setLockWords({ secret: args.privateKey, wordset: args.wordset });
            }
        }
        if (args.wordset) {
            const key1 = getReducedKey({ root: args.rootKey!, wordset: args.wordset.slice(0, 4) });
            const key2 = getReducedKey({ root: args.rootKey!, wordset: args.wordset.slice(4, 8) });
            args.documentsIndex = new HDKIndex(HDKIndexType.Sequential | HDKIndexType.Private, key1, key2, args.wordset.slice(8));
            args.documentsIndex.getSequentialKeyset(0, 0);
            args.documentsIndex.getSequentialKeyset(keyStoreRsvpDocumentsOffset, 0);
        }
        if (args.privateKey && args.wordset) {
            this.save({ publicKey: args.publicKey, masterKey: args.masterKey, wordset: args.wordset });
        }

        return args.documentsIndex!;
    }

    setLockWords(args: { secret?: string, wordset?: Uint32Array }): Uint32Array {
        if (args.secret) {
            const secretHash = args.secret.match(/^[a-f0-9]$/) && args.secret.length % 2 === 0
                ? sha512(hexToBytes(args.secret))
                : sha512(new TextEncoder().encode(args.secret));
            return new Uint32Array((secretHash).buffer);
        } else if (args.wordset && args.wordset.length === 16) {
            return args.wordset;
        } else {
            throw new Error('16 lockwords or a secret to generate them is required to setLockwords().');
        }
    }

    createSession() {
        const sessionKey = bytesToHex(window.crypto.getRandomValues(new Uint8Array(32)));
        const expires = (new Date(Date.now() + KeyStoreWebStorage.sessionExpireMinutes * 60000)).toUTCString();
        document.cookie = `${KeyStoreWebStorage.sessionIdName}=${sessionKey}; Secure; SameSite=Strict; expires=${expires}; path=/;`
        return sessionKey;
    }

    clearSession() {
        window.sessionStorage.removeItem(KeyStoreWebStorage.sessionKey);
        document.cookie = `${KeyStoreWebStorage.sessionIdName}=1; Secure; SameSite=Strict; expires=0; path=/;`
    }
}

