/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { getPublicKey } from 'nostr-tools';
import { HDKey, Versions } from '../keys';
import { Wallet } from '../wallet/Wallet';
import { IWalletStorage, WalletStorageArgs, WalletConstructorArgs } from './interfaces';

function getCookie(name: string) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift();
}

export class WebWalletStorage implements IWalletStorage {

    static backupKey = 'nip76-wallet';
    static sessionKey = 'nip76-session';
    static sessionIdName = 'nip76-session-id';
    static sessionExpireMinutes = 15;

    static async fromStorage(args: { publicKey?: string, privateKey?: string }) {
        if (!args.publicKey && !args.privateKey) {
            throw new Error('A public or private hex key is needed to load a wallet.');
        }
        if (args.privateKey) {
            args.publicKey = getPublicKey(args.privateKey);
        }
        const info = await new WebWalletStorage().load(args.publicKey!, args.privateKey);
        return new Wallet(info);
    }

    async save(args: WalletStorageArgs): Promise<boolean> {
        const isSession = !args.privateKey && !!WebWalletStorage.sessionExpireMinutes;
        if (!args.key || (isSession && !args.key && !args.wordset)) {
            throw new Error('HD privateKey key needed for WebWalletStorage.save(). lockwords required for sessions.');
        }
        if (isSession && !WebWalletStorage.sessionExpireMinutes) {
            throw new Error('Sessions have been disabled in WebWalletStorage.  To enable set sessionExpireMinutes to a non-zero value.');
        }
        let storeSecret = isSession ? hexToBytes(this.createSession()) : sha256(hexToBytes(args.privateKey!));
        if (storeSecret) {
            const keyBuffer = concatBytes(args.key.chainCode, args.key.privateKey);
            const cryptoBuffer = isSession
                ? concatBytes(keyBuffer, new Uint8Array(args.wordset!.buffer))
                : keyBuffer;
            const iv = window.crypto.getRandomValues(new Uint8Array(16));
            const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
            const secretKey = await window.crypto.subtle.importKey('raw', storeSecret, alg, false, ['encrypt']);
            const encrypted = await window.crypto.subtle.encrypt(alg, secretKey, cryptoBuffer);
            const stored = base64.encode(concatBytes(iv, new Uint8Array(encrypted)));
            if (isSession) {
                window.sessionStorage.setItem(WebWalletStorage.sessionKey, stored);
            } else {
                window.localStorage.setItem(WebWalletStorage.backupKey, stored);
            }
            return true;
        } else {
            return false;
        }
    }

    async load(publicKey: string, privateKey?: string): Promise<WalletConstructorArgs> {
        const rtn: WalletConstructorArgs = {
            publicKey,
            privateKey,
            store: this,
            isInSession: false,
            isGuest: !window.localStorage.getItem(WebWalletStorage.backupKey),
        };
        if (!rtn.isGuest) {
            try {
                rtn.isInSession = !privateKey;
                let storeData: string | null = null;
                let storeSecret: Uint8Array | null = null;
                if (rtn.isInSession) {
                    const cookie = getCookie(WebWalletStorage.sessionIdName);
                    storeData = window.sessionStorage.getItem(WebWalletStorage.sessionKey);
                    if (cookie && cookie.match(/^[a-f0-9]{64}$/i)) {
                        storeSecret = hexToBytes(cookie);
                    } else if (storeData) {
                        console.log('WebWalletStorage.load(): cleaning out old session')
                        window.sessionStorage.removeItem(WebWalletStorage.sessionKey);
                    }
                } else {
                    storeData = window.localStorage.getItem(WebWalletStorage.backupKey);
                    storeSecret = sha256(hexToBytes(privateKey!));
                }
                if (storeData && storeSecret) {
                    const encrypted = base64.decode(storeData);
                    const iv = encrypted.slice(0, 16);
                    const data = encrypted.slice(16);
                    const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
                    const secretKey = await window.crypto.subtle.importKey('raw', storeSecret, alg, false, ['decrypt']);
                    const decrypted = new Uint8Array(await window.crypto.subtle.decrypt(alg, secretKey, data));
                    rtn.key = new HDKey({
                        chainCode: decrypted.slice(0, 32),
                        privateKey: decrypted.slice(32, 64),
                        version: Versions.nip76API1
                    });
                    rtn.wordset = new Uint32Array(decrypted.slice(64).buffer);
                } else {
                    rtn.isInSession = false;
                }
            } catch (ex) {
                rtn.isInSession = false;
                console.error('WebWalletStorage.readKey() ex=', ex);
            }
        }
        return rtn;
    }

    createSession() {
        const sessionKey = bytesToHex(window.crypto.getRandomValues(new Uint8Array(32)));
        const expires = (new Date(Date.now() + WebWalletStorage.sessionExpireMinutes * 60000)).toUTCString();
        document.cookie = `${WebWalletStorage.sessionIdName}=${sessionKey}; Secure; SameSite=Strict; expires=${expires}; path=/;`
        return sessionKey;
    }

    clearSession() {
        window.sessionStorage.removeItem(WebWalletStorage.sessionKey);
        document.cookie = `${WebWalletStorage.sessionIdName}=1; Secure; SameSite=Strict; expires=0; path=/;`
    }
}

