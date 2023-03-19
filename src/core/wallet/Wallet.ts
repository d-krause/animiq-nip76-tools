/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { sha512 } from '@noble/hashes/sha512';
import { hexToBytes } from '@noble/hashes/utils';
import * as nostrTools from 'nostr-tools';
import { PrivateChannel } from '../content';
import { HDKey, Versions } from '../keys';
import { IWalletStorage, WalletConstructorArgs } from './interfaces';

export class Wallet {
    
    private master: HDKey;
    private lockwords!: Int32Array;
    
    store: IWalletStorage;
    isGuest = false;
    isInSession = false;

    ownerPubKey!: string;
    channels: PrivateChannel[] = [];
    following: PrivateChannel[] = [];

    constructor(args: WalletConstructorArgs) {
        this.ownerPubKey = args.publicKey;
        this.master = args.key!;
        this.store = args.store;
        this.isGuest = args.isGuest
        this.isInSession = args.isInSession
        if (this.isGuest) {
            this.reKey();
        } else if (this.master) {
            this.setLockWords({ secret: args.privateKey, lockwords: args.lockwords });
            if (!this.isInSession) {
                this.store.save({ publicKey: this.ownerPubKey, key: this.master, lockwords: this.lockwords });
                this.isInSession = true;
            }
            this.getChannel(0);
        }
    }

    async saveWallet(privateKey?: string) {
        if (privateKey) {
            await this.store.save({ privateKey, publicKey: this.ownerPubKey, key: this.master, lockwords: this.lockwords });
        }
        await this.store.save({ publicKey: this.ownerPubKey, key: this.master, lockwords: this.lockwords });
        this.isInSession = true;
    }

    async clearSession() {
        this.store.clearSession()
        this.isInSession = false;
        const randoms = new Uint8Array(256);
        window.crypto.getRandomValues(randoms);
        this.master = HDKey.parseMasterSeed(randoms, Versions.nip76API1);
        this.setLockWords({ secret: ' ' });
        this.channels = [];
        this.following = [];
    }

    reKey(secret?: string): void {
        if (!this.isGuest) {
            throw new Error('Existing Wallet cannot be rekeyed.');
        }
        const randoms = new Uint8Array(256);
        window.crypto.getRandomValues(randoms);
        this.master = HDKey.parseMasterSeed(randoms, Versions.nip76API1);
        if (secret) {
            this.setLockWords({ secret });
        }
        this.channels = [];
        this.following = [];
        this.getChannel(0);
    }

    restoreFromKey(extendedPrivateKey: string, secret: string): boolean {
        this.master = HDKey.parseExtendedKey(extendedPrivateKey);
        this.setLockWords({ secret });
        this.isGuest = false;
        return true;
    }

    setLockWords(args: { secret?: string, lockwords?: Int32Array }) {
        if (args.secret) {
            const secretHash = args.secret.match(/^[a-f0-9]$/) && args.secret.length % 2 === 0
                ? sha512(hexToBytes(args.secret))
                : sha512(new TextEncoder().encode(args.secret));
            this.lockwords = new Int32Array((secretHash).buffer).map(i => Math.abs(i));
        } else if (args.lockwords && args.lockwords.length === 16) {
            this.lockwords = args.lockwords;
        } else {
            throw new Error('16 lockwords or a secret to generate them is required to setLockwords().');
        }
    }

    getChannel(index: number): PrivateChannel {
        if (!this.lockwords || !this.master) {
            throw new Error('locknums and master needed before getChannel().');
        }
        if (!this.channels[index]) {
            const reducer = (hdk: HDKey, num: number) => hdk.deriveChildKey((num * (index + 1)) % HDKey.hardenedKeyOffset, true);
            const parent = this.lockwords.slice(0, 4).reduce(reducer, this.master.derive(`m/44'/1237'/0'/1776'`));
            const ap = this.lockwords.slice(4, 8).reduce(reducer, parent);
            const sp = this.lockwords.slice(8, 12).reduce(reducer, parent);
            const channel = new PrivateChannel();
            channel.ownerPubKey = this.ownerPubKey;
            channel.content = {
                kind: nostrTools.Kind.ChannelMetadata,
                name: 'Loading Channel Info ...',
                pubkey: this.ownerPubKey,
                last_known_index: 0
            };
            channel.setOwnerKeys(ap, sp);
            sp.wipePrivateData();
            this.channels = [...this.channels, channel];
        }
        return this.channels[index];
    }
}
