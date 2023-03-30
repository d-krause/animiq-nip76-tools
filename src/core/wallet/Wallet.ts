/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */

import { sha512 } from '@noble/hashes/sha512';
import { hexToBytes } from '@noble/hashes/utils';
import * as nostrTools from 'nostr-tools';
import { Invitation, NostrEventDocument, PrivateChannel } from '../content';
import { HDKey, HDKIndex, HDKIndexType, Versions } from '../keys';
import { getReducedKey } from '../util';
import { IWalletStorage, WalletConstructorArgs } from './interfaces';

export const walletRsvpDocumentsOffset = 0x10000000;

export class Wallet {

    private master: HDKey;
    private root!: HDKey;
    private wordset!: Uint32Array;

    store: IWalletStorage;
    isGuest = false;
    isInSession = false;

    ownerPubKey!: string;
    documentsIndex!: HDKIndex;

    constructor(args: WalletConstructorArgs) {
        this.ownerPubKey = args.publicKey;
        this.master = args.key!;
        this.store = args.store;
        this.isGuest = args.isGuest
        this.isInSession = args.isInSession
        if (this.isGuest) {
            this.reKey();
        } else if (this.master) {
            this.root = this.master.derive(`m/44'/1237'/0'/1776'`);
            this.setLockWords({ secret: args.privateKey, lockwords: args.wordset });
            if (!this.isInSession) {
                this.store.save({ publicKey: this.ownerPubKey, key: this.master, wordset: this.wordset });
                this.isInSession = true;
            }
            const key1 = getReducedKey({ root: this.root, wordset: this.wordset.slice(0, 4) });
            const key2 = getReducedKey({ root: this.root, wordset: this.wordset.slice(4, 8) });
            this.documentsIndex = new HDKIndex(HDKIndexType.Sequential | HDKIndexType.Private, key1, key2, this.wordset.slice(8));
        }
    }

    get channels(): PrivateChannel[] {
        return (this.documentsIndex.documents as PrivateChannel[]).filter(x => x.content.kind === nostrTools.Kind.ChannelMetadata);
    }

    get rsvps(): Invitation[] {
        return (this.documentsIndex.documents as Invitation[]).filter(x => x.content.kind === 1776).map(x => {
            x.channel = this.channels.find(c => c.dkxPost.signingParent.nostrPubKey === x.content.signingParent?.nostrPubKey)!;
            return x;
        }).filter(x => !!x.channel);
    }

    async saveWallet(privateKey?: string) {
        if (privateKey) {
            await this.store.save({ privateKey, publicKey: this.ownerPubKey, key: this.master, wordset: this.wordset });
        }
        await this.store.save({ publicKey: this.ownerPubKey, key: this.master, wordset: this.wordset });
        this.isInSession = true;
    }

    async clearSession() {
        this.store.clearSession()
        this.isInSession = false;
        const randoms = new Uint8Array(256);
        window.crypto.getRandomValues(randoms);
        this.master = HDKey.parseMasterSeed(randoms, Versions.nip76API1);
        this.setLockWords({ secret: ' ' });
        this.documentsIndex.documents = [];
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
        this.documentsIndex.documents = [];
    }

    restoreFromKey(extendedPrivateKey: string, secret: string): boolean {
        this.master = HDKey.parseExtendedKey(extendedPrivateKey);
        this.setLockWords({ secret });
        this.isGuest = false;
        return true;
    }

    setLockWords(args: { secret?: string, lockwords?: Uint32Array }) {
        if (args.secret) {
            const secretHash = args.secret.match(/^[a-f0-9]$/) && args.secret.length % 2 === 0
                ? sha512(hexToBytes(args.secret))
                : sha512(new TextEncoder().encode(args.secret));
            this.wordset = new Uint32Array((secretHash).buffer);
        } else if (args.lockwords && args.lockwords.length === 16) {
            this.wordset = args.lockwords;
        } else {
            throw new Error('16 lockwords or a secret to generate them is required to setLockwords().');
        }
    }

    createChannel(): PrivateChannel {
        if (!this.wordset || !this.master || !this.root) {
            throw new Error('locknums and master needed before getChannel().');
        }
        const index = this.channels.filter(x => x.ownerPubKey === this.ownerPubKey).length + 1;
        const keyset = this.documentsIndex.getKeysFromIndex(index);
        const channel = new PrivateChannel(keyset.signingKey!, keyset.cryptoKey);
        channel.nostrEvent = { pubkey: keyset.signingKey!.nostrPubKey } as NostrEventDocument;
        channel.docIndex = index;
        channel.ownerPubKey = this.ownerPubKey;
        channel.content = {
            kind: nostrTools.Kind.ChannelMetadata,
            name: 'New Channel ' + index,
            pubkey: this.ownerPubKey,
        };
        this.documentsIndex.documents.push(channel);
        return channel;
    }
}
