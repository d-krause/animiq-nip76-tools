/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */

import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import * as nostrTools from 'nostr-tools';
import { Invitation, NostrEventDocument, NostrKinds, PrivateChannel, Rsvp } from '../content';
import { HDKey, HDKIndex, HDKIndexType, Versions } from '../keys';
import { getCreatedAtIndexes, getNowSeconds, getReducedKey } from '../util';
import { IWalletStorage, WalletConstructorArgs } from './interfaces';

export const walletRsvpDocumentsOffset = 0x10000000;

export class Wallet {

    private master: HDKey;
    private root!: HDKey;
    private wordset!: Uint32Array;

    store: IWalletStorage;
    isGuest = false;
    isInSession = false;
    isExtensionManaged = false;

    ownerPubKey!: string;
    documentsIndex!: HDKIndex;

    constructor(args: WalletConstructorArgs) {
        this.ownerPubKey = args.publicKey;
        this.master = args.masterKey!;
        this.root = args.rootKey!;
        this.documentsIndex = args.documentsIndex!;
        this.store = args.store;
        this.isGuest = args.isGuest
        this.isInSession = args.isInSession
        if (this.isGuest) {
            const randoms = new Uint8Array(256);
            window.crypto.getRandomValues(randoms);
            this.master = HDKey.parseMasterSeed(randoms, Versions.nip76API1);
            this.root = this.master.derive(`m/44'/1237'/0'/1776'`);
            if (args.privateKey) {
                this.setLockWords({ secret: args.privateKey! });
            }
        } else if (this.master || this.root) {
            this.isExtensionManaged = this.root && !this.master;
            if (!this.isExtensionManaged) {
                this.root = this.master.derive(`m/44'/1237'/0'/1776'`);
                if (args.privateKey || args.wordset) {
                    this.setLockWords({ secret: args.privateKey, wordset: args.wordset });
                }
            }
        }
        if (!this.isExtensionManaged && this.wordset) {
            const key1 = getReducedKey({ root: this.root, wordset: this.wordset.slice(0, 4) });
            const key2 = getReducedKey({ root: this.root, wordset: this.wordset.slice(4, 8) });
            this.documentsIndex = new HDKIndex(HDKIndexType.Sequential | HDKIndexType.Private, key1, key2, this.wordset.slice(8));
        }
        if (!this.isInSession && this.wordset) {
            this.store.save({ publicKey: this.ownerPubKey, masterKey: this.master, wordset: this.wordset });
            this.isInSession = true;
        }
    }

    get channels(): PrivateChannel[] {
        return (this.documentsIndex.documents as PrivateChannel[]).filter(x => x.content.kind === NostrKinds.ChannelMetadata);
    }

    get rsvps(): Rsvp[] {
        return (this.documentsIndex.documents as Rsvp[]).filter(x => x.content.kind === NostrKinds.PrivateChannelRSVP).map(x => {
            x.channel = this.channels.find(c => c.invitation?.pointer === x.pointer)!;
            return x;
        });
    }

    async saveWallet(privateKey?: string) {
        if (privateKey) {
            await this.store.save({ privateKey, publicKey: this.ownerPubKey, masterKey: this.master, wordset: this.wordset });
        }
        await this.store.save({ publicKey: this.ownerPubKey, masterKey: this.master, wordset: this.wordset });
        this.isInSession = true;
        this.isGuest = false;
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

    restoreFromKey(extendedPrivateKey: string, secret: string): boolean {
        this.master = HDKey.parseExtendedKey(extendedPrivateKey);
        this.setLockWords({ secret });
        this.isGuest = false;
        return true;
    }

    setLockWords(args: { secret?: string, wordset?: Uint32Array }) {
        if (args.secret) {
            const secretHash = args.secret.match(/^[a-f0-9]$/) && args.secret.length % 2 === 0
                ? sha512(hexToBytes(args.secret))
                : sha512(new TextEncoder().encode(args.secret));
            this.wordset = new Uint32Array((secretHash).buffer);
        } else if (args.wordset && args.wordset.length === 16) {
            this.wordset = args.wordset;
        } else {
            throw new Error('16 lockwords or a secret to generate them is required to setLockwords().');
        }
    }

    createChannel(): PrivateChannel {
        if (!this.wordset || !this.root) {
            throw new Error('wordset and root key needed before createChannel().');
        }
        const index = this.channels.filter(x => x.ownerPubKey === this.ownerPubKey).length + 1;
        const keyset = this.documentsIndex.getDocumentKeyset(index);
        const channel = new PrivateChannel();
        channel.setIndexKeys(keyset.signingKey!, keyset.encryptKey!);
        channel.nostrEvent = { pubkey: keyset.signingKey!.nostrPubKey } as NostrEventDocument;
        channel.docIndex = index;
        channel.ownerPubKey = this.ownerPubKey;
        channel.content = {
            kind: nostrTools.Kind.ChannelMetadata,
            name: 'New Channel ' + index,
            pubkey: this.ownerPubKey,
            created_at: getNowSeconds()
        };
        this.documentsIndex.documents = [channel, ...this.documentsIndex.documents];
        return channel;
    }
}
