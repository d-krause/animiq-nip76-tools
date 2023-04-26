/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */

import * as nostrTools from 'nostr-tools';
import { NostrEventDocument, NostrKinds, PrivateChannel, Rsvp } from '../content';
import { HDKIndex } from '../keys';
import { getNowSeconds } from '../util';
import { WalletConstructorArgs } from './interfaces';
import { WebWalletStorage } from './WalletStorage';

export const walletRsvpDocumentsOffset = 0x10000000;

export class Wallet {

    private constructorArgs: WalletConstructorArgs;

    isInExtension = (globalThis as any).chrome && (globalThis as any).chrome.runtime && (globalThis as any).chrome.tabs;
    ownerPubKey: string;
    documentsIndex: HDKIndex | undefined;

    constructor(args: WalletConstructorArgs) {
        this.constructorArgs = args;
        this.ownerPubKey = args.publicKey;
        this.documentsIndex = args.documentsIndex;
    }

    get isExtensionManaged() {
        return !!(globalThis as any).nostr?.nip76;
    }

    get isReady() {
        return !!this.documentsIndex;
    }

    get isGuest() {
        return !this.isInExtension && !this.isExtensionManaged && !globalThis.localStorage.getItem(WebWalletStorage.backupKey);
    }

    get channels(): PrivateChannel[] {
        if (this.documentsIndex) {
            return (this.documentsIndex.documents as PrivateChannel[]).filter(x => x.content.kind === NostrKinds.ChannelMetadata);
        } else {
            return [];
        }
    }

    get rsvps(): Rsvp[] {
        if (this.documentsIndex) {
            return (this.documentsIndex.documents as Rsvp[])
                .filter(x => x.content.kind === NostrKinds.PrivateChannelRSVP)
                .map(x => {
                    x.channel = this.channels.find(c => c.invitation?.pointer === x.pointer)!;
                    return x;
                });
        } else {
            return [];
        }
    }

    async saveWallet(privateKey?: string) {
        if (this.constructorArgs.store) {
            const saveArgs = {
                privateKey,
                publicKey: this.ownerPubKey,
                masterKey: this.constructorArgs.masterKey,
                wordset: this.constructorArgs.wordset
            };
            await this.constructorArgs.store.save(saveArgs);
            if (privateKey) {
                delete saveArgs.privateKey;
                await this.constructorArgs.store.save(saveArgs);
            }
        }
    }

    async clearSession() {
        if (this.constructorArgs.store) {
            this.constructorArgs.store.clearSession()
        }
        this.documentsIndex = undefined;
    }

    createChannel(): PrivateChannel {
        if (!this.documentsIndex) {
            throw new Error('documentsIndex is needed before calling createChannel().');
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
