/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */

import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import * as nostrTools from 'nostr-tools';
import { ContentDocument, FollowDocument, Invitation, NostrEventDocument, PostDocument, PrivateChannel } from '../content';
import { getCreatedAtIndexes, getReducedKey } from '../util';
import { HDKey } from './HDKey';

export enum HDKIndexType {
    Private = 1,            // 0001
    Sequential = 1 << 1,    // 0010
    TimeBased = 1 << 2,     // 0100
}

interface DocumentKeyset {
    signingKey?: HDKey;
    cryptoKey: HDKey
}


export class HDKIndex {
    eventTag: string;
    documents: ContentDocument[] = [];
    constructor(
        public type: HDKIndexType,
        public signingParent: HDKey,
        public cryptoParent: HDKey,
        public wordset?: Uint32Array
    ) {
        if (!this.isTimeBased && !this.isSequential) {
            throw new Error('HDKIndex must either be Sequential and TimeBased.');
        }
        if (this.isTimeBased && this.isSequential) {
            throw new Error('HDKIndex cannot be both Sequential and TimeBased.');
        }
        if (this.isPrivate && !cryptoParent.privateKey) {
            throw new Error('privateKey is required on the cryptoParent when the type is Private.');
        }
        if (this.isPrivate && !this.wordset) {
            this.wordset = new Uint32Array((sha256(signingParent.privateKey)).buffer);
        }
        this.eventTag = signingParent.deriveChildKey(0, this.isPrivate).deriveChildKey(0, this.isPrivate).pubKeyHash;
    }

    get isPrivate(): boolean {
        return (this.type & HDKIndexType.Private) === HDKIndexType.Private;
    }

    get isTimeBased(): boolean {
        return (this.type & HDKIndexType.TimeBased) === HDKIndexType.TimeBased;
    }

    get isSequential(): boolean {
        return (this.type & HDKIndexType.Sequential) === HDKIndexType.Sequential;
    }

    getKeysFromIndex(docIndex: number, privateKey?: string): DocumentKeyset {
        let signingKey: HDKey | undefined = undefined;
        let cryptoKey: HDKey;
        if (this.isPrivate) {
            if (this.signingParent.privateKey) {
                signingKey = getReducedKey({ root: this.signingParent, offset: docIndex, wordset: this.wordset!.slice(0, 4) });
            }
            cryptoKey = getReducedKey({ root: this.cryptoParent, offset: docIndex, wordset: this.wordset!.slice(4, 8) });
        } else {
            if (privateKey) {
                signingKey = new HDKey({
                    privateKey: hexToBytes(privateKey),
                    chainCode: this.signingParent.chainCode,
                    version: this.signingParent.version
                }).deriveChildKey(docIndex, false);
            }
            cryptoKey = this.cryptoParent.deriveChildKey(docIndex!, false);
        }

        return { signingKey, cryptoKey };
    }

    async createEvent(doc: ContentDocument, privateKey: string): Promise<NostrEventDocument> {

        if (!doc.docIndex && this.isSequential) {
            throw new Error('docIndex is required to create events on sequential HDKIndexType.');
        }
        if (!privateKey && !this.isPrivate) {
            throw new Error('privateKey is required to create non-private events.');
        }
        const cati = getCreatedAtIndexes();
        if (this.isTimeBased) {
            doc.docIndex = cati.index1;
        }
        const keyset = this.getKeysFromIndex(doc.docIndex, privateKey);
        const keydata = keyset.cryptoKey.publicKey.slice(1);
        const content = new TextEncoder().encode(doc.serialize());
        const iv = randomBytes(16);
        const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
        const key = await globalThis.crypto.subtle.importKey('raw', keydata, alg, false, ['encrypt']);
        const encrypted = new Uint8Array(await globalThis.crypto.subtle.encrypt(alg, key, content));

        const event = nostrTools.getBlankEvent() as NostrEventDocument;
        event.tags = [['e', this.isSequential ? keyset.signingKey!.deriveChildKey(0, true).pubKeyHash : this.eventTag]];
        event.created_at = cati.created_at;
        event.kind = 17761;
        event.pubkey = keyset.signingKey!.nostrPubKey;
        event.content = base64.encode(concatBytes(iv, encrypted));
        event.sig = nostrTools.signEvent(event, keyset.signingKey!.hexPrivKey!) as any;
        event.id = nostrTools.getEventHash(event);
        doc.nostrEvent = event;

        return event;
    }

    async readEvent(event: NostrEventDocument, sequentialIndex?: number): Promise<ContentDocument | undefined> {
        if (this.isSequential && !sequentialIndex === undefined) {
            throw new Error('docIndex is required to read events on sequential HDKIndexType.');
        }
        try {
            const cati = getCreatedAtIndexes(event.created_at);
            const docIndex = this.isSequential ? sequentialIndex! : cati.index1;
            const keyset = this.getKeysFromIndex(docIndex!);
            const keydata = keyset.cryptoKey.publicKey.slice(1);
            const encrypted = base64.decode(event.content);
            const iv = encrypted.slice(0, 16);
            const data = encrypted.slice(16);
            const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
            const secretKey = await globalThis.crypto.subtle.importKey('raw', keydata, alg, false, ['decrypt']);
            const decrypted = new Uint8Array(await globalThis.crypto.subtle.decrypt(alg, secretKey, data));
            const json = new TextDecoder().decode(decrypted);
            return this.getDocumentFromJson(json, docIndex, event, keyset);
        } catch (e) {
            if (event.created_at > 1679660971)
                console.error('HDKIndex.readEvent error', event);
            return undefined;
        }
    }

    private getDocumentFromJson(json: string, docIndex: number, event: NostrEventDocument, keyset: DocumentKeyset): ContentDocument {

        let doc: ContentDocument;
        const kind = parseInt(json.match(/\d+/)![0]);
        const existing = this.isSequential
            ? this.documents.find(x => x.docIndex === docIndex)
            : this.documents.find(x => x.nostrEvent?.pubkey === event.pubkey);

        switch (kind) {
            case nostrTools.Kind.ChannelMetadata:
                doc = new PrivateChannel(keyset.signingKey!, keyset.cryptoKey, existing as PrivateChannel);
                break;
            case nostrTools.Kind.Text:
            case nostrTools.Kind.Reaction:
                doc = new PostDocument();
                break;
            case 1776:
                doc = new Invitation();
                break;
            case nostrTools.Kind.Contacts:
                doc = new FollowDocument();
                break;
            default:
                throw new Error(`Kind ${kind} not supported.`)
        }

        doc.deserialize(json);
        const publicKey = !this.isPrivate && doc.content.pubkey ? hexToBytes('02' + doc.content.pubkey) : this.signingParent.publicKey;
        const signerKey = new HDKey({ publicKey, chainCode: this.signingParent.chainCode, version: this.signingParent.version });
        doc.verified = signerKey.deriveChildKey(docIndex).nostrPubKey === event.pubkey;
        doc.ownerPubKey = doc.content.pubkey;
        doc.docIndex = docIndex;
        doc.nostrEvent = event;
        doc.dkxParent = this;
        doc.ready = true;

        if (existing) {
            const i = this.documents.indexOf(existing);
            this.documents.splice(i, 1);
        }
        this.documents = [...this.documents, doc].sort((a, b) => b.nostrEvent?.created_at - a.nostrEvent?.created_at);

        return doc;
    }

    getDocKeys(start = 1, length = 20): string[] {
        if (this.isSequential) {
            return this.isPrivate
                ? Array(length).fill(0).map((_, i) => getReducedKey({ root: this.signingParent, offset: i + start, wordset: this.wordset!.slice(0, 4) }).nostrPubKey)
                : Array(length).fill(0).map((_, i) => this.signingParent.deriveChildKey(i + start).nostrPubKey);
        } else {
            return [];
        }
    }
}