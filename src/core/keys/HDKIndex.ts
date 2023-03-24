/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */

import { bytesToHex, concatBytes, hexToBytes, randomBytes } from '@noble/hashes/utils';
import * as secp from '@noble/secp256k1';
import { base64 } from '@scure/base';
import * as nostrTools from 'nostr-tools';
import { ContentDocument, FollowDocument, NostrEventDocument, PostDocument, PrivateChannel } from '../content';
import { getCreatedAtIndexes } from '../util';
import { HDKey } from './HDKey';

export enum HDKIndexType {
    Private = 1,            // 0001
    Sequential = 1 << 1,    // 0010
    TimeBased = 1 << 2,     // 0100
}

export class HDKIndex {
    eventTag: string;
    documents: ContentDocument[] = [];
    constructor(
        public type: HDKIndexType,
        public signingParent: HDKey,
        public cryptoParent: HDKey
    ) {
        // if (!signingParent.privateKey && !guestSigner?.privateKey) {
        //     throw new Error('privateKey is required on the signingParent.');
        // }
        if (!this.isTimeBased && !this.isSequential) {
            throw new Error('HDKIndex must either be Sequential and TimeBased.');
        }
        if (this.isTimeBased && this.isSequential) {
            throw new Error('HDKIndex cannot be both Sequential and TimeBased.');
        }
        if (this.isPrivate && !cryptoParent.privateKey) {
            throw new Error('privateKey is required on the cryptoParent when the type is Private.');
        }
        // if (this.isPrivate && guestSigner) {
        //     throw new Error('guestSigner is not permitted when the type is Private.');
        // }
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

    private getKeysFromIndex(docIndex: number, isTopLevel: boolean, privateKey?: string)
        : { signingKey?: HDKey | null, cryptoKey: Uint8Array } {
        let signingKey: HDKey | null = null;
        if (isTopLevel) {
            if (this.signingParent.privateKey) {
                signingKey = this.signingParent;
            }
        } else if (privateKey) {
            signingKey = new HDKey({
                privateKey: hexToBytes(privateKey),
                chainCode: this.signingParent.chainCode,
                version: this.signingParent.version
            }).deriveChildKey(docIndex);
        } else {
            signingKey = this.signingParent.deriveChildKey(docIndex, this.isPrivate);
        }

        let cryptoKey: Uint8Array;
        if (this.isPrivate) {
            cryptoKey = isTopLevel ? this.cryptoParent.privateKey
                : this.cryptoParent.deriveChildKey(docIndex!, this.isPrivate).privateKey;
        } else {
            cryptoKey = isTopLevel ? this.cryptoParent.publicKey.slice(1)
                : this.cryptoParent.deriveChildKey(docIndex!, this.isPrivate).publicKey.slice(1);
        }
        return { signingKey, cryptoKey };
    }

    async createEvent(doc: ContentDocument, privateKey: string, docIndex = 0): Promise<NostrEventDocument> {

        if (!docIndex && this.isSequential) {
            throw new Error('docIndex is required to create events on sequential HDKIndexType.');
        }
        if (!privateKey && !this.isPrivate) {
            throw new Error('privateKey is required to create non-private events.');
        }
        const cati = getCreatedAtIndexes();
        if (this.isTimeBased) {
            docIndex = cati.index1;
        }

        const keyset = this.getKeysFromIndex(docIndex!, doc.isTopLevel, privateKey);
        const content = new TextEncoder().encode(doc.serialize());

        const iv = randomBytes(16);
        const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
        const key = await globalThis.crypto.subtle.importKey('raw', keyset.cryptoKey, alg, false, ['encrypt']);
        const encrypted = new Uint8Array(await globalThis.crypto.subtle.encrypt(alg, key, content));

        const event = nostrTools.getBlankEvent() as NostrEventDocument;
        event.tags = [['e', this.eventTag]];
        event.created_at = cati.created_at;
        event.kind = 17761;
        event.pubkey = keyset.signingKey!.nostrPubKey;
        event.content = base64.encode(concatBytes(iv, encrypted));
        event.sig = nostrTools.signEvent(event, keyset.signingKey!.hexPrivKey!) as any;
        event.id = nostrTools.getEventHash(event);

        return event;
    }

    async readEvent(event: NostrEventDocument, isTopLevel = false, docIndex = 0): Promise<ContentDocument | undefined> {
        if (!docIndex && this.isSequential) {
            throw new Error('docIndex is required to read events on sequential HDKIndexType.');
        }
        try {
            const cati = getCreatedAtIndexes(event.created_at);
            if (this.isTimeBased) {
                docIndex = cati.index1;
            }
            const keyset = this.getKeysFromIndex(docIndex!, isTopLevel);
            const encrypted = base64.decode(event.content);
            const iv = encrypted.slice(0, 16);
            const data = encrypted.slice(16);
            const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
            const secretKey = await globalThis.crypto.subtle.importKey('raw', keyset.cryptoKey, alg, false, ['decrypt']);
            const decrypted = new Uint8Array(await globalThis.crypto.subtle.decrypt(alg, secretKey, data));
            const json = new TextDecoder().decode(decrypted);

            const doc = this.getDocumentFromJson(json);
            doc.hdkIndex = this;
            doc.deserialize(json);
            doc.ownerPubKey = doc.content.pubkey;
            doc.nostrEvent = event;
            doc.ready = true;
            const signerKey = new HDKey({
                publicKey: hexToBytes('02'+doc.content.pubkey),
                chainCode: this.signingParent.chainCode,
                version: this.signingParent.version
            });
            doc.verified = signerKey.deriveChildKey(docIndex).nostrPubKey === event.pubkey;
            this.documents = [...this.documents, doc].sort((a, b) => b.nostrEvent.created_at - a.nostrEvent.created_at);
            return doc;

        } catch (e) {
            console.error('HDKIndex.readEvent error' + e);
            return undefined;
        }
    }

    private getDocumentFromJson(json: string): ContentDocument {
        const kind = parseInt(json.match(/\d+/)![0]);
        switch (kind) {
            case nostrTools.Kind.ChannelMetadata:
                return new PrivateChannel();
            case nostrTools.Kind.Text:
            case nostrTools.Kind.Reaction:
                return new PostDocument();
            case nostrTools.Kind.Contacts:
                return new FollowDocument();
            default:
                throw new Error(`Kind ${kind} not supported.`)
        }
    }
}