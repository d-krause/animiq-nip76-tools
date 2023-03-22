/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */

import { bytesToHex, concatBytes, randomBytes } from '@noble/hashes/utils';
import { signSync } from '@noble/secp256k1';
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
    constructor(
        public type: HDKIndexType,
        public signingParent: HDKey,
        public cryptoParent: HDKey,
        public guestSigner?: HDKey
    ) {
        if (!signingParent.privateKey && !guestSigner?.privateKey) {
            throw new Error('privateKey is required on the signingParent.');
        }
        if (!this.isTimeBased && !this.isSequential) {
            throw new Error('HDKIndex must either be Sequential and TimeBased.');
        }
        if (this.isTimeBased && this.isSequential) {
            throw new Error('HDKIndex cannot be both Sequential and TimeBased.');
        }
        if (this.isPrivate && !cryptoParent.privateKey) {
            throw new Error('privateKey is required on the cryptoParent when the type is Private.');
        }
        if (this.isPrivate && guestSigner) {
            throw new Error('guestSigner is not permitted when the type is Private.');
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

    private getKeysFromIndex(docIndex: number, isTopLevel: boolean) {
        let signingKey: HDKey;
        if (this.signingParent.privateKey) {
            signingKey = isTopLevel ? this.signingParent : this.signingParent.deriveChildKey(docIndex!, this.isPrivate);
        } else if (this.guestSigner && !this.isPrivate) {
            signingKey = isTopLevel ? this.guestSigner : this.guestSigner.deriveChildKey(docIndex!);
        } else {
            throw new Error('no valid signing key found on the index');
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

    async createEvent(doc: ContentDocument, privateKey?: string, docIndex = 0): Promise<NostrEventDocument> {

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
        const keyset = this.getKeysFromIndex(docIndex!, doc.isTopLevel);

        if (!this.isPrivate) {
            doc.content.sig = bytesToHex(signSync(doc.hash, privateKey!));
        }
        const content = new TextEncoder().encode(doc.serialize());

        const iv = randomBytes(16);
        const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
        const key = await globalThis.crypto.subtle.importKey('raw', keyset.cryptoKey, alg, false, ['encrypt']);
        const encrypted = new Uint8Array(await globalThis.crypto.subtle.encrypt(alg, key, content));

        const event = nostrTools.getBlankEvent() as NostrEventDocument;
        event.tags = [['e', this.eventTag]];
        event.created_at = cati.created_at;
        event.kind = 17761;
        event.pubkey = keyset.signingKey.nostrPubKey;
        event.content = base64.encode(concatBytes(iv, encrypted));
        event.sig = nostrTools.signEvent(event, keyset.signingKey.hexPrivKey!) as any;
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
            doc.deserialize(json);
            doc.ownerPubKey = doc.content.pubkey;
            doc.nostrEvent = event;
            doc.ready = true;
            return doc;

        } catch (e) {
            console.error('HDKIndex.readEvent error' + e);
            return undefined;
        }
    }
}