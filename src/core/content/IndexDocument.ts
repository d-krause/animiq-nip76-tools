/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { bytesToHex, concatBytes, randomBytes } from '@noble/hashes/utils';
import { signSync } from '@noble/secp256k1';
import { base64 } from '@scure/base';
import * as nostrTools from 'nostr-tools';
import { HDKey } from '../keys';
import { getCreatedAtIndexes } from '../util';
import { Wallet } from '../wallet/Wallet';
import { ContentDocument, NostrEventDocument } from './ContentDocument';
import { FollowDocument } from './FollowDocument';
import { PrivateChannel } from './PrivateChannel';

export class IndexDocument {
    ap!: HDKey;
    sp!: HDKey;
    permission!: IndexPermission;

    static createIndex(permission: IndexPermission, ap: HDKey, sp: HDKey): IndexDocument {
        const rtn = new IndexDocument();
        rtn.permission = permission;
        rtn.ap = ap;
        rtn.sp = sp;
        return rtn;
    }

    private setDocKeys(doc: ContentDocument): void {
        if (!doc.sp) {
            const [ap, sp] = [
                this.ap.deriveChildKey(doc.index),
                this.sp.deriveChildKey(doc.index),
            ];
            doc.setKeys(ap, sp);
        }
    }

    async decrypt2(doc: ContentDocument, event: nostrTools.Event): Promise<boolean> {
        try {
            doc.nostrEvent = event as NostrEventDocument;
            doc.ready = true;
            const cati = getCreatedAtIndexes(event.created_at);
            doc.index = cati.index1;
            this.setDocKeys(doc);

            const encrypted = base64.decode(event.content);
            const iv = encrypted.slice(0, 16);
            const data = encrypted.slice(16);
            const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
            const secretKey = await globalThis.crypto.subtle.importKey('raw', doc.sp.publicKey.slice(1), alg, false, ['decrypt']);
            const decrypted = new Uint8Array(await globalThis.crypto.subtle.decrypt(alg, secretKey, data));
            const json = new TextDecoder().decode(decrypted);
            doc.deserialize(json);
            doc.ownerPubKey = doc.content.pubkey;
            return doc.ready;
        } catch (e) {
            console.log('Address.decrypt error' + e);
            return false;
        }
    }

    async decrypt3(doc: ContentDocument, event: nostrTools.Event): Promise<boolean> {
        try {
            doc.nostrEvent = event as NostrEventDocument;
            doc.ready = true;
            this.setDocKeys(doc);

            const encrypted = base64.decode(event.content);
            const iv = encrypted.slice(0, 16);
            const data = encrypted.slice(16);
            const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
            const secretKey = await globalThis.crypto.subtle.importKey('raw', doc.sp.publicKey.slice(1), alg, false, ['decrypt']);
            const decrypted = new Uint8Array(await globalThis.crypto.subtle.decrypt(alg, secretKey, data));
            const json = new TextDecoder().decode(decrypted);

            doc.deserialize(json);
            doc.ownerPubKey = doc.content.pubkey;
            return doc.ready;
        } catch (e) {
            console.log('Address.decrypt error' + e);
            return false;
        }
    }

    async encrypt2(doc: ContentDocument, channel: PrivateChannel, privateKey: string, signingKey: HDKey): Promise<NostrEventDocument> {


        doc.content.sig = bytesToHex(signSync(doc.hash, privateKey));

        const cati = getCreatedAtIndexes();
        doc.index = cati.index1;
        this.setDocKeys(doc);
        signingKey = doc === channel ? doc.ap : signingKey.deriveChildKey(cati.index1, true);
        // const secretsKey = doc === channel ? doc.sp : signingKey.deriveChildKey(cati.index1, true);
        const iv = randomBytes(16);
        const content = new TextEncoder().encode(doc.serialize());
        const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
        const secretKey = await globalThis.crypto.subtle.importKey('raw', doc.sp.publicKey.slice(1), alg, false, ['encrypt']);
        const encrypted = new Uint8Array(await globalThis.crypto.subtle.encrypt(alg, secretKey, content));

        const event = nostrTools.getBlankEvent() as NostrEventDocument;
        event.tags = [['e', channel.beacon]];
        event.created_at = cati.created_at;
        event.kind = 17761;
        event.pubkey = signingKey.nostrPubKey;
        event.content = base64.encode(concatBytes(iv, encrypted));
        event.sig = nostrTools.signEvent(event, signingKey.hexPrivKey!) as any;
        event.id = nostrTools.getEventHash(event);

        return event;
    }

    async encrypt3(doc: FollowDocument, wallet: Wallet, privateKey: string): Promise<NostrEventDocument> {


        doc.content.sig = bytesToHex(signSync(doc.hash, privateKey));

        const cati = getCreatedAtIndexes();
        doc.index = wallet.following.length;
        this.setDocKeys(doc);
        const signingKey = doc.ap;
        // const secretsKey = doc === channel ? doc.sp : signingKey.deriveChildKey(cati.index1, true);
        const iv = randomBytes(16);
        const content = new TextEncoder().encode(doc.serialize());
        const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
        const secretKey = await globalThis.crypto.subtle.importKey('raw', doc.sp.publicKey.slice(1), alg, false, ['encrypt']);
        const encrypted = new Uint8Array(await globalThis.crypto.subtle.encrypt(alg, secretKey, content));

        const event = nostrTools.getBlankEvent() as NostrEventDocument;
        event.tags = [['e', wallet.beaconKey.deriveChildKey(0, true).pubKeyHash]];
        event.created_at = cati.created_at;
        event.kind = 17761;
        event.pubkey = signingKey.nostrPubKey;
        event.content = base64.encode(concatBytes(iv, encrypted));
        event.sig = nostrTools.signEvent(event, signingKey.hexPrivKey!) as any;
        event.id = nostrTools.getEventHash(event);

        return event;
    }

    // async encrypt(doc: ContentDocument, signingKey: string, created_at?: number): Promise<NostrEventDocument> {

    //     created_at = created_at || Math.floor(Date.now() / 1000);
    //     doc.content.sig = bytesToHex(signSync(doc.hash, signingKey));

    //     this.setDocKeys(doc);
    //     const iv = randomBytes(16);
    //     const content = new TextEncoder().encode(doc.serialize());
    //     const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
    //     const secretKey = await globalThis.crypto.subtle.importKey('raw', doc.sp.publicKey.slice(1), alg, false, ['encrypt']);
    //     const encrypted = new Uint8Array(await globalThis.crypto.subtle.encrypt(alg, secretKey, content));

    //     const event = nostrTools.getBlankEvent() as NostrEventDocument;
    //     event.tags = [['e', this.ap.pubKeyHash]];
    //     event.created_at = created_at;
    //     event.kind = 17761;
    //     event.pubkey = doc.ap.nostrPubKey;
    //     event.content = base64.encode(concatBytes(iv, encrypted));
    //     event.sig = nostrTools.signEvent(event, doc.ap.hexPrivKey!) as any;
    //     event.id = nostrTools.getEventHash(event);

    //     return event;
    // }

    // async decrypt(doc: ContentDocument, event: nostrTools.Event): Promise<boolean> {
    //     try {
    //         doc.nostrEvent = event as NostrEventDocument;
    //         doc.ready = true;

    //         this.setDocKeys(doc);

    //         const encrypted = base64.decode(event.content);
    //         const iv = encrypted.slice(0, 16);
    //         const data = encrypted.slice(16);
    //         const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
    //         const secretKey = await globalThis.crypto.subtle.importKey('raw', doc.sp.publicKey.slice(1), alg, false, ['decrypt']);
    //         const decrypted = new Uint8Array(await globalThis.crypto.subtle.decrypt(alg, secretKey, data));
    //         const json = new TextDecoder().decode(decrypted);
    //         doc.deserialize(json);

    //         return doc.ready;
    //     } catch (e) {
    //         console.log('Address.decrypt error' + e);
    //         return false;
    //     }
    // }
}

export enum IndexPermission {
    /**
     * Anyone who can can create a document on this index.
     */
    CreateByPublic = 1,
    /**
     * Anyone listed in the group can create a document on this index.
     */
    CreateByGroupMember = 2,
    /**
     * TBD - perhaps anyone with a password can create a document on this index.
     */
    CreateByCustom = 4,
    /**
     * Only the owner can create a document on this index.
     */
    CreateByOwner = 8,
}
