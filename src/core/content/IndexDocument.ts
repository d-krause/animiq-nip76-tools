/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { bytesToHex, concatBytes, randomBytes } from '@noble/hashes/utils';
import { signSync } from '@noble/secp256k1';
import { base64 } from '@scure/base';
import * as nostrTools from 'nostr-tools';
import { HDKey } from '../keys';
import { ContentDocument, NostrEventDocument } from './ContentDocument';

export class IndexDocument {
    ap!: HDKey;
    sp!: HDKey;
    permission!: IndexPermission;

    static createIndex(permission: IndexPermission, ap: HDKey, sp: HDKey): IndexDocument {
        const rtn = new IndexDocument();
        // rtn.type = type;
        rtn.permission = permission;
        rtn.ap = ap;
        rtn.sp = sp;
        return rtn;
    }

    private setDocKeys(doc: ContentDocument): void {
        if (!doc.ap || !doc.sp) {
            const [ap, sp] = [
                this.ap.deriveChildKey(doc.index),
                this.sp.deriveChildKey(doc.index),
            ];
            doc.setKeys(ap, sp);
        }
    }

    async encrypt(doc: ContentDocument, signingKey: string, created_at?: number, tags?: string[][]): Promise<NostrEventDocument> {

        created_at = created_at || Math.floor(Date.now() / 1000);
        doc.content.sig = bytesToHex(signSync(doc.hash, signingKey));

        this.setDocKeys(doc);
        const iv = randomBytes(16);
        const content = new TextEncoder().encode(doc.serialize());
        const alg = { name: 'AES-GCM', iv, length: 256 } as AesKeyAlgorithm;
        const secretKey = await globalThis.crypto.subtle.importKey('raw', doc.sp.publicKey.slice(1), alg, false, ['encrypt']);
        const encrypted = new Uint8Array(await globalThis.crypto.subtle.encrypt(alg, secretKey, content));

        const event = nostrTools.getBlankEvent() as NostrEventDocument;
        event.tags = tags || [];
        event.created_at = created_at;
        event.kind = 17761;
        event.pubkey = doc.ap.nostrPubKey;
        event.content = base64.encode(concatBytes(iv, encrypted));
        event.sig = nostrTools.signEvent(event, doc.ap.hexPrivKey!) as any;
        event.id = nostrTools.getEventHash(event);

        return event;
    }

    async decrypt(doc: ContentDocument, event: nostrTools.Event): Promise<boolean> {
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

            return doc.ready;
        } catch (e) {
            console.log('Address.decrypt error' + e);
            return false;
        }
    }
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
