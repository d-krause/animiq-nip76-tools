/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
// re: Buffer - vscode pretends it doesn't need this Buffer import, but tsc complains when building
import * as nostrTools from 'nostr-tools';
import { HDKissAddress as Address, HDKey } from '../keys';

export const foo: nostrTools.Event = {
    content: '', 
    created_at: 1, 
    id: '', 
    sig: '', 
    
    kind: 1, 
    tags: [], 
    pubkey: ''
}

/**
 * client only content fields, properties and methods
 */
export class ContentDocument implements nostrTools.Event {
    // nostr Event fields
    id!: string;
    sig!: string;
    created_at!: number;
    pubkey!: string;
    kind!: number;
    tags: string[][] = []
    content!: string;

    ownerPubKey!: string;
    ready = false;
    decryptedContent: any;
    v!: number;
    a!: string;
    i!: number;
    address!: Address;
    parent!: ContentDocument;
    ap!: HDKey;
    sp!: HDKey;

    setKeys(ap: HDKey, sp: HDKey): boolean {
        const keysReset = (ap && sp) && (!this.ap || !this.sp);
        if (keysReset) {
            this.ap = ap;
            this.sp = sp;
        }
        return keysReset;
    }

    get formattedAddress() {
        return Address.formatAddress(this.a);
    }

    get displayAddress() {
        return Address.formatAddress(this.a, true);
    }

    get datetime(): Date {
        return new Date(this.created_at);
    }

    get indexIsValid(): boolean {
        return this.i !== null && this.i !== undefined && !isNaN(this.i) && this.i >= 0 && this.i < HDKey.hardenedKeyOffset;
    }
}

export interface IDocumentConstructor { new(rawData: any, parent: ContentDocument | undefined): ContentDocument; }
