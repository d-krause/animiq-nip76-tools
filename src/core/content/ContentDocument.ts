/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as nostrTools from 'nostr-tools';
import { HDKissAddress as Address, HDKey } from '../keys';

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
}

export interface IDocumentConstructor { new(rawData: any, parent: ContentDocument | undefined): ContentDocument; }
