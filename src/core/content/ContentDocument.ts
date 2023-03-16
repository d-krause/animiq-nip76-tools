/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import * as nostrTools from 'nostr-tools';
import { utf8Encoder } from 'nostr-tools/utils';
import { HDKey } from '../keys';

export class ContentDocument {
    parent!: ContentDocument;
    index!: number;
    ap!: HDKey;
    sp!: HDKey;

    nostrEvent!: NostrEventDocument;
    ownerPubKey!: string;

    ready = false;
    editing = false;

    content!: ContentTemplate;

    get payload(): any[] {
        return [
            this.content.kind,
            this.content.pubkey,
            this.content.sig,
            this.content.tags,
        ];
    }

    get hash(): string {
        const payload = this.payload;
        payload[2] = null;
        const bytes = utf8Encoder.encode(JSON.stringify(payload));
        return bytesToHex(sha256(bytes));
    }

    serialize(): string {
        return JSON.stringify(this.payload)
    }

    deserialize(payload: string): any[] {
        const raw = JSON.parse(payload);
        this.content = {
            kind: raw[0],
            pubkey: raw[1],
            sig: raw[2],
            tags: raw[3],
        };
        return raw;
    }

    setKeys(ap: HDKey, sp: HDKey): void {
        this.ap = ap;
        this.sp = sp;
    }
}


export interface ContentTemplate {
    kind: nostrTools.Kind | number;
    pubkey: string;
    sig?: string;
    tags?: string[][];
}

export interface NostrEventDocument extends nostrTools.Event {
    contentCut: boolean;
    tagsCut: boolean;

    replyEventId?: string;
    rootEventId?: string;
    parentEventId?: string;
}

export interface IDocumentConstructor { new(rawData: any, parent: ContentDocument | undefined): ContentDocument; }
