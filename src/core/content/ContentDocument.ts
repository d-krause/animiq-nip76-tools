/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import * as nostrTools from 'nostr-tools';
import { HDKey, HDKIndex } from '../keys';


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

export class ContentDocument {
    hdkIndex!: HDKIndex;
    isTopLevel = false;
    ready = false;
    verified = false;
    editing = false;
    content!: ContentTemplate;
    nostrEvent!: NostrEventDocument;
    ownerPubKey!: string;

    get payload(): any[] {
        return [
            this.content.kind,
            this.content.pubkey,
            this.content.sig,
            this.content.tags,
        ];
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
}

export interface IDocumentConstructor { new(rawData: any, parent: ContentDocument | undefined): ContentDocument; }
