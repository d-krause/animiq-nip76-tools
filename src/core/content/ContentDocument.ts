/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as nostrTools from 'nostr-tools';
import { HDKIndex } from '../keys';


export interface ContentTemplate {
    kind: nostrTools.Kind | number;
    pubkey: string;
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
    dkxParent!: HDKIndex;
    docIndex = 0;
    ready = false;
    verified = false;
    editing = false;
    content!: ContentTemplate;
    nostrEvent!: NostrEventDocument;
    ownerPubKey!: string;

    get payload(): any[] {
        return [[
            this.content.kind,
            this.content.pubkey,
            this.content.tags,
        ]];
    }

    serialize(): string {
        return JSON.stringify(this.payload)
    }

    deserialize(payload: string): any[] {
        const raw = JSON.parse(payload);
        this.content = {
            kind: raw[0][0],
            pubkey: raw[0][1],
            tags: raw[0][2],
        };
        return raw;
    }
}

// export interface IDocumentConstructor { new(rawData: any, parent: ContentDocument | undefined): ContentDocument; }
