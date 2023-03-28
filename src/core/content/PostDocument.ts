/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */

import * as nostrTools from 'nostr-tools';
import { ContentDocument, ContentTemplate } from './ContentDocument';

export interface IPostPayload extends ContentTemplate {
    text: string;
}

export class PostDocument extends ContentDocument {
    override content!: IPostPayload;

    get ref(): PostDocument | undefined {
        if (this.content.tags && this.content.tags![0][0] === 'e') {
            return this.dkxParent.documents.find(x => x.nostrEvent.id === this.content.tags![0][1]) as PostDocument;
        }
    }

    get replies(): PostDocument[] {
            return (this.dkxParent.documents as PostDocument[]).filter(x => x.ref === this && x.content.kind === nostrTools.Kind.Text);
    }


    get reactions(): PostDocument[] {
            return (this.dkxParent.documents as PostDocument[]).filter(x => x.ref === this && x.content.kind === nostrTools.Kind.Reaction);
    }

    get reactionTracker(): { [key: string | symbol]: number } {
        return this.reactions.reduce((a: { [key: string | symbol]: number }, b: PostDocument) => {
            const count = a[b.content.text!];
            a[b.content.text!] = count ? count + 1 : 1;
            return a;
        }, {});
    }

    override get payload(): any[] {
        return [...super.payload, this.content.text];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.text = raw[1];
        return raw;
    }
}
