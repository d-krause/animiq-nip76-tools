/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */

import { ContentDocument, ContentTemplate, NostrKinds } from './ContentDocument';

export interface IPostPayload extends ContentTemplate {
    text: string;
}

export class PostDocument extends ContentDocument {
    override content!: IPostPayload;

    get refId(): string | undefined {
        return this.content.tags?.[0]?.[1];
    }

    getRef(): PostDocument | undefined {
        return this.dkxParent.documents.find(x => x.nostrEvent.id === this.refId) as PostDocument;
    }

    getReplies(): PostDocument[] {
        return (this.dkxParent.documents as PostDocument[])
            .filter(x => x.content.kind === 1 && x.refId === this.nostrEvent.id)
    }

    getReactions(): PostDocument[] {
        return (this.dkxParent.documents as PostDocument[])
            .filter(x => x.content.kind === 7 && x.refId === this.nostrEvent.id)
    }

    getReactionTracker(): { [key: string | symbol]: number } {
        return this.getReactions().reduce((a: { [key: string | symbol]: number }, b: PostDocument) => {
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
