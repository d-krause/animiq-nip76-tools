/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { PrivateChannel } from './PrivateChannel';

export interface IPostPayload extends ContentTemplate {
    text: string;
}

export class PostDocument extends ContentDocument {
    override content!: IPostPayload;
    channel!: PrivateChannel;
    reactionTracker: { [key: string | symbol]: number } = {};
    reactions: PostDocument[] = [];
    replies: PostDocument[] = [];

    override get payload(): any[] {
        return [...super.payload, this.content.text];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.text = raw[4];
        return raw;
    }
}
