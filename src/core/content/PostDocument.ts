/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { HDKey } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { IndexDocument, IndexPermission } from './IndexDocument';
import { PrivateChannel } from './PrivateChannel';

export interface IPostPayload extends ContentTemplate {
    text: string;
}

export class PostDocument extends ContentDocument {
    override content!: IPostPayload;
    channel!: PrivateChannel;
    // rp!: HDKey;
    // reactionsIndex!: IndexDocument;
    reactionTracker: { [key: string | symbol]: number } = {};
    reactions: PostDocument[] = [];
    replies: PostDocument[] = [];


    // override setKeys(ap: HDKey, sp: HDKey) {
    //     super.setKeys(ap, sp);
    //     this.rp = this.ap.deriveNewMasterKey();
    //     this.reactionsIndex = IndexDocument.createIndex(
    //         IndexPermission.CreateByPublic,
    //         this.rp.deriveChildKey(0),
    //         this.rp.deriveChildKey(1)
    //     );
    //     this.reactions = [];
    // }

    override get payload(): any[] {
        return [...super.payload, this.content.text];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.text = raw[4];
        return raw;
    }
}

export interface FileInfo {
    name: string;
    size: number;
    type: string;
    lastModified: number;
}
export interface Attachments {
    data?: AttachmentsDatum[];
}

export interface AttachmentsDatum {
    ogUrl?: string;
    ogImageUrl?: string;
    ogImageBytes?: Uint8Array;
    ogTitle?: string;
    ogDescription?: string;
    ogSiteName?: string;
    ogSiteHost?: string;
    fileInfo?: FileInfo;
}

export interface AttachmentsDatumFB {
    description?: string;
    media?: Media;
    target?: Target;
    type?: Type;
    url?: string;
    title?: string;
}

export interface Media {
    image?: Image;
}

export interface Image {
    src?: string;
    height?: number;
    width?: number;
}

export interface Target {
    id?: string;
    url?: string;
}

export enum Type {
    Photo = 'photo',
    Share = 'share',
    Unavailable = 'unavailable',
    VideoInline = 'video_inline',
}
