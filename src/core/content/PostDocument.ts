/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { ContentDocument } from './ContentDocument';
import { IndexDocument, IndexPermission } from './IndexDocument';
import { HDKey, HDKissDocumentType } from '../keys';
import { PrivateThread } from './PrivateThread';

export class PostDocument extends ContentDocument {
    override p!: IPostPayload;

    ownerPubKey!: string;
    nostrEvent: any;
    thread!: PrivateThread;
    rp!: HDKey;
    reactionsIndex!: IndexDocument;
    reactions!: PostDocument[];
    repliesIndex!: IndexDocument;
    replies!: PostDocument[];

    static override get default() {
        return new PostDocument(undefined, undefined);
    }

    override setKeys(ap: HDKey, sp: HDKey) {

        const resetKeys = super.setKeys(ap, sp);
        if (resetKeys) {
            this.rp = this.ap.deriveNewMasterKey(this.ownerPubKey);
            this.reactionsIndex = IndexDocument.createIndex(
                'Reaction',
                HDKissDocumentType.Reaction,
                IndexPermission.CreateByPublic,
                this.rp.deriveChildKey(0),
                this.rp.deriveChildKey(1)
            );
            this.reactions = [];
            this.repliesIndex = IndexDocument.createIndex(
                'Post',
                HDKissDocumentType.Post,
                IndexPermission.CreateByPublic,
                this.rp.deriveChildKey(2),
                this.rp.deriveChildKey(3)
            );
            this.replies = [];
        }
        return resetKeys;
    }
}

export interface FileInfo {
    name: string;
    size: number;
    type: string;
    lastModified: number;
}

export interface IPostPayload {
    attachments?: Attachments;
    full_picture?: string;
    link?: string;
    message?: string;

    authorPubKey?: string;
    sig?: string;
    type?: 0 | 1 | 2;  //Post|Reaction|Reply
    // privacy?:      Privacy;
}

export interface Attachments {
    data?: AttachmentsDatum[];
}

export interface AttachmentsDatum {
    ogUrl?: string;
    ogImageUrl?: string;
    ogImageBytes?: Buffer;
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
