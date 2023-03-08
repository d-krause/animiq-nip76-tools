/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { ContentDocument } from './ContentDocument';
import { IndexDocument, IndexPermission } from './IndexDocument';
import { HDKey } from '../keys';
import { PrivateThread } from './PrivateThread';

export class PostDocument extends ContentDocument {
    override p!: IPostPayload;
    ownerPubKey!: string;
    nostrEvent: any;
    thread!: PrivateThread;
    documentsMap!: IndexDocument;
    documents!: any[];

    constructor(rawData: any, parent: ContentDocument | undefined) {
        super(rawData, parent);
        if (rawData && rawData.apKey && rawData.spKey) {
            const ap = HDKey.parseExtendedKey(rawData.apKey);
            const sp = HDKey.parseExtendedKey(rawData.spKey);
            this.setKeys(ap, sp);
        }
    }

    override setKeys(ap: HDKey, sp: HDKey): boolean {

        const resetKeys = super.setKeys(ap, sp);

        if (resetKeys) {

            this.documents = [] as any[];  //TODO: need new document type
        }

        return resetKeys;
    }

    static override get default() {
        return new PostDocument(undefined, undefined);
    }

    get posterName() {
        if (this.thread) {
            if (this.thread.p && this.thread.p.name) {
                return this.thread.p.name;
            } else {
                return 'Anonymous-' + this.thread.displayAddress;
            }
        } else {
            return 'undefined - error';
        }
    }

    get posterAddress() {
        if (this.thread) {
            return this.thread.a;
        } else {
            return undefined;
        }
    }

    override toDataDocument(): any {
        const dd = super.toDataDocument() as any;
        return dd;
    }

    override toSaveTip(): PostDocument {
        const savetip = super.toSaveTip() as any;
        if (this.parent) {
            savetip.pa = this.parent.a;
        }
        return Object.assign(PostDocument.default, savetip);
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
