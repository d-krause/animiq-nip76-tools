/*
 * Copyright Kepler Group, Inc. - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * The contents of this file are considered proprietary and confidential.
 * Written by Dave Krause <dkrause@keplergroupsystems.com>, February 2019
 */
import { ContentDocument } from './ContentDocument';
import { IndexDocument, IndexPermission } from './IndexDocument';
import { HDKey } from '../keys';
import { ProfileDocument } from './ProfileDocument';

export class PostDocument extends ContentDocument {
    override p!: IPostPayload;
    profile!: ProfileDocument;
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
        if (this.profile) {
            if (this.profile.p && this.profile.p.name) {
                return this.profile.p.name;
            } else {
                return 'Anonymous-' + this.profile.displayAddress;
            }
        } else {
            return 'undefined - error';
        }
    }

    get posterAddress() {
        if (this.profile) {
            return this.profile.a;
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
