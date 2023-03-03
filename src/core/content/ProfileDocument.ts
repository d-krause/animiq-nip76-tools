/*
 * Copyright Kepler Group, Inc. - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * The contents of this file are considered proprietary and confidential.
 * Written by Dave Krause <dkrause@keplergroupsystems.com>, February 2019
 */
import { Buffer } from 'buffer';
import { ContentDocument } from './ContentDocument';
import { IndexDocument, IndexPermission } from './IndexDocument';
import { PostDocument } from './PostDocument';
import { HDKey, HDKissAddress as Address, HDKissDocumentType as ContentDocumentType, Bip32NetworkInfo } from '../keys';

export interface ProfileKeySet {
    ver: Bip32NetworkInfo;
    pp: HDKey;
    ap: HDKey;
    sp: HDKey;
}

export class ProfileDocumentIndexMap {
    profile!: IndexDocument;
    post!: IndexDocument;
    follow!: IndexDocument;
    get canRead() {
        return !!this.profile && !!this.post;
    }
}

export interface IProfilePayload {

    name?: string;
    pic?: string;
    message?: string;
    link?: string;
    is_public: boolean;
    /**
     * API version 2 and under ONLY!
     */
    ex_pub_key?: string;
}

export class ProfileDocument extends ContentDocument {

    static override get default() {
        return new ProfileDocument(undefined, undefined);
    }

    static readonly emptyProfile = Object.assign(ProfileDocument.default, {
        a: 'AQ000000000000000000000000000000000000000',
        p: {
            name: 'Loading ...',
            message: '',
        }
    });

    override p!: IProfilePayload;
    pp!: HDKey;
    signingParent!: HDKey;
    iqon!: string;
    isPublic!: boolean;
    isGuest!: boolean;
    isLegacyProfile!: boolean;
    ready = false;
    indexMap = new ProfileDocumentIndexMap();
    posts = [] as PostDocument[];
    notifInterval: any;

    constructor(rawData: any, parent: ContentDocument | undefined) {
        super(rawData, parent);
        if (rawData) {
            if (rawData.indexes) {
                this.indexMap.profile = new IndexDocument(rawData.indexes.profile, this);
                this.indexMap.post = new IndexDocument(rawData.indexes.post, this);
            }
            if (rawData.pp) {
                this.setProfileKey(HDKey.parseExtendedKey(rawData.pp));
            }
        }
    }


    get keyset(): ProfileKeySet {
        return {
            pp: this.pp, ap: this.ap, sp: this.sp, ver: this.pp.version
        } as ProfileKeySet;
    }

    get isEmpty() {
        return this.a === ProfileDocument.emptyProfile.a;
    }

    setProfileKey(pp: HDKey) {
        this.pp = pp;
        this.address = Address.from(this.pp.publicKey, ContentDocumentType.Profile, this.pp.version);
        this.a = this.address.value;
        this.signingParent = pp.deriveChildKey(101);
    }

    override setKeys(ap: HDKey, sp: HDKey) {

        const resetKeys = super.setKeys(ap, sp);
        if (resetKeys) {

            this.indexMap = new ProfileDocumentIndexMap();

            this.indexMap.profile = IndexDocument.createIndex(
                'Profile',
                ContentDocumentType.Profile,
                IndexPermission.CreateByOwner,
                this.v > 2 ? this.pp : this.ap,
                this.v > 2 ? this.sp.deriveChildKey(201, true) : this.ap
            );

            this.indexMap.post = IndexDocument.createIndex(
                'Post',
                ContentDocumentType.Post,
                IndexPermission.CreateByOwner,
                this.v > 2 ? this.ap.deriveChildKey(1001, true) : this.ap.deriveChildKey(2),
                this.v > 2 ? this.sp.deriveChildKey(1001, true) : this.ap.deriveChildKey(3)
            );
            if (this.v > 2) {
                this.indexMap.follow = IndexDocument.createIndex(
                    'Follow',
                    ContentDocumentType.Follow,
                    IndexPermission.CreateByOwner,
                    this.ap.deriveChildKey(7001, true),
                    this.sp.deriveChildKey(7001, true)
                );
            }

            this.posts = [] as PostDocument[];
        }
        return resetKeys;
    }

    get canRead() {
        return this.pp !== undefined && this.ap !== undefined && this.sp !== undefined;
    }

    get canSign() {
        return this.canRead && this.pp.privateKey !== null;
    }

    verifyDocumentOwner(doc: ContentDocument): boolean {
        const nonce = Buffer.from(doc.n, 'hex');
        const signingIndexes = [Math.abs(nonce.readInt32BE(0)), Math.abs(nonce.readInt32BE(8))];
        if (doc instanceof IndexDocument) {
            if (!doc.ap || !doc.ap.publicKey) {
                throw new Error('Cannot verify ownership of an Index without an address parent public key (ap).');
            }
            const idx = doc; // as IndexDocument;
            const signingKey = idx.ap.derive(`${signingIndexes[0]}/${signingIndexes[1]}`);
            const message = `${doc.t}&${doc.h}&${this.address.value}&${doc.n}&${idx.a}`;
            const addr = Address.from(idx.ap.publicKey, ContentDocumentType.Index, idx.ap.version);
            return addr.value === idx.a && Address.verify(message, doc.s, signingKey.publicKey, this.v);
        } else {
            const signingKey = this.signingParent.derive(`${signingIndexes[0]}/${signingIndexes[1]}`);
            const message = `${doc.t}&${doc.h}&${this.address.value}&${doc.n}`;
            return Address.verify(message, doc.s, signingKey.publicKey, this.v);
        }
    }

    override toSaveTip(): ProfileDocument {
        const saveTip = super.toSaveTip() as any;
        saveTip.pp = this.pp ? this.pp.extendedPublicKey : undefined;
        if (this.isPublic === true && this.indexMap.profile && this.indexMap.post) {
            saveTip.indexes = {
                profile: this.indexMap.profile.toSaveTip(),
                post: this.indexMap.post.toSaveTip()
            };
        }
        return saveTip;
    }

    override toDataDocument() {
        const dd = super.toDataDocument() as any;
        dd.pp = this.pp ? this.pp.extendedPublicKey : undefined;
        if (this.isPublic === true && this.indexMap.profile && this.indexMap.post) {
            dd.ix = {
                profile: this.indexMap.profile.a,
                post: this.indexMap.post.a
            };
        }
        return dd;
    }
}
