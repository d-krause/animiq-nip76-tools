/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { Buffer } from 'buffer';
import { ContentDocument } from './ContentDocument';
import { IndexDocument, IndexPermission } from './IndexDocument';
import { PostDocument } from './PostDocument';
import { HDKey, HDKissAddress as Address, HDKissDocumentType as ContentDocumentType, Bip32NetworkInfo, Versions } from '../keys';
import { nprivateThreadEncode, PrivateThreadPointer } from '../../nostr-tools/nip19-extension';

export interface ThreadKeySet {
    ver: Bip32NetworkInfo;
    pp: HDKey;
    ap: HDKey;
    sp: HDKey;
}

export class ThreadIndexMap {
    post!: IndexDocument;
    following!: IndexDocument;
}

export interface IThreadPayload {

    name?: string;
    pic?: string;
    description?: string;
    is_public?: boolean;
    created_at?: number
    last_known_index: number;
}

export class PrivateThread extends ContentDocument {

    static override get default() {
        return new PrivateThread(undefined, undefined);
    }

    override p!: IThreadPayload;
    ownerPubKey!: string;
    pp!: HDKey;
    ready = false;
    indexMap = new ThreadIndexMap();
    posts = [] as PostDocument[];
    following = [] as PrivateThread[];

    static fromPointer(pointer: PrivateThreadPointer): PrivateThread {
        const ap = new HDKey({ publicKey: pointer.addresses.pubkey, chainCode: pointer.addresses.chain, version: Versions.animiqAPI3 });
        const sp = new HDKey({ publicKey: pointer.secrets.pubkey, chainCode: pointer.secrets.chain, version: Versions.animiqAPI3 });
        const thread = PrivateThread.default;
        thread.ownerPubKey = pointer.ownerPubKey;
        thread.indexMap = new ThreadIndexMap();
        thread.indexMap.post = IndexDocument.createIndex(
            'Post',
            ContentDocumentType.Post,
            IndexPermission.CreateByOwner,
            ap,
            sp);
        thread.ap = ap;
        thread.sp = sp;
        thread.v = 3;
        thread.address = Address.from(ap.publicKey, ContentDocumentType.Profile, ap.version);
        thread.a = thread.address.value;
        thread.p = {
            last_known_index: 0
        };
        return thread;
    }

    override setKeys(ap: HDKey, sp: HDKey) {

        const resetKeys = super.setKeys(ap, sp);
        if (resetKeys) {

            this.indexMap = new ThreadIndexMap();

            this.indexMap.post = IndexDocument.createIndex(
                'Post',
                ContentDocumentType.Post,
                IndexPermission.CreateByOwner,
                this.ap.deriveChildKey(1001, true),
                this.sp.deriveChildKey(1001, true)
            );
            this.indexMap.following = IndexDocument.createIndex(
                'Follow',
                ContentDocumentType.Follow,
                IndexPermission.CreateByOwner,
                this.ap.deriveChildKey(7001, true),
                this.sp.deriveChildKey(7001, true)
            );

            this.address = Address.from(this.indexMap.post.ap.publicKey, ContentDocumentType.Profile, ap.version);
            this.a = this.address.value;

            this.posts = [] as PostDocument[];
        }
        return resetKeys;
    }

    getThreadPointer(secret: string | Buffer[] = ''): string {
        return nprivateThreadEncode({
            ownerPubKey: this.ownerPubKey,
            addresses: {
                pubkey: this.indexMap.post.ap.publicKey,
                chain: this.indexMap.post.ap.chainCode
            },
            secrets: {
                pubkey: this.indexMap.post.sp.publicKey,
                chain: this.indexMap.post.sp.chainCode
            }
        }, secret);
    }

    override toSaveTip(): PrivateThread {
        const saveTip = super.toSaveTip() as any;
        saveTip.pp = this.pp ? this.pp.extendedPublicKey : undefined;
        // if (this.isPublic === true && this.indexMap.post) {
        //     saveTip.indexes = {
        //         post: this.indexMap.post.toSaveTip()
        //     };
        // }
        return saveTip;
    }

    override toDataDocument() {
        const dd = super.toDataDocument() as any;
        dd.pp = this.pp ? this.pp.extendedPublicKey : undefined;
        // if (this.isPublic === true && this.indexMap.post) {
        //     dd.ix = {
        //         post: this.indexMap.post.a
        //     };
        // }
        return dd;
    }
}
