/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as nostrTools from 'nostr-tools';
import { nprivateThreadEncode, PrivateThreadPointer } from '../../nostr-tools/nip19-extension';
import { Bip32NetworkInfo, HDKey, Versions } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { IndexDocument, IndexPermission } from './IndexDocument';
import { PostDocument } from './PostDocument';

export interface ThreadKeySet {
    ver: Bip32NetworkInfo;
    ap: HDKey;
    sp: HDKey;
}

export class ThreadIndexMap {
    post!: IndexDocument;
    following!: IndexDocument;
}

export interface IThreadPayload extends ContentTemplate {

    name?: string;
    about?: string;
    picture?: string;
    last_known_index: number;
}

export class PrivateThread extends ContentDocument {

    override content!: IThreadPayload;
    override index = 0;
    indexMap = new ThreadIndexMap();
    posts = [] as PostDocument[];
    following = [] as PrivateThread[];

    static fromPointer(pointer: PrivateThreadPointer): PrivateThread {
        const ap = new HDKey({ publicKey: pointer.addresses.pubkey, chainCode: pointer.addresses.chain, version: Versions.nip76API1 });
        const sp = new HDKey({ publicKey: pointer.secrets.pubkey, chainCode: pointer.secrets.chain, version: Versions.nip76API1 });
        const thread = new PrivateThread();
        thread.ownerPubKey = pointer.ownerPubKey;
        thread.indexMap = new ThreadIndexMap();
        thread.indexMap.post = IndexDocument.createIndex(
            IndexPermission.CreateByOwner,
            ap,
            sp);
        thread.setKeys(
            thread.indexMap.post.ap.deriveChildKey(thread.index),
            thread.indexMap.post.sp.deriveChildKey(thread.index)
        );
        thread.content = {
            kind: nostrTools.Kind.ChannelMetadata,
            pubkey: pointer.ownerPubKey,
            sig: '',
            tags: [],
            last_known_index: 0
        };
        return thread;
    }
    override get payload(): any[] {
        return [
            ...super.payload, 
            this.content.name,
            this.content.about,
            this.content.picture,
            this.content.last_known_index,
        ];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.name = raw[4];
        this.content.about = raw[5];
        this.content.picture = raw[6];
        this.content.last_known_index = raw[7];
        return raw;
    }

    setOwnerKeys(ap: HDKey, sp: HDKey) {
        if (!ap.privateKey) {
            throw new Error('ap.privateKey needed to setOwnerKeys.')
        }
        this.indexMap = new ThreadIndexMap();
        this.indexMap.post = IndexDocument.createIndex(
            IndexPermission.CreateByOwner,
            ap.deriveChildKey(1001, true),
            sp.deriveChildKey(1001, true)
        );
        this.indexMap.following = IndexDocument.createIndex(
            IndexPermission.CreateByOwner,
            ap.deriveChildKey(7001, true),
            sp.deriveChildKey(7001, true)
        );

        super.setKeys(
            this.indexMap.post.ap.deriveChildKey(this.index),
            this.indexMap.post.sp.deriveChildKey(this.index)
        )
    }

    async getThreadPointer(secret: string | Uint8Array[] = ''): Promise<string> {
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

    getRelayFilter(startIndex = 0, length = 20): nostrTools.Filter[] {
        const filters: nostrTools.Filter[] = [];
        const postPubKeys: string[] = [];
        const replyTags: string[] = [];
        postPubKeys.push(this.ap.nostrPubKey);
        if (startIndex === 0) startIndex = 1;
        for (let i = startIndex + length; i >= startIndex; i--) {
            const ap = this.indexMap.post.ap.deriveChildKey(i);
            const sp = this.indexMap.post.sp.deriveChildKey(i);
            const post = new PostDocument();
            post.setKeys(ap, sp);
            post.index = i;
            post.ownerPubKey = this.ownerPubKey;
            this.posts.push(post);
            postPubKeys.push(post.ap.nostrPubKey);
            replyTags.push(post.rp.nostrPubKey);
        }
        filters.push({
            authors: postPubKeys,
            kinds: [17761],
            limit: length
        });

        filters.push({
            '#e': replyTags,
            kinds: [17761],
            limit: length
        });
        return filters;
    }
}
