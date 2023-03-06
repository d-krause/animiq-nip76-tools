/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { Buffer } from 'buffer';
import { ContentDocument } from './ContentDocument';
import { IndexDocument, IndexPermission } from './IndexDocument';
import { PostDocument } from './PostDocument';
import { HDKey, HDKissAddress as Address, HDKissDocumentType as ContentDocumentType, Bip32NetworkInfo } from '../keys';
import { nsecthreadEncode, SecureThreadPointer } from '../../nostr-tools/nip19-extension';

export interface ThreadKeySet {
    ver: Bip32NetworkInfo;
    pp: HDKey;
    ap: HDKey;
    sp: HDKey;
}

export class ThreadIndexMap {
    post!: IndexDocument;
    follow!: IndexDocument;
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
    signingParent!: HDKey;
    isPublic!: boolean;
    ready = false;
    indexMap = new ThreadIndexMap();
    posts = [] as PostDocument[];

    constructor(rawData: any, parent: ContentDocument | undefined) {
        super(rawData, parent);
        if (rawData) {
            if (rawData.indexes) {
                this.indexMap.post = new IndexDocument(rawData.indexes.post, this);
            }
            if (rawData.pp) {
                this.setProfileKey(HDKey.parseExtendedKey(rawData.pp));
            }
        }
    }

    get keyset(): ThreadKeySet {
        return {
            pp: this.pp, ap: this.ap, sp: this.sp, ver: this.pp.version
        } as ThreadKeySet;
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

            this.indexMap = new ThreadIndexMap();

            this.indexMap.post = IndexDocument.createIndex(
                'Post',
                ContentDocumentType.Post,
                IndexPermission.CreateByOwner,
                this.ap.deriveChildKey(1001, true),
                this.sp.deriveChildKey(1001, true)
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

    override toSaveTip(): PrivateThread {
        const saveTip = super.toSaveTip() as any;
        saveTip.pp = this.pp ? this.pp.extendedPublicKey : undefined;
        if (this.isPublic === true && this.indexMap.post) {
            saveTip.indexes = {
                post: this.indexMap.post.toSaveTip()
            };
        }
        return saveTip;
    }

    override toDataDocument() {
        const dd = super.toDataDocument() as any;
        dd.pp = this.pp ? this.pp.extendedPublicKey : undefined;
        if (this.isPublic === true && this.indexMap.post) {
            dd.ix = {
                post: this.indexMap.post.a
            };
        }
        return dd;
    }

    get thread(): string {
        return nsecthreadEncode({
            version: 3,
            addresses: {
                pubkey: this.indexMap.post.ap.publicKey.toString('hex'),
                chain: this.indexMap.post.ap.chainCode.toString('hex')
            },
            secrets: {
                pubkey: this.indexMap.post.sp.publicKey.toString('hex'),
                chain: this.indexMap.post.sp.chainCode.toString('hex')
            }
        });
    }
}
