/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { Buffer } from 'buffer';
import { ContentDocument } from './ContentDocument';
import { HDKey, HDKissAddress as Address, HDKissDocumentType as ContentDocumentType } from '../keys';

export class IndexDocument extends ContentDocument {
    override decryptedContent!: IIndexPayload;
    m?: IIndexInfo;

    static createIndex(name: string, type: ContentDocumentType, permission: IndexPermission, ap: HDKey, sp?: HDKey): IndexDocument {
        const rtn = new IndexDocument();
        if (ap) {
            rtn.address = Address.from(ap.publicKey, ContentDocumentType.Index, ap.version);
            rtn.a = rtn.address.value;
        }
        rtn.ap = ap;
        if(sp) rtn.sp = sp;
        rtn.decryptedContent = {
            name: name,
            type: type,
            permission: permission,
            ap: rtn.ap?.extendedPublicKey,
            sp: rtn.sp?.extendedPublicKey
        } as IIndexPayload;

        return rtn;
    }
}

export interface EncryptionKeys {
    address: Address;
    secret: Buffer;
}

export interface IIndexPayload {
    name: string;
    type: ContentDocumentType;
    ap: string;
    sp: string;
    permission: IndexPermission;
}

export enum IndexPermission {
    /**
     * Anyone who can can create a document on this index.
     */
    CreateByPublic = 1,
    /**
     * Anyone listed in the group can create a document on this index.
     */
    CreateByGroupMember = 2,
    /**
     * TBD - perhaps anyone with a password can create a document on this index.
     */
    CreateByCustom = 4,
    /**
     * Only the owner can create a document on this index.
     */
    CreateByOwner = 8,
}

export interface IIndexInfo {
    lastId: number;
    updated: number;
    skipped: number[];
}
