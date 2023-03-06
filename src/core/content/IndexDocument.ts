/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { Buffer } from 'buffer';
import { ContentDocument } from './ContentDocument';
import { HDKey, HDKissAddress as Address, HDKissDocumentType as ContentDocumentType } from '../keys';

export class IndexDocument extends ContentDocument {
    override p = null as any as IIndexPayload;
    m?: IIndexInfo;

    constructor(rawData: any, parent: ContentDocument) {
        super(rawData, parent);
        if (this.p) {
            if (this.p.ap) {
                this.ap = HDKey.parseExtendedKey(this.p.ap);
                this.address = Address.from(this.ap.publicKey, ContentDocumentType.Index, this.ap.version);
                this.a = this.address.value;
            }
            if (this.p.sp) {
                this.sp = HDKey.parseExtendedKey(this.p.sp);
            }
        }
    }

    static override get default() {
        return new IndexDocument(undefined as any, undefined as any as ContentDocument);
    }

    static createIndex(name: string, type: ContentDocumentType, permission: IndexPermission, ap: HDKey, sp?: HDKey): IndexDocument {
        const rtn = IndexDocument.default;
        if (ap) {
            rtn.address = Address.from(ap.publicKey, ContentDocumentType.Index, ap.version);
            rtn.a = rtn.address.value;
        }
        rtn.ap = ap;
        if(sp) rtn.sp = sp;
        rtn.p = {
            name: name,
            type: type,
            permission: permission,
            ap: rtn.ap ? rtn.ap.extendedPublicKey : undefined,
            sp: rtn.sp ? rtn.sp.extendedPublicKey : undefined
        } as IIndexPayload;

        return rtn;
    }

    get type(): ContentDocumentType {
        return this.p.type; // as ContentDocumentType;
    }

    get permission(): IndexPermission {
        return this.p.permission; // as IndexPermission;
    }

    private getEncryptionKeys(doc: ContentDocument): EncryptionKeys {
        if (this.type === ContentDocumentType.Profile) {
            const nonce = Buffer.from(doc.n, 'hex');
            const keyIndexes = [Math.abs(nonce.readInt32BE(0)), Math.abs(nonce.readInt32BE(8))];
            const sp = this.sp.derive(`${keyIndexes[0]}/${keyIndexes[1]}`);
            return { address: Address.from(this.ap.publicKey, this.type, this.ap.version), secret: sp.publicKey };
        } else {
            if (doc.pending) {
                const nonce = Buffer.from(doc.n, 'hex');
                const keyIndexes = [Math.abs(nonce.readInt32BE(0)), Math.abs(nonce.readInt32BE(8))];
                const sp = this.sp.derive(`${keyIndexes[0]}/${keyIndexes[1]}`);
                return { address: Address.from(this.ap.publicKey, this.type, this.ap.version), secret: sp.publicKey };
            } else if (doc.indexIsValid) {
                const ap = this.ap.deriveChildKey(doc.i);
                const sp = this.sp.deriveChildKey(doc.i);
                return { address: Address.from(ap.publicKey, this.type, ap.version), secret: sp.publicKey };
            } else {
                throw new Error('IndexDocument.getEncryptionKeys)() error - document needs a valid i value to derive an ap and sp.');
            }
        }
    }

    decrypt(doc: ContentDocument): void {

        if (!doc.e) { return; }
        const keys = this.getEncryptionKeys(doc);
        const errorTemplate = `decrypt(address=${doc.a},index=${doc.i}).`;
        let decrypted: string;

        try {
            decrypted = keys.address.decrypt(doc.e, keys.secret, doc.v);
        } catch (ex) {
            doc.error = { message: 'address.decrypt(doc.v="' + doc.v + '"):' + ex + ':' + errorTemplate };
            return;
        }
        try {
            doc.p = JSON.parse(decrypted);
        } catch (ex) {
            doc.error = { message: 'JSON.parse"' + decrypted + '"):' + ex + ':' + errorTemplate };
            return;
        }
        if (!doc.p || (Object.keys(doc.p).length === 0 && doc.p.constructor === Object)) {
            doc.error = { message: 'Empty doc.p:decrypted="' + decrypted + '":' + errorTemplate };
        }
    }

    encrypt(doc: ContentDocument, deleteClearText = true): void {

        const keys = this.getEncryptionKeys(doc);
        const errorTemplate = `encrypt(address=${doc.a},index=${doc.i}).`;

        if (!doc.e || (Object.keys(doc.e).length === 0 && doc.e.constructor === Object)) {
            delete doc.e;
        }
        if (!doc.p || (Object.keys(doc.p).length === 0 && doc.p.constructor === Object)) {
            delete doc.p;
        } else {
            const ptype = typeof doc.p;
            let message: string | undefined = undefined;
            switch (ptype) {
                case 'string':
                    message = doc.p;
                    break;
                case 'object':
                    if(doc.p.attachments?.data[0]?.ogImageBytes) {
                        message = doc.p.attachments.data[0].ogImageBytes;
                    } else {
                        message = JSON.stringify(doc.p);
                    }
                    break;
            }
            if (message !== undefined) {
                doc.e = keys.address.encrypt(message, keys.secret, doc.v);
                if (deleteClearText) {
                    delete doc.p;
                }
            } else {
                doc.error = { message: 'value e on the record has an unexpected type "' + ptype + '":' + errorTemplate };
            }
        }
    }

    override toDataDocument() {
        const dd = super.toDataDocument(true) as any;
        if (this.m) { dd.m = this.m; }
        return dd;
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
