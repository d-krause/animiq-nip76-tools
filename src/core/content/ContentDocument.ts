/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
// re: Buffer - vscode pretends it doesn't need this Buffer import, but tsc complains when building
import { Buffer } from 'buffer';
import { HDKissAddress as Address, HDKey } from '../keys';

/**
 * raw content database document
 */
export interface IDataDocument {
    /**
     * timestamp
     */
    t: number;
    /**
     * unencrypted payload
     */
    p: any;
    /**
     * encrypted payload
     */
    e?: any;
    /**
     * version
     */
    v: number;
    /**
     * nonce
     */
    n: string;
    /**
     * hash of payload
     */
    h: string;
    /**
     * signature
     */
    s: string;
    /**
     * owner of reservation waiting for final update
     */
    pending: string;
}

/**
 * client only content fields, properties and methods
 */
export class ContentDocument implements IDataDocument {
    t!: number;
    p: any;
    e?: any;
    v!: number;
    n!: string;
    h!: string;
    s!: string;

    /**
     * address
     */
    a!: string;
    /**
     * index of the address on the keychain
     */
    i!: number;
    /**
     * error object - maybe defined more later
     */
    error: any;
    address!: Address;
    parent: ContentDocument | undefined;
    ap!: HDKey;
    sp!: HDKey;
    pending = '';

    constructor(rawData: any, parent: ContentDocument | undefined) {
        if (rawData) {
            Object.assign(this, rawData);
        }
        if(parent) this.parent = parent;
    }

    static get default() {
        return new ContentDocument(undefined, undefined as any as ContentDocument);
    }

    setKeys(ap: HDKey, sp: HDKey): boolean {
        const keysReset = (ap && sp) && (!this.ap || !this.sp);
        if (keysReset) {
            this.ap = ap;
            this.sp = sp;
        }
        return keysReset;
    }

    get formattedAddress() {
        return Address.formatAddress(this.a);
    }

    get displayAddress() {
        return Address.formatAddress(this.a, true);
    }

    get datetime(): Date {
        return new Date(this.t);
    }

    get indexIsValid(): boolean {
        return this.i !== null && this.i !== undefined && !isNaN(this.i) && this.i >= 0 && this.i < HDKey.hardenedKeyOffset;
    }

    toDataDocument(includeP = false): IDataDocument {
        const dd = {} as IDataDocument;
        if (this.v !== undefined) { dd.v = this.v; }
        if (this.n !== undefined) { dd.n = this.n; }
        if (this.s !== undefined) { dd.s = this.s; }
        if (this.h !== undefined) { dd.h = this.h; }
        if (includeP && this.p !== undefined) { dd.p = this.p; }
        if (this.e !== undefined) { dd.e = this.e; }
        if (this.t !== undefined) { dd.t = this.t; }
        if (this.pending) { dd.pending = this.pending; }
        return dd;
    }

    toSaveTip(): ContentDocument {
        const cd = ContentDocument.default;
        if (this.v !== undefined) { cd.v = this.v; }
        if (this.a !== undefined) { cd.a = this.a; }
        if (this.n !== undefined) { cd.n = this.n; }
        if (this.i !== undefined) { cd.i = this.i; }
        if (this.s !== undefined) { cd.s = this.s; }
        if (this.h !== undefined) { cd.h = this.h; }
        if (this.p !== undefined) { cd.p = this.p; }
        if (this.e !== undefined) { cd.e = this.e; }
        if (this.t !== undefined) { cd.t = this.t; }
        if (this.pending) { cd.pending = this.pending; }
        return cd;
    }
}

export interface IDocumentConstructor { new(rawData: any, parent: ContentDocument | undefined): ContentDocument; }
