
import { HDKey } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';

export interface IKeysetPayload extends ContentTemplate {
    signingParent: HDKey;
    cryptoParent: HDKey
}

export class Keyset extends ContentDocument {
    override content!: IKeysetPayload;
    override get payload(): any[] {
        return [
            ...super.payload,
            [
                this.content.signingParent.extendedPublicKey,
                this.content.cryptoParent.extendedPublicKey,
            ]
        ];
    }
    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.signingParent = HDKey.parseExtendedKey(raw[1][0]);
        this.content.cryptoParent = HDKey.parseExtendedKey(raw[1][1]);
        return raw;
    }
}