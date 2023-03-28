
import { hexToBytes } from '@noble/hashes/utils';
import { nprivateChannelEncode } from '../../nostr-tools/nip19-extension';
import { HDKey } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';

export interface IInvitationPayload extends ContentTemplate {
    for?: string;
    password?: string;
    signingParent: HDKey;
    cryptoParent: HDKey;
}

export class Invitation extends ContentDocument {
    override content!: IInvitationPayload;
    override get payload(): any[] {
        return [
            ...super.payload,
            [
                this.content.for,
                this.content.password,
                this.content.signingParent.extendedPublicKey,
                this.content.cryptoParent.extendedPublicKey,
            ]
        ];
    }
    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.for = raw[1][0];
        this.content.password = raw[1][1];
        this.content.signingParent = HDKey.parseExtendedKey(raw[1][2]);
        this.content.cryptoParent = HDKey.parseExtendedKey(raw[1][3]);
        return raw;
    }
    async getPointer(): Promise<string> {
        const keyset = this.dkxParent.getKeysFromIndex(this.docIndex);
        const secret: string | Uint8Array[] = this.content.password ? this.content.password
            : [hexToBytes(this.content.for!), keyset.signingKey?.privateKey!];
        return nprivateChannelEncode({
            type: 0,
            signingKey: keyset.signingKey!.publicKey,
            cryptoKey: keyset.cryptoKey.publicKey,
        }, secret);
    }
}