
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { nip19Extension } from '../../nostr-tools';
import { nprivateChannelEncode, PrivateChannelPointer } from '../../nostr-tools/nip19-extension';
import { HDKey, Versions } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';

export interface IInvitationPayload extends ContentTemplate {
    for?: string;
    password?: string;
    docIndex: number;
    signingParent?: HDKey;
    cryptoParent?: HDKey;
}

export class Invitation extends ContentDocument {
    rsvps: Invitation[] = [];
    pointer!: nip19Extension.PrivateChannelPointer; 
    override content!: IInvitationPayload;
    override get payload(): any[] {
        return [
            ...super.payload,
            [
                this.content.for,
                this.content.password,
                this.content.signingParent?.extendedPublicKey,
                this.content.cryptoParent?.extendedPublicKey,
                this.content.docIndex
            ]
        ];
    }
    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.for = raw[1][0];
        this.content.password = raw[1][1];
        this.content.signingParent = raw[1][2] ? HDKey.parseExtendedKey(raw[1][2]) : undefined;
        this.content.cryptoParent = raw[1][3] ? HDKey.parseExtendedKey(raw[1][3]) : undefined;
        this.content.docIndex = raw[1][4];
        return raw;
    }
    async getPointer(): Promise<string> {
        const keyset = this.dkxParent.getKeysFromIndex(this.docIndex);
        if (this.content.for) {
            return nprivateChannelEncode({
                type: 0,
                docIndex: this.docIndex,
                signingKey: keyset.signingKey!.publicKey,
                cryptoKey: keyset.cryptoKey.publicKey,
            }, bytesToHex(this.dkxParent.signingParent.privateKey), this.content.for);
        } else {
            return nprivateChannelEncode({
                type: 0,
                docIndex: this.docIndex,
                signingKey: keyset.signingKey!.publicKey,
                cryptoKey: keyset.cryptoKey.publicKey,
            }, this.content.password!);
        }
    }
}