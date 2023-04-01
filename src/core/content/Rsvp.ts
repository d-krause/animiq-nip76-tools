
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { nip19Extension } from '../../nostr-tools';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { PrivateChannel } from './PrivateChannel';

export interface IRsvpPayload extends ContentTemplate {
    type: nip19Extension.PointerType;
    pointerDocIndex: number;
    signingKey?: Uint8Array;
    cryptoKey?: Uint8Array;
}

export class Rsvp extends ContentDocument {

    pointer!: nip19Extension.PrivateChannelPointer;
    channel?: PrivateChannel;

    override content!: IRsvpPayload;
    override get payload(): any[] {
        return [
            ...super.payload,
            [
                this.content.type,
                this.content.pointerDocIndex,
                this.content.signingKey ? bytesToHex(this.content.signingKey) : null,
                this.content.cryptoKey ? bytesToHex(this.content.cryptoKey) : null,
            ]
        ];
    }
    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.type = raw[1][0];
        this.content.pointerDocIndex = raw[1][1];
        this.content.signingKey = raw[1][2] ? hexToBytes(raw[1][2]) : undefined;
        this.content.cryptoKey = raw[1][3] ? hexToBytes(raw[1][3]) : undefined;
        return raw;
    }
}