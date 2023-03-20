/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { HDKey } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { PrivateChannel } from './PrivateChannel';

export interface IFollowPayload extends ContentTemplate {
    owner: string;
    ap: HDKey;
    sp: HDKey;
}

export class FollowDocument extends ContentDocument {
    override content!: IFollowPayload;
    channel!: PrivateChannel;

    override get payload(): any[] {
        return [
            ...super.payload, 
            this.content.owner, 
            this.content.ap?.extendedPublicKey,
            this.content.sp?.extendedPublicKey
        ];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.owner = raw[4];
        this.content.ap = HDKey.parseExtendedKey(raw[5]);
        this.content.sp = HDKey.parseExtendedKey(raw[6]);
        return raw;
    }
}
