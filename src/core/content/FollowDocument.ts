/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { HDKey } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { PrivateChannel } from './PrivateChannel';

export interface IFollowPayload extends ContentTemplate {
    owner: string;
    signing_key: string;
    crypto_key: string;
}

export class FollowDocument extends ContentDocument {
    override content!: IFollowPayload;
    channel!: PrivateChannel;

    override get payload(): any[] {
        return [
            ...super.payload, 
            this.content.owner, 
            this.content.signing_key,
            this.content.crypto_key
        ];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.owner = raw[4];
        this.content.signing_key = raw[5];
        this.content.crypto_key = raw[6];
        return raw;
    }
}
