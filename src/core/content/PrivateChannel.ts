/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as nostrTools from 'nostr-tools';
import { nprivateChannelEncode, PrivateChannelPointer } from '../../nostr-tools/nip19-extension';
import { HDKey, HDKIndex, HDKIndexType, Versions } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { PostDocument } from './PostDocument';

export interface IChannelPayload extends ContentTemplate {

    name?: string;
    about?: string;
    picture?: string;
    relays?: string[];
}

export class PrivateChannel extends ContentDocument {
    override content!: IChannelPayload;

    get posts(): PostDocument[] {
        return (this.hdkIndex.documents as PostDocument[]).filter(x => !x.ref && x.content.kind === nostrTools.Kind.Text);
    }

    static fromPointer(pointer: PrivateChannelPointer): PrivateChannel {
        const signingKey = new HDKey({ publicKey: pointer.signingKey, chainCode: new Uint8Array(32), version: Versions.nip76API1 });
        const cryptoKey = new HDKey({ publicKey: pointer.cryptoKey, chainCode: new Uint8Array(32), version: Versions.nip76API1 });
        const channel = new PrivateChannel();
        // channel.ownerPubKey = pointer.ownerPubKey;
        channel.hdkIndex = new HDKIndex(HDKIndexType.TimeBased, signingKey, cryptoKey);
        channel.content = {
            kind: nostrTools.Kind.ChannelMetadata,
            pubkey: '',
        };
        return channel;
    }

    override get payload(): any[] {
        return [
            ...super.payload,
            [
                this.content.name,
                this.content.about,
                this.content.picture,
                this.content.relays
            ]
        ];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.name = raw[1][0];
        this.content.about = raw[1][1];
        this.content.picture = raw[1][2];
        this.content.relays = raw[1][3];
        return raw;
    }

    async getChannelPointer(secret: string | Uint8Array[] = ''): Promise<string> {
        return nprivateChannelEncode({
            type: 0,
            signingKey: this.hdkIndex.signingParent.publicKey,
            cryptoKey: this.hdkIndex.cryptoParent.publicKey,
            relays: this.content.relays
        }, secret);
    }
}
