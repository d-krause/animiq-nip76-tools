/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as nostrTools from 'nostr-tools';
import { nprivateChannelEncode, PrivateChannelPointer } from '../../nostr-tools/nip19-extension';
import { Bip32NetworkInfo, HDKey, Versions, HDKIndex, HDKIndexType } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { PostDocument } from './PostDocument';

export interface IChannelPayload extends ContentTemplate {

    name?: string;
    about?: string;
    picture?: string;
    last_known_index: number;
    chain_sign?: string;
    chain_crypto?: string;
}

export class PrivateChannel extends ContentDocument {
    override isTopLevel = true;
    override content!: IChannelPayload;
    hdkIndex!: HDKIndex;
    posts = [] as PostDocument[];

    static fromPointer(pointer: PrivateChannelPointer, publishParent: HDKey): PrivateChannel {
        const signingKey = new HDKey({ publicKey: pointer.signingKey, chainCode: new Uint8Array(32), version: Versions.nip76API1 });
        const cryptoKey = new HDKey({ publicKey: pointer.cryptoKey, chainCode: new Uint8Array(32), version: Versions.nip76API1 });
        const channel = new PrivateChannel();
        channel.ownerPubKey = pointer.ownerPubKey;
        channel.hdkIndex = new HDKIndex(HDKIndexType.TimeBased, signingKey, cryptoKey, publishParent);
        channel.content = {
            kind: nostrTools.Kind.ChannelMetadata,
            pubkey: pointer.ownerPubKey,
            last_known_index: 0
        };
        return channel;
    }
    override get payload(): any[] {
        this.content.chain_sign = this.hdkIndex.signingParent.hexChainCode;
        this.content.chain_crypto = this.hdkIndex.cryptoParent.hexChainCode;
        return [
            ...super.payload,
            this.content.name,
            this.content.about,
            this.content.picture,
            this.content.last_known_index,
            this.content.chain_sign,
            this.content.chain_crypto,
        ];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.name = raw[4];
        this.content.about = raw[5];
        this.content.picture = raw[6];
        this.content.last_known_index = raw[7];
        this.content.chain_sign = raw[8];
        this.content.chain_crypto = raw[9];
        return raw;
    }

    async getChannelPointer(secret: string | Uint8Array[] = ''): Promise<string> {
        return nprivateChannelEncode({
            ownerPubKey: this.ownerPubKey,
            signingKey: this.hdkIndex.signingParent.publicKey,
            cryptoKey: this.hdkIndex.cryptoParent.publicKey,
        }, secret);
    }
}
