/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import * as nostrTools from 'nostr-tools';
import { nprivateChannelEncode, PrivateChannelPointer } from '../../nostr-tools/nip19-extension';
import { HDKey, HDKIndex, HDKIndexType, Versions } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { Invitation } from './Invitation';
import { PostDocument } from './PostDocument';
import { Rsvp } from './Rsvp';

export interface IChannelPayload extends ContentTemplate {

    name?: string;
    about?: string;
    picture?: string;
    relays?: string[];
}

export class PrivateChannel extends ContentDocument {
    override content!: IChannelPayload;
    dkxPost: HDKIndex;
    dkxRsvp: HDKIndex;
    dkxInvite!: HDKIndex;
    invitation!: Invitation;

    constructor(signingKey: HDKey, cryptoKey: HDKey, existing?: PrivateChannel) {
        super();
        this.dkxPost = new HDKIndex(HDKIndexType.TimeBased, signingKey, cryptoKey);
        this.dkxRsvp = new HDKIndex(
            HDKIndexType.TimeBased,
            signingKey.deriveChildKey(0).deriveChildKey(0),
            cryptoKey.deriveChildKey(0).deriveChildKey(0)
        );
        if (signingKey.privateKey) {
            this.dkxInvite = new HDKIndex(HDKIndexType.Sequential | HDKIndexType.Private, signingKey, cryptoKey);
        }
        if (existing) {
            // we just reloaded after editing, keeping the same documents arrays
            this.dkxPost.documents = existing.dkxPost.documents;
            this.dkxRsvp.documents = existing.dkxRsvp.documents;
            if (this.dkxInvite && existing.dkxInvite) {
                this.dkxInvite.documents = existing.dkxInvite.documents;
            }
        }
    }

    get posts(): PostDocument[] {
        return (this.dkxPost.documents as PostDocument[]).filter(x => !x.ref && x.content.kind === nostrTools.Kind.Text);
    }

    get invites(): Invitation[] {
        const foo = (this.dkxInvite.documents as Invitation[]).map(invite => {
            invite.rsvps = this.rsvps.filter(x => x.content.pointerDocIndex === invite.docIndex);
            return invite;
        });
        // console.log(foo)
        return foo;
    }

    get rsvps(): Rsvp[] {
        return this.dkxRsvp.documents as Rsvp[];
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
}
