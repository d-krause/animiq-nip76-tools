/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { HDKey, HDKIndex, HDKIndexType } from '../keys';
import { ContentDocument, ContentTemplate } from './ContentDocument';
import { Invitation } from './Invitation';
import { PostDocument } from './PostDocument';
import { Rsvp } from './Rsvp';

export interface IChannelPayload extends ContentTemplate {

    name?: string;
    about?: string;
    picture?: string;
    created_at: number;
}

export class PrivateChannel extends ContentDocument {
    override content!: IChannelPayload;
    dkxPost!: HDKIndex;
    dkxRsvp!: HDKIndex;
    dkxInvite!: HDKIndex;
    invitation!: Invitation;

    setIndexKeys(signingKey: HDKey, cryptoKey: HDKey, existing?: PrivateChannel) {
        this.dkxPost = new HDKIndex(HDKIndexType.TimeBased, signingKey, cryptoKey);
        this.dkxPost.parentDocument = this;
        this.dkxRsvp = new HDKIndex(
            HDKIndexType.TimeBased,
            signingKey.deriveChildKey(0).deriveChildKey(0),
            cryptoKey.deriveChildKey(0).deriveChildKey(0)
        );
        this.dkxRsvp.parentDocument = this;
        if (signingKey.privateKey && cryptoKey.privateKey) {
            this.dkxInvite = new HDKIndex(HDKIndexType.Sequential | HDKIndexType.Private, signingKey, cryptoKey);
            this.dkxInvite.parentDocument = this;
        }
        if (existing) {
            // we just reloaded after editing, keeping the same documents arrays
            this.dkxPost.documents = existing.dkxPost.documents;
            this.dkxRsvp.documents = existing.dkxRsvp.documents;
            this.dkxInvite = existing.dkxInvite;
        }
    }

    get posts(): PostDocument[] {
        return (this.dkxPost.documents as PostDocument[]).filter(x => !x.refId && x.content.kind === 1);
    }

    get invites(): Invitation[] {
        const invitesWithRsvps = (this.dkxInvite.documents as Invitation[]).map(invite => {
            invite.rsvps = this.rsvps.filter(x => x.content.pointerDocIndex === invite.docIndex);
            return invite;
        });
        return invitesWithRsvps;
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
                this.content.created_at
            ]
        ];
    }

    override deserialize(payload: string): any[] {
        const raw = super.deserialize(payload);
        this.content.name = raw[1][0];
        this.content.about = raw[1][1];
        this.content.picture = raw[1][2];
        this.content.created_at = raw[1][3];
        return raw;
    }
}
