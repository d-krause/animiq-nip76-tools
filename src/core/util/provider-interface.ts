import { nip19Extension } from "../../nostr-tools";
import { ContentDocument, NostrEventDocument } from "../content";
import { HDKIndexDTO, HDKIndex } from "../keys";

export interface Nip76ProviderIndexArgs {
    publicIndex?: HDKIndexDTO;
    privateIndexId?: number;
    keyPage?: number;
}

export const Nip76ProviderIndexArgDefaults: Nip76ProviderIndexArgs = { privateIndexId: NaN, keyPage: 0 };

export interface INostrNip76Provider {
    getIndex(privateIndexId?: number, keyPage?: number): Promise<HDKIndex>;
    createEvent(doc: ContentDocument): Promise<NostrEventDocument>;
    createDeleteEvent(doc: ContentDocument): Promise<NostrEventDocument>;
    readInvitation(channelPointer: string): Promise<nip19Extension.PrivateChannelPointer>;
    createInvitation(pointer: nip19Extension.PrivateChannelPointer, forPubkey: string): Promise<string>;
}