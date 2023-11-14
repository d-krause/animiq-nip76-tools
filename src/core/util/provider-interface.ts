import { nip19Extension } from "../../nostr-tools";
import { ContentDocument, NostrEventDocument } from "../content";
import { HDKIndexDTO, HDKIndex } from "../keys";

export interface DefyToolsKeyProviderIndexArgs {
    publicIndex?: HDKIndexDTO;
    privateIndexId?: number;
    keyPage?: number;
}

export const DefyToolsProviderIndexArgDefaults: DefyToolsKeyProviderIndexArgs = { privateIndexId: undefined, keyPage: 0 };

export interface DefyToolsProvider {
    getIndex(privateIndexId?: number, keyPage?: number): Promise<HDKIndex>;
    createEvent(doc: ContentDocument): Promise<NostrEventDocument>;
    createDeleteEvent(doc: ContentDocument): Promise<NostrEventDocument>;
    readInvitation(channelPointer: string): Promise<nip19Extension.PrivateChannelPointer>;
    createInvitation(pointer: nip19Extension.PrivateChannelPointer, forPubkey: string): Promise<string>;
}