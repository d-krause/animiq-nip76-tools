/*! animiq-nip76-tools - MIT License (c) 2023 David Krause (animiq.com) */
import { sha512 } from '@noble/hashes/sha512';
import { hexToBytes } from '@noble/hashes/utils';
import * as nostrTools from 'nostr-tools';
import { PrivateChannel } from '../content';
import { HDKey, HDKIndex, HDKIndexType, Versions } from '../keys';
import { getReducedKey, getReducedKeySet, KeySetCommon } from '../util';
import { IWalletStorage, WalletConstructorArgs } from './interfaces';

export class Wallet {

    private master: HDKey;
    private nip76Root!: HDKey;
    private lockwords!: Int32Array;

    store: IWalletStorage;
    isGuest = false;
    isInSession = false;

    ownerPubKey!: string;
    signingKey!: HDKey;
    documentsIndex!: HDKIndex;
    channels: PrivateChannel[] = [];
    following: PrivateChannel[] = [];


    constructor(args: WalletConstructorArgs) {
        this.ownerPubKey = args.publicKey;
        this.master = args.key!;
        this.store = args.store;
        this.isGuest = args.isGuest
        this.isInSession = args.isInSession
        if (this.isGuest) {
            this.reKey();
        } else if (this.master) {
            this.setLockWords({ secret: args.privateKey, lockwords: args.lockwords });
            if (!this.isInSession) {
                this.store.save({ publicKey: this.ownerPubKey, key: this.master, lockwords: this.lockwords });
                this.isInSession = true;
            }
            this.nip76Root = this.master.derive(`m/44'/1237'/0'/1776'`);
            this.signingKey = getReducedKey({
                root: this.nip76Root,
                wordset: this.lockwords,
                offset: KeySetCommon.offsets[1]
            });
            const followingKeyset = getReducedKeySet({
                root: this.nip76Root,
                wordset: this.lockwords,
                sort: KeySetCommon.sort.desc,
                offset: 20
            });
            // this.followingIndex = IndexDocument.createIndex(IndexPermission.CreateByOwner, followingKeyset.ap, followingKeyset.sp);
            this.documentsIndex = new HDKIndex(HDKIndexType.Private | HDKIndexType.TimeBased, followingKeyset.ap, followingKeyset.sp);
            this.getChannel(0);
            // this.beacons = Array(10).map((_, i) => this.beaconKey.deriveChildKey(i, true).nostrPubKey);
        }
    }

    async saveWallet(privateKey?: string) {
        if (privateKey) {
            await this.store.save({ privateKey, publicKey: this.ownerPubKey, key: this.master, lockwords: this.lockwords });
        }
        await this.store.save({ publicKey: this.ownerPubKey, key: this.master, lockwords: this.lockwords });
        this.isInSession = true;
    }

    async clearSession() {
        this.store.clearSession()
        this.isInSession = false;
        const randoms = new Uint8Array(256);
        window.crypto.getRandomValues(randoms);
        this.master = HDKey.parseMasterSeed(randoms, Versions.nip76API1);
        this.setLockWords({ secret: ' ' });
        this.channels = [];
        this.following = [];
    }

    reKey(secret?: string): void {
        if (!this.isGuest) {
            throw new Error('Existing Wallet cannot be rekeyed.');
        }
        const randoms = new Uint8Array(256);
        window.crypto.getRandomValues(randoms);
        this.master = HDKey.parseMasterSeed(randoms, Versions.nip76API1);
        if (secret) {
            this.setLockWords({ secret });
        }
        this.channels = [];
        this.following = [];
        this.getChannel(0);
    }

    restoreFromKey(extendedPrivateKey: string, secret: string): boolean {
        this.master = HDKey.parseExtendedKey(extendedPrivateKey);
        this.setLockWords({ secret });
        this.isGuest = false;
        return true;
    }

    setLockWords(args: { secret?: string, lockwords?: Int32Array }) {
        if (args.secret) {
            const secretHash = args.secret.match(/^[a-f0-9]$/) && args.secret.length % 2 === 0
                ? sha512(hexToBytes(args.secret))
                : sha512(new TextEncoder().encode(args.secret));
            this.lockwords = new Int32Array((secretHash).buffer).map(i => Math.abs(i));
        } else if (args.lockwords && args.lockwords.length === 16) {
            this.lockwords = args.lockwords;
        } else {
            throw new Error('16 lockwords or a secret to generate them is required to setLockwords().');
        }
    }

    getChannel(index: number): PrivateChannel {
        if (!this.lockwords || !this.master || !this.nip76Root) {
            throw new Error('locknums and master needed before getChannel().');
        }
        if (!this.channels[index]) {
            const channel = new PrivateChannel();
            channel.ownerPubKey = this.ownerPubKey;
            channel.content = {
                kind: nostrTools.Kind.ChannelMetadata,
                name: 'Loading Channel Info ...',
                pubkey: this.ownerPubKey,
                last_known_index: 0
            };
            const keyset = getReducedKeySet({
                root: this.nip76Root,
                wordset: this.lockwords.reverse(),
                offset: KeySetCommon.offsets[2] + index,
                right: true,
            });
            channel.hdkIndex = new HDKIndex(HDKIndexType.TimeBased, keyset.ap, keyset.sp);
            keyset.sp.wipePrivateData();
            this.channels = [...this.channels, channel];
        }
        return this.channels[index];
    }
}
