
import * as secp256k1 from '@noble/secp256k1'
import { nip19Extension } from "../src/nostr-tools";
import { HDKey, Versions } from "../src/core";
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const realRandom = secp256k1.utils.randomBytes;
secp256k1.utils.randomBytes = (length: number | undefined) => {
    return Uint8Array.from([241, 78, 130, 118, 139, 157, 149, 47, 208, 218, 203, 135, 138, 224, 211, 154]);
};

let kp = HDKey.parseMasterSeed(hexToBytes('000102030405060708090a0b0c0d0e0f'), Versions.bitcoinMain);
let ap = kp.derive(`m/44'/1237'/0'/123'/456'`);
let sp = kp.derive(`m/44'/1237'/0'/789'/999'`);


describe('nprivatechan', () => {

    it('it should encode and decode with a password', async () => {

        const testPassword = 'example password 1';
        const testNip19Text = 'nprivatechan1798gya5tnk2jl5x6ewrc4cxnntshdtj0frwsapaq4ujl02drrpt8hvu8nlsgurhcdzngrvw3v6d2xs78jtqy76cen4gg6uy2n9f55qecxyql53f2zumty8ahnrp2738q8pd0tyw0xz8hr0evgv9075tj3ykeqtash2x4vsvgya3hjewr8qhk58uy68wvntlzser84hpq3vnlky5fs7nk0z';

        const testPointer: nip19Extension.PrivateChannelPointer = {
            // ownerPubKey: kp.nostrPubKey,
            type: 0,
            signingKey: ap.publicKey,
            cryptoKey: sp.publicKey,
        };
        const privatechannel1 = await nip19Extension.nprivateChannelEncode(testPointer, testPassword);

        expect(privatechannel1).toEqual(testNip19Text);

        let nip19DecodeResult = await nip19Extension.decode(testNip19Text, testPassword);
        expect(nip19DecodeResult!.type).toBe('nprivatechan');
        const resultPointer = nip19DecodeResult!.data as nip19Extension.PrivateChannelPointer;
        // expect(resultPointer.ownerPubKey).toBe(testPointer.ownerPubKey);
        expect(bytesToHex(resultPointer.signingKey!)).toBe(bytesToHex(testPointer.signingKey!));
        expect(bytesToHex(resultPointer.cryptoKey!)).toBe(bytesToHex(testPointer.cryptoKey!));
    })


    it('it should work with key pairs and relays ', async () => {

        let senderKey = kp.derive(`m/44'/1237'/0'/867'/5309'`);
        let receiverKey = kp.derive(`m/44'/1237'/0'/588'/2300'`);
        let normalizedReceiverPubKey = receiverKey.publicKey.slice(1);
        let normalizedSenderPubKey = senderKey.publicKey.slice(1);
        const testNip19Text = 'nprivatechan1798gya5tnk2jl5x6ewrc4cxnng0xwmx9m72sc7p4w00j4cltts674t4wx7y8rqyqhhdufraepqlmuf35zqrjn0swvx3h2r07kh86cglrgatg0an84ha73h5gjrdgc3acdp7e6mql6m79mee9q5rfms984c78gnh5qe3wqny6c9wfc2h0z2y0anhradcxw7lsewncmhpd6uvfxc2luuuj8tr8ppyr74yr4jyx0tclcqryrlqjdkvml25l3rlcfdd5r7zurtedemsmzp8tqh0qwhvelr4g0yw0pkkg208v6zlylc84nxw2na4dlukukyvkuu2sgj24cq';

        const testPointer: nip19Extension.PrivateChannelPointer = {
            type: 0,
            // ownerPubKey: kp.nostrPubKey,
            signingKey: ap.publicKey,
            cryptoKey: sp.publicKey,
            relays: [
                'wss://relay.nostr.example.mydomain.example.com',
                'wss://nostr.banana.com'
            ]
        };
        const privatechannel1 = await nip19Extension.nprivateChannelEncode(testPointer, [normalizedReceiverPubKey, senderKey.privateKey]);
        expect(privatechannel1).toEqual(testNip19Text);

        let nip19DecodeResult = await nip19Extension.decode(testNip19Text, [normalizedSenderPubKey, receiverKey.privateKey]);
        expect(nip19DecodeResult!.type).toBe('nprivatechan');

        const resultPointer = nip19DecodeResult!.data as nip19Extension.PrivateChannelPointer;
        // expect(resultPointer.ownerPubKey).toBe(testPointer.ownerPubKey);
        expect(bytesToHex(resultPointer.signingKey!)).toBe(bytesToHex(testPointer.signingKey!));
        expect(bytesToHex(resultPointer.cryptoKey!)).toBe(bytesToHex(testPointer.cryptoKey!));
        expect(resultPointer.relays![0]).toBe(testPointer.relays![0]);
        expect(resultPointer.relays![1]).toBe(testPointer.relays![1]);

    })

});