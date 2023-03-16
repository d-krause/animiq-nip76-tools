
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


describe('nprivatethread1', () => {

    it('it should encode and decode with a password', async () => {

        const testPassword = 'example password 1';
        const testNip19Text = 'nprivatethread11798gya5tnk2jl5x6ewrc4cxnntshdtj0frwsapaq4ujl02drrpt8hvu8nlsgurhcdzngrvw3v6d2xs78jtqy76cen4gg6uy2n9f55qecxyql53f2zumty8ahnrp2738q8qtfx5dqmmh48g5wrh2c5092tk6u6hz0wu4e8pvtmzzgenxvscgk0p9fvdyfcv4pns5nzaqyz4klfrj4s0hdtflxeu6ktj42szwguhusxsd55ygcmsmmvf8tukpex89870pezpe2zskf78g0h0gqjfks4xstpxthjk7vcwh59zeumd9v5kkv4xqlswhxz';

        const testPointer: nip19Extension.PrivateChannelPointer = {
            ownerPubKey: kp.nostrPubKey,
            addresses: {
                pubkey: ap.publicKey,
                chain: ap.chainCode,
            },
            secrets: {
                pubkey: sp.publicKey,
                chain: sp.chainCode,
            }
        };
        const privatechannel1 = await nip19Extension.nprivateChannelEncode(testPointer, testPassword);

        expect(privatechannel1).toEqual(testNip19Text);

        let nip19DecodeResult = await nip19Extension.decode(testNip19Text, testPassword);
        expect(nip19DecodeResult!.type).toBe('nprivatethread1');
        const resultPointer = nip19DecodeResult!.data as nip19Extension.PrivateChannelPointer;
        expect(resultPointer.ownerPubKey).toBe(testPointer.ownerPubKey);
        expect(bytesToHex(resultPointer.addresses.pubkey)).toBe(bytesToHex(testPointer.addresses.pubkey));
        expect(bytesToHex(resultPointer.addresses.chain)).toBe(bytesToHex(testPointer.addresses.chain));
        expect(bytesToHex(resultPointer.secrets!.pubkey)).toBe(bytesToHex(testPointer.secrets!.pubkey));
        expect(bytesToHex(resultPointer.secrets!.chain)).toBe(bytesToHex(testPointer.secrets!.chain));
    })


    it('it should work with key pairs and relays ', async () => {

        let senderKey = kp.derive(`m/44'/1237'/0'/867'/5309'`);
        let receiverKey = kp.derive(`m/44'/1237'/0'/588'/2300'`);
        let normalizedReceiverPubKey = receiverKey.publicKey.slice(1);
        let normalizedSenderPubKey = senderKey.publicKey.slice(1);
        const testNip19Text = 'nprivatethread11798gya5tnk2jl5x6ewrc4cxnng0xwmx9m72sc7p4w00j4cltts674t4wx7y8rqyqhhdufraepqlmuf35zqrjn0swvx3h2r07kh86cglrgatg0an84ha73h5gjrdgc3acdqclhtrs8zw8l758t0v73ttl02jzj0gte0zztzye86aknqlq4jm0x4dq8dwl2nehakuxlrf5a6hq5nk6kwa9y2ws9jjd8l52xa03hacsxlhtgdeq4w2t2ss0pmv0kc2gss7c4vtzygc9dtszewzsk7t28uxemluqzjldsedvjfzt6fcaeqq2rafnhmxmhumarf62mjdw6npa4d8al0epqe0xlwun8d8ekyph27gkzxeh3dnzurmc9xh4uru97nqnt8nqrvs85qmw66vjav7j5rxamqj0h5nfsm3x63zapv3j4962';

        const testPointer: nip19Extension.PrivateChannelPointer = {
            ownerPubKey: kp.nostrPubKey,
            addresses: {
                pubkey: ap.publicKey,
                chain: ap.chainCode,
            },
            secrets: {
                pubkey: sp.publicKey,
                chain: sp.chainCode,
            },
            relays: [
                'wss://relay.nostr.example.mydomain.example.com',
                'wss://nostr.banana.com'
            ]
        };
        const privatechannel1 = await nip19Extension.nprivateChannelEncode(testPointer, [normalizedReceiverPubKey, senderKey.privateKey]);
        expect(privatechannel1).toEqual(testNip19Text);

        let nip19DecodeResult = await nip19Extension.decode(testNip19Text, [normalizedSenderPubKey, receiverKey.privateKey]);
        expect(nip19DecodeResult!.type).toBe('nprivatethread1');

        const resultPointer = nip19DecodeResult!.data as nip19Extension.PrivateChannelPointer;
        expect(resultPointer.ownerPubKey).toBe(testPointer.ownerPubKey);
        expect(bytesToHex(resultPointer.addresses.pubkey)).toBe(bytesToHex(testPointer.addresses.pubkey));
        expect(bytesToHex(resultPointer.addresses.chain)).toBe(bytesToHex(testPointer.addresses.chain));
        expect(bytesToHex(resultPointer.secrets!.pubkey)).toBe(bytesToHex(testPointer.secrets!.pubkey));
        expect(bytesToHex(resultPointer.secrets!.chain)).toBe(bytesToHex(testPointer.secrets!.chain));
        expect(resultPointer.relays![0]).toBe(testPointer.relays![0]);
        expect(resultPointer.relays![1]).toBe(testPointer.relays![1]);

    })

});