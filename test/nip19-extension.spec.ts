
import * as secp256k1 from '@noble/secp256k1'
import { nip19Extension } from "../src/nostr-tools";
import { HDKey, Versions } from "../src/core";
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import * as ff from '@noble/hashes/utils';;

const realRandom = ff.randomBytes;
(ff as any).randomBytes = (length: number | undefined) => {
    return Uint8Array.from([241, 78, 130, 118, 139, 157, 149, 47, 208, 218, 203, 135, 138, 224, 211, 154]);
};

let kp = HDKey.parseMasterSeed(hexToBytes('000102030405060708090a0b0c0d0e0f'), Versions.bitcoinMain);
let ap = kp.derive(`m/44'/1237'/0'/123'/456'`);
let sp = kp.derive(`m/44'/1237'/0'/789'/999'`);


describe('nprivatechan', () => {

    it('it should create some test data', async () => {
        const threadPointer: nip19Extension.PrivateChannelPointer = {
            type: 0,
            docIndex: NaN,
            signingKey: ap.publicKey,
            signingChain: ap.chainCode,
            cryptoKey: sp.publicKey,
            cryptoChain: sp.chainCode,
        };
        const pointer1 = await nip19Extension.nprivateChannelEncode(threadPointer, 'example password 1');

        let senderKey = kp.derive(`m/44'/1237'/0'/867'/5309'`);
        let receiverKey = kp.derive(`m/44'/1237'/0'/588'/2300'`);
        threadPointer.relays = [
            'wss://relay.nostr.example.mydomain.example.com',
            'wss://nostr.banana.com'
        ];
        const pointer2 = await nip19Extension.nprivateChannelEncode(threadPointer, bytesToHex(senderKey.privateKey), receiverKey.nostrPubKey);

        console.log('create test data', { pointer1, pointer2 });
        expect(pointer1).toBe('nprivatechan18hc5aqnk3wwe2t7smt9c0zhq6wdd34e8uvvrggfmre0eta9z55e3qk3sm2vmepxk3948kfrnrlylawkdkyhwxnvfn693enaxsg9jry07mjvt3fj5ms7wx0ge0duffvrx0krryt3qkrhlmqu3c0r6c38zh59hkxw37rkjujsszglrwc4x4fl03t5c3svgdhefkn7kk29asurt3w2sfdc49h354vck2cwkda9p4nllzg572g6y3wtufmaz4wrgwfjhtkgqrqq3zaq53');
        expect(pointer2).toBe('nprivatechan18a85ej5hadfswdya5886dn52dd0hr0na30qjkyh44j4khls2c5dw9u2wsfmgh8v49lgd4ju83tsd8x38cmjknrmuy0zghqm0985w6amnevklxvw50dv0r0cxv9xh0f6m575y9tpy9dwgjal0xldlvfaawl0q0mh0m0nerp3wvlvyguyvjdjjt4s4gmwkqzvw4lyu4qdqyeekstr2lkctg5wplswspkqgsl5cv4zl8fyc2synke2z9r86wezt0ltmg7gvgsgxtxafm5h56l3yllwetftey2ssyzaskvy0lhjdmzhk3ha2uh5x4m9zanauaef62pkprpxvtwl3s2gvxq4yc4c7d32hk5a3p4qq4n6jmj4futjhvsfk7t96fzw668l0palarpj6nv9z8k6gnfw0vpe7v0gc078vtl250s5gcer4j2l');

    }),
        it('it should encode and decode with a password', async () => {

            const testPassword = 'example password 1';
            const testNip19Text = 'nprivatechan1zhc5aqnk3wwe2t7smt9c0zhq6wddf4e8uvvrggfmre0eta9z55e3qk3sm2vmepxk3948kfrnrlylawkdkyhwxnvfn693enaxsg9jry07mjvt3fj5ms7wx0ge0duffvrx0krryt5klykrqeadp8kxgd9dsnr8cujpnzp87f';

            const testPointer: nip19Extension.PrivateChannelPointer = {
                docIndex: 12,
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
        let normalizedReceiverPubKey = receiverKey.nostrPubKey;
        const testNip19Text = 'nprivatechan1ze85ej5hadfswdya5886dn52dd0hr0na30qjkyh44j4khls2c5dw9u2wsfmgh8v49lgd4ju83tsd8x3dcmjknrmuy0zghqm0985w6amnevklxvw50dv0r0cxv9xh0f6m575y9tpy9dwgjal0xldlvfaawl0q0mh0m0nerp3wvlvyguyvjdjjt4s4g6fxksxg602r4wjq3h6qjczn7qr8qudmr36k7g0t3xu8xtwyasege2rx04nwfq0snm2rrksyjdk9l72dgl6hzqcn059crfk406j9tng2fm6pygkj5jjfl8j0d8z37fh0wc3086prruxnd7c5lhzyq';

        const testPointer: nip19Extension.PrivateChannelPointer = {
            type: 0,
            docIndex: 10,
            signingKey: ap.publicKey,
            cryptoKey: sp.publicKey,
            relays: [
                'wss://relay.nostr.example.mydomain.example.com',
                'wss://nostr.banana.com'
            ]
        };
        const privatechannel1 = await nip19Extension.nprivateChannelEncode(testPointer, bytesToHex(senderKey.privateKey), normalizedReceiverPubKey);
        expect(privatechannel1).toEqual(testNip19Text);

        let nip19DecodeResult = await nip19Extension.decode(testNip19Text, bytesToHex(receiverKey.privateKey));
        expect(nip19DecodeResult!.type).toBe('nprivatechan');

        const resultPointer = nip19DecodeResult!.data as nip19Extension.PrivateChannelPointer;
        // expect(resultPointer.ownerPubKey).toBe(testPointer.ownerPubKey);
        expect(bytesToHex(resultPointer.signingKey!)).toBe(bytesToHex(testPointer.signingKey!));
        expect(bytesToHex(resultPointer.cryptoKey!)).toBe(bytesToHex(testPointer.cryptoKey!));
        expect(resultPointer.relays![0]).toBe(testPointer.relays![0]);
        expect(resultPointer.relays![1]).toBe(testPointer.relays![1]);

    })

});