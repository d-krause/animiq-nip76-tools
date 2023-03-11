
import * as secp256k1 from '@noble/secp256k1'
import { nip19Extension } from "./index";
import { HDKey, Versions } from "../core";
import { fixedMasterSeed } from "../core/keys/HDKey.spec";
const crypto = require('crypto').webcrypto;

let kp = HDKey.parseMasterSeed(fixedMasterSeed, Versions.bitcoinMain);
let ap = kp.derive(`m/44'/1237'/0'/123'/456'`);
let sp = kp.derive(`m/44'/1237'/0'/789'/999'`);

const realRandom = secp256k1.utils.randomBytes;
const mockRandom = (length: number | undefined) => {
    return Uint8Array.from([241, 78, 130, 118, 139, 157, 149, 47, 208, 218, 203, 135, 138, 224, 211, 154]);
};

test('nprivateThreadEncode', () => {

    secp256k1.utils.randomBytes = mockRandom;

    const testPassword = 'example password 1';
    const testNip19Text = 'nprivatethread1194wtsp370e9hc8waecwda6yf3hc5aqnk3wwe2t7smt9c0zhq6wdpuutlck42yepz4kqrjw329tdcm94sh34hss346ssplc9ceqgrug6rrja3phd2jqwe5fx598wxqv4eug89kxrv6er98u3fwyk7uas0cpgqjsavpna75wwj256pw047gaztlynex674zmh5p7axw2frpjmvqdu97hpyk2j5g7yatmkzejkrhfjnd2gzt4xxc3xtr7vpkh3je098v8xtknxd0t8gn44auh49rqaw9h0e00f2c2l6e7v6s4ak2qtpna5rw3q43aksv';

    const testPointer: nip19Extension.PrivateThreadPointer = {
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
    const privatethread1 = nip19Extension.nprivateThreadEncode(testPointer, testPassword);

    expect(crypto.subtle).toBeTruthy();
    expect(privatethread1).toEqual(testNip19Text);

    let nip19DecodeResult = nip19Extension.decode(testNip19Text, testPassword);
    expect(nip19DecodeResult!.type).toBe('nprivatethread1');
    const resultPointer = nip19DecodeResult!.data as nip19Extension.PrivateThreadPointer;
    expect(resultPointer.ownerPubKey).toBe(testPointer.ownerPubKey);
    expect(resultPointer.addresses.pubkey.toString('hex')).toBe(testPointer.addresses.pubkey.toString('hex'));
    expect(resultPointer.addresses.chain.toString('hex')).toBe(testPointer.addresses.chain.toString('hex'));
    expect(resultPointer.secrets!.pubkey.toString('hex')).toBe(testPointer.secrets!.pubkey.toString('hex'));
    expect(resultPointer.secrets!.chain.toString('hex')).toBe(testPointer.secrets!.chain.toString('hex'));

    secp256k1.utils.randomBytes = realRandom;
})


test('nprivateThreadEncode-with-relays-and-pubkey-encrypt', () => {

    secp256k1.utils.randomBytes = mockRandom;

    let senderKey = kp.derive(`m/44'/1237'/0'/867'/5309'`);
    let receiverKey = kp.derive(`m/44'/1237'/0'/588'/2300'`);
    let normalizedReceiverPubKey = receiverKey.publicKey.slice(1);
    let normalizedSenderPubKey = senderKey.publicKey.slice(1);
    const testNip19Text = 'nprivatethread11teg49gz4edgnnlsdlrah8uvvslc5aqnk3wwe2t7smt9c0zhq6wdqs7qkxpnj376k5r2r7jerm6ps52t4tfqdlul3w7ysffvag6udx6qh5t5fyrs3k87fm993r26xyf870kg50300wdrc6x4cxxpd8k6pkxa5ju8fnwzgdh9xywrr8g7602aj6egdrzdfjq60tjdl3l7k064w0fy225x0tn03swd4c2vsvhslgy0l368gujvj9sxp3m497glzpmg8j7qpm5smxkfu44zwnjng98pa20e5sk4wctqn8j88f70czf2jv73n2slm6mfe5gv8p9xd6qnyqynqpcy2uajwvd4353fzkznwsfyk69uaqpnwn8t9g3l74exdy0342u5ntwgrhkpn7c8tqnfqe6r576ctvjnkycsruzcma4es7q8fqeew';

    const testPointer: nip19Extension.PrivateThreadPointer = {
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
    const privatethread1 = nip19Extension.nprivateThreadEncode(testPointer, [normalizedReceiverPubKey, senderKey.privateKey]);

    expect(crypto.subtle).toBeTruthy();
    expect(privatethread1).toEqual(testNip19Text);

    let nip19DecodeResult = nip19Extension.decode(testNip19Text, [normalizedSenderPubKey, receiverKey.privateKey]);
    expect(nip19DecodeResult!.type).toBe('nprivatethread1');
    const resultPointer = nip19DecodeResult!.data as nip19Extension.PrivateThreadPointer;
    expect(resultPointer.ownerPubKey).toBe(testPointer.ownerPubKey);
    expect(resultPointer.addresses.pubkey.toString('hex')).toBe(testPointer.addresses.pubkey.toString('hex'));
    expect(resultPointer.addresses.chain.toString('hex')).toBe(testPointer.addresses.chain.toString('hex'));
    expect(resultPointer.secrets!.pubkey.toString('hex')).toBe(testPointer.secrets!.pubkey.toString('hex'));
    expect(resultPointer.secrets!.chain.toString('hex')).toBe(testPointer.secrets!.chain.toString('hex'));
    expect(resultPointer.relays![0]).toBe(testPointer.relays![0]);
    expect(resultPointer.relays![1]).toBe(testPointer.relays![1]);

    secp256k1.utils.randomBytes = realRandom;
})