
import * as secp256k1 from '@noble/secp256k1'
import { nip19Extension } from "./index";
import { HDKey, Versions } from "../core";
import { fixtures } from '../core/keys/HDKey.spec';
const crypto = require('crypto').webcrypto;

let kp = HDKey.parseMasterSeed(Buffer.from(fixtures[0].seed), Versions.bitcoinMain);
let ap = kp.derive(`m/44'/1237'/0'/123'/456'`);
let sp = kp.derive(`m/44'/1237'/0'/789'/999'`);

const realRandom = secp256k1.utils.randomBytes;
const mockRandom = (length: number | undefined) => {
    return Uint8Array.from([241, 78, 130, 118, 139, 157, 149, 47, 208, 218, 203, 135, 138, 224, 211, 154]);
};

test('nprivateThreadEncode', () => {

    secp256k1.utils.randomBytes = mockRandom;

    const testPassword = 'example password 1';
    const testNip19Text = 'nprivatethread11nrm6a3wcjgzgh36543xjr3rektc5aqnk3wwe2t7smt9c0zhq6wdx6dg24dp8vd4h5423qqx2l5p562gj854nca6k9tnlnxut7p4z4rzzflxv5c45tx9545ha3np74yfhchrdwaggcf58p7ayc6pklpt09rv0ulngch720xrc7wgt0syg9em8nsrw0mal0k6mrl9pfdyyhjmfx0y9mdt98wrfzpkccqgeaq0zzghkfwrfyygyqfejpzg69q6vekujgnc0n6m0f58azzdz7zn68699k6l78jzw26sqy5lcllretun9fl2tfsc4d93a0';

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
    const testNip19Text = 'nprivatethread11y30jx3xzw5mwtpstgxpkdg44cmc5aqnk3wwe2t7smt9c0zhq6wdv9vfhf5gxm8vz6hsv647qcnx93sn9neu4p0ge77pxjs9sz9zlxtt8r2z4mf2srtpvj5w92u7zgqgdsut76j92tu8uay2vw9n3e4zqr6yz3af0zhessh7zq3ply9sdwsuz6pws8mdrxst63auxd6jc46vfc7pyjs9uqt0tax9pn275zd3j68rgk9ekfjp7f03nhhaxk83ta8au63tskgd73cz0ty8fu8ckh9zqkk7nktmnjyatgtq7aga9hwus86gl04jwpk764my48y676r3r2jsd0hcyayuhdzqzdudr2x3fqnph8rr55utdcce0qzrfkxjzaurqc7zmlzrng8u40uxxw4vftfqnuarrw6vqzym28gqg28sfpvagkyyq';

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