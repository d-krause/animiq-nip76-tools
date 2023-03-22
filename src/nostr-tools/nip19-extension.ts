import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import * as secp256k1 from '@noble/secp256k1'
import { bech32, utf8 } from '@scure/base'

type TLV = { [t: number]: Uint8Array[] }

const Bech32MaxSize = 5000

function parseTLV(data: Uint8Array): TLV {
    let result: TLV = {}
    let rest = data
    while (rest.length > 0) {
        let t = rest[0]
        let l = rest[1]
        let v = rest.slice(2, 2 + l)
        rest = rest.slice(2 + l)
        if (v.length < l) continue
        result[t] = result[t] || []
        result[t].push(v)
    }
    return result
}

function encodeTLV(tlv: TLV): Uint8Array {
    let entries: Uint8Array[] = []

    Object.entries(tlv).forEach(([t, vs]) => {
        vs.forEach(v => {
            let entry = new Uint8Array(v.length + 2)
            entry.set([parseInt(t)], 0)
            entry.set([v.length], 1)
            entry.set(v, 2)
            entries.push(entry)
        })
    })

    return secp256k1.utils.concatBytes(...entries)
}

async function encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    const iv = secp256k1.utils.randomBytes(16);
    const secretBytes = key.slice(0, 32);
    const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
    const secretKey = await window.crypto.subtle.importKey('raw', secretBytes, alg, false, ['encrypt']);
    const encrypted = new Uint8Array(await window.crypto.subtle.encrypt(alg, secretKey, data));
    const out = secp256k1.utils.concatBytes(iv, encrypted);
    return out;
}

async function decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array | undefined> {
    try {
        const encrypted = data;
        const iv2 = encrypted.slice(0, 16);
        const payload = encrypted.slice(16);
        const secretBytes = key.slice(0, 32);
        const alg = { name: 'AES-GCM', iv: iv2, length: 256 } as AesKeyAlgorithm;
        const secretKey = await window.crypto.subtle.importKey('raw', secretBytes, alg, false, ['decrypt']);
        const decrypted = new Uint8Array(await window.crypto.subtle.decrypt(alg, secretKey, payload));
        return decrypted;
    } catch (e) {
        console.log('decrypt error' + e);
        return undefined;
    }
}

export type PrivateChannelPointer = {
    ownerPubKey: string;
    signingKey: Uint8Array;
    cryptoKey: Uint8Array;
    relays?: string[]
}

const keyFromSecretString = (secret: string) => {
    return hmac.create(sha256, new Uint8Array(utf8ToBytes('nip76'))).update(new Uint8Array(utf8ToBytes(secret))).digest();
};

const keyFromSharedSecret = (pubkey: Uint8Array, privkey: Uint8Array) => {
    const pubkeyPoint = secp256k1.Point.fromHex(pubkey);
    const sharedKey = secp256k1.getSharedSecret(privkey, pubkeyPoint).slice(1);
    return sharedKey;
};

export async function nprivateChannelEncode(tp: PrivateChannelPointer, secret: string | Uint8Array[]): Promise<string> {
    let cryptKey: Uint8Array;
    if (typeof (secret) === 'string') {
        cryptKey = keyFromSecretString(secret);
    } else {
        cryptKey = keyFromSharedSecret(secret[0], secret[1]);
    }
    const ownerPubKey = secp256k1.utils.hexToBytes(tp.ownerPubKey);
    let relayData = encodeTLV({
        0: (tp.relays || []).map(url => new TextEncoder().encode(url))
    })
    const data = secp256k1.utils.concatBytes(
        ownerPubKey,
        tp.signingKey,
        tp.cryptoKey,
        relayData
    );
    const encrypted = await encrypt(data, cryptKey);
    const words = bech32.toWords(encrypted);
    return bech32.encode('nprivatechan', words, Bech32MaxSize)
}

export async function decode(nip19: string, secret: string | Uint8Array[]): Promise<{
    type: string
    data: PrivateChannelPointer | string
}> {
    const { prefix, words } = bech32.decode(nip19, Bech32MaxSize);
    if (prefix === 'nprivatechan') {
        let cryptKey: Uint8Array;
        if (typeof (secret) === 'string') {
            cryptKey = keyFromSecretString(secret);
        } else {
            cryptKey = keyFromSharedSecret(secret[0], secret[1]);
        }
        let encrypted = Uint8Array.from(bech32.fromWords(words));
        let data = await decrypt(encrypted, cryptKey);
        if (!data) throw new Error('invalid decryption for nprivatechan');
        let tlv = parseTLV(data.slice(98));
        return {
            type: 'nprivatechan',
            data: {
                ownerPubKey: secp256k1.utils.bytesToHex(data.slice(0, 32)),
                signingKey: data.slice(32, 65),
                cryptoKey: data.slice(65, 98),
                relays: (tlv[0] || []).map(d => new TextDecoder().decode(d))
            }
        }

    } else {
        throw new Error(`The prefix ${prefix} cannot de decoded in this nip19 extension.`)
    }
}
