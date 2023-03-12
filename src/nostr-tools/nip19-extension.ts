import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as secp256k1 from '@noble/secp256k1'
import { bech32, utf8 } from '@scure/base'
import { uint8ArrayFromBuffer } from '../core/util';

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

async function encrypt(data: Buffer, key: Buffer): Promise<Uint8Array> {
    const iv = secp256k1.utils.randomBytes(16);
    const secretBytes = uint8ArrayFromBuffer(key.slice(0, 32));
    const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
    const secretKey = await window.crypto.subtle.importKey('raw', secretBytes, alg, false, ['encrypt']);
    const buffer = uint8ArrayFromBuffer(data);
    const encrypted = new Uint8Array(await window.crypto.subtle.encrypt(alg, secretKey, buffer));
    const out = secp256k1.utils.concatBytes(iv, encrypted);
    return out;
}

async function decrypt(data: Buffer, key: Buffer): Promise<Buffer | undefined> {
    try {
        const encrypted = uint8ArrayFromBuffer(data);
        const iv2 = encrypted.slice(0, 16);
        const buffer = encrypted.slice(16);
        const secretBytes = uint8ArrayFromBuffer(key.slice(0,32));
        const alg = { name: 'AES-GCM', iv: iv2, length: 256 } as AesKeyAlgorithm;
        const secretKey = await window.crypto.subtle.importKey('raw', secretBytes, alg, false, ['decrypt']);
        const decrypted = await window.crypto.subtle.decrypt(alg, secretKey, buffer);
        return Buffer.from(decrypted);
    } catch (e) {
        console.log('decrypt error' + e);
        return undefined;
    }
}

export type PrivateThreadPointer = {
    ownerPubKey: string;
    addresses: {
        pubkey: Buffer,
        chain: Buffer
    },
    secrets: {
        pubkey: Buffer,
        chain: Buffer
    }
    relays?: string[]
}

const keyFromSecretString = (secret: string) => {
    return Buffer.from(hmac.create(sha256, utf8.decode('nip76')).update(utf8.decode(secret)).digest());
};

const keyFromSharedSecret = (pubkey: Buffer, privkey: Buffer) => {
    const pubkeyPoint = secp256k1.Point.fromHex(pubkey);
    const sharedKey = secp256k1.getSharedSecret(privkey, pubkeyPoint).slice(1);
    return Buffer.from(sharedKey);
};

export async function nprivateThreadEncode(tp: PrivateThreadPointer, secret: string | Buffer[]): Promise<string> {
    let cryptKey: Buffer;
    if (typeof (secret) === 'string') {
        cryptKey = keyFromSecretString(secret);
    } else {
        cryptKey = keyFromSharedSecret(secret[0], secret[1]);
    }
    const ownerPubKey = Buffer.from(tp.ownerPubKey, 'hex');
    let relayData = encodeTLV({
        0: (tp.relays || []).map(url => utf8.decode(url))
    })
    const data = Buffer.concat([
        ownerPubKey,
        tp.addresses.pubkey,
        tp.addresses.chain,
        tp.secrets.pubkey,
        tp.secrets.chain,
        relayData
    ]);
    const encrypted = await encrypt(data, cryptKey);
    const words = bech32.toWords(encrypted);
    return bech32.encode('nprivatethread1', words, Bech32MaxSize)
}

export async function decode(nip19: string, secret: string | Buffer[]): Promise<{
    type: string
    data: PrivateThreadPointer | string
}> {
    const { prefix, words } = bech32.decode(nip19, Bech32MaxSize);
    if (prefix === 'nprivatethread1') {
        let cryptKey: Buffer;
        if (typeof (secret) === 'string') {
            cryptKey = keyFromSecretString(secret);
        } else {
            cryptKey = keyFromSharedSecret(secret[0], secret[1]);
        }
        let encrypted = Buffer.from(bech32.fromWords(words));
        let data = await decrypt(encrypted, cryptKey);
        if (!data) throw new Error('invalid decryption for nprivatethread1');
        let tlv = parseTLV(data.slice(162));
        return {
            type: 'nprivatethread1',
            data: {
                ownerPubKey: data.slice(0, 32).toString('hex'),
                addresses: {
                    pubkey: data.slice(32, 65),
                    chain: data.slice(65, 97),
                },
                secrets: {
                    pubkey: data.slice(97, 130),
                    chain: data.slice(130, 162),
                },
                relays: (tlv[0] || []).map(d => utf8.encode(d))
            }
        }

    } else {
        throw new Error(`The prefix ${prefix} cannot de decoded in this nip19 extension.`)
    }
}
