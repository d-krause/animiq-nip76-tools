import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import * as secp256k1 from '@noble/secp256k1';
import { bech32 } from '@scure/base';

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

    return concatBytes(...entries)
}

async function encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    const iv = randomBytes(16);
    const secretBytes = key.slice(0, 32);
    const alg = { name: 'AES-GCM', iv: iv, length: 256 } as AesKeyAlgorithm;
    const secretKey = await window.crypto.subtle.importKey('raw', secretBytes, alg, false, ['encrypt']);
    const encrypted = new Uint8Array(await window.crypto.subtle.encrypt(alg, secretKey, data));
    const out = concatBytes(iv, encrypted);
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
export enum PointerType {
    Password = 1,                           // 0000 0001
    SharedSecret = 1 << 1,                  // 0000 0010
    HasSignKey = 1 << 2,                    // 0000 0100
    HasSignChain = 1 << 3,                  // 0000 1000
    HasCryptKey = 1 << 4,                   // 0001 0000
    HasCryptChain = 1 << 5,                 // 0010 0000
    HasBothKeys = (1 << 2) | (1 << 4),      // 0001 0100
    HasBothChains = (1 << 3) | (1 << 5),    // 0010 1000
    FullKeySet = (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5),    // 0011 1100
}

export type PrivateChannelPointer = {
    type: PointerType;
    docIndex: number;
    signingKey?: Uint8Array;
    cryptoKey?: Uint8Array;
    signingChain?: Uint8Array;
    cryptoChain?: Uint8Array;
    relays?: string[]
}

const keyFromSecretString = (secret: string) => {
    return hmac.create(sha256, new Uint8Array(utf8ToBytes('nip76'))).update(new Uint8Array(utf8ToBytes(secret))).digest();
};

const keyFromSharedSecret = (pubkey: Uint8Array, privkey: Uint8Array) => {
    const pubkeyPoint = secp256k1.Point.fromHex(pubkey);
    const sharedKey = secp256k1.getSharedSecret(privkey, pubkeyPoint).slice(1);
    console.log({pubkey, privkey, sharedKey, pubOfPriv: secp256k1.getPublicKey(privkey, true).slice(1) })
    return sharedKey;
};

export async function nprivateChannelEncode(tp: PrivateChannelPointer, secretOrPrivateKey: string, publicKey?: string): Promise<string> {
    let cryptKey: Uint8Array;
    if (publicKey) {
        const keyPriv = hexToBytes(secretOrPrivateKey);
        const keyPub = hexToBytes(publicKey);
        cryptKey = keyFromSharedSecret(keyPub, keyPriv);
        tp.type |= PointerType.SharedSecret;
    } else if (secretOrPrivateKey) {
        cryptKey = keyFromSecretString(secretOrPrivateKey);
        tp.type |= PointerType.Password;
    } else {
        throw new Error('Channel Pointers need a secret password or a public private key pair.')
    }
    let data = Uint8Array.from([tp.docIndex]);
    if (tp.signingKey) {
        data = concatBytes(data, tp.signingKey);
        tp.type |= PointerType.HasSignKey;
    }
    if (tp.cryptoKey) {
        data = concatBytes(data, tp.cryptoKey);
        tp.type |= PointerType.HasCryptKey;
    }
    if (tp.signingChain) {
        data = concatBytes(data, tp.signingChain);
        tp.type |= PointerType.HasSignChain;
    }
    if (tp.cryptoChain) {
        data = concatBytes(data, tp.cryptoChain);
        tp.type |= PointerType.HasCryptChain;
    }
    let relayData = encodeTLV({
        0: (tp.relays || []).map(url => new TextEncoder().encode(url))
    });
    data = concatBytes(data, relayData);

    let leadBytes = Uint8Array.from([tp.type]);
    if ((tp.type & PointerType.SharedSecret) === PointerType.SharedSecret) {
        const keyPub = secp256k1.getPublicKey(secretOrPrivateKey, true).slice(1);
        leadBytes = concatBytes(leadBytes, keyPub);
    }
    const encrypted = await encrypt(data, cryptKey);
    const words = bech32.toWords(concatBytes(leadBytes, encrypted));
    return bech32.encode('nprivatechan', words, Bech32MaxSize)
}

export async function decode(nip19: string, secretOrPrivateKey: string): Promise<{
    type: string
    data: PrivateChannelPointer | string
}> {
    const { prefix, words } = bech32.decode(nip19, Bech32MaxSize);
    if (prefix === 'nprivatechan') {
        let cryptKey: Uint8Array;
        let data: Uint8Array | undefined;
        const bytes = bech32.fromWords(words);
        const pointerType = bytes[0] as PointerType;
        if ((pointerType & PointerType.SharedSecret) == PointerType.SharedSecret) {
            const publicKey = bytes.slice(1, 33);
            cryptKey = keyFromSharedSecret(publicKey, hexToBytes(secretOrPrivateKey));
            data = await decrypt(bytes.slice(33), cryptKey);
        } else {
            cryptKey = keyFromSecretString(secretOrPrivateKey);
            data = await decrypt(bytes.slice(1), cryptKey);
        }

        if (!data) throw new Error('invalid decryption for nprivatechan');
        let signingKey: Uint8Array | undefined;
        let cryptoKey: Uint8Array | undefined;
        let signingChain: Uint8Array | undefined;
        let cryptoChain: Uint8Array | undefined;
        let docIndex = data[0];
        let start = 1;
        if ((pointerType & PointerType.HasSignKey) === PointerType.HasSignKey) {
            signingKey = data.slice(start, start + 33);
            start += 33;
        }
        if ((pointerType & PointerType.HasCryptKey) === PointerType.HasCryptKey) {
            cryptoKey = data.slice(start, start + 33);
            start += 33;
        }
        if ((pointerType & PointerType.HasSignChain) === PointerType.HasSignChain) {
            signingChain = data.slice(start, start + 32);
            start += 32;
        }
        if ((pointerType & PointerType.HasCryptChain) === PointerType.HasCryptChain) {
            cryptoChain = data.slice(start, start + 32);
            start += 32;
        }
        let tlv = parseTLV(data.slice(start));
        return {
            type: 'nprivatechan',
            data: {
                type: pointerType,
                docIndex,
                signingKey,
                cryptoKey,
                signingChain,
                cryptoChain,
                relays: (tlv[0] || []).map(d => new TextDecoder().decode(d))
            }
        }

    } else {
        throw new Error(`The prefix ${prefix} cannot de decoded in this nip19 extension.`)
    }
}
