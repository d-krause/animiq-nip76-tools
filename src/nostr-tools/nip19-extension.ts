import * as crypto from 'crypto';
import * as secp256k1 from '@noble/secp256k1'
import { bech32 } from '@scure/base'

type TLV = { [t: number]: Uint8Array[] }

export const utf8Decoder = new TextDecoder('utf-8')
export const utf8Encoder = new TextEncoder()
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

function encrypt(data: Buffer, key: Buffer): Buffer {

    const iv = secp256k1.utils.randomBytes(16);
    const secret = key.slice(0, 32);
    const cipher = crypto.createCipheriv('aes-256-gcm', secret, iv);
    const crypted = cipher.update(data);
    const final = cipher.final();
    const out = Buffer.concat([cipher.getAuthTag(), iv, crypted, final]);
    return out;
}

function decrypt(data: Buffer, key: Buffer): Buffer | undefined {
    try {
        const bdata = data.slice(32) as any;
        const auth = data.slice(0, 16);
        const iv = data.slice(16, 32);
        const secret = key.slice(0, 32);
        const cipher = crypto.createDecipheriv('aes-256-gcm', secret, iv);
        cipher.setAuthTag(auth);
        const crypted = cipher.update(bdata, 'utf8');
        const final = cipher.final();
        const out = Buffer.concat([crypted, final]);
        return out;

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
    return crypto.createHmac('sha256', 'nip76').update(secret, 'utf8').digest();
};

const keyFromSharedSecret = (pubkey: Buffer, privkey: Buffer) => {
    const pubkeyPoint = secp256k1.Point.fromHex(pubkey);
    const sharedKey = secp256k1.getSharedSecret(privkey, pubkeyPoint).slice(1);
    return Buffer.from(sharedKey);
};

export function nprivateThreadEncode(tp: PrivateThreadPointer, secret: string | Buffer[]): string {
    let cryptKey: Buffer;
    if (typeof (secret) === 'string') {
        cryptKey = keyFromSecretString(secret);
    } else {
        cryptKey = keyFromSharedSecret(secret[0], secret[1]);
    }
    const ownerPubKey = Buffer.from(tp.ownerPubKey, 'hex');
    let relayData = encodeTLV({
        0: (tp.relays || []).map(url => utf8Encoder.encode(url))
    })
    const data = Buffer.concat([
        ownerPubKey,
        tp.addresses.pubkey,
        tp.addresses.chain,
        tp.secrets.pubkey,
        tp.secrets.chain,
        relayData
    ]);
    const encrypted = encrypt(data, cryptKey);
    const words = bech32.toWords(encrypted);
    return bech32.encode('nprivatethread1', words, Bech32MaxSize)
}

export function decode(nip19: string, secret: string | Buffer[]): {
    type: string
    data: PrivateThreadPointer | string
} {
    const { prefix, words } = bech32.decode(nip19, Bech32MaxSize);
    if (prefix === 'nprivatethread1') {
        let cryptKey: Buffer;
        if (typeof (secret) === 'string') {
            cryptKey = keyFromSecretString(secret);
        } else {
            cryptKey = keyFromSharedSecret(secret[0], secret[1]);
        }
        let encrypted = Buffer.from(bech32.fromWords(words));
        let data = decrypt(encrypted, cryptKey);
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
                relays: (tlv[0] || []).map(d => utf8Decoder.decode(d))
            }
        }

    } else {
        throw new Error(`The prefix ${prefix} cannot de decoded in this nip19 extension.`)
    }
}
