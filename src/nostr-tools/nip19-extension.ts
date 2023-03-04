import * as secp256k1 from '@noble/secp256k1'
import { bech32 } from '@scure/base'
// import { nip19 } from 'nostr-tools';

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

export type SecureThreadPointer = {
    version: number;
    addresses: {
        pubkey: string, // hex
        chain?: string // hex
    },
    secrets?: {
        pubkey: string, // hex
        chain?: string // hex
    }
    relays?: string[]
}


export function nsecthreadEncode(secthread: SecureThreadPointer): string {
    let version = new ArrayBuffer(2)
    new DataView(version).setUint16(0, secthread.version, false)
    let data = encodeTLV({
        0: [new Uint8Array(version)],
        1: [
            secp256k1.utils.hexToBytes(secthread.addresses.pubkey),
            secthread.addresses.chain ? secp256k1.utils.hexToBytes(secthread.addresses.chain) : new Uint8Array(),
            secthread.secrets?.pubkey ? secp256k1.utils.hexToBytes(secthread.secrets.pubkey) : new Uint8Array(),
            secthread.secrets?.chain ? secp256k1.utils.hexToBytes(secthread.secrets.chain) : new Uint8Array()
        ],
        2: (secthread.relays || []).map(url => utf8Encoder.encode(url))
    })
    let words = bech32.toWords(data)
    return bech32.encode('nsecthread', words, Bech32MaxSize)
}

export function decode(nip19: string): {
    type: string
    data: SecureThreadPointer | string
} {
    const { prefix, words } = bech32.decode(nip19, Bech32MaxSize);
    if (prefix === 'nsecthread') {
        let data = new Uint8Array(bech32.fromWords(words))
        let tlv = parseTLV(data)
        if (tlv[1][0].length !== 32) throw new Error('TLV 1-0 should be 32 bytes')
        if (tlv[1][1].length !== 0 && tlv[1][1].length !== 32) throw new Error('TLV 1-1 should be 0 or 32 bytes')
        if (tlv[1][2].length !== 0 && tlv[1][2].length !== 32) throw new Error('TLV 1-2 should be 0 or 32 bytes')
        if (tlv[1][3].length !== 0 && tlv[1][3].length !== 32) throw new Error('TLV 1-3 should be 0 or 32 bytes')

        return {
            type: 'nsecthread',
            data: {
                version: parseInt(secp256k1.utils.bytesToHex(tlv[0][0]), 16),
                addresses: {
                    pubkey: secp256k1.utils.bytesToHex(tlv[1][0]),
                    chain: tlv[1][1].length ? secp256k1.utils.bytesToHex(tlv[1][1]) : undefined,
                },
                secrets: tlv[1][2].length ? {
                    pubkey: secp256k1.utils.bytesToHex(tlv[1][2]),
                    chain: tlv[1][3].length ? secp256k1.utils.bytesToHex(tlv[1][3]) : undefined,
                }: undefined,
                relays: (tlv[2]||[]).map(d => utf8Decoder.decode(d))
            }
        }
    } else {
        throw new Error(`The prefix ${prefix} cannot de decoded in this nip19 extension.`)
    }
}
