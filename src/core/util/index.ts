import { HARDENED_KEY_OFFSET, HDKey } from '../keys';

export const max_date_seconds = 8640000000000;

export const getNowSeconds = () => Math.floor(Date.now() / 1000);

export function getCreatedAtIndexes(created_at?: number): { created_at: number, index0: number, index1: number } {
    created_at = created_at || getNowSeconds();
    const index0 = Math.floor(created_at / HARDENED_KEY_OFFSET);
    const index1 = created_at % HARDENED_KEY_OFFSET;
    return { created_at, index0, index1 };
}
export interface KeySetReductionArgs {
    root: HDKey;
    wordset: Uint32Array;
    offset?: number;
    right?: boolean;
    map?: (n: number) => number;
    sort?: (a: number, b: number) => number;
}

export function getIndexReducer(index: number): (hdk: HDKey, num: number) => HDKey {
    return (hdk: HDKey, num: number) => hdk.deriveChildKey((num * (index + 1)) % HARDENED_KEY_OFFSET, true);
}

export function getReducedKey(args: KeySetReductionArgs): HDKey {
    const reducer = getIndexReducer(args.offset || 0);
    let wordset = args.wordset;
    if (args.map) wordset = wordset.map(args.map);
    if (args.sort) wordset = wordset.sort(args.sort);
    if (args.right) {
        return wordset.reduceRight<HDKey>(reducer, args.root);
    } else {
        return wordset.reduce<HDKey>(reducer, args.root);
    }
}

export const KeySetCommon = {
    offsets: [0, 0x10000000, 0x20000000, 0x30000000, 0x40000000, 0x50000000, 0x60000000, 0x70000000],
    sort: {
        asc: (a: number, b: number) => a - b,
        desc: (a: number, b: number) => b - a
    },
    map: {
        square: (a: number) => Math.pow(a, 2),
        squareRoot: (a: number) => Math.floor(Math.sqrt(a)),
        closestSquare: (a: number) => Math.pow(Math.floor(Math.sqrt(a)), 2),
        closestSquareDistance: (a: number) => a - Math.pow(Math.floor(Math.sqrt(a)), 2),
    }

}