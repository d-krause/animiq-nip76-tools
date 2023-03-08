
import { HDKey, Versions } from '../index';

export const fixedMasterSeed = Uint32Array.from(
    [
        3123626959, 3154208545, 3994305465, 1472568558,
        3618158349, 3439014541, 3076634082, 633804803,
        4263442355, 3170210389, 505229381, 2560623682,
        686940108, 2059047636, 928116089, 412977049,
        2174918852, 2494639319, 4195938927, 3120642578,
        3035152170, 2248083361, 1431437554, 27719868,
        2664534681, 2934908797, 3366745739, 3643461863,
        439150876, 2772462065, 3041920294, 2184494669
    ]);
const crypto = require('crypto').webcrypto;;
export const randomMasterSeed = crypto.getRandomValues(new Uint32Array(32));

test('parseExtendedKey', () => {
    let k = HDKey.parseMasterSeed(fixedMasterSeed, Versions.bitcoinMain);
    expect(k.extendedPrivateKey)
        .toEqual('xprv9s21ZrQH143K4KWc5QaZvLAkfPygYaYauNNgaGy3YdTitrrMY15iYQ9pX1ozJhgrE5hLTqqDbaP5chw6opeXw89iMom7sBHu5xbJj8gyNo7');
    k = HDKey.parseMasterSeed(fixedMasterSeed, Versions.animiqAPI3);
    expect(k.extendedPrivateKey)
        .toEqual('aprvQ8ZyfbqpKrY9phnmSsSLU2B4NTmrr1dQTgECiyuik3uqnXM8K3janGZeQafcNsFL8mZMw53QarXmaneGuNPm2HK88bwb9Lf');
})

test('deriveChildKey', () => {
    let k = HDKey.parseMasterSeed(fixedMasterSeed, Versions.animiqAPI3);
    let c = k.deriveChildKey(0, false);
    expect(c.extendedPrivateKey)
        .toEqual('aprvNyoGiFUM17j2xcss1Q4fez1r4XBmCTj2QgbS5TG8g2Qwe4G7K5jxXNKCbB6XkCLmwtLLkYzA1vXZimdFJpnytf5zXXQUNtj');
    expect(c.extendedPublicKey)
        .toEqual('apubYbU1ctRJcY5sAaHGMPHxwsNe1hqzFn8Fjk5rrWDwAiJfFb8ei1yhXFgq9EhNgBiiY4zLu1ug9YZy62ENjBezFTdJndF7YQt');
    expect(c.extendedPublicKeyHash)
        .toEqual('G7cyxvzqDYAtRpDqUBfb8dM76FafirMWVgb8qKpwdQVT');

    let x = new HDKey({ publicKey: k.publicKey, chainCode: k.chainCode, version: k.version });
    expect(x.extendedPublicKey).toEqual(k.extendedPublicKey);
    expect(x.extendedPrivateKey).toBeNull();
    let cx = x.deriveChildKey(0, false);
    expect(cx.extendedPublicKey).toEqual(c.extendedPublicKey);

})