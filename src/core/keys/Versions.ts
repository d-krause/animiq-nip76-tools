/*
 * Copyright Kepler Group, Inc. - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * The contents of this file are considered proprietary and confidential.
 * Written by Dave Krause <dkrause@keplergroupsystems.com>, February 2019
 */

export interface Bip32SerializationPrefix {
    public: number;
    private: number;
}

export interface Bip32NetworkInfo {
    bip32: Bip32SerializationPrefix;
    networkId: number;
    name: string;
    cloaked: boolean;
}

export const Versions = {
    bitcoinMain: {
        name: 'bitcoinMain',
        bip32: {
            public: 0x0488b21e,
            private: 0x0488ade4
        },
        networkId: 0
    } as Bip32NetworkInfo,
    bitcoinTest: {
        name: 'bitcoinTest',
        bip32: {
            public: 0x043587cf,
            private: 0x04358394
        },
        networkId: 0x6f
    } as Bip32NetworkInfo,
    animiqAPI3: {
        name: 'animiqAPI3',
        bip32: {
            public:  0x08f3b11b,
            private: 0x08f3a350
        },
        networkId: 0,
        cloaked: true
    } as Bip32NetworkInfo,
    animiqAPI2: {
        name: 'animiqAPI2',
        bip32: {
            public:  0x02bf4968,
            private: 0x02bf452d
        },
        networkId: 0
    } as Bip32NetworkInfo
};
