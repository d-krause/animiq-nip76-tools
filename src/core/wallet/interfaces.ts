
import { HDKey } from '../keys';

export interface IWalletStorage {
    clearSession(): void;
    save(args: WalletStorageArgs): Promise<boolean>;
    load(publicKey: string, privateKey?: string): Promise<WalletConstructorArgs>;
}

export interface WalletStorageArgs {
    key?: HDKey;
    lockwords?: Int32Array;
    publicKey: string;
    privateKey?: string;
}

export interface WalletConstructorArgs extends WalletStorageArgs {
    store: IWalletStorage;
    isGuest: boolean;
    isInSession: boolean;
}