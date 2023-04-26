
import { HDKey, HDKIndex } from '../keys';

export interface IWalletStorage {
    clearSession(): void;
    getDocumentsIndex(args: WalletConstructorArgs): HDKIndex;
    save(args: WalletStorageArgs): Promise<boolean>;
    load(publicKey: string, privateKey?: string): Promise<WalletConstructorArgs>;
}

export interface WalletStorageArgs {
    publicKey: string;
    privateKey?: string;
    masterKey?: HDKey;
    wordset?: Uint32Array;
}

export interface WalletConstructorArgs extends WalletStorageArgs {
    rootKey?: HDKey;
    documentsIndex?: HDKIndex;
    store?: IWalletStorage;
}