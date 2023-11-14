
import { HDKey, HDKIndex } from '../keys';

export interface KeyStoreStorage {
    clearSession(): void;
    getDocumentsIndex(args: KeyStoreConstructorArgs): HDKIndex;
    save(args: KeyStoreStorageArgs): Promise<boolean>;
    load(publicKey: string, privateKey?: string): Promise<KeyStoreConstructorArgs>;
}

export interface KeyStoreStorageArgs {
    publicKey: string;
    privateKey?: string;
    masterKey?: HDKey;
    wordset?: Uint32Array;
}

export interface KeyStoreConstructorArgs extends KeyStoreStorageArgs {
    rootKey?: HDKey;
    documentsIndex?: HDKIndex;
    store?: KeyStoreStorage;
}