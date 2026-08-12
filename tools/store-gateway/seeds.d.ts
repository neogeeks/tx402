export declare const SEED_SCOPE: string;
export declare const SEED_NETWORK: string;
export declare const SEED_ASSET_ADDRESS: string;
export declare const SEED_ASSET_ID: string;
export declare const SEED_PINS: readonly string[];
export declare const SEED_NAMES: readonly string[];
export declare function applySeed(store: unknown, name: string, now: number): Promise<void>;
