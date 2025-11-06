declare module "tweetnacl" {
  export interface SignModule {
    detached(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
    keyPair: {
      (): { publicKey: Uint8Array; secretKey: Uint8Array };
      fromSecretKey(secretKey: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
    };
  }
  const nacl: {
    sign: SignModule;
  };
  export = nacl;
}

// Intentionally minimal; relying on installed types where possible
declare module "express" {
  export interface Request {
    body: unknown;
    params: Record<string, string>;
    query: Record<string, string>;
    headers: Record<string, string | string[] | undefined>;
    method: string;
  }
  
  export interface Response {
    statusCode: number;
    status(code: number): this;
    json(body: unknown): this;
    send(body: unknown): this;
  }
  
  export interface NextFunction {
    (err?: unknown): void;
  }
  
  export interface Express {
    use(...handlers: unknown[]): void;
    get(path: string, ...handlers: unknown[]): void;
    post(path: string, ...handlers: unknown[]): void;
    listen(port: number, callback?: () => void): void;
  }
  
  function express(): Express;
  namespace express {
    function json(options?: { limit?: string | number }): unknown;
  }
  
  export default express;
}

declare module "dotenv" {
  export interface DotenvConfigOptions {
    path?: string;
    encoding?: string;
    debug?: boolean;
    override?: boolean;
  }
  export function config(options?: DotenvConfigOptions): void;
  const _default: { config: typeof config };
  export default _default;
}

declare module "pg" {
  export class Client {
    constructor(config?: { connectionString?: string });
    connect(): Promise<void>;
    end(): Promise<void>;
    query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount?: number }>;
  }
}

declare module "@solana/web3.js" {
  export class PublicKey {
    constructor(value: string | Uint8Array | number[]);
    static findProgramAddressSync(seeds: (Buffer | Uint8Array)[], programId: PublicKey): [PublicKey, number];
    toBytes(): Uint8Array;
    toString(): string;
    static readonly SYSVAR_INSTRUCTIONS_PUBKEY: PublicKey;
    static readonly SYSVAR_CLOCK_PUBKEY: PublicKey;
  }
  
  export class Keypair {
    publicKey: PublicKey;
    secretKey: Uint8Array;
    static fromSecretKey(secretKey: Uint8Array): Keypair;
    static generate(): Keypair;
    sign(message: Uint8Array): Uint8Array;
  }
  
  export class TransactionInstruction {
    constructor(opts: { keys: AccountMeta[]; programId: PublicKey; data?: Buffer | Uint8Array });
    keys: AccountMeta[];
    programId: PublicKey;
    data: Uint8Array;
  }
  
  export interface AccountMeta {
    pubkey: PublicKey;
    isSigner: boolean;
    isWritable: boolean;
  }
  
  export class Transaction {
    recentBlockhash?: string;
    feePayer?: PublicKey;
    add(...items: TransactionInstruction[]): this;
    sign(...signers: Keypair[]): void;
  }
  
  export class SystemProgram {
    static readonly programId: PublicKey;
  }
  
  export class ComputeBudgetProgram {
    static setComputeUnitLimit(units: number): TransactionInstruction;
  }
  
  export class Ed25519Program {
    static createInstructionWithPublicKey(params: {
      publicKey: Uint8Array;
      message: Uint8Array;
      signature: Uint8Array;
    }): TransactionInstruction;
  }
  
  export type Commitment = "processed" | "confirmed" | "finalized";
  
  export interface GetAccountInfoConfig {
    commitment?: Commitment;
  }
  
  export interface AccountInfo<T> {
    data: T;
    executable: boolean;
    lamports: number;
    owner: PublicKey;
    rentEpoch?: number;
  }
  
  export interface ConfirmedSignatureInfo {
    signature: string;
    slot: number;
    err: unknown;
    memo: string | null;
    blockTime?: number | null;
  }
  
  export interface SignatureStatus {
    confirmationStatus?: Commitment;
    confirmations: number | null;
    err: unknown;
    slot: number;
  }
  
  export interface SignatureStatusResult {
    value: (SignatureStatus | null)[];
  }
  
  export class Connection {
    constructor(endpoint: string, config?: { commitment?: Commitment });
    getAccountInfo(pubkey: PublicKey, config?: GetAccountInfoConfig): Promise<AccountInfo<Buffer> | null>;
    getProgramAccounts(programId: PublicKey): Promise<{ pubkey: PublicKey; account: AccountInfo<Buffer> }[]>;
    getSignaturesForAddress(address: PublicKey, options?: { limit?: number }, commitment?: Commitment): Promise<ConfirmedSignatureInfo[]>;
    getSignatureStatuses(signatures: string[], config?: { searchTransactionHistory?: boolean }): Promise<SignatureStatusResult>;
    getLatestBlockhash(commitment?: Commitment): Promise<{ blockhash: string; lastValidBlockHeight: number }>;
    getSlot(): Promise<number>;
    onProgramAccountChange(programId: PublicKey, callback: (info: { accountId: PublicKey; accountInfo: AccountInfo<Buffer> }) => void | Promise<void>): Promise<number>;
    sendAndConfirmTransaction(transaction: Transaction, signers: Keypair[], options?: unknown): Promise<string>;
  }
  
  export function sendAndConfirmTransaction(connection: Connection, transaction: Transaction, signers: Keypair[]): Promise<string>;
}

