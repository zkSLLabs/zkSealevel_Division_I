declare module "tweetnacl" {
  const nacl: any;
  export = nacl;
}

// Intentionally minimal; relying on installed types where possible
declare module "express" {
  const e: any;
  export default e;
  export type Request = any;
  export type Response = any;
}

declare module "dotenv" {
  export function config(...args: any[]): void;
  const _default: { config: typeof config };
  export default _default;
}

declare module "pg" {
  export class Client {
    constructor(...args: any[]);
    connect(): Promise<void>;
    end(): Promise<void>;
    query(...args: any[]): Promise<any>;
  }
}

declare module "@solana/web3.js" {
  export const PublicKey: any;
  export const Keypair: any;
  export const TransactionInstruction: any;
  export const Transaction: any;
  export const SystemProgram: any;
  export const ComputeBudgetProgram: any;
  export const Ed25519Program: any;
  export const Connection: any;
  export function sendAndConfirmTransaction(...args: any[]): Promise<string>;
}

