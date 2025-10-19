declare module "@solana/web3.js" {
  export class PublicKey { constructor(value: string | Uint8Array); toBytes(): Uint8Array }
  export class Keypair { static fromSecretKey(sk: Uint8Array): any; publicKey: PublicKey }
  export class TransactionInstruction { constructor(args: any) }
  export class Transaction { recentBlockhash: string; feePayer: PublicKey; add(ix: any): void; sign(...k: any[]): void }
  export class SystemProgram { static programId: PublicKey }
  export function sendAndConfirmTransaction(conn: any, tx: any, signers: any[], opts?: any): Promise<string>
  export class Connection { constructor(url: string, opts?: any); getLatestBlockhash(): Promise<{ blockhash: string }> }
}


