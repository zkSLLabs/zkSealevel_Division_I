declare module "bs58" {
  export function encode(input: Uint8Array | Buffer): string;
  export function decode(input: string): Buffer;
}


