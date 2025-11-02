// PDA KATs per spec: compute PDAs for fixed seeds
const web3 = require('@solana/web3.js');

(function main() {
  const programIdStr = process.env.PROGRAM_ID_VALIDATOR_LOCK || '11111111111111111111111111111111';
  const programId = new web3.PublicKey(programIdStr);

  const configPda = web3.PublicKey.findProgramAddressSync([
    Buffer.from('zksl'), Buffer.from('config')
  ], programId)[0];

  const aggregatorPda = web3.PublicKey.findProgramAddressSync([
    Buffer.from('zksl'), Buffer.from('aggregator')
  ], programId)[0];

  const rangePda = web3.PublicKey.findProgramAddressSync([
    Buffer.from('zksl'), Buffer.from('range')
  ], programId)[0];

  const zero32 = Buffer.alloc(32, 0);
  const seqLe = Buffer.alloc(8); seqLe.writeBigUInt64LE(1n);
  const proofPda = web3.PublicKey.findProgramAddressSync([
    Buffer.from('zksl'), Buffer.from('proof'), zero32, seqLe
  ], programId)[0];

  const validatorSeed = new web3.Keypair().publicKey.toBytes();
  const validatorPda = web3.PublicKey.findProgramAddressSync([
    Buffer.from('zksl'), Buffer.from('validator'), Buffer.from(validatorSeed)
  ], programId)[0];

  // eslint-disable-next-line no-console
  console.log(JSON.stringify({
    programId: programId.toBase58(),
    configPda: configPda.toBase58(),
    aggregatorPda: aggregatorPda.toBase58(),
    rangePda: rangePda.toBase58(),
    proofPda: proofPda.toBase58(),
    validatorPda: validatorPda.toBase58()
  }, null, 2));
})();


