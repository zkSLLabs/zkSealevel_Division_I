# zkSealevel Keys Directory

⚠️ **WARNING: NEVER COMMIT ACTUAL PRIVATE KEYS TO VERSION CONTROL!** ⚠️

This directory contains cryptographic keypairs for the zkSealevel system. All actual key files are gitignored.

## Key Files

### aggregator.json (GITIGNORED)
Ed25519 keypair used by the orchestrator to sign domain separation messages.

**Generate with:**
```bash
node scripts/gen_aggregator_key.js keys/aggregator.json
```

**Format:**
```json
{
  "secretKey": "128_character_hex_string_representing_64_bytes"
}
```

Or Solana array format:
```json
[1,2,3,...64_numbers]
```

### sol_agg.json (GITIGNORED)
Solana keypair used as fee payer for transactions. Can be the same as aggregator or different.

**Generate with:**
```bash
solana-keygen new --outfile keys/sol_agg.json --no-bip39-passphrase
```

**Format:** Solana standard 64-byte array
```json
[1,2,3,...64_numbers]
```

## Security Best Practices

1. **Never commit** actual key files to Git
2. **Restrict permissions** on key files: `chmod 600 keys/*.json` (Unix) or equivalent
3. **Generate unique keys** for each environment (dev, staging, production)
4. **Rotate keys regularly** using the `update_config` instruction
5. **Back up keys securely** to encrypted storage
6. **Use hardware wallets** or HSMs for production deployments

## File Permissions

Ensure key files have restricted permissions:
```bash
# Unix/Linux/macOS
chmod 600 keys/*.json

# Windows (PowerShell as Administrator)
icacls keys\*.json /inheritance:r /grant:r "$env:USERNAME:(R,W)"
```

## Environment Variables

Configure your `.env` file to point to the correct keys:
```bash
AGGREGATOR_KEYPAIR_PATH=./keys/aggregator.json
FEE_PAYER_KEYPAIR_PATH=./keys/sol_agg.json
```

## Gitignore Status

✅ All `keys/*.json` files are gitignored  
✅ Only `keys/*.example.json` and `keys/README.md` are tracked  
✅ Target deploy keypairs are also gitignored: `target/deploy/*-keypair.json`

