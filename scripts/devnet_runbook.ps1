Param(
  [string]$RpcUrl = "https://api.devnet.solana.com",
  [string]$WsUrl = "wss://api.devnet.solana.com",
  [string]$ChainId = "103",
  [string]$DatabaseUrl = "postgres://postgres:postgres@localhost:5432/zksl",
  [string]$AggregatorKeyPath = "./keys/aggregator.json",
  [string]$ProgramName = "validator_lock"
)

$ErrorActionPreference = "Stop"

function Require($cmd) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    Write-Error "Missing required tool: $cmd"; exit 1
  }
}

Require solana
Require anchor

Write-Host "[zksl][devnet] Setting Solana RPC: $RpcUrl"
solana config set --url $RpcUrl | Out-Null

if (-not $env:HOME) { $env:HOME = $env:USERPROFILE }
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE "t" }

Write-Host "[zksl][devnet] Preparing Cargo lockfiles for Solana toolchain"
if (Test-Path "programs/$ProgramName/Cargo.lock") {
  Remove-Item -Force "programs/$ProgramName/Cargo.lock"
}

Push-Location "programs/$ProgramName"
Write-Host "[zksl][devnet] Generating Cargo.lock (v3) with Solana toolchain"
cargo +solana generate-lockfile
Write-Host "[zksl][devnet] Pinning transitive crates for Solana MSRV"
cargo +solana update -p proc-macro-crate@3.4.0 --precise 3.2.0
cargo +solana update -p indexmap --precise 2.11.4
cargo +solana update -p toml_edit --precise 0.22.27
Pop-Location

Write-Host "[zksl][devnet] Building Anchor program (skip IDL)"
anchor build --no-idl

Write-Host "[zksl][devnet] Deploying program to Devnet"
anchor deploy --provider.cluster devnet

Write-Host "[zksl][devnet] Resolving program ID from 'anchor keys list'"
$keys = anchor keys list | Out-String
$progId = ($keys -split "`n" | Where-Object { $_ -match "^$ProgramName\s*:\s*([1-9A-HJ-NP-Za-km-z]{32,44})" } | ForEach-Object { ($Matches[1]) })
if (-not $progId) { Write-Error "Unable to resolve program id for $ProgramName"; exit 1 }
Write-Host "[zksl][devnet] Program ID: $progId"

Write-Host "[zksl][devnet] Updating declare_id! in programs/$ProgramName/src/lib.rs"
$libPath = Join-Path "programs/$ProgramName/src" "lib.rs"
$content = Get-Content -Raw $libPath
$updated = ($content -replace 'declare_id!\("[^"]+"\);', "declare_id!(`"$progId`");")
if ($updated -ne $content) {
  Set-Content -NoNewline -Path $libPath -Value $updated
  Write-Host "[zksl][devnet] Updated declare_id!. Rebuilding..."
  anchor build
}

Write-Host "[zksl][devnet] Ensuring aggregator key at $AggregatorKeyPath"
node scripts/gen_aggregator_key.js $AggregatorKeyPath

Write-Host "[zksl][devnet] Writing .env"
$envPath = ".env"
$envLines = @(
  "RPC_URL=$RpcUrl",
  "WS_URL=$WsUrl",
  "PROGRAM_ID_VALIDATOR_LOCK=$progId",
  "CHAIN_ID=$ChainId",
  "MIN_FINALITY_COMMITMENT=finalized",
  "AGGREGATOR_KEYPAIR_PATH=$AggregatorKeyPath",
  "ARTIFACT_DIR=./orchestrator/data/artifacts",
  "DATABASE_URL=$DatabaseUrl",
  "PORT=8080",
  "TZ=UTC",
  "LC_ALL=C",
  "LANG=C"
)
Set-Content -Path $envPath -Value ($envLines -join "`n")

Write-Host "[zksl][devnet] Apply database migrations"
if (Get-Command psql -ErrorAction SilentlyContinue) {
  & scripts/db_migrate.sh
} else {
  Write-Warning "psql not found, skip migrations"
}

Write-Host "[zksl][devnet] Devnet program deployed and environment prepared."
Write-Host "[zksl][devnet] Next steps:"
Write-Host "  1) Initialize config: npx tsx cli/src/main.ts init-config --keypair <PAYER.json> --mint <ZKSL_MINT> --agg-key $AggregatorKeyPath --chain-id $ChainId"
Write-Host "  2) Register validator: npx tsx cli/src/main.ts register --keypair <VALIDATOR.json> --mint <ZKSL_MINT>"
Write-Host "  3) Start orchestrator and indexer with Devnet .env and anchor a proof via /prove + /anchor"


