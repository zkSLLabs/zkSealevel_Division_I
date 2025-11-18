Param(
    [string]$RpcUrl = "https://api.devnet.solana.com",
    [int]$BackSlots = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$slot = solana -u $RpcUrl slot
if (-not $slot) { throw "Failed to fetch current slot" }

$start = [int]$slot - $BackSlots
if ($start -lt 1) { $start = 1 }

$outDir = Join-Path $PSScriptRoot "..\\prover"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$out = Join-Path $outDir ("proof_devnet_{0}.json" -f $slot)

Write-Host ("Generating proof: start={0} end={1} out={2}" -f $start, $slot, $out)

$proverExe = Join-Path $PSScriptRoot "..\\prover\\target\\release\\prover.exe"
& $proverExe stark-prove-real `
    --rpc $RpcUrl `
    --start $start `
    --end $slot `
    --proof-hash 0000000000000000000000000000000000000000000000000000000000000000 `
    --out $out

Write-Host "Proof generated at: $out"


