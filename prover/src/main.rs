#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
//! zksl-prover: canonical artifact hashing and DS signing

use blake3::Hasher as Blake3;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    input: String,
    #[arg(long)]
    out: String,
    #[arg(long, default_value = "./keys/aggregator.json")]
    agg_key: String,
    #[arg(long, default_value_t = 1u64)]
    chain_id: u64,
    #[arg(long, default_value = "Val1dAt0rLock1111111111111111111111111111111")]
    program_id: String,
    #[arg(long, default_value_t = 1u64)]
    seq: u64,
}

#[derive(Serialize, Deserialize)]
struct Artifact {
    artifact_id: String,
    start_slot: u64,
    end_slot: u64,
    state_root_before: String,
    state_root_after: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let data = fs::read_to_string(&args.input)?;
    let artifact: Artifact = serde_json::from_str(&data)?;
    // proof_hash over canonical JSON (JCS-like) bytes
    let json = canonicalize(&artifact);
    let mut h = Blake3::new();
    h.update(json.as_bytes());
    let proof_hash = *h.finalize().as_bytes();
    // build DS from real inputs
    let chain_id: u64 = args.chain_id;
    let program_id = bs58::decode(args.program_id).into_vec()?;
    let program_id: [u8; 32] = program_id.try_into().map_err(|_| anyhow::anyhow!("invalid program_id"))?;
    let seq: u64 = args.seq;
    let mut ds = Vec::new();
    ds.extend_from_slice(b"zKSL/anchor/v1");
    ds.extend_from_slice(&chain_id.to_le_bytes());
    ds.extend_from_slice(&program_id);
    ds.extend_from_slice(&proof_hash);
    ds.extend_from_slice(&artifact.start_slot.to_le_bytes());
    ds.extend_from_slice(&artifact.end_slot.to_le_bytes());
    ds.extend_from_slice(&seq.to_le_bytes());
    let mut hd = Blake3::new();
    hd.update(&ds);
    let ds_hash = *hd.finalize().as_bytes();
    // sign DS using aggregator secret key from file (hex 64 bytes seed+key)
    let agg_bytes = read_aggregator_secret(&args.agg_key)?;
    let sk = SecretKey::from_bytes(&agg_bytes[0..32])?;
    let kp = SigningKey::from(sk);
    let sig = kp.sign(&ds);

    let out = serde_json::json!({
        "artifact_id": artifact.artifact_id,
        "proof_hash": hex::encode(proof_hash),
        "ds_hash": hex::encode(ds_hash),
        "signature": hex::encode(sig.to_bytes()),
    });
    fs::write(&args.out, serde_json::to_vec_pretty(&out)?)?;
    Ok(())
}

fn canonicalize<T: Serialize>(value: &T) -> String {
    // Deterministic map key ordering
    // Serialize, parse, and re-serialize with sorted keys
    let v = serde_json::to_value(value).expect("serialize");
    stringify_canonical(&v)
}

fn stringify_canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => {
            if *b { "true".to_string() } else { "false".to_string() }
        }
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap(),
        serde_json::Value::Array(a) => {
            let inner: Vec<String> = a.iter().map(stringify_canonical).collect();
            format!("[{}]", inner.join(","))
        }
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys.iter().map(|k| {
                let key = serde_json::to_string(k).unwrap();
                let val = stringify_canonical(&m.get(*k).unwrap());
                format!("{}:{}", key, val)
            }).collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

fn read_aggregator_secret(path: &str) -> anyhow::Result<Vec<u8>> {
    let p = PathBuf::from(path);
    let raw = fs::read_to_string(p)?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let hex = v.get("secretKey").and_then(|x| x.as_str()).ok_or_else(|| anyhow::anyhow!("missing secretKey"))?;
    let bytes = hex::decode(hex)?;
    if bytes.len() != 64 { anyhow::bail!("secretKey must be 64 hex bytes"); }
    Ok(bytes)
}


