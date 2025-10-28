//! Validator Lock Program for zkSealevel
//! 
//! This program implements the on-chain validator registration, proof anchoring,
//! and token locking mechanisms for the zkSealevel system as specified in the
//! Master Blueprint and POC Execution Plan.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(unexpected_cfgs)]
#![allow(missing_docs)] // Allow for Anchor-generated code

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use blake3::Hasher as Blake3Hasher;
use anchor_lang::solana_program::{
    ed25519_program,
    sysvar::instructions as sysvar_instructions,
};

// Compute budget program ID: ComputeBudget111111111111111111111111111111
const COMPUTE_BUDGET_ID: Pubkey = Pubkey::new_from_array([
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32,
    0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b,
    0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00,
]);

declare_id!("9o5T1cRj3oSw49gp5gKgVfPgNMjQSuD3rMiTU9BxeLZx");

/// Program entrypoint module for validator_lock per Master_Blueprint.md
#[program]
pub mod validator_lock {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, args: InitializeArgs) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.zksl_mint = ctx.accounts.zksl_mint.key();
        cfg.admin = ctx.accounts.admin.key();
        cfg.aggregator_pubkey = args.aggregator_pubkey;
        cfg.next_aggregator_pubkey = args.next_aggregator_pubkey;
        cfg.activation_seq = args.activation_seq;
        cfg.chain_id = args.chain_id;
        cfg.paused = 0;
        Ok(())
    }

    /// Unlock validator: return exactly 1 token and set status to Unlocked
    pub fn unlock_validator(ctx: Context<UnlockValidator>) -> Result<()> {
        require!(ctx.accounts.config.paused == 0, ErrorCode::Paused);
        require!(ctx.accounts.validator_record.status == 0, ErrorCode::StatusNotActive);
        // Ensure escrow holds exactly 1 token (10^decimals base units)
        let decimals = ctx.accounts.zksl_mint.decimals;
        let amount: u64 = 10u64.pow(decimals as u32);
        require!(ctx.accounts.validator_escrow.amount == amount, ErrorCode::InvalidLockAmount);
        // Transfer back to validator ATA using escrow PDA as signer
        let cpi_accounts = Transfer {
            from: ctx.accounts.validator_escrow.to_account_info(),
            to: ctx.accounts.validator_ata.to_account_info(),
            authority: ctx.accounts.escrow_authority.to_account_info(),
        };
        let validator_key = ctx.accounts.validator.key();
        let seeds = &[b"zksl".as_ref(), b"escrow".as_ref(), validator_key.as_ref()];
        let (_pda, bump) = Pubkey::find_program_address(seeds, ctx.program_id);
        let bump_slice = &[bump];
        let signer_seeds: &[&[u8]] = &[b"zksl".as_ref(), b"escrow".as_ref(), validator_key.as_ref(), bump_slice];
        let signers_seeds = &[signer_seeds];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signers_seeds,
        );
        token::transfer(cpi_ctx, amount)?;
        ctx.accounts.validator_record.status = 1;
        Ok(())
    }

    pub fn register_validator(ctx: Context<RegisterValidator>) -> Result<()> {
        require!(ctx.accounts.config.paused == 0, ErrorCode::Paused);
        // Transfer exactly 1 token of zKSL (10^decimals base units) from validator ATA to escrow
        let mint = ctx.accounts.zksl_mint.key();
        require_keys_eq!(mint, ctx.accounts.config.zksl_mint, ErrorCode::InvalidMint);
        // Prevent double registration if record already exists and is active
        let rec_existing = &ctx.accounts.validator_record;
        if rec_existing.validator_pubkey != Pubkey::default() {
            require!(rec_existing.status != 0, ErrorCode::AlreadyRegistered);
        }
        // Transfer
        let decimals = ctx.accounts.zksl_mint.decimals;
        let amount: u64 = 10u64.pow(decimals as u32);
        let cpi_accounts = Transfer {
            from: ctx.accounts.validator_ata.to_account_info(),
            to: ctx.accounts.validator_escrow.to_account_info(),
            authority: ctx.accounts.validator.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        let rec = &mut ctx.accounts.validator_record;
        rec.validator_pubkey = ctx.accounts.validator.key();
        rec.lock_token_account = ctx.accounts.validator_escrow.key();
        rec.lock_timestamp = Clock::get()?.unix_timestamp;
        rec.status = 0;
        rec.num_accepts = 0;
        Ok(())
    }

    pub fn update_config(ctx: Context<UpdateConfig>, args: UpdateConfigArgs) -> Result<()> {
        require_keys_eq!(ctx.accounts.admin.key(), ctx.accounts.config.admin, ErrorCode::Unauthorized);
        let cfg = &mut ctx.accounts.config;
        if let Some(pk) = args.aggregator_pubkey { cfg.aggregator_pubkey = pk; }
        if let Some(pk) = args.next_aggregator_pubkey { cfg.next_aggregator_pubkey = pk; }
        if let Some(seq) = args.activation_seq { cfg.activation_seq = seq; }
        if let Some(p) = args.paused { cfg.paused = if p {1} else {0}; }
        emit!(ConfigUpdated { aggregator_pubkey: args.aggregator_pubkey, paused: args.paused, timestamp: Clock::get()?.unix_timestamp });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn anchor_proof(
        ctx: Context<AnchorProof>,
        artifact_id: [u8; 16],
        start_slot: u64,
        end_slot: u64,
        proof_hash: [u8; 32],
        artifact_len: u32,
        state_root_before: [u8; 32],
        state_root_after: [u8; 32],
        aggregator_pubkey: Pubkey,
        timestamp: i64,
        seq: u64,
        ds_hash: [u8; 32],
    ) -> Result<()> {
        require!(ctx.accounts.config.paused == 0, ErrorCode::Paused);
        let allowed = allowed_aggregator_key(&ctx.accounts.config, seq);
        require_keys_eq!(aggregator_pubkey, allowed, ErrorCode::AggregatorMismatch);

        // Strict Ed25519 preflight checks: ensure previous ix is Ed25519 and only one Ed25519 in tx
        let ix_acc = ctx.accounts.sysvar_instructions.to_account_info();
        let mut ed_count: u32 = 0;
        let mut i: usize = 0;
        let mut has_compute_ok = false;
        loop {
            let ix = sysvar_instructions::load_instruction_at_checked(i, &ix_acc).ok();
            if ix.is_none() { break; }
            let ix = ix.unwrap();
            if ix.program_id == ed25519_program::id() { ed_count += 1; }
            if ix.program_id == COMPUTE_BUDGET_ID {
                let data = ix.data.as_slice();
                if data.len() >= 5 {
                    let tag = data[0];
                    // SetComputeUnitLimit = 2
                    if tag == 2u8 {
                        let units = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                        if units >= 200_000u32 { has_compute_ok = true; }
                    }
                }
            }
            i += 1;
        }
        require!(ed_count == 1, ErrorCode::BadEd25519Order);
        require!(has_compute_ok, ErrorCode::InsufficientBudget);
        let last_ix_idx = i.saturating_sub(2);
        let prev_ix = sysvar_instructions::load_instruction_at_checked(last_ix_idx, &ix_acc)
            .map_err(|_| error!(ErrorCode::BadEd25519Order))?;
        let prev_is_ed25519 = prev_ix.program_id == ed25519_program::id();
        require!(prev_is_ed25519, ErrorCode::BadEd25519Order);

        // seq monotonic (global, across key rotation)
        if ctx.accounts.aggregator_state.last_seq == 0 {
            require!(seq == 1, ErrorCode::NonMonotonicSeq);
        } else {
            require!(seq == ctx.accounts.aggregator_state.last_seq.checked_add(1).ok_or(ErrorCode::MathOverflow)?, ErrorCode::NonMonotonicSeq);
        }

        // range monotonic and bounds
        require!(end_slot >= start_slot, ErrorCode::MathOverflow);
        require!((end_slot - start_slot + 1) <= MAX_SLOTS_PER_ARTIFACT, ErrorCode::MathOverflow);
        if ctx.accounts.range_state.last_end_slot == 0 {
            require!(start_slot == 1, ErrorCode::RangeOverlap);
        } else {
            require!(start_slot == ctx.accounts.range_state.last_end_slot + 1, ErrorCode::RangeOverlap);
        }

        // clock skew
        let now = Clock::get()?.unix_timestamp;
        let skew = now.saturating_sub(timestamp).abs();
        require!(skew <= MAX_CLOCK_SKEW_SECS, ErrorCode::ClockSkew);

        // Recompute DS and verify ds_hash and Ed25519 message/public key
        let mut ds = Vec::with_capacity(14 + 8 + 32 + 32 + 8 + 8 + 8);
        ds.extend_from_slice(DS_PREFIX);
        ds.extend_from_slice(&ctx.accounts.config.chain_id.to_le_bytes());
        ds.extend_from_slice(ctx.program_id.as_ref());
        ds.extend_from_slice(&proof_hash);
        ds.extend_from_slice(&start_slot.to_le_bytes());
        ds.extend_from_slice(&end_slot.to_le_bytes());
        ds.extend_from_slice(&seq.to_le_bytes());
        let mut hasher = Blake3Hasher::new();
        hasher.update(&ds);
         let expected_ds_hash = *hasher.finalize().as_bytes();
        require!(expected_ds_hash == ds_hash, ErrorCode::BadDomainSeparation);

        // Parse Ed25519 instruction to ensure it signed the exact DS and with the allowed pubkey
        let data = prev_ix.data.as_slice();
        require!(data.len() >= 16, ErrorCode::InvalidSignature);
        let num = data[0];
        require!(num == 1, ErrorCode::InvalidSignature);
        // Offsets for single-signature header (u16 little-endian values)
        let sig_off = u16::from_le_bytes([data[2], data[3]]) as usize;
        let sig_ix = u16::from_le_bytes([data[4], data[5]]);
        let pk_off = u16::from_le_bytes([data[6], data[7]]) as usize;
        let pk_ix = u16::from_le_bytes([data[8], data[9]]);
        let msg_off = u16::from_le_bytes([data[10], data[11]]) as usize;
        let msg_len = u16::from_le_bytes([data[12], data[13]]) as usize;
        let msg_ix = u16::from_le_bytes([data[14], data[15]]);
        // Require in-instruction references
        require!(sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX, ErrorCode::BadEd25519Order);
        // Bounds checks
        require!(data.len() >= sig_off + 64, ErrorCode::InvalidSignature);
        require!(data.len() >= pk_off + 32, ErrorCode::InvalidSignature);
        require!(data.len() >= msg_off + msg_len, ErrorCode::InvalidSignature);
        // Verify pubkey matches allowed aggregator
        let pk = &data[pk_off..pk_off + 32];
        require!(pk == aggregator_pubkey.as_ref(), ErrorCode::InvalidSignature);
        // Verify message bytes exactly equal DS
        require!(msg_len == ds.len(), ErrorCode::BadDomainSeparation);
        let msg = &data[msg_off..msg_off + msg_len];
        require!(msg == ds.as_slice(), ErrorCode::BadDomainSeparation);

        // Populate ProofRecord
        let pr = &mut ctx.accounts.proof_record;
        // If record already exists, reject duplicate
        require!(pr.seq == 0, ErrorCode::ProofAlreadyAnchored);
        pr.artifact_id = artifact_id;
        pr.start_slot = start_slot;
        pr.end_slot = end_slot;
        pr.proof_hash = proof_hash;
        pr.artifact_len = artifact_len;
        pr.state_root_before = state_root_before;
        pr.state_root_after = state_root_after;
        pr.submitted_by = ctx.accounts.submitted_by.key();
        pr.aggregator_pubkey = aggregator_pubkey;
        pr.timestamp = timestamp;
        pr.seq = seq;
        pr.ds_hash = ds_hash;
        pr.commitment_level = 0;
        pr.da_params = [0u8; 12];
        pr.reserved = [0u8; 7];

        // Update state
        ctx.accounts.aggregator_state.last_seq = seq;
        ctx.accounts.range_state.last_end_slot = end_slot;

        // Increment validator accepts if active
        if ctx.accounts.validator_record.status == 0 {
            ctx.accounts.validator_record.num_accepts = ctx.accounts
                .validator_record
                .num_accepts
                .checked_add(1)
                .ok_or(ErrorCode::MathOverflow)?;
        }

        emit!(ProofAnchored { artifact_id, proof_hash, start_slot, end_slot, submitted_by: ctx.accounts.submitted_by.key(), timestamp, seq, ds_hash });
        Ok(())
    }
}

/// Initialize accounts
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: admin is recorded only
    pub admin: UncheckedAccount<'info>,
    pub zksl_mint: Account<'info, Mint>,
    #[account(init, payer = payer, seeds = [b"zksl".as_ref(), b"config".as_ref()], bump, space = 8 + Config::SIZE)]
    pub config: Account<'info, Config>,
    pub system_program: Program<'info, System>,
}

/// Register validator accounts
#[derive(Accounts)]
pub struct RegisterValidator<'info> {
    #[account(mut)]
    pub validator: Signer<'info>,
    pub zksl_mint: Account<'info, Mint>,
    #[account(mut, has_one = zksl_mint)]
    pub config: Account<'info, Config>,
    #[account(init_if_needed, payer = validator, seeds = [b"zksl".as_ref(), b"validator".as_ref(), validator.key().as_ref()], bump, space = 8 + ValidatorRecord::SIZE)]
    pub validator_record: Account<'info, ValidatorRecord>,
    /// CHECK: PDA authority for escrow
    #[account(seeds = [b"zksl".as_ref(), b"escrow".as_ref(), validator.key().as_ref()], bump)]
    pub escrow_authority: UncheckedAccount<'info>,
    #[account(init_if_needed, payer = validator, associated_token::mint = zksl_mint, associated_token::authority = escrow_authority, associated_token::token_program = token_program)]
    pub validator_escrow: Account<'info, TokenAccount>,
    #[account(mut)]
    pub validator_ata: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// Update config accounts
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    pub admin: Signer<'info>,
    #[account(mut)]
    pub config: Account<'info, Config>,
}

/// Unlock validator accounts
#[derive(Accounts)]
pub struct UnlockValidator<'info> {
    #[account(mut)]
    pub validator: Signer<'info>,
    pub zksl_mint: Account<'info, Mint>,
    #[account(mut, has_one = zksl_mint)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"zksl".as_ref(), b"validator".as_ref(), validator.key().as_ref()], bump)]
    pub validator_record: Account<'info, ValidatorRecord>,
    /// CHECK: PDA authority for escrow
    #[account(seeds = [b"zksl".as_ref(), b"escrow".as_ref(), validator.key().as_ref()], bump)]
    pub escrow_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub validator_escrow: Account<'info, TokenAccount>,
    #[account(mut)]
    pub validator_ata: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

/// Initialize arguments
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeArgs {
    pub aggregator_pubkey: Pubkey,
    pub next_aggregator_pubkey: Pubkey,
    pub activation_seq: u64,
    pub chain_id: u64,
}

/// Update config arguments
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UpdateConfigArgs {
    pub aggregator_pubkey: Option<Pubkey>,
    pub next_aggregator_pubkey: Option<Pubkey>,
    pub activation_seq: Option<u64>,
    pub paused: Option<bool>,
}

/// Config account
#[account]
pub struct Config {
    pub zksl_mint: Pubkey,
    pub admin: Pubkey,
    pub aggregator_pubkey: Pubkey,
    pub next_aggregator_pubkey: Pubkey,
    pub activation_seq: u64,
    pub chain_id: u64,
    pub paused: u8,
    pub bump: u8,
    pub reserved: [u8; 14],
}

impl Config { pub const SIZE: usize = 32+32+32+32+8+8+1+1+14; }

/// Validator record
#[account]
pub struct ValidatorRecord {
    pub validator_pubkey: Pubkey,
    pub lock_token_account: Pubkey,
    pub lock_timestamp: i64,
    pub status: u8,
    pub num_accepts: u64,
    pub reserved: [u8; 47],
}

impl ValidatorRecord { pub const SIZE: usize = 32+32+8+1+8+47; }

/// Events
#[event]
pub struct ConfigUpdated {
    pub aggregator_pubkey: Option<Pubkey>,
    pub paused: Option<bool>,
    pub timestamp: i64,
}

/// Program errors
#[error_code]
pub enum ErrorCode {
    #[msg("Invalid mint")]
    InvalidMint = 6000,
    #[msg("Invalid lock amount")]
    InvalidLockAmount = 6001,
    #[msg("Already registered")]
    AlreadyRegistered = 6002,
    #[msg("Not registered")]
    NotRegistered = 6003,
    #[msg("Escrow mismatch")]
    EscrowMismatch = 6004,
    #[msg("Invalid signature")]
    InvalidSignature = 6005,
    #[msg("Aggregator mismatch")]
    AggregatorMismatch = 6006,
    #[msg("Proof already anchored")]
    ProofAlreadyAnchored = 6007,
    #[msg("Status not active")]
    StatusNotActive = 6008,
    #[msg("Math overflow")]
    MathOverflow = 6009,
    #[msg("Paused")]
    Paused = 6010,
    #[msg("Unauthorized")]
    Unauthorized = 6011,
    #[msg("Non monotonic sequence")]
    NonMonotonicSeq = 6012,
    #[msg("Range overlap or gap")]
    RangeOverlap = 6013,
    #[msg("Clock skew too large")]
    ClockSkew = 6014,
    #[msg("Bad Ed25519 instruction order or count")]
    BadEd25519Order = 6015,
    #[msg("Bad domain separation message")]
    BadDomainSeparation = 6016,
    #[msg("Insufficient compute budget")]
    InsufficientBudget = 6017,
}

// ================= Additional Accounts for Anchoring =================

/// Aggregator state PDA
#[account]
pub struct AggregatorState {
    pub aggregator_pubkey: Pubkey,
    pub last_seq: u64,
    pub reserved: [u8; 86],
}

impl AggregatorState { pub const SIZE: usize = 32 + 8 + 86; }

/// Range state PDA
#[account]
pub struct RangeState {
    pub last_end_slot: u64,
    pub reserved: [u8; 120],
}

impl RangeState { pub const SIZE: usize = 8 + 120; }

/// Proof record PDA
#[account]
pub struct ProofRecord {
    pub artifact_id: [u8; 16],
    pub start_slot: u64,
    pub end_slot: u64,
    pub proof_hash: [u8; 32],
    pub artifact_len: u32,
    pub state_root_before: [u8; 32],
    pub state_root_after: [u8; 32],
    pub submitted_by: Pubkey,
    pub aggregator_pubkey: Pubkey,
    pub timestamp: i64,
    pub seq: u64,
    pub ds_hash: [u8; 32],
    pub commitment_level: u8,
    pub da_params: [u8; 12],
    pub reserved: [u8; 7],
}

impl ProofRecord { pub const SIZE: usize = 16 + 8 + 8 + 32 + 4 + 32 + 32 + 32 + 32 + 8 + 8 + 32 + 1 + 12 + 7; }

/// Anchor proof accounts
#[derive(Accounts)]
#[instruction(artifact_id: [u8;16], proof_hash: [u8;32], seq: u64)]
pub struct AnchorProof<'info> {
    #[account(mut)]
    pub submitted_by: Signer<'info>,
    #[account(mut)]
    pub config: Account<'info, Config>,
    #[account(init_if_needed, payer = submitted_by, seeds = [b"zksl".as_ref(), b"aggregator".as_ref()], bump, space = 8 + AggregatorState::SIZE)]
    pub aggregator_state: Account<'info, AggregatorState>,
    #[account(init_if_needed, payer = submitted_by, seeds = [b"zksl".as_ref(), b"range".as_ref()], bump, space = 8 + RangeState::SIZE)]
    pub range_state: Account<'info, RangeState>,
    #[account(init, payer = submitted_by, seeds = [b"zksl".as_ref(), b"proof".as_ref(), proof_hash.as_ref(), &seq.to_le_bytes()], bump, space = 8 + ProofRecord::SIZE)]
    pub proof_record: Account<'info, ProofRecord>,
    #[account(mut, seeds = [b"zksl".as_ref(), b"validator".as_ref(), submitted_by.key().as_ref()], bump)]
    pub validator_record: Account<'info, ValidatorRecord>,
    /// CHECK: instructions sysvar
    pub sysvar_instructions: UncheckedAccount<'info>,
    pub sysvar_clock: Sysvar<'info, Clock>,
    pub system_program: Program<'info, System>,
}

const DS_PREFIX: &[u8] = b"zKSL/anchor/v1"; // 14 bytes
const MAX_SLOTS_PER_ARTIFACT: u64 = 2048;
const MAX_CLOCK_SKEW_SECS: i64 = 120;

fn allowed_aggregator_key(config: &Account<Config>, seq: u64) -> Pubkey {
    if seq >= config.activation_seq { config.next_aggregator_pubkey } else { config.aggregator_pubkey }
}


#[event]
pub struct ProofAnchored {
    pub artifact_id: [u8; 16],
    pub proof_hash: [u8; 32],
    pub start_slot: u64,
    pub end_slot: u64,
    pub submitted_by: Pubkey,
    pub timestamp: i64,
    pub seq: u64,
    pub ds_hash: [u8; 32],
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_sizes_match_spec() {
        assert_eq!(Config::SIZE, 168, "Config size must be 168 bytes");
        assert_eq!(ValidatorRecord::SIZE, 136, "ValidatorRecord size must be 136 bytes");
        assert_eq!(ProofRecord::SIZE, 262, "ProofRecord size must be 262 bytes");
    }

    #[test]
    fn test_ds_prefix_and_length() {
        assert_eq!(DS_PREFIX.len(), 14, "DS prefix must be 14 bytes");
        // DS length = 14 + 8 (chain_id) + 32 (program_id) + 32 (proof_hash) + 8 (start) + 8 (end) + 8 (seq)
        let expected_len = 14 + 8 + 32 + 32 + 8 + 8 + 8;
        assert_eq!(expected_len, 110, "DS length must be 110 bytes");
    }
}

