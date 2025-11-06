#![allow(clippy::missing_errors_doc)]
use anyhow::Result;
use winterfell::math::fields::f62::BaseElement;
use serde::{Deserialize, Serialize};
use winterfell::{Air, AirContext, Assertion, ProofOptions, StarkProof, Trace, TraceTable, TransitionConstraintDegree, VerifierError, FieldExtension};

type Felt = BaseElement;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    pub start: u64,
    pub end: u64,
    pub steps: u64,
}

// Simple AIR: x_{i+1} = x_i + 1 for `steps` steps; public inputs bind start and end.
#[derive(Clone)]
pub struct SumAir {
    context: AirContext<Felt>,
    pub_inputs: PublicInputs,
}

impl Air for SumAir {
    type BaseField = Felt;
    type PublicInputs = PublicInputs;

    fn new(trace_info: winterfell::TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::with_cycles(1, vec![1])];
        let context = AirContext::new(trace_info, degrees, 2, options);
        Self { context, pub_inputs }
    }

    fn context(&self) -> &AirContext<Felt> { &self.context }

    fn evaluate_transition<E: winterfell::FieldElement<BaseField=Felt>>(&self, frame: &winterfell::EvaluationFrame<E>, _periodic_values: &[E], result: &mut [E]) {
        let cur = frame.current()[0];
        let next = frame.next()[0];
        result[0] = next - cur - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let start = Felt::from(self.pub_inputs.start);
        let end = Felt::from(self.pub_inputs.end);
        vec![
            Assertion::single(0, 0, start),
            Assertion::single(0, (self.pub_inputs.steps as usize), end),
        ]
    }
}

fn build_trace(pub_inputs: &PublicInputs) -> TraceTable<Felt> {
    let steps = pub_inputs.steps as usize;
    let mut col = Vec::with_capacity(steps + 1);
    let mut cur = Felt::from(pub_inputs.start);
    col.push(cur);
    for _ in 0..steps { cur = cur + Felt::ONE; col.push(cur); }
    let mut trace = TraceTable::new(1, steps + 1);
    trace.fill_column(0, col);
    trace
}

#[derive(Serialize, Deserialize)]
pub struct StarkOutput {
    pub public_inputs: PublicInputs,
    /// Proof encoded as base64 of proof bytes
    pub proof_b64: String,
}

pub fn generate_stark_proof(start: u64, end: u64) -> Result<StarkOutput> {
    let steps = end.checked_sub(start).ok_or_else(|| anyhow::anyhow!("end must be >= start"))?;
    let pub_inputs = PublicInputs { start, end, steps };
    let options = ProofOptions::default();
    let trace = build_trace(&pub_inputs);
    let air = SumAir::new(trace.get_info(), pub_inputs.clone(), options.clone());
    let proof: StarkProof = winterfell::prove::<Felt, SumAir, FieldExtension::None>(air, trace, options)?;
    let bytes = proof.to_bytes();
    let proof_b64 = base64::encode(bytes);
    Ok(StarkOutput { public_inputs, proof_b64 })
}

pub fn verify_stark_proof(stark: &StarkOutput) -> Result<()> {
    let proof_bytes = base64::decode(&stark.proof_b64)?;
    let proof = StarkProof::from_bytes(&proof_bytes)?;
    let options = ProofOptions::default();
    let dummy_trace = build_trace(&stark.public_inputs);
    let air = SumAir::new(dummy_trace.get_info(), stark.public_inputs.clone(), options);
    winterfell::verify::<Felt, SumAir>(proof, air).map_err(|e: VerifierError| anyhow::anyhow!(format!("STARK verify failed: {e}")))
}


