1. Setup



Field: finite field \(\mathbb{F}\).

Hash: collision-resistant \(H : \{0,1\}^{\ast} \to \{0,1\}^{\ast}\).

Commitment: Merkle tree using \(H\).

LD-test: FRI.



⸻



2. State, Blocks, Batches



Global state:



\[
\mathrm{State} = \{(k_i, v_i)\}_{i \in I}.
\]



State roots:



\[
C_{\mathrm{in}} = \mathrm{Commit}(\mathrm{State}_{\mathrm{in}}), \quad
C_{\mathrm{out}} = \mathrm{Commit}(\mathrm{State}_{\mathrm{out}}).
\]



Block:



\[
B = \{ \mathrm{tx}_j \}_{j=1}^{N}.
\]



Each transaction:



\[
\mathrm{tx}_j = (\mathrm{meta}_j,\ \mathrm{prog}_j,\ \mathrm{data}_j),
\]



where \(\mathrm{meta}_j\) contains:

• Read-only accounts R_j

• Writable accounts W_j



Parallel batches:



\[
\mathrm{Batch} \in \{1,\dots,B_{\max}\}.
\]



Each transaction has a batch id:



\[
\mathrm{batch}(\mathrm{tx}_j) \in \{1,\dots,B_{\max}\}.
\]



Public inputs of computation STARK:



\[
\mathrm{pub} = \bigl(C_{\mathrm{in}},\ C_{\mathrm{out}},\ H_B,\ S_{\mathrm{in}},\ S_{\mathrm{out}}\bigr).
\]



where:

• \(H_B = H(B)\)

• \(S_{\mathrm{in}} = \{(a_\ell, v^{\mathrm{in}}_\ell)\}_{\ell=1}^{M}\)

• \(S_{\mathrm{out}} = \{(a_\ell, v^{\mathrm{out}}_\ell)\}_{\ell=1}^{M}\)



These are the list of all (account, value) pairs touched by the block at start and end, respectively.



⸻



3. Traces



3.1 VM Trace X (time-sorted)

Total steps: \(T\).

Domain: \(D = \{\omega^0,\dots,\omega^{T-1}\}\).



Trace:



\[
X \in \mathbb{F}^{T \times m_X}.
\]



Row X[t] contains:



\[
(\mathrm{tx\_id}^{X}[t],\ \mathrm{batch}^{X}[t],\ \mathrm{pc}[t],\ \mathrm{opcode}[t],\ \{\mathrm{reg}_j[t]\},\ \mathrm{acct\_id}^{X}[t],\ \mathrm{val\_r}^{X}[t],\ \mathrm{val\_w}^{X}[t],\ \mathrm{is\_read}^{X}[t],\ \mathrm{is\_write}^{X}[t]).
\]



Ordering: rows follow machine time; t and t+1 are consecutive steps.



3.2 Account Trace A (sorted by account, batch, time)

Total accesses: \(T_A\).

Domain: \(D_A = \{\rho^0,\dots,\rho^{T_A-1}\}\).



Trace:



\[
A \in \mathbb{F}^{T_A \times m_A}.
\]



Row A[i] contains:



\[
(\mathrm{acct\_id}^{A}[i],\ \mathrm{batch}^{A}[i],\ \mathrm{time\_tag}^{A}[i],\ \mathrm{tx\_id}^{A}[i],\ \mathrm{val\_r}^{A}[i],\ \mathrm{val\_w}^{A}[i],\ r[i],\ w[i]).
\]



where:

• r[i] \in \{0,1\} is read flag

• w[i] \in \{0,1\} is write flag



Ordering:



A is sorted lexicographically by \((\mathrm{acct\_id}^{A},\ \mathrm{batch}^{A},\ \mathrm{time\_tag}^{A})\).



3.3 Transaction Metadata Table T

Table T encodes for each transaction:

• \(\mathrm{tx\_id}\)

• \(\mathrm{batch}(\mathrm{tx\_id})\)

• Writable accounts \(W_{\mathrm{tx\_id}}\)



Encodable as rows:



\[
T \in \mathbb{F}^{L \times m_T}, \quad
T[\ell] = \bigl(\mathrm{tx\_id}^{T}[\ell],\ \mathrm{batch}^{T}[\ell],\ \mathrm{acct\_id}^{T}[\ell],\ \mathrm{is\_decl\_writable}^{T}[\ell]\bigr).
\]



where each \((\mathrm{tx\_id}^{T}[\ell], \mathrm{acct\_id}^{T}[\ell])\) pair belongs either to \(W_{\mathrm{tx\_id}}\) or is marked accordingly.



⸻



4. Constraints



All constraints are polynomials over \mathbb{F} evaluated row-wise; valid traces satisfy them for all rows.



4.1 VM Semantics (on X)

For each opcode \(\mathrm{op}\), define selector:



\[
s_{\mathrm{op}}[t] = 1 \;\text{iff}\; \mathrm{opcode}[t] = \mathrm{op}.
\]



Example for \(\mathrm{ADD}\):



\[
s_{\mathrm{ADD}}[t]\cdot\bigl(\mathrm{reg}_{\mathrm{dst}}[t+1] - \mathrm{reg}_{r1}[t] - \mathrm{reg}_{r2}[t]\bigr) = 0
\]



\[
s_{\mathrm{ADD}}[t]\cdot\bigl(\mathrm{pc}[t+1] - (\mathrm{pc}[t] + 1)\bigr) = 0
\]



Analogous constraints for all opcodes, including account ops:

• \(\mathrm{ACCT\_READ}\):

ensure r^X[t] = 1,\ w^X[t]=0, propagate registers and pc.

• \(\mathrm{ACCT\_WRITE}\):

ensure \(w^{X}[t] = 1\) and define \(\mathrm{val\_w}^{X}[t]\) as function of \(\mathrm{val\_r}^{X}[t]\) and registers.



4.2 Linking X and A (access permutation)

There exists a permutation \pi: \{0,\dots,T-1\}\to\{0,\dots,T_A-1\} such that each memory access in X appears exactly once in A.



Encode via permutation argument / multiset equality constraints between:



\[
M_X = \{ (\mathrm{acct\_id}^{X}[t],\ \mathrm{batch}^{X}[t],\ \mathrm{time\_tag}^{X}[t],\ \mathrm{tx\_id}^{X}[t],\ \mathrm{val\_r}^{X}[t],\ \mathrm{val\_w}^{X}[t],\ r^{X}[t],\ w^{X}[t]) \}_t
\]



and



\[
M_A = \{ (\mathrm{acct\_id}^{A}[i],\ \mathrm{batch}^{A}[i],\ \mathrm{time\_tag}^{A}[i],\ \mathrm{tx\_id}^{A}[i],\ \mathrm{val\_r}^{A}[i],\ \mathrm{val\_w}^{A}[i],\ r[i],\ w[i]) \}_i
\]



Constraint: multiset equality M_X = M_A (standard permutation / lookup argument).



4.3 Account Value Evolution (on A)

Define for each row:



\[
e_{\mathrm{acct}}[i] = \mathrm{Eq}(\mathrm{acct\_id}^{A}[i], \mathrm{acct\_id}^{A}[i+1]) \in \{0,1\}.
\]



\[
e_{\mathrm{batch}}[i] = \mathrm{Eq}(\mathrm{batch}^{A}[i], \mathrm{batch}^{A}[i+1]) \in \{0,1\}.
\]



Implement \(\mathrm{Eq}(\cdot,\cdot)\) with standard boolean equality polynomials.



4.3.1 Intra-batch evolution

Constraint for evolution within same account and same batch:



\[
e_{\mathrm{acct}}[i]\cdot e_{\mathrm{batch}}[i]\cdot\bigl(\mathrm{val\_r}^{A}[i+1] - \mathrm{val\_w}^{A}[i]\bigr) = 0
\]



4.3.2 Inter-batch evolution

Constraint for evolution between same account across different batches:



\[
e_{\mathrm{acct}}[i]\cdot(1 - e_{\mathrm{batch}}[i])\cdot\bigl(\mathrm{val\_r}^{A}[i+1] - \mathrm{val\_w}^{A}[i]\bigr) = 0
\]



Together, 4.3.1 and 4.3.2 enforce:



\[
\text{If } \mathrm{acct\_id}^{A}[i] = \mathrm{acct\_id}^{A}[i+1],\ \text{then }\mathrm{val\_r}^{A}[i+1] = \mathrm{val\_w}^{A}[i].
\]



holds globally, including transitions between batches.



4.3.3 Initial and final values vs \(S_{\mathrm{in}}, S_{\mathrm{out}}\)

At the first access for each account in A (minimal \(\mathrm{time\_tag}^{A}\) in its \((\mathrm{acct\_id}, \mathrm{batch})\) chain), enforce:



\[
\mathrm{val\_r}^{A}[i] = v^{\mathrm{in}}_{\ell} \quad \text{for the matching } a_\ell = \mathrm{acct\_id}^{A}[i].
\]



At the last access for each account in A (maximal \(\mathrm{time\_tag}^{A}\) across all batches), enforce:



\[
\mathrm{val\_w}^{A}[i] = v^{\mathrm{out}}_{\ell} \quad \text{for the matching } a_\ell = \mathrm{acct\_id}^{A}[i].
\]



These are enforced using lookup constraints from \(A\) into the public sets \(S_{\mathrm{in}}, S_{\mathrm{out}}\):

• For each account, there is exactly one match in \(S_{\mathrm{in}}\) for its first access.

• For each account, there is exactly one match in \(S_{\mathrm{out}}\) for its final access.



No Merkle paths appear inside this STARK; state roots are handled by a separate proof.



⸻



4.4 Sealevel Parallel Safety



4.4.1 Writer uniqueness per (account, batch)

Define running sum \(W_{\mathrm{run}}[i]\) over A, reset per \((\mathrm{acct\_id}, \mathrm{batch})\)-segment.



Let:



\[
e_{\mathrm{seg\mbox{-}start}}[i] = 1 \text{ if } i=0 \text{ or } (\mathrm{acct\_id}^{A}[i], \mathrm{batch}^{A}[i]) \neq (\mathrm{acct\_id}^{A}[i-1], \mathrm{batch}^{A}[i-1]).
\]



Constraint:



\[
e_{\mathrm{seg\mbox{-}start}}[i]\cdot W_{\mathrm{run}}[i] = 0
\]



and



\[
(1 - e_{\mathrm{seg\mbox{-}start}}[i])\cdot\bigl(W_{\mathrm{run}}[i] - (W_{\mathrm{run}}[i-1] + w[i-1])\bigr) = 0
\]



Additionally enforce range:



\[
\forall i,\quad W_{\mathrm{run}}[i] \in \{0,1\}.
\]



This implies:



\[
\sum_{i:\ (\mathrm{acct\_id}^{A}[i],\mathrm{batch}^{A}[i]) = (a,b)} w[i] \le 1
\]



for every (a,b), i.e. at most one writer per account per batch.



4.4.2 Writes must be declared writable

For each row A[i] with w[i] = 1:



Constraint via lookup into T:



\[
(\mathrm{tx\_id}^{A}[i], \mathrm{acct\_id}^{A}[i]) \in \{ (\mathrm{tx\_id}^{T}[\ell], \mathrm{acct\_id}^{T}[\ell]) \mid \mathrm{is\_decl\_writable}^{T}[\ell] = 1 \}.
\]



Arithmetized as a standard lookup argument:



\[
w[i]\cdot\mathrm{NotInLookup}\bigl((\mathrm{tx\_id}^{A}[i], \mathrm{acct\_id}^{A}[i]),\ T\bigr) = 0.
\]



With 4.4.1 and 4.4.2, the allowed pattern per \((\mathrm{acct\_id},\mathrm{batch})\) is:

• Zero or one writer, any number of reads, all serialized in \(\mathrm{time\_tag}\) order.



No additional read/write adjacency constraints are imposed.



⸻



5. Composition Polynomial and STARK



Let all constraints across X, A, T be denoted \{C_k\}_{k=1}^K.

Let \alpha_k be random coefficients (Fiat–Shamir).

Define for each row index in the unified evaluation domain a composition:



\[
P(z) = \sum_{k=1}^{K} \alpha_k \cdot C_k(z).
\]



Valid traces imply P(z) = 0 on the base domain.

As usual, extend columns and P to a larger domain, commit via Merkle, and use FRI to prove low degree and vanishing.



Prover output:



\[
\pi_{\mathrm{comp}} = (\text{trace commitments},\ \text{composition commitments},\ \text{FRI transcript},\ \text{openings}).
\]



Verifier checks:

• Local constraints for sampled points.

• FRI proofs of low degree.

• Lookup/permutation arguments between \(X, A, T, S_{\mathrm{in}}, S_{\mathrm{out}}\).



⸻



6. Separate State-Root Proof



Input: \(C_{\mathrm{in}}, C_{\mathrm{out}}, S_{\mathrm{in}}, S_{\mathrm{out}}\).



State proof must establish:

1. \(S_{\mathrm{in}}\) is a set of leaves consistent with \(C_{\mathrm{in}}\).

2. \(S_{\mathrm{out}}\) is a set of leaves consistent with \(C_{\mathrm{out}}\).

3. All other leaves are unchanged or accounted for by the block semantics (outside this ZK, or via additional proof).



Realization:

• Batch Merkle proof or dedicated SNARK/STARK:



\[
\pi_{\mathrm{state}}
\]



Verifier then checks:



\[
\mathrm{VerifyState}(C_{\mathrm{in}}, C_{\mathrm{out}}, S_{\mathrm{in}}, S_{\mathrm{out}}, \pi_{\mathrm{state}}) = 1
\]



⸻



7. Final Verification Condition



Global verification accepts if:



\[
\mathrm{VerifyComp}(C_{\mathrm{in}}, C_{\mathrm{out}}, H_B, S_{\mathrm{in}}, S_{\mathrm{out}}, \pi_{\mathrm{comp}}) = 1
\]



and



\[
\mathrm{VerifyState}(C_{\mathrm{in}}, C_{\mathrm{out}}, S_{\mathrm{in}}, S_{\mathrm{out}}, \pi_{\mathrm{state}}) = 1
\]