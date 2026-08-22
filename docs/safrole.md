# Safrole: block production & its role in block import

Why the block-import STF (`import_block`) delegates a whole cluster of state
chapters to `safrole::transition`, what Safrole *is*, and how it maps onto
Polkadot.

> Chinese version: [`safrole.zh.md`](./safrole.zh.md)

## 1. What Safrole is

**Safrole** (a production-ready variant of **Sassafras**) is JAM's
**block-production consensus**: it decides *who may seal each slot's block* and
supplies the chain's *randomness*. It is a **ring-VRF ticket lottery**:

- Ahead of each epoch, validators privately generate **tickets** (ring-VRF
  outputs) and submit them on-chain. A ticket proves "a validator (anonymous,
  via the ring signature) is entitled to a slot" without revealing which one.
- The winning tickets are ordered into a **per-slot sealing sequence**; the
  ticket-holder for slot *n* is the only validator allowed to author it.
- This gives **anonymous, front-running-resistant** leader selection: nobody
  learns the next author until they reveal it by sealing.
- If not enough tickets accumulate, the epoch falls back to a **deterministic
  key sequence** derived from entropy (`fallback_keys(η, κ)`).

## 2. The state Safrole owns

Safrole is the sole writer of these σ chapters (GP letters in parentheses):

| Chapter | State | Meaning |
|---|---|---|
| C11 (τ) | `timeslot` | most recent slot |
| C6 (η) | `entropy` (4 buffers) | the randomness beacon (per-block VRF fold + epoch rotation) |
| C7/C8/C9 (ι/κ/λ) | staging / active / previous validators | validator sets, rotated each epoch |
| C4 (γ) | `safrole` = { `pending` γ_k, `ring_commitment` γ_z, `tickets_or_keys` γ_s, `accumulator` γ_a } | the ticket contest + sealing source |

Constants (tiny): epoch `E = 12`, ticket-submission tail starts at
`TAIL_START = 10`, `tickets_per_validator = 3`.

## 3. What Safrole does on every block

1. **Advance τ** to the block's slot (must be strictly monotonic).
2. **Fold entropy:** `η₀' = blake2b(η₀ ‖ VRF_output(seal))` — every block feeds
   the beacon.
3. **Accumulate tickets:** a block before the tail (`slot mod E < 10`) may carry
   a tickets extrinsic; valid tickets are added to `γ_a`, sorted by id, capped at `E`.
4. **On an epoch boundary** (`slot/E` increments):
   - rotate validators `λ'=κ, κ'=γ_k, γ_k'=Φ(ι)` (Φ nulls offender keys);
   - recompute the ring commitment `γ_z' = ring_commitment(γ_k')` (bandersnatch);
   - rotate `η`;
   - choose the epoch's **sealing source** `γ_s'`: the winning tickets `Z(γ_a)`
     if the contest saturated, else `Keys(fallback_keys(η₂', κ'))`;
   - reset `γ_a` — **and still admit this boundary block's own tickets** (the new
     contest can begin immediately).

## 4. Why block import needs it

Importing a block is a **state transition**; Safrole's chapters must evolve so
that:

- the **next** block's author can be checked (the seal is validated against
  `γ_s`),
- the **randomness beacon** `η` advances (it seeds guarantor assignment, ticket
  lotteries, and fallback keys),
- **validator sets rotate** correctly across epochs.

So *every* block touches Safrole — even a `fallback` block with no tickets still
advances τ and η, and an epoch-boundary block still rotates. Skipping Safrole
would leave the state root wrong on the very first block.

## 5. Role in `import_block`

`import_block(pre, block)` **delegates the Safrole-owned chapters**
(τ/η/ι/κ/λ/γ) to the tested `safrole::transition`, mapping the unified `State`
to/from the safrole STF state, and computes the remaining chapters
(π statistics, α authorizer pools, β recent-blocks) itself. This reproduces the
whole `fallback` and `safrole` trace categories byte-exact.

Landing the `safrole` traces also exposed and fixed a latent bug: the
epoch-transition branch previously discarded a boundary block's ticket extrinsic
(it reset `γ_a` to empty and ignored the new tickets). The safrole STF vectors
never combined an epoch boundary with a ticket submission, so it went unnoticed
until a real trace did both in slot 12.

## 6. Correspondence to Polkadot

| JAM | Polkadot |
|---|---|
| Safrole (Sassafras ring-VRF ticketing) | **BABE** (slot/epoch block production), evolving toward **Sassafras** |
| `η` randomness beacon | BABE VRF randomness / epoch randomness |
| ticket lottery → per-slot author | BABE primary/secondary slot VRF claims |
| validator-set epoch rotation | session / epoch validator rotation |

Safrole's advantage over BABE: tickets make the author sequence **known in
order but anonymous until sealing**, removing the last-mover/grinding and
targeted-DoS weaknesses of exposed VRF slot claims.

## 7. Status in minimal-jam

- Implemented: `safrole.rs` STF (within-epoch advance, ticket accumulation,
  epoch transition, fallback/winning sealing, `γ_z` ring commitment, **and
  Bandersnatch RingVRF proof verification** — all via `ark-vrf` 0.1.0 + the
  Zcash SRS). Passes the `safrole` STF vectors **14/14** (including
  `bad_ticket_proof`) and the 100 `safrole` block-import traces.
- Ticket verification: each proof is checked against the epoch's ring
  commitment `γ_z` over the VRF input `jam_ticket_seal ‖ η'₂ ‖ attempt` (note:
  the GP writes the context with a `$` sigil, but the on-wire bytes are
  `jam_ticket_seal` without it); an invalid proof yields `bad_ticket_proof`.
