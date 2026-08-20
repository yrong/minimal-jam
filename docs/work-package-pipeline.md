# Work-Package Pipeline: Guarantee & Assurance (JAM ↔ Polkadot)

Foundational note on how a work-package becomes *available* and then *accumulated*
in JAM, why the guarantee and assurance stages exist, and how they map onto the
original Polkadot (ELVES) parachain-consensus stages.

> Chinese version: [`work-package-pipeline.zh.md`](./work-package-pipeline.zh.md)

## 1. The full pipeline

```
refine(in-core) → guarantee → assurance → audit/approval → accumulate
   "computed"      "correct"    "data is     "re-checked"    "applied to
                                 retrievable"                  on-chain state"
```

A **work-package** is assigned to a **core** and executed off-chain by that core's
validators via **refine** (the stateless heavy compute — e.g. running a parachain
block). Refine produces a **work-report**. The two stages in question follow.

- STFs in this repo: `src/reports.rs` (guarantee), `src/assurances.rs` (assurance),
  `src/accumulate.rs` + `src/accumulate_exec.rs` (accumulate).

## 2. Guarantee — "this computation is correct"

- **Who:** the **guarantors** assigned to the core (a subset of validators; a
  ≥2/3 quorum of that group must sign).
- **What:** they re-run / check refine and attach **Ed25519 signatures** to the
  work-report, vouching for the result.
- **On-chain:** the `guarantees` extrinsic (`E_G`) enters the block; valid reports
  are assigned to their core and enter *pending availability* (`ρ`).
- **Code (`reports.rs`):** guarantor assignment (entropy shuffle + rotation),
  Ed25519 credential verification, per-report **contextual validity** (anchor
  recency, dependencies, gas, authorization), then writes `ρ` + core/service stats.

**Why it's needed:** a guarantee is a **cheap correctness endorsement**. It lets a
report be optimistically accepted; if anyone doubts it, disputes settle it later.
It decouples *computation* from *consensus* — only a small group re-computes,
not the whole network.

## 3. Assurance — "the backing data is retrievable network-wide"

- **Who:** the full active validator set.
- **What:** the work-package is **erasure-coded** into chunks distributed to every
  validator; each signs a **bitfield** declaring "I hold my chunk for core X".
- **Becomes available:** when a core gets a **strict two-thirds super-majority** of
  assurances, its report is *available*, removed from `ρ`, and returned to
  accumulation. Reports past the timeout (`ASSURANCE_TIMEOUT = 5`) are cleared
  (but not accumulated).
- **Code (`assurances.rs`):** per-core 2/3 super-majority marking + timeout clearing.

**Why it's needed:** this is the **linchpin of optimistic-rollup-style security**.
Only if the backing data is network-reconstructable can the later **audit/approval**
and **disputes** actually re-check whether refine cheated. If data is unavailable,
no one can audit — so **unavailable data must never be finalised**. Erasure coding
guarantees the full data can be rebuilt as long as ~1/3 of validators are online.

### Erasure coding: two different thresholds (one chunk per validator)

Distribution is **one chunk per validator**: the work-package data (and its
exported segments) is erasure-coded into **V chunks** (V = validator count);
validator `i` holds chunk `i`, and its bitfield bit for a core means "I hold my
chunk for that core's report".

A common misconception is that reassembly needs 2/3 of the chunks. It does not —
**these are two separate thresholds**:

| Threshold | Value | Meaning |
|---|---|---|
| assurance signing | **> 2/3 of validators** | declares the report *available* (`assurances.rs`, `3·count > 2·V`) |
| erasure-code reconstruction | **~1/3 of chunks** (⌈V/3⌉) | enough chunks to rebuild the full data (systematic Reed-Solomon, ~3× redundancy) |

- full: V=1023 → reconstruct from ~342 ≈ V/3 chunks; `core_count = 341 = V/3`.
- tiny: V=6 → reconstruct from 2 chunks; availability needs ≥5 signers.

**Why 2/3 sign but 1/3 reconstruct (Byzantine 1/3 tolerance):** with ≤1/3
malicious validators, if >2/3 honestly assure they hold a chunk, then even after
removing the 1/3 that may vanish or lie, >1/3 honest chunks still remain — exactly
the reconstruction threshold. So the 2/3 assurance is the *safety margin*
guaranteeing "enough chunks survive after subtracting 1/3 adversaries";
reconstruction itself needs only 1/3. Reconstruction serves **audit/approval and
disputes**: an auditor pulls chunks from a minority of validators, rebuilds the
data, and re-runs refine to check for cheating.

> minimal-jam is an STF over decoded JSON and does **not** implement erasure
> coding / chunk distribution (that is the networking layer). `assurances.rs`
> only checks the 2/3 bitfield super-majority.

## 4. Why two separate stages

| | guarantee | assurance |
|---|---|---|
| Asserts | computation is **correct** | data is **retrievable** |
| Participants | small guarantor group | full validator set |
| Threshold | 2/3 of the group | 2/3 of the network |
| Defends against | invalid state transitions (backstopped by disputes) | data-withholding attacks |

The two are **orthogonal**: correct-but-withheld = unauditable; available-but-wrong
= disputed away. A report is safe to accumulate only when **both** hold.

## 5. Correspondence to Polkadot (ELVES / parachain consensus)

| JAM | Polkadot | Notes |
|---|---|---|
| work-package / work-report | candidate / **candidate receipt** | the thing awaiting inclusion |
| refine | **`validate_block` / PVF execution** | in-core validation logic |
| guarantor (guarantor group) | **backing group** | validator subset for the core/para |
| **guarantee** (signatures) | **backing** (backing statements → "backed candidate") | endorsement |
| **assurance** (availability bitfield) | **availability bitfields / availability distribution** | same structure; same erasure coding |
| report becomes "available" → accumulate | **inclusion** (candidate written into the relay block) | |
| audit / approval | **approval checking** (secondary approval checkers) | random post-hoc re-validation |
| disputes | **disputes** | dispute resolution |
| accumulate | (no direct Polkadot equivalent) | integrates results into on-chain state, generalised to any service |

One line: **guarantee ≈ Polkadot backing; assurance ≈ Polkadot availability.**
These are exactly Polkadot's parachain-consensus "backing + availability" phases.

## 6. Key difference (JAM's generalisation)

- Polkadot is **parachain-specific**: refine = running a parachain block (PVF).
- JAM generalises to **arbitrary services**: refine is generic in-core compute, and
  a new **accumulate** stage synchronises refine results into on-chain state
  (in Polkadot the application of a parachain state root is implicit and dedicated;
  JAM makes it explicit and general).
- Hence "decentralised supercomputer": Polkadot's battle-tested backing/availability
  security is kept (renamed guarantee/assurance), but computation and state
  integration are made general-purpose.

## 7. Who is selected: guarantors vs auditors

The two validator groups are chosen by **fundamentally different** mechanisms:
guarantors by a **deterministic** entropy shuffle (fixed per-core groups, rotated),
auditors by an **unpredictable** VRF lottery.

### Guarantors (backing group) — deterministic assignment

In `reports.rs`:
- **Base grouping** (`:131`): validator `i` maps to base core `⌊i/3⌋` — i.e. **3
  validators per core** (V/C = 3).
- **Entropy shuffle** (`:132`, `fisher_yates` `:139`): a Fisher-Yates shuffle seeded
  by on-chain randomness `η[2]` (`:418`) decides *which* 3 land on which core.
- **Rotation** (`:134-135`): every `ROTATION` slots (tiny 4, full 10) the core index
  is offset by `⌊(t mod E)/ROTATION⌋` — periodic re-assignment.
- **Cross-rotation / epoch** (`assignment_for` `:409`): a guarantee's slot must fall
  in the current or previous rotation (`:208-215`); across an epoch boundary it uses
  `prev_validators` + `η[3]` (`:431`).
- **Signing threshold:** a report needs **≥2 of** the core's 3 guarantors' Ed25519
  signatures (a majority of the group).

So the guarantors are the ~3 validators the entropy shuffle currently maps to that
core. **Why deterministic + rotated:** guarantors must *coordinate* to produce and
sign a report, so they must know who is on the core (predictable within a rotation);
periodic rotation limits long-term collusion.

### Auditors (approval / audit) — unpredictable VRF lottery

Drawn from the **whole validator set** (not the core's backing subset). The aim is
**independent** checkers: the backers already validated during backing, so approval
adds fresh, independent re-checks (it is *independence*, not necessarily a hard
protocol-level exclusion of backers).

- **VRF self-selection (nobody assigns you):** each validator computes VRF outputs
  to self-determine *which candidates it must audit and at which tranche*. There is
  no coordinator; nobody knows in advance who is selected until they reveal the VRF
  proof.
- **Tranche = on-demand pool expansion, NOT a voting round:** tranche 0, 1, 2 … are
  escalation *levels* within one candidate. Tranche 0's VRF winners check first;
  **later tranches activate only when approvals are still short** (a no-show, or too
  few tranche-0 assignees) — not "reach a threshold to advance". Winning tranche 0
  means "you are an initial approval checker for that candidate". Tranches are also
  distinct from the pipeline **stages** (backing → approval).
- **What they do:** pull erasure-coded chunks from a minority of validators (~1/3
  reconstructs), re-run refine, vote valid/invalid.
- **When is a candidate approved:** it needs `needed_approvals` **valid approval
  votes** — from assigned checkers who actually re-ran refine and voted valid (this
  is *not* the backing/guarantee signatures) — **and** no unresolved no-shows. If an
  assigned checker times out (no-show), a higher tranche activates more checkers; the
  count must be reached with no outstanding no-show.
  - `needed_approvals` is a **Polkadot** parameter (mainnet default **30**); JAM does
    not fix this value on-chain (see the note below).

**Why VRF / unpredictable:** the value of auditing is that an attacker *cannot know
in advance who will check*, so cannot bribe/corrupt the checkers ahead of time. A
predictable set (like the backing group) could be targeted.

### Comparison

| | guarantor (guarantee) | auditor (approval/audit) |
|---|---|---|
| Drawn from | the core's subset (~3) | the whole validator set |
| Mechanism | entropy shuffle + rotation (**deterministic**) | VRF lottery (**unpredictable**) |
| Predictability | known within a rotation | secret until revealed |
| Size | fixed 3 per core | dynamic, grows by tranche |
| Purpose | efficient coordinated report production | anti-collusion post-hoc re-check |
| Polkadot | backing group | approval checking (relay-vrf assignment + tranches + no-shows) |

> In this repo: **guarantor assignment is implemented** (`reports.rs`
> `assignment`/`assignment_for`: η shuffle + rotation + epoch boundary).
> **Audit/approval is not** — it is a consensus/networking process (VRF lottery,
> tranches, chunk reconstruction), outside the tiny STF vectors.
>
> JAM formalises only **disputes/judgements** on-chain (`disp.tex`); the auditing
> tranche sizes and vote counts are an off-chain protocol, not fixed by the main GP.
> `needed_approvals = 30`, RelayVRFModulo/Delay above are **Polkadot** specifics
> given as the reference design JAM inherits.

## 8. Audit outcome: no-shows and disputes

### No-show — "assigned but didn't vote in time" (not just "didn't vote")

- A **no-show** is a validator that **won the VRF assignment** to check a candidate
  but has **not delivered its approval vote within the timeout**. A validator that
  was never assigned is *not* a no-show.
- It is a **transient/unresolved** state: the vote may still arrive (then resolved),
  or be covered by replacement checkers.
- **Why it matters:** a no-show is suspicious — the checker may have found a problem
  and is stalling, or an attacker may be delaying to prevent enough honest checks.
  So **each no-show activates the next tranche**, pulling in more replacement checkers.
- **"No unresolved no-shows"** therefore means: every assigned checker has either
  voted, or its absence has been covered by higher-tranche replacements that voted.
  A candidate is approved only with `needed_approvals` valid votes **and** no
  dangling no-show.
- (No-shows / tranches are the off-chain Polkadot approval concept; not in this repo.)

### One `invalid` triggers a dispute — but triggering ≠ deciding

- **Trigger:** the optimistic model turns on "**one honest checker suffices**". Even
  if everyone else approved, a single assigned checker whose re-execution says
  *invalid* **escalates to a dispute** (not an ordinary approval vote). The raising
  bar is deliberately one vote.
- **Decide:** the dispute then escalates to **all** validators; the verdict is
  settled by a **2/3 super-majority**, not by that single vote. In `disputes.rs`
  (GP §10, implemented, 28/28):
  - **verdict** `ψ` ∈ {good / bad / wonky}: ≥2/3 valid → **good** (report stands);
    ≥2/3 invalid → **bad** (report rejected, availability `ρ` cleared); ~`⌊V/3⌋`
    split (`WONKY_VOTES`) → **wonky** (no consensus).
  - **culprits:** the **guarantors** of a *bad* report (≥ `MIN_CULPRITS` = 2) — they
    vouched for a bad report → slashed.
  - **faults:** validators whose vote **contradicts the final verdict** → slashed.
- **So the scenario "all approve, one votes invalid":** that one vote *triggers* the
  dispute and forces a full re-check; if the report is truly valid the verdict is
  good (2/3 valid) and the lone invalid voter is slashed as a **fault**. A single
  vote can *force a check* but cannot by itself reject the report.

**The asymmetry is the point:** raising is cheap (1 vote), but false accusations are
punished (fault slash) to prevent griefing, and vouching for a bad report is punished
(culprit slash). With ≤1/3 adversaries, honest validators can always push the truth
to a 2/3 super-majority.

### None of these is "multi-round vote accumulation"

A common misconception is that backing/approval proceed in *rounds*, each round
adding votes until a threshold gates the next round. They do **not**:

- **backing:** a single 2-of-3 group threshold (collect the guarantor signatures once).
- **approval:** votes from all activated tranches **accumulate into one pool**;
  there is a **single global completion condition** (`needed_approvals` valid votes
  + no unresolved no-shows), *not* a per-tranche gate. Tranches expand the checker
  pool **only when approvals are still short** (a no-show, or too few tranche-0
  assignees); enough votes *ends* it — in the happy path tranche 0 alone completes it.
- **dispute:** a single escalation to all validators, decided by a 2/3 super-majority.

The genuine "rounds/periods" in JAM are elsewhere and unrelated to this vote flow:
**epochs** and the guarantor **rotation period** (`reports.rs` `ROTATION`), and the
block-production / finality consensus — a separate subsystem.

## 9. Implementation status in minimal-jam (what maps, what's missing)

This repo implements the **on-chain STF-validation half** of the pipeline
(byte-exact against the tiny vectors). The **in-core (refine)** and **off-chain**
processes (audit/approval, erasure coding, guarantor/assurer P2P) are **out of
scope by design** — this is an STF over decoded JSON, not a full node.

| Stage | Code | Status | What's missing |
|---|---|---|---|
| **refine** (in-core "compute") | `pvm.rs` / `pvm_exec.rs` (PVM engine, 311/311) | 🟡 engine only, stage not wired | the refine invocation `Ψ_R` + refine host ABI (import/export segments, historical_lookup …), actually running a work-package. Vectors feed refine's *output* (`work-report.results` + `refine_load`), never re-run refine |
| **guarantee** ("correct") | `reports.rs` (42/42) | ✅ on-chain STF | the off-chain guaranteeing *protocol*: report production/distribution, guarantor gossip, signature collection (only the extrinsic is validated) |
| **assurance** ("retrievable") | `assurances.rs` (10/10) | ✅ on-chain STF | **erasure coding + chunk distribution/retrieval** (networking) |
| **audit / approval** ("re-checked") | — (none) | ❌ not implemented | everything: VRF assignment, tranches, no-shows, re-download chunks + re-run refine, vote |
| ↳ on-chain **consequence** of audit: disputes | `disputes.rs` (28/28) | ✅ on-chain STF | the on-chain verdict is done; the off-chain approval that *triggers* it is not |
| **accumulate** ("apply to state") | `accumulate.rs` + `accumulate_exec.rs` (30/30) | ✅ on-chain STF | a few host calls, `on_transfer` PVM, non-tiny params (see `docs/accumulate.md` §II/III) |

**Gap markers (summary):**
- ❌ **refine execution** (in-core): `Ψ_R` + refine host ABI + segment import/export.
- ❌ **audit / approval** (off-chain): VRF lottery, tranches, no-shows, re-check votes.
- ❌ **erasure coding / chunk distribution & retrieval** (networking).
- ❌ **P2P networking** for guaranteeing / assurance / auditing.
- ❌ **block production / finality consensus** (SAFROLE's block-authoring VRF; note
  `safrole.rs` is only the *ticket-processing STF*, 13/14 — `bad_ticket_proof`
  ring-proof still pending).
- 🟡 accumulate: a few host calls, `on_transfer`, full-scale params.

**In one line:** the **on-chain state transitions** (guarantee / assurance /
accumulate, plus disputes as audit's on-chain consequence) are implemented
byte-exact; **refine execution** and the **audit/approval + erasure-coding + P2P +
block-authoring** layers are not — that is the boundary of a "minimal JAM STF".

## References

- GP §11: `guaranteeing.tex` / `reporting_assurance.tex`, `assur.tex`
  (`availassignmentspostguarantees`, `availassignmentspostassurances`).
- Repo: `src/reports.rs`, `src/assurances.rs`, `src/accumulate.rs`.
- Polkadot: parachain consensus (ELVES) — backing, availability distribution,
  approval checking, disputes.
