# Minimal JAM — Design & Rationale

Status: 4 STF subsystems implemented and verified against
`davxy/jam-test-vectors` (tiny). 18/18 vectors pass byte-for-byte.
This note records what was built and **why each choice was made**, so the next
slices (codec, state trie, PVM) build on solid ground.

---

## 1. Goal and scope decision

Ask: "implement a minimal JAM that passes `davxy/jam-conformance`".

Full conformance (Milestone 1) is not one-session work. It requires:

- Safrole (bandersnatch RingVRF), disputes/reports (ed25519/BLS, availability).
- `accumulate` — a full PVM interpreter plus host calls.
- The state Merkle trie + JAM codec (needed for byte-exact **state roots**).
- Erasure coding, and a TCP **fuzzer target** speaking `fuzz-proto`.

So scope was cut to a **genuinely verifiable subset**: the STF subsystems whose
test vectors are pure decoded JSON (`pre_state` + `input` -> `post_state`) and
need **no** trie, codec, PVM, or heavy crypto. That subset can be proven correct
today, and forms the semantic core the rest attaches to.

Chosen subsystems:

| Module | GP | Why picked |
|---|---|---|
| `statistics` | §13 | Zero crypto. Pure counters. Simplest correct starting point. |
| `authorizations` | §8 | Zero crypto. Small ring/pool logic. |
| `preimages` | §12 | Adds Blake2b-256 keying + validity errors. |
| `history` | §7 | Adds Keccak MMR + super-peak — the one non-trivial hash structure. |

Deliberately excluded: `safrole`, `disputes`, `assurances`, `reports`,
`accumulate`. Each needs crypto or the PVM and cannot be verified without large
extra machinery. Excluding them is honest, not a stub.

---

## 2. Why "STF on decoded JSON" is faithful

The vectors ship the state already decoded to JSON. The Gray Paper defines each
subsystem as a function on **values** (sets, sequences, maps), not on encoded
bytes. So implementing the transition over structs that mirror the JSON is a
faithful reading of the GP.

Byte-exact **state-root** checks (the `traces/` vectors) *do* need the codec and
trie. Those are out of this slice by design — see §7. The `stf/` vectors we
target compare **decoded** post-state, so struct equality is the correct oracle.

Consequence: hashes and blobs are kept as `0x`-prefixed **strings** end to end.
We only convert to bytes when a hash must actually be computed (preimage key,
MMR). This keeps comparison trivial and avoids a premature byte model that the
real codec will later define properly.

---

## 3. Crypto choices

`src/crypto.rs`:

- `blake2b_256` = JAM `H`. Used for preimage keys. Blake2b is the general JAM
  hash; a preimage's key is `H(blob)`.
- `keccak_256` = JAM `H_K`. Used **only** by the recent-history MMR. JAM uses
  Keccak for the BEEFY/MMR commitment; Blake2b everywhere else. Using the wrong
  one here fails `history` immediately — the passing vectors confirm Keccak.
- `mmr_append`: standard MMR carry. A new leaf rises through peak slots; a filled
  slot at height `n` combines as `H_K(peaks[n] ++ carry)` (existing-then-carry
  order) and clears, carry rises. Order verified against `progress_blocks_history-2/3`.
- `mmr_super_peak`: `M_R`. `[]`→zero; one peak→itself; else fold low→high with
  the `"peak"` domain separator: `H_K("peak" ++ M_R(rest) ++ last)`. In all four
  vectors the post-append MMR collapses to a single peak, so the block's
  `beefy_root` equals that peak; the multi-peak fold is implemented per GP for
  correctness even though these vectors do not exercise it.

---

## 4. Per-subsystem rationale

### statistics (§13)
- Epoch length `EPOCH_DURATION = 12` (tiny). Epoch = `slot / 12`.
- On `new_epoch > prior_epoch`: `last := prior curr`, `curr := zeros`. Else both
  carry forward. Increments always apply to `curr`.
- Increments (all verified against `stats_with_some_extrinsic-1`):
  - author: `blocks += 1`, `tickets += |E_T|`, `pre_images += |E_P|`,
    `pre_images_size += Σ len(blob)`.
  - each guarantee **credential** (signature `validator_index`): `guarantees += 1`.
  - each assurance `validator_index`: `assurances += 1`.
- **Key subtlety:** `State.slot` is τ (the *prior* timeslot) and is **not**
  advanced by this subsystem — the vectors keep `post.slot == pre.slot`. The
  statistics STF reads τ only to detect the epoch boundary; τ' is owned
  elsewhere. We therefore copy `pre.slot` through unchanged. Advancing it (the
  "obvious" choice) would fail the vector.
- `curr_validators` (κ') is passed through unchanged and stored as
  `serde_json::Value` — we never inspect validator keys here, so modelling their
  fields (bandersnatch/ed25519/bls/metadata) would be dead weight.

### authorizations (§8)
- Per core, in order: (1) remove the authorizer **consumed** by each guaranteed
  report on that core (first match removed), (2) push the scheduled queue entry
  `φ[c][slot mod |φ[c]|]`, (3) truncate to the newest `MAX_POOL = 8`.
- `MAX_POOL` is the constant `O` and is the same for tiny and full, so it is
  hard-coded; the queue length `Q` is read from the data (`|φ[c]|`) rather than
  assumed, so the same code works for tiny (80) and full without change.
- `progress_authorizations-1` (no consumption) proves the trim: an 8-entry pool
  + 1 push → drop front. The appended value is exactly `φ[0][42]`, confirming the
  slot-rotation index.

### preimages (§12)
Two validity gates, then apply. State is unchanged on either error (matches the
🔴 vectors whose `post_state == pre_state`).

1. **Order/unique** by `(service, blob)` — strictly increasing.
   - **Bug found & fixed:** first implementation ordered by `(service, H(blob))`.
     `preimage_not_needed-1` has two blobs for one service whose *hashes*
     descend but whose *blobs* ascend; it must reach the *unneeded* gate, not the
     sort gate. The vector proves ordering is over the **blob bytes**, not the
     hash. Fixed accordingly (`src/preimages.rs`, step 1).
2. **Needed**: for each `(service, blob)`, there must exist a request keyed
   `(H(blob), len(blob))` with an **empty** slot list (solicited, unprovided).
   Otherwise `preimage_unneeded`.
- Gate order is sort→needed; `preimages_order_check-1` is a sort error even
  though it would also be unneeded, so sort must run first.
- Apply: insert blob into `a_p` keyed by `H(blob)` (kept sorted by hash, as the
  map serializes), stamp the request's value to `[slot]`, and bump the service's
  `provided_count`/`provided_size` (creating the stats record if absent). Only
  those two `π_S` fields change (README confirms).

### history (§7)
- Back-fill `parent_state_root` (`H_r`) into the **previous** head's `state_root`
  (the prior head's root was unknown until this block reveals it).
- Append `accumulate_root` to the MMR; the new head's `beefy_root` = super-peak of
  the post-append MMR; new head `state_root` = zero (unknown until next block).
- Cap history at `MAX_HISTORY = 8`.

---

## 5. Constants (tiny chain-spec)

`V=6` validators, `C=2` cores, `EPOCH_DURATION=12`, auth pool `O=8`, auth queue
`Q=80`, recent history `H=8`. Where a value differs between tiny/full and is
present in the data (e.g. `Q`), it is derived from the data, not hard-coded.

---

## 6. Test harness

`tests/conformance.rs`: for each component, read every `tests/vectors/<c>/*.json`,
deserialize into a generic `Case<Input, State>`, run `transition`, and
`assert_eq!` computed vs expected `post_state` (and, for preimages, the `output`
choice). The struct `PartialEq` derive **is** the byte-for-byte oracle because
the structs cover every field the vector carries. A mismatch names the offending
file.

## 6b. JAM codec (GP Appendix C) — DONE

`src/codec.rs` + `src/types.rs`. Passes all 15 `codec/tiny` vectors in **both**
directions: `encode(from_json(.json)) == .bin` and `decode(.bin) == value` with
no trailing bytes (`tests/codec.rs`).

Encoding rules (verified against the vectors and the reference `jam-types-py`):

- **Fixed-width little-endian** for most integers: `U8/U16/U32/U64`, and the
  aliases `ServiceId=U32`, `TimeSlot=U32`, `Gas=U64`, `CoreIndex/ValidatorIndex=U16`.
- **General-natural (variable) encoding** — `encode_nat`/`decode_nat` — is used in
  two places only:
  1. the **length prefix** of every variable-length sequence (incl. `ByteSequence`);
  2. fields explicitly typed `Compact<…>` in the schema.
- **Fixed-size sequences** (`SIZE(n)`) carry **no** length prefix; bounded/unbounded
  sequences (`SEQUENCE OF`, `SIZE(0..n)`, `SIZE(1..n)`) do.
- `Option<T>` = 1 tag byte (0/1) + value; `bool` = 1 byte; `CHOICE` = 1 tag byte +
  payload; structs = fields in declaration order.

**Key correction the vectors forced.** The GP note ("variable length used only
for sequence prefixes") is *not* the whole story. Some scalar fields are
`Compact`, and it is **per-field, not per-type**: `WorkResult.accumulate_gas`
(a `Gas`) is fixed 8-byte, but `RefineLoad.gas_used` (also `Gas`) is `Compact`.
First implementation used width-by-type and produced an 18-byte `RefineLoad`
where the vector wanted 5. Fixed by consulting the reference type mappings.
The `Compact` set in the codec-vector types: all of `RefineLoad`,
`WorkReport.core_index`, `WorkReport.auth_gas_used`, `TicketEnvelope.attempt`,
`TicketBody.attempt`. `WorkExecResult` tag numbers also follow the reference
(0 ok, 1 out_of_gas, 2 panic, 3 bad_exports, 4 output_oversize, 5 bad_code,
6 code_oversize), which differs from the ASN comment ordering.

**Design choices.**
- `Codec` trait (`encode_to`/`decode`) with a `codec_struct!` macro that emits
  the struct, its serde derives, and a field-order codec in one place — the field
  list is the single source of truth for both JSON and binary.
- `Hex<const N>` for fixed byte arrays (no prefix), `Blob` for `ByteSequence`
  (prefixed), `FixedSeq<T, N>` for `SIZE(n)` sequences, `Compact` for variable
  scalars. Each pairs a serde impl (hex string / number / array) with a `Codec`
  impl, so the same value type verifies both directions.
- Byte types keep raw `[u8; N]`/`Vec<u8>`; only JSON boundaries use hex strings.

---

## 6c. State Merkle trie (GP Appendix D) — trie primitive DONE

`src/trie.rs`. Passes all 11 `trie/trie.json` cases (`tests/trie.rs`): a
key/value set maps to a 32-byte root.

Binary Merkle trie, Blake2b-256, 64-byte nodes hashed to 32:
- **leaf** (eq. 287): head `0b10_xxxxxx` embeds the value when `|v| ≤ 32` (low 6
  bits = length), else `0b11000000` stores `H(v)`; body is `key[..31]` then the
  value (zero-padded) or the value hash.
- **branch** (eq. 286): head `left[0] & 0x7f` (top bit cleared = branch marker),
  then `left[1..32]` and the full 32-byte `right`.
- partition the set by key **bit at the current depth** (MSB-first within a byte),
  recurse; empty set → the all-zero hash. Root = `merkle(kvs, 0)`.

The result is order-independent (partition-by-bit), so input order does not matter.

**Verified on real state (`traces/`).** `tests/traces.rs` rebuilds the `pre_state`
and `post_state` roots of block-import traces from their key/value sets and checks
them against the vector's `state_root`. GP **state keys are 31 bytes**; the trie
takes 32-byte keys and a leaf stores `key[..31]`, so the 31→32 mapping appends a
trailing `0x00` (`trie::state_key`) — confirmed against real pre/post roots. A
lean 2-block `fallback` sample is vendored (traces JSON is ~600 KB/file, ~2.4 GB
total, so the full set is not committed); set `JAM_TRACES_DIR` to a full checkout
for an exhaustive run. Validated locally against 24 files across fallback/safrole/
storage (48 root computations).

Still pending for full block import: **state-key derivation** (the `C(...)`
constructor per component + service accounts) and **per-component serialization**
(σ → `T(σ)` via the codec), which let us check a post-state root after running the
STFs rather than trusting the vector's keyvals.


## 6d. State-key constructor `C(...)` (GP Appendix D §Serialization) — DONE

`src/state_key.rs`. State is a map from **31-byte** keys to octet sequences.
Three key forms:
- `C(i)` — top-level component (chapter) `i`: `[i, 0, 0, …]`.
- `C(i, s)` — chapter `i` scoped to service `s`: `[i, n0, 0, n1, 0, n2, 0, n3, 0, …]`
  with `n = E4(s)`.
- `C(s, h)` — service dictionary entry: `[n0, a0, n1, a1, n2, a2, n3, a3, a4, …, a26]`
  with `n = E4(s)`, `a = blake2b(h)`. The three per-service dictionaries prefix a
  4-byte marker to `h`: storage `2^32-1`, preimage `2^32-2`, request `= length`.

**Verified against real traces** (`tests/state_key.rs`): every key in a trace's
pre/post state is explained as a chapter `C(1..=16)`, an account `C(255, s)`, or
a dict entry `C(s, ·)` whose service `s` has an account in the same state. Ran on
the vendored `fallback` sample and, via `JAM_TRACES_DIR`, on 24 files across
fallback/safrole/storage (the last exercises non-zero service ids). Unit tests
pin the interleave layouts.

## 6e. State value serialization (GP Appendix D §Serialization) — all chapters DONE

`src/state.rs`. Encodes every state component to its `C(i)` value, verified by
**byte-exact round-trip** against real trace state (`tests/state.rs`): decode a
component's value from a trace, re-encode, assert identical. Covers all
top-level chapters and service-account metadata:
- `C(1)` α auth pools; `C(2)` φ auth queues; `C(5)` ψ disputes records
- `C(3)` β recent blocks — `history: Vec<BlockInfo>` + `mmr: Vec<Option<hash>>`
- `C(4)` γ safrole — pending validators + ring commitment(144) + `TicketsOrKeys`
  (tag: tickets/keys) + ticket accumulator
- `C(6)` η entropy; `C(7)/C(8)/C(9)` ι/κ/λ validator sets (`ValidatorData` =
  bandersnatch+ed25519+bls(144)+metadata(128))
- `C(10)` ρ availability assignments (`WorkReport` + timeout)
- `C(11)` τ timeslot; `C(12)` χ privileges
- `C(13)` π statistics — validator records (fixed u32) + core/service records
  (**`Compact`**, confirmed against the storage traces)
- `C(14)` ϑ ready queue; `C(15)` ξ accumulated; `C(16)` last-accout
- `C(255, s)` service account — `ServiceInfo` (89 bytes: version + code hash +
  5×u64 + 4×u32), matching the vectors' 0.7.x layout (not GP 0.8 main)

Key findings: most state numerics are fixed-length, **except** the statistics
core/service activity records which use `Compact`. The account layout is the
`jam-types.asn` `ServiceInfo`, confirming the vectors track ~0.7.x rather than
GP 0.8. Ran on the vendored fallback sample and, via `JAM_TRACES_DIR`, on 24
files across fallback/safrole/storage (which exercise β MMR, γ tickets, π
service stats, and ρ/ϑ with real work reports).

## 6f. Full state assembly + merklization (GP Appendix D) — DONE

`State` in `src/state.rs` is the full σ: typed top-level chapters + service
accounts, plus per-service dictionary entries carried opaquely as
`(state-key, value)` (their keys are one-way hashes, which GP App. D notes an
implementation need not invert). It provides:
- `serialize()` → the `T(σ)` dictionary (state-key → value bytes)
- `root()` → the 32-byte state root (serialize, pad keys 31→32, merklize)
- `from_entries()` → parse a serialized `T(σ)` back into a typed σ

End-to-end (`tests/state_root.rs`): parse a real trace's state into σ, assert
`serialize()` reproduces the exact key/value set, and `root() == state_root`.
Verified on the vendored fallback sample and, via `JAM_TRACES_DIR`, on 24 files
across fallback/safrole/storage — **48 state snapshots** (pre+post), all matching.
This closes the state-serialization + merklization loop.

## 6g. Block-import STF wiring (fallback) — DONE

`src/block_import.rs` runs the implemented transitions against a decoded
[`types::Block`] (the trace `block` field deserializes straight into it) and a
typed pre-`State`:
- `next_timeslot` — τ' = block slot
- `next_statistics` — π' validator records (author blocks; ticket/preimage
  counts; per-credential guarantees/assurances), with epoch rotation of
  `vals_curr` → `vals_last`. Core/service records carried through (exact when
  there are no reports/preimages).
- `next_auth_pools` — α' per core: drop consumed authorizers, enqueue the
  slot's queued authorizer, keep the newest `MAX_POOL`.

Verified (`tests/block_import.rs`) against real **fallback** traces: recompute
C11/C13/C1 from the pre-state + block and assert they equal the post-state.
Ran on the vendored sample and 12 fallback blocks via `JAM_TRACES_DIR`
(crossing the epoch boundary at slot 12, exercising `vals_last` rotation).
Restricted to fallback because other sets need transitions not yet wired
(β accumulation root, η/γ bandersnatch, reports-driven core/service stats).

## 7. What is intentionally NOT here, and the dependency order to add it

To reach byte-exact **post-STF state roots** and then M1:

1. **JAM codec** (GP Appendix C) — ✅ DONE (§6b). Passes `codec/tiny`.
2. **State Merkle trie + serialization** (GP Appendix D) — ✅ DONE (§6c–§6f).
   `root(σ) == state_root` on real traces.
3. **Block-import STFs** — partial ✅ (§6g: τ, π, α on fallback). Remaining:
   β (accumulation-output root), disputes ψ, and reports-driven core/service π.
4. **PVM** — register machine + gas metering + host calls.
5. **accumulate / reports** — depend on the PVM.
6. **safrole** (bandersnatch RingVRF), **disputes** (ed25519/BLS), **assurances**.
7. **fuzzer target** — TCP server speaking `fuzz-proto`, which is how
   `jam-conformance` actually drives an implementation.

The STF subsystems (§4) and the codec (§6b) are the value-level semantics and
serialization those layers wrap; they are reused unchanged once the state trie
lets us feed real encoded blocks and check state roots.

---

## 8. Appendix: `preimages::transition` walkthrough

Pure function `transition(pre: &State, input: &Input) -> (Outcome, State)`. On
any validity error it returns `pre.clone()` unchanged — validation fully
precedes mutation, so there is never a partial write. Three phases run in order.

### Phase 1 — order & uniqueness
GP requires the extrinsic to be **strictly increasing** by `(service, blob)`.
Sort key is the **raw blob bytes**, not the hash. `order: Vec<(u64, Vec<u8>)>`
gets Rust lexicographic `Ord` (service first, then blob bytes). `windows(2)` with
`w[0] >= w[1]` catches both out-of-order (`>`) and duplicate (`==`) in one test.

### Phase 2 — every preimage must be needed
`keyed` recomputes each blob's Blake2b-256 hash (the `a_p`/`a_l` map key — a
different key from the Phase-1 sort key, deliberately). "Needed" = the requester
account exists AND has a request entry keyed exactly `(H(blob), len(blob))` whose
value is `[]` (solicited, not yet filled). Any failure → `Unneeded`, unchanged.

### Phase 3 — apply (only if all items passed; works on a clone)
Per `(service s, blob b)`, `hash = H(b)`, `len = |b|`:
1. Insert blob into `a_p` (`preimage_blobs`) via `binary_search_by(hash)` →
   `Err(pos)` when absent → insert at `pos`, keeping ascending-by-hash order
   (the map's serialized order).
2. Stamp the matching request: `a_l[(hash,len)]` value `[] → [slot]`.
3. Advance `π_S`: `provided_count += 1`, `provided_size += len`, creating the
   service record (sorted by id) if absent; other fields stay 0.

### Worked example — `preimage_needed-2` (success)
Input `{ requester: 3, blob: 0x92cdf5…6d3f (46 bytes) }`, `slot: 43`.
Prior service 3: blobs `[0xb9de…]`, requests `[(0x9e0e…,46)→[], (0xb9de…,48)→[37,40]]`.
- P1: single item → pass.
- `blake2b(0x92cdf5…) = 0x9e0e7d32…`.
- P2: request `(0x9e0e…,46)` has value `[]` → needed. Pass.
- P3: insert blob at index 0 (`9e < b9`) → `[0x9e0e…, 0xb9de…]`; request
  `(0x9e0e…,46)` → `[43]`; new stat `{provided_count:1, provided_size:46}`.

### Worked examples — errors
- `preimage_not_needed-1`: two blobs for service 3, only `(0x9e0e…,46)` solicited.
  P1 passes (blob `0x31…` < `0x92…`); P2 first item hashes to `0xb9de…,48` with no
  such request → `Unneeded`, state unchanged.
- `preimages_order_check-1`: requesters `36,36,45,36,45`; P1 pair `(45,·)`→`(36,·)`
  gives `w[0] >= w[1]` → `NotSortedUnique`. Order check precedes the needed check,
  so this wins even though some blobs are also unneeded.

### Why "provide only if previously solicited" (GP §12) — it IS a requirement
The request map `a_l` maps `(hash, length)` to a slot-list that encodes the
preimage lifecycle: `[]` = requested/unavailable, `[t]` = available since `t`,
`[t1,t2]` = was available then forgotten, etc. The provide operation is only
valid when the status is `[]`. Rationale:
- **State-bloat / DoS control.** Preimage blobs live in consensus state that every
  validator stores. Without prior solicitation anyone could stuff arbitrary data
  into global state. Requiring a request means only data a service committed to
  needing gets stored.
- **Accounting is pre-committed.** The request fixes `(hash, length)` up front, so
  the storage footprint (and the service's deposit/threshold) is known and bounded
  before the blob arrives — not discovered after the fact.
- **Idempotency.** Re-providing an already-provided preimage (status non-empty) is
  rejected, preventing duplicate growth; expiry/expunge is a separate lifecycle step.
- **Availability semantics.** refine/accumulate look preimages up by hash, and the
  historical-lookup predicate ("was hash `h` available at time `t`?") reads the
  request's slot-list. A blob with no request would have no valid lifecycle entry,
  so the lookup would be meaningless. Solicitation is step one of that lifecycle,
  not arbitrary insertion.

The STF's `preimage_unneeded` error is exactly this rule.

### Where the GP states it explicitly (v0.8.0; unchanged in substance from 0.7.x)

It is a formal validity condition, in two places.

**§ Preimage Integration** (`text/accumulation.tex`, lines 483–495). The lookup
extrinsic `E_P` must be order-unique, and every entry must be `providable`
against the *prior* accounts `δ`:

```
E_P ∈ [(ServiceId, blob)]
E_P = order-unique(E_P)                              (eq. preimagesareordered)
∀ (s, d) ∈ E_P : providable(δ, s, d)
```

`providable` (same section, lines 319–325) is true **only** when the request
status is the empty sequence `[]` and the service exists:

```
providable(d, s, i) = ( d[s].requests[(blake(i), len(i))] = [] )   if s ∈ keys(d)
                    =  ⊥                                            otherwise
```

`provide` (lines 309–317) then sets `requests[(H(i),len(i))] = [τ']` and
`preimages[H(i)] = i`.

**§ Preimage Lookups** (`text/accounts.tex`, lines 70–120). Status modes:
`[]` requested / `[t0]` available since t0 / `[t0,t1]` unavailable / `[t0,t1,t2]`
re-available. Invariant `eq:preimageconstraints`: a preimage in state implies a
request entry exists —
`(h↦d) ∈ preimages ⇒ h = blake(d) ∧ (h, len(d)) ∈ keys(requests)` — i.e. a blob
cannot exist without a prior request.

Mapping to our code: eq. `preimagesareordered` → Phase 1; `∀ providable`
(status `[]`) → Phase 2; `provide` → Phase 3.

**Nuance.** GP's `provide` *silently disregards* items whose request was dropped
by accumulation mid-block ("without prejudice"). The STF vectors instead treat a
non-`providable` item as a hard `preimage_unneeded` error (block validity per
eq. 489); our code implements the STF-vector behavior, which is what conformance
checks. Source: `github.com/gavofyork/graypaper`.
