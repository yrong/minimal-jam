//! Accumulate execution engine (GP §12 `accone`/`Ψ_A` + host-call ABI).
//!
//! Runs a service's `accumulate` logic in the PVM with the accumulate host-call
//! subset, then reports the mutated accounts, gas used, and yielded output.

use crate::state::ServiceInfo;
use crate::state_key::{key_service, service_preimage, service_request, service_storage, StateKey};
use crate::bytes::Hex;
use crate::crypto::blake2b_256;
use crate::pvm::{ExitStatus, Memory, Vm};
use std::collections::BTreeMap;

const Z: u64 = 1 << 16; // init zone
const I: u64 = 1 << 24; // init input size
const P: u64 = 4096; // page
/// Per-storage-item octet overhead (GP service footprint).
const ITEM_OVERHEAD: u64 = 34;
const NONE: u64 = u64::MAX;
const WHO: u64 = u64::MAX - 1;
const HUH: u64 = u64::MAX - 3;
const CASH: u64 = u64::MAX - 5;

/// A deferred balance transfer emitted by `transfer`, applied after all
/// services have accumulated (credited to the destination if it still exists,
/// otherwise burnt).
#[derive(Clone)]
pub struct Transfer {
    pub dest: u32,
    pub amount: u64,
}

/// Service state visible to accumulate: per-service metadata plus the opaque
/// state-key dictionary (storage/preimages/requests). `key_raw` records the raw
/// storage key behind each hashed storage state-key so the typed accumulate STF
/// post-state can be reconstructed; it is irrelevant to the trace path.
#[derive(Clone, Default)]
pub struct ExecState {
    pub accounts: BTreeMap<u32, ServiceInfo>,
    pub dict: BTreeMap<StateKey, Vec<u8>>,
    pub key_raw: BTreeMap<StateKey, (u32, Vec<u8>)>,
}

/// Result of running one service's accumulate logic.
pub struct AccOut {
    pub state: ExecState,
    pub gas_used: i64,
    pub yielded: Option<[u8; 32]>,
    pub transfers: Vec<Transfer>,
}

fn le(bytes: &[u8], off: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for k in 0..n {
        v |= (bytes[off + k] as u64) << (8 * k);
    }
    v
}

/// Locate the GP standard-program blob inside a jam-pvm container by finding the
/// offset whose length header consumes exactly to the blob end.
fn program_offset(b: &[u8]) -> Option<usize> {
    for start in 0..256usize {
        if start + 11 > b.len() {
            break;
        }
        let ol = le(b, start, 3) as usize;
        let wl = le(b, start + 3, 3) as usize;
        let p = start + 11 + ol + wl;
        if p + 4 > b.len() {
            continue;
        }
        let pl = le(b, p, 4) as usize;
        if start + 11 + ol + wl + 4 + pl == b.len() {
            return Some(start);
        }
    }
    None
}

/// Standard program initialization `Y`: decode the blob and lay out memory +
/// registers for `args`.
fn spi(jam: &[u8], args: &[u8]) -> Option<(Vec<u8>, [u64; 13], Memory, u64, u64)> {
    let base = program_offset(jam)?;
    let mut o = base;
    let olen = le(jam, o, 3) as usize;
    o += 3;
    let wlen = le(jam, o, 3) as usize;
    o += 3;
    let z = le(jam, o, 2) as usize;
    o += 2;
    let s = le(jam, o, 3) as usize;
    o += 3;
    let ro = jam.get(o..o + olen)?.to_vec();
    o += olen;
    let rw = jam.get(o..o + wlen)?.to_vec();
    o += wlen;
    let plen = le(jam, o, 4) as usize;
    o += 4;
    let pvm = jam.get(o..o + plen)?.to_vec();

    let pq = |x: u64| P * x.div_ceil(P);
    let qq = |x: u64| Z * x.div_ceil(Z);
    let mut mem = Memory::default();
    mem.map(Z as u32, pq(olen as u64) as u32, false);
    mem.store(Z as u32, &ro);
    let wbase = 2 * Z + qq(olen as u64);
    mem.map(wbase as u32, (pq(wlen as u64) + z as u64 * P) as u32, true);
    mem.store(wbase as u32, &rw);
    // Heap break starts at the accessible RW end; `sbrk` may grow it to the end
    // of the reserved heap zone (`rnq(|w| + z·P)`).
    mem.heap_top = (wbase + pq(wlen as u64) + z as u64 * P) as u32;
    mem.heap_max = (wbase + qq(wlen as u64 + z as u64 * P)) as u32;
    let stack_lo = (1u64 << 32) - 2 * Z - I - pq(s as u64);
    mem.map(stack_lo as u32, pq(s as u64) as u32, true);
    let abase = (1u64 << 32) - Z - I;
    mem.map(abase as u32, pq(args.len() as u64) as u32, false);
    mem.store(abase as u32, args);

    let mut regs = [0u64; 13];
    regs[0] = (1u64 << 32) - (1 << 16);
    regs[1] = (1u64 << 32) - 2 * Z - I;
    regs[7] = abase;
    regs[8] = args.len() as u64;
    // RW heap page bounds (for a future allocator host call).
    let a = wbase / P;
    let b = ((1u64 << 32) - 3 * Z - I - qq(s as u64)) / P;
    Some((pvm, regs, mem, a, b))
}

/// Encode `AccumulateParams` (compact slot ‖ service ‖ item_count).
fn acc_args(slot: u32, service: u32, n: u32) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&compact(slot as u64));
    a.extend_from_slice(&compact(service as u64));
    a.extend_from_slice(&compact(n as u64));
    a
}

/// General-natural (compact) length encoding for a byte sequence prefix.
fn compact(n: u64) -> Vec<u8> {
    if n < 128 {
        return vec![n as u8];
    }
    let mut len = 1usize;
    while n >= (1u64 << (7 * (len + 1))) && len < 8 {
        len += 1;
    }
    let mut out = vec![0u8; len + 1];
    let mut rem = n;
    for b in out.iter_mut().skip(1) {
        *b = rem as u8;
        rem >>= 8;
    }
    out[0] = (256u16 - (1u16 << (8 - len as u16))) as u8 | (n >> (8 * len)) as u8;
    out
}

/// Preimage-request expunge period `C_expungeperiod` (GP): a forgotten request
/// may be fully dropped only once its unavailability is this old.
const EXPUNGE: u32 = 14_400 + 4_800;

/// Decode a preimage-request status: a length byte (0–3) then that many 4-byte
/// little-endian timeslots.
fn decode_status(bytes: &[u8]) -> Vec<u32> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let n = bytes[0] as usize;
    (0..n)
        .map(|i| u32::from_le_bytes([bytes[1 + i * 4], bytes[2 + i * 4], bytes[3 + i * 4], bytes[4 + i * 4]]))
        .collect()
}

/// Encode a preimage-request status (inverse of [`decode_status`]).
fn encode_status(slots: &[u32]) -> Vec<u8> {
    let mut v = compact(slots.len() as u64);
    for s in slots {
        v.extend_from_slice(&s.to_le_bytes());
    }
    v
}

/// Encode one operand as `AccumulateItem::WorkItem(WorkItemRecord)` (jam-types
/// SCALE layout) for the `fetch` host call.
fn encode_operand(op: &Operand) -> Vec<u8> {
    let mut v = vec![0u8]; // enum tag: WorkItem = 0
    v.extend_from_slice(&op.package_hash);
    v.extend_from_slice(&op.seg_root);
    v.extend_from_slice(&op.authorizer);
    v.extend_from_slice(&op.payload_hash);
    v.extend_from_slice(&compact(op.gas_limit));
    // CompactRefineResult: Ok → 0 ‖ WorkOutput(compact-len blob); Err → code.
    match &op.result {
        Ok(out) => {
            v.push(0);
            v.extend_from_slice(&compact(out.len() as u64));
            v.extend_from_slice(out);
        }
        Err(code) => v.push(*code),
    }
    // auth_output (AuthTrace): compact-len blob.
    v.extend_from_slice(&compact(op.auth_trace.len() as u64));
    v.extend_from_slice(&op.auth_trace);
    v
}

/// The `ProtocolParameters` blob for `fetch(kind=0)` — jam-types `tiny()`
/// values in exact struct field order (all fixed-width; Balance/Gas u64,
/// Slot/u32 4 bytes, indices/u16 2 bytes).
fn protocol_params() -> Vec<u8> {
    let mut v = Vec::new();
    let mut e = |val: u64, n: usize| {
        for k in 0..n {
            v.push((val >> (8 * k)) as u8);
        }
    };
    e(10, 8); // deposit_per_item
    e(1, 8); // deposit_per_byte
    e(100, 8); // deposit_per_account
    e(2, 2); // core_count
    e(32, 4); // min_turnaround_period
    e(12, 4); // epoch_period
    e(10_000_000, 8); // max_accumulate_gas
    e(50_000_000, 8); // max_is_authorized_gas
    e(1_000_000_000, 8); // max_refine_gas
    e(20_000_000, 8); // block_gas_limit
    e(8, 2); // recent_block_count
    e(16, 2); // max_work_items
    e(8, 2); // max_dependencies
    e(3, 2); // max_tickets_per_block
    e(24, 4); // max_lookup_anchor_age
    e(3, 2); // tickets_attempts_number
    e(8, 2); // auth_window
    e(6, 2); // slot_period_sec
    e(80, 2); // auth_queue_len
    e(4, 2); // rotation_period
    e(128, 2); // max_extrinsics
    e(5, 2); // availability_timeout
    e(6, 2); // val_count
    e(64_000, 4); // max_authorizer_code_size
    e(13_791_360, 4); // max_input
    e(4_000_000, 4); // max_service_code_size
    e(4, 4); // basic_piece_len
    e(3_072, 4); // max_imports
    e(1_026, 4); // segment_piece_count
    e(48 * 1024, 4); // max_report_elective_data
    e(128, 4); // transfer_memo_size
    e(3_072, 4); // max_exports
    e(10, 4); // epoch_tail_start
    v
}

/// An operand tuple (the accumulate input for one work digest).
pub struct Operand {
    pub package_hash: [u8; 32],
    pub seg_root: [u8; 32],
    pub authorizer: [u8; 32],
    pub payload_hash: [u8; 32],
    pub gas_limit: u64,
    pub auth_trace: Vec<u8>,
    pub result: Result<Vec<u8>, u8>,
}

/// Run one service's accumulate logic.
pub fn run_service(
    code: &[u8],
    slot: u32,
    service: u32,
    gas: i64,
    operands: &[Operand],
    state: ExecState,
) -> AccOut {
    let args = acc_args(slot, service, operands.len() as u32);
    let Some((pvm, regs, memory, _a, _b)) = spi(code, &args) else {
        return AccOut { state, gas_used: 0, yielded: None, transfers: Vec::new() };
    };
    let Some(mut vm) = Vm::new(&pvm, 5, gas, regs, memory) else {
        return AccOut { state, gas_used: 0, yielded: None, transfers: Vec::new() };
    };
    let orig = state.clone();
    let mut ctx = state;
    let mut yielded: Option<[u8; 32]> = None;
    let mut transfers: Vec<Transfer> = Vec::new();
    let encoded_operands: Vec<Vec<u8>> = operands.iter().map(encode_operand).collect();

    loop {
        match vm.run() {
            ExitStatus::HostCall(n) => {
                host(n, &mut vm, service, slot, &mut ctx, &encoded_operands, &mut yielded, &mut transfers);
                vm.advance_host();
            }
            ExitStatus::Halt => break,
            _ => {
                // Panic/out-of-gas/fault: the exceptional dimension discards the
                // regular-context changes (no checkpoint in the covered vectors).
                return AccOut { state: orig, gas_used: gas - vm.gas, yielded: None, transfers: Vec::new() };
            }
        }
    }
    AccOut { state: ctx, gas_used: gas - vm.gas, yielded, transfers }
}

/// Dispatch a host call, mutating VM state and the accumulate context.
fn host(
    n: u64,
    vm: &mut Vm,
    service: u32,
    slot: u32,
    state: &mut ExecState,
    operands: &[Vec<u8>],
    yielded: &mut Option<[u8; 32]>,
    transfers: &mut Vec<Transfer>,
) {
    // Host-call gas (tiny test model): a flat 10 per host call, except a memo
    // `transfer`, which additionally reserves its destination's `on_transfer`
    // gas limit (r9). The `ecalli` instruction itself is charged with its block.
    vm.gas -= if n == 20 { 10 + vm.regs[9] as i64 } else { 10 };
    let reg = vm.regs;
    match n {
        0 => {
            // gas: remaining gas counter
            vm.regs[7] = vm.gas as u64;
        }
        1 => {
            // fetch(buffer=r7, offset=r8, buffer_len=r9, kind=r10, a=r11, b=r12)
            let data: Option<Vec<u8>> = match reg[10] {
                0 => Some(protocol_params()),
                14 => {
                    let mut all = compact(operands.len() as u64);
                    for o in operands {
                        all.extend_from_slice(o);
                    }
                    Some(all)
                }
                15 => operands.get(reg[11] as usize).cloned(),
                _ => None,
            };
            write_out(vm, data);
        }
        3 => {
            // read(service=r7, key_ptr=r8, key_len=r9, out=r10, offset=r11, out_len=r12)
            let who = if reg[7] == NONE { service } else { reg[7] as u32 };
            if !vm.memory.readable_range(reg[8] as u32, reg[9]) {
                vm.regs[7] = NONE;
                return;
            }
            let key = vm.memory.load(reg[8] as u32, reg[9] as usize);
            let val = state.dict.get(&service_storage(who, &key)).cloned();
            match val {
                Some(v) => {
                    let f = (reg[11] as usize).min(v.len());
                    let l = (reg[12] as usize).min(v.len() - f);
                    vm.memory.store(reg[10] as u32, &v[f..f + l]);
                    vm.regs[7] = v.len() as u64;
                }
                None => vm.regs[7] = NONE,
            }
        }
        4 => {
            // write(key_ptr=r7, key_len=r8, value_ptr=r9, value_len=r10) — caller storage
            if !vm.memory.readable_range(reg[7] as u32, reg[8])
                || !vm.memory.readable_range(reg[9] as u32, reg[10])
            {
                vm.regs[7] = NONE;
                return;
            }
            let key = vm.memory.load(reg[7] as u32, reg[8] as usize);
            let value = vm.memory.load(reg[9] as u32, reg[10] as usize);
            if !state.accounts.contains_key(&service) {
                vm.regs[7] = WHO;
                return;
            }
            let sk = service_storage(service, &key);
            let old = state.dict.get(&sk).map(|v| v.len());
            if reg[10] == 0 {
                if let Some(old_len) = old {
                    state.dict.remove(&sk);
                    state.key_raw.remove(&sk);
                    if let Some(a) = state.accounts.get_mut(&service) {
                        a.items -= 1;
                        a.bytes -= ITEM_OVERHEAD + key.len() as u64 + old_len as u64;
                    }
                }
            } else {
                if let Some(a) = state.accounts.get_mut(&service) {
                    match old {
                        Some(old_len) => a.bytes = a.bytes - old_len as u64 + value.len() as u64,
                        None => {
                            a.items += 1;
                            a.bytes += ITEM_OVERHEAD + key.len() as u64 + value.len() as u64;
                        }
                    }
                }
                state.dict.insert(sk, value);
                state.key_raw.insert(sk, (service, key));
            }
            vm.regs[7] = old.map_or(NONE, |l| l as u64);
        }
        5 => {
            // info(service=r7, ptr=r8, offset=r9, len=r10)
            let who = if reg[7] == NONE { service } else { reg[7] as u32 };
            let data = state.accounts.get(&who).map(encode_info);
            let (o, f0, z) = (reg[8], reg[9], reg[10]);
            match data {
                None => vm.regs[7] = NONE,
                Some(v) => {
                    let f = (f0 as usize).min(v.len());
                    let l = (z as usize).min(v.len() - f);
                    vm.memory.store(o as u32, &v[f..f + l]);
                    vm.regs[7] = v.len() as u64;
                }
            }
        }
        25 => {
            // yield(hash_ptr=r7)
            let bytes = vm.memory.load(reg[7] as u32, 32);
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes);
            *yielded = Some(h);
            vm.regs[7] = 0;
        }
        21 => {
            // eject(target=r7): remove the target service, crediting its full
            // balance to the caller (GP Ω_J, tiny 0.7.2 model).
            let d = reg[7] as u32;
            if !state.accounts.contains_key(&d) {
                vm.regs[7] = WHO;
            } else if d == service {
                vm.regs[7] = HUH;
            } else {
                let bal = state.accounts[&d].balance;
                state.accounts.remove(&d);
                state.dict.retain(|k, _| key_service(k) != d);
                state.key_raw.retain(|k, _| key_service(k) != d);
                if let Some(me) = state.accounts.get_mut(&service) {
                    me.balance += bal;
                }
                vm.regs[7] = 0;
            }
        }
        20 => {
            // transfer(dest=r7, amount=r8, gas_limit=r9, memo_ptr=r10): deduct
            // the caller's balance now and record a deferred transfer, credited
            // to the destination after all services accumulate (GP Ω_T).
            let dest = reg[7] as u32;
            let amount = reg[8];
            if !state.accounts.contains_key(&dest) {
                vm.regs[7] = WHO;
            } else if state.accounts.get(&service).is_none_or(|a| a.balance < amount) {
                vm.regs[7] = CASH;
            } else {
                if let Some(me) = state.accounts.get_mut(&service) {
                    me.balance -= amount;
                }
                transfers.push(Transfer { dest, amount });
                vm.regs[7] = 0;
            }
        }
        100 => { /* log: no-op */ }
        2 => {
            // lookup(service=r7, hash_ptr=r8, out=r9, offset=r10, out_len=r11):
            // read a preimage blob by hash from `service`'s dictionary.
            let who = if reg[7] == NONE { service } else { reg[7] as u32 };
            if !vm.memory.readable_range(reg[8] as u32, 32) {
                vm.regs[7] = NONE;
                return;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&vm.memory.load(reg[8] as u32, 32));
            match state.dict.get(&service_preimage(who, &h)).cloned() {
                Some(v) => {
                    let f = (reg[10] as usize).min(v.len());
                    let l = (reg[11] as usize).min(v.len() - f);
                    vm.memory.store(reg[9] as u32, &v[f..f + l]);
                    vm.regs[7] = v.len() as u64;
                }
                None => vm.regs[7] = NONE,
            }
        }
        22 => {
            // query(target=r7, hash_ptr=r8, length=r9): report a preimage
            // request's status in r7 (count + first-slot<<32) and r8 (rest).
            let s = if reg[7] == NONE { service } else { reg[7] as u32 };
            let z = reg[9] as u32;
            if !vm.memory.readable_range(reg[8] as u32, 32) {
                vm.regs[7] = NONE;
                return;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&vm.memory.load(reg[8] as u32, 32));
            if !state.accounts.contains_key(&s) {
                vm.regs[7] = WHO;
                return;
            }
            match state.dict.get(&service_request(s, z, &h)).map(|b| decode_status(b)) {
                None => {
                    vm.regs[7] = NONE;
                    vm.regs[8] = 0;
                }
                Some(a) => {
                    let sl = |i: usize| a.get(i).copied().unwrap_or(0) as u64;
                    vm.regs[7] = a.len() as u64 + (sl(0) << 32);
                    vm.regs[8] = sl(1) + (sl(2) << 32);
                }
            }
        }
        23 => {
            // solicit(target=r7, hash_ptr=r8, length=r9): request a preimage.
            let d = if reg[7] == NONE { service } else { reg[7] as u32 };
            let z = reg[9] as u32;
            if !vm.memory.readable_range(reg[8] as u32, 32) {
                vm.regs[7] = NONE;
                return;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&vm.memory.load(reg[8] as u32, 32));
            if !state.accounts.contains_key(&d) {
                vm.regs[7] = WHO;
                return;
            }
            let rk = service_request(d, z, &h);
            match state.dict.get(&rk).map(|b| decode_status(b)) {
                None => {
                    state.dict.insert(rk, encode_status(&[]));
                    if let Some(a) = state.accounts.get_mut(&d) {
                        a.items += 2;
                        a.bytes += 81 + z as u64;
                    }
                    vm.regs[7] = 0;
                }
                Some(s) if s.len() == 2 => {
                    let ns = [s[0], s[1], slot];
                    state.dict.insert(rk, encode_status(&ns));
                    vm.regs[7] = 0;
                }
                _ => vm.regs[7] = HUH,
            }
        }
        24 => {
            // forget(target=r7, hash_ptr=r8, length=r9): drop a preimage request.
            let d = if reg[7] == NONE { service } else { reg[7] as u32 };
            let z = reg[9] as u32;
            if !vm.memory.readable_range(reg[8] as u32, 32) {
                vm.regs[7] = NONE;
                return;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&vm.memory.load(reg[8] as u32, 32));
            if !state.accounts.contains_key(&d) {
                vm.regs[7] = WHO;
                return;
            }
            let rk = service_request(d, z, &h);
            let drop_request = |state: &mut ExecState| {
                state.dict.remove(&rk);
                if let Some(a) = state.accounts.get_mut(&d) {
                    a.items -= 2;
                    a.bytes -= 81 + z as u64;
                }
            };
            match state.dict.get(&rk).map(|b| decode_status(b)) {
                Some(s) if s.is_empty() => {
                    drop_request(state);
                    vm.regs[7] = 0;
                }
                Some(s) if s.len() == 2 && s[1] < slot.saturating_sub(EXPUNGE) => {
                    drop_request(state);
                    state.dict.remove(&service_preimage(d, &h));
                    vm.regs[7] = 0;
                }
                Some(s) if s.len() == 1 => {
                    state.dict.insert(rk, encode_status(&[s[0], slot]));
                    vm.regs[7] = 0;
                }
                Some(s) if s.len() == 3 && s[1] < slot.saturating_sub(EXPUNGE) => {
                    state.dict.insert(rk, encode_status(&[s[2], slot]));
                    vm.regs[7] = 0;
                }
                _ => vm.regs[7] = HUH,
            }
        }
        _ => {
            vm.regs[7] = HUH;
        }
    }
}

/// Write `data` to memory at (r7, offset r8, len r9); r7' = total length or NONE.
fn write_out(vm: &mut Vm, data: Option<Vec<u8>>) {
    let (o, f0, z) = (vm.regs[7], vm.regs[8], vm.regs[9]);
    match data {
        None => vm.regs[7] = NONE,
        Some(v) => {
            let f = (f0 as usize).min(v.len());
            let l = (z as usize).min(v.len() - f);
            vm.memory.store(o as u32, &v[f..f + l]);
            vm.regs[7] = v.len() as u64;
        }
    }
}

/// Encode service info for the `info` host call.
fn encode_info(s: &crate::state::ServiceInfo) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&s.code_hash.0);
    v.extend_from_slice(&s.balance.to_le_bytes());
    v.extend_from_slice(&s.min_item_gas.to_le_bytes());
    v.extend_from_slice(&s.min_memo_gas.to_le_bytes());
    v.extend_from_slice(&s.bytes.to_le_bytes());
    v.extend_from_slice(&(s.items).to_le_bytes());
    v
}

/// A provided preimage hash helper (blake2b) — used by preimage integration.
pub fn preimage_key(blob: &[u8]) -> Hex<32> {
    Hex(blake2b_256(blob))
}
