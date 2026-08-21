//! Golden per-instruction trace diff harness.
//!
//! Runs one service's `accumulate` invocation in this implementation's PVM,
//! capturing a per-instruction trace, and diffs it against a jamduna golden
//! stream (`jam-test-vectors/0.7.2/fuzzy/<block>/<acc>/<service>/`). Reports the
//! first step whose pc / opcode / registers disagree — pinning exactly which
//! instruction (and thus which host call) first diverges from the reference.
//!
//! Inputs come from two sources so no full-config state decode is needed:
//!   * the davxy fuzzy trace JSON supplies the pre-state key/values (service
//!     accounts, storage, and code preimage) and the posterior entropy;
//!   * the golden service directory supplies `input` (slot/service/operand
//!     count), `accumulate_input` (the `fetch` 14/15 operand bytes), and the
//!     decompressed per-instruction streams `pc`, `opcode`, `r0`..`r12`.
//!
//! Usage:
//!   cargo run --example golden_diff -- <trace.json> <golden_dir> <service_id>
//!
//! The golden `*.gz` streams must be decompressed into `<golden_dir>` first
//! (e.g. `for f in *.gz; do gzip -dc "$f" > "${f%.gz}"; done`).

use std::collections::BTreeMap;
use std::fs;

use jam_codec::Decode;
use minimal_jam::accumulate_exec::{run_service_raw, trace_start, trace_take, ExecState, TraceRow};
use minimal_jam::bytes::FixedSeq;
use minimal_jam::hexutil::from_hex;
use minimal_jam::state::{Privileges, ServiceInfo};
use minimal_jam::state_key::{service_preimage, StateKey};
use minimal_jam::types::CORE_COUNT;
use serde::Deserialize;

#[derive(Deserialize)]
struct KeyVal {
    key: String,
    value: String,
}
#[derive(Deserialize)]
struct Snapshot {
    keyvals: Vec<KeyVal>,
}
#[derive(Deserialize)]
struct Trace {
    pre_state: Snapshot,
    post_state: Snapshot,
}

fn key31(hex: &str) -> StateKey {
    let mut k = [0u8; 31];
    k.copy_from_slice(&from_hex(hex));
    k
}

/// Decode a GP compact integer, returning (value, bytes_consumed).
fn read_compact(b: &[u8]) -> (u64, usize) {
    let first = b[0];
    if first == 0 {
        return (0, 1);
    }
    let len = first.leading_ones() as usize; // number of extra bytes
    if len == 0 {
        return (first as u64, 1);
    }
    if len == 8 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&b[1..9]);
        return (u64::from_le_bytes(v), 9);
    }
    let low = (first & (0xff >> len)) as u64;
    let mut val = 0u64;
    for i in 0..len {
        val |= (b[1 + i] as u64) << (8 * i);
    }
    val |= low << (8 * len);
    (val, 1 + len)
}

fn read_u64s(path: &str) -> Vec<u64> {
    let b = fs::read(path).unwrap_or_else(|_| panic!("missing stream {path}"));
    b.chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: golden_diff <trace.json> <golden_dir> <service_id>");
        std::process::exit(2);
    }
    let trace_path = &args[1];
    let gdir = args[2].trim_end_matches('/').to_string();
    let target: u32 = args[3].parse().expect("service id");

    let t: Trace = serde_json::from_str(&fs::read_to_string(trace_path).unwrap()).unwrap();

    // --- Build ExecState from raw pre-state key/values (config-agnostic). ---
    let mut dict: BTreeMap<StateKey, Vec<u8>> = BTreeMap::new();
    let mut accounts: BTreeMap<u32, ServiceInfo> = BTreeMap::new();
    for kv in &t.pre_state.keyvals {
        let k = key31(&kv.key);
        let v = from_hex(&kv.value);
        // Service account `C(255, s)`: chapter byte 255, zeros at 2/4/6.
        if k[0] == 255 && k[2] == 0 && k[4] == 0 && k[6] == 0 {
            let s = u32::from_le_bytes([k[1], k[3], k[5], k[7]]);
            if let Ok(info) = ServiceInfo::decode(&mut &v[..]) {
                accounts.insert(s, info);
            }
        }
        dict.insert(k, v);
    }
    // read()/preimage lookups recompute the same hashed key, so the raw dict is
    // a faithful storage backend.
    let exec = ExecState {
        accounts: accounts.clone(),
        dict: dict.clone(),
        key_raw: BTreeMap::new(),
        privileges: Privileges {
            manager: 0,
            assign: FixedSeq(vec![0u32; CORE_COUNT]),
            delegator: 0,
            registrar: 0,
            always_acc: Vec::new(),
        },
        auth_queues: FixedSeq(Vec::new()),
        staging: FixedSeq(Vec::new()),
        next_free_id: 0,
    };

    // --- Service code = preimage of the account's code hash. ---
    let info = accounts
        .get(&target)
        .unwrap_or_else(|| panic!("service {target} has no account in pre-state"));
    let code_hash = info.code_hash.0;
    let code = dict
        .get(&service_preimage(target, &code_hash))
        .cloned()
        .unwrap_or_else(|| panic!("no code preimage for service {target}"));

    // --- Inputs from golden. ---
    let input = fs::read(format!("{gdir}/input")).expect("golden input");
    let (slot, n0) = read_compact(&input);
    let (svc_in, n1) = read_compact(&input[n0..]);
    let (count, _) = read_compact(&input[n0 + n1..]);
    assert_eq!(svc_in as u32, target, "golden input service mismatch");

    let acc_in = fs::read(format!("{gdir}/accumulate_input")).expect("golden accumulate_input");
    let (op_count, off) = read_compact(&acc_in);
    assert_eq!(op_count, count, "operand count mismatch input vs accumulate_input");
    // Split the concatenated operands (fetch 14 returns compact(count) ‖ each
    // encoded operand). Each operand is:
    //   tag(1) ‖ 4×hash(128) ‖ compact(gas) ‖ result ‖ compact(auth_len) ‖ auth
    // where result = 0x00 ‖ compact(len) ‖ blob   (Ok)  |  err_code(1) (Err).
    let mut encoded_operands: Vec<Vec<u8>> = Vec::new();
    let mut pos = off;
    for _ in 0..count {
        let start = pos;
        pos += 1 + 128; // tag + four hashes
        let (_, n) = read_compact(&acc_in[pos..]);
        pos += n; // gas_limit
        let rtag = acc_in[pos];
        pos += 1; // result tag
        if rtag == 0 {
            let (blen, n) = read_compact(&acc_in[pos..]);
            pos += n + blen as usize; // Ok blob
        }
        let (alen, an) = read_compact(&acc_in[pos..]);
        pos += an + alen as usize; // auth trace
        encoded_operands.push(acc_in[start..pos].to_vec());
    }
    assert_eq!(pos, acc_in.len(), "operand split did not consume the whole blob");

    // Entropy = posterior η'_0 (first 32 bytes of chapter 6), overridable.
    let entropy = match std::env::var("ENTROPY") {
        Ok(h) => {
            let mut e = [0u8; 32];
            e.copy_from_slice(&from_hex(&h));
            e
        }
        Err(_) => {
            let ck = {
                let mut k = [0u8; 31];
                k[0] = 6;
                k
            };
            let mut e = [0u8; 32];
            let post: BTreeMap<StateKey, Vec<u8>> = t
                .post_state
                .keyvals
                .iter()
                .map(|kv| (key31(&kv.key), from_hex(&kv.value)))
                .collect();
            if let Some(v) = post.get(&ck) {
                e.copy_from_slice(&v[..32]);
            }
            e
        }
    };

    // Exact budget: with per-instruction charging, step 0 deducts one unit, so
    // the initial grant is golden gas[0] + 1.
    let g_gas0 = read_u64s(&format!("{gdir}/gas"))[0];
    let gas: i64 = g_gas0 as i64 + 1;

    trace_start();
    let out = run_service_raw(&code, slot as u32, target, gas, encoded_operands, &entropy, exec);
    let rows: Vec<TraceRow> = trace_take();

    println!(
        "service {target}: slot={slot} operands={count} code_len={} steps={} yielded={} gas_used={}",
        code.len(),
        rows.len(),
        out.yielded.map(|h| hex::encode(h)).unwrap_or_else(|| "none".into()),
        out.gas_used,
    );

    // --- Load golden streams and diff. ---
    let g_op = fs::read(format!("{gdir}/opcode")).expect("golden opcode");
    let g_pc = read_u64s(&format!("{gdir}/pc"));
    let g_r: Vec<Vec<u64>> = (0..13).map(|j| read_u64s(&format!("{gdir}/r{j}"))).collect();
    let g_steps = g_op.len();
    println!("golden steps={g_steps}");

    let n = rows.len().min(g_steps);
    for i in 0..n {
        let r = &rows[i];
        let mut diffs: Vec<String> = Vec::new();
        if r.pc as u64 != g_pc[i] {
            diffs.push(format!("pc mine={} golden={}", r.pc, g_pc[i]));
        }
        if r.op != g_op[i] {
            diffs.push(format!("op mine={} golden={}", r.op, g_op[i]));
        }
        for j in 0..13 {
            if r.regs[j] != g_r[j][i] {
                diffs.push(format!("r{j} mine={} golden={}", r.regs[j], g_r[j][i]));
            }
        }
        if !diffs.is_empty() {
            println!("FIRST DIVERGENCE at step {i}:");
            // Context: previous two golden steps.
            for k in i.saturating_sub(2)..i {
                println!("  step {k}: pc={} op={} r7={}", g_pc[k], g_op[k], g_r[7][k]);
            }
            for d in &diffs {
                println!("  {d}");
            }
            return;
        }
    }
    if rows.len() == g_steps {
        println!("MATCH: all {g_steps} steps identical (pc/opcode/registers)");
    } else {
        println!(
            "PREFIX MATCH for {n} steps; lengths differ (mine={} golden={})",
            rows.len(),
            g_steps
        );
    }
}
