//! PVM interpreter conformance (GP Appendix A, Ψ): run each program blob and
//! assert the final status, pc, gas, registers, and memory.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use minimal_jam::pvm::{run, ExitStatus, MemoryChunk, PageMapEntry};
use serde::Deserialize;

#[derive(Deserialize)]
struct PageMap {
    address: u32,
    length: u32,
    #[serde(rename = "is-writable")]
    is_writable: bool,
}

#[derive(Deserialize)]
struct Chunk {
    address: u32,
    contents: Vec<u8>,
}

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "initial-regs")]
    initial_regs: Vec<u64>,
    #[serde(rename = "initial-pc")]
    initial_pc: u32,
    #[serde(rename = "initial-page-map")]
    initial_page_map: Vec<PageMap>,
    #[serde(rename = "initial-memory")]
    initial_memory: Vec<Chunk>,
    #[serde(rename = "initial-gas")]
    initial_gas: i64,
    program: Vec<u8>,
    #[serde(rename = "expected-status")]
    expected_status: String,
    #[serde(rename = "expected-regs")]
    expected_regs: Vec<u64>,
    #[serde(rename = "expected-pc")]
    expected_pc: u32,
    #[serde(rename = "expected-memory")]
    expected_memory: Vec<Chunk>,
    #[serde(rename = "expected-gas")]
    expected_gas: i64,
}

fn status_str(s: ExitStatus) -> &'static str {
    match s {
        ExitStatus::Halt => "halt",
        ExitStatus::Panic => "panic",
        ExitStatus::OutOfGas => "out-of-gas",
        ExitStatus::PageFault(_) => "page-fault",
        ExitStatus::HostCall(_) => "host-call",
    }
}

fn nonzero_map(chunks: &[Chunk]) -> BTreeMap<u32, u8> {
    let mut m = BTreeMap::new();
    for c in chunks {
        for (k, &b) in c.contents.iter().enumerate() {
            if b != 0 {
                m.insert(c.address + k as u32, b);
            }
        }
    }
    m
}

fn run_case(name: &str) -> Result<(), String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/pvm")
        .join(format!("{name}.json"));
    let c: Case = serde_json::from_str(&fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|e| panic!("parse {name}: {e}"));

    let mut regs = [0u64; 13];
    regs.copy_from_slice(&c.initial_regs);
    let page_map: Vec<PageMapEntry> = c
        .initial_page_map
        .iter()
        .map(|p| PageMapEntry {
            address: p.address,
            length: p.length,
            writable: p.is_writable,
        })
        .collect();
    let mem_init: Vec<MemoryChunk> = c
        .initial_memory
        .iter()
        .map(|m| MemoryChunk {
            address: m.address,
            contents: m.contents.clone(),
        })
        .collect();

    let out = run(&c.program, c.initial_pc, c.initial_gas, regs, &page_map, &mem_init);

    let got = status_str(out.status);
    if got != c.expected_status {
        return Err(format!("status: got {got} want {}", c.expected_status));
    }
    if out.pc != c.expected_pc {
        return Err(format!("pc: got {} want {}", out.pc, c.expected_pc));
    }
    if out.gas != c.expected_gas {
        return Err(format!("gas: got {} want {}", out.gas, c.expected_gas));
    }
    if out.regs.as_slice() != c.expected_regs.as_slice() {
        return Err(format!("regs: got {:?} want {:?}", out.regs, c.expected_regs));
    }
    let got_mem: BTreeMap<u32, u8> = out.memory.nonzero().into_iter().collect();
    let want_mem = nonzero_map(&c.expected_memory);
    if got_mem != want_mem {
        return Err("memory differs".into());
    }
    Ok(())
}

#[test]
fn pvm_vectors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/pvm");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "json").then(|| p.file_stem()?.to_str().map(String::from))?
        })
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no pvm vectors found");
    let mut failures = Vec::new();
    for name in &names {
        if let Err(why) = run_case(name) {
            failures.push(format!("{name}: {why}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{}/{} failed:\n{}",
        failures.len(),
        names.len(),
        failures.join("\n")
    );
}
