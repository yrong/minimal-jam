//! PolkaVM interpreter — the JAM PVM function Ψ (GP Appendix A).
//!
//! A 64-bit register machine with 13 registers, paged 2³²-byte memory, and
//! per-basic-block gas charging. `run` executes a program blob to a halting
//! condition (halt, panic, out-of-gas, page-fault, or host-call).

use std::collections::{BTreeMap, BTreeSet};

const PAGE_SIZE: u64 = 4096;
const DYN_ALIGN: u64 = 2;
const HALT_ADDR: u64 = 0xffff_0000;
const REG_COUNT: usize = 13;

/// Reason a PVM execution stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    Halt,
    Panic,
    OutOfGas,
    PageFault(u32),
    HostCall(u64),
}

/// An accessible memory region for the initial page map.
#[derive(Clone, Copy, Debug)]
pub struct PageMapEntry {
    pub address: u32,
    pub length: u32,
    pub writable: bool,
}

/// A run of bytes at a memory address.
#[derive(Clone, Debug)]
pub struct MemoryChunk {
    pub address: u32,
    pub contents: Vec<u8>,
}

/// Paged random-access memory (`µ`).
#[derive(Clone, Debug, Default)]
pub struct Memory {
    pages: BTreeMap<u32, Page>,
}

#[derive(Clone, Debug)]
struct Page {
    data: Vec<u8>,
    writable: bool,
}

impl Memory {
    fn ensure(&mut self, page: u32, writable: bool) {
        self.pages.entry(page).or_insert_with(|| Page {
            data: vec![0u8; PAGE_SIZE as usize],
            writable,
        });
    }

    fn readable(&self, addr: u64) -> bool {
        addr >= (1 << 16) && self.pages.contains_key(&((addr / PAGE_SIZE) as u32))
    }

    fn writable(&self, addr: u64) -> bool {
        addr >= (1 << 16)
            && self
                .pages
                .get(&((addr / PAGE_SIZE) as u32))
                .is_some_and(|p| p.writable)
    }

    /// Check an access range, returning the exceptional status if any byte is
    /// inaccessible (panic below 2¹⁶, else a page-fault at the lowest page).
    fn check(&self, addr: u64, len: usize, write: bool) -> Result<(), ExitStatus> {
        let mut min_bad: Option<u64> = None;
        for k in 0..len as u64 {
            let x = (addr + k) & 0xffff_ffff;
            let ok = if write { self.writable(x) } else { self.readable(x) };
            if !ok {
                min_bad = Some(min_bad.map_or(x, |m| m.min(x)));
            }
        }
        match min_bad {
            None => Ok(()),
            Some(m) if m < (1 << 16) => Err(ExitStatus::Panic),
            // A mapped-but-read-only page hit by a write is a hard panic; an
            // unmapped page is a recoverable page-fault.
            Some(m) if self.pages.contains_key(&((m / PAGE_SIZE) as u32)) => {
                Err(ExitStatus::Panic)
            }
            Some(m) => Err(ExitStatus::PageFault((m / PAGE_SIZE * PAGE_SIZE) as u32)),
        }
    }

    fn read(&self, addr: u64, len: usize) -> u64 {
        let mut v = 0u64;
        for k in 0..len {
            let x = (addr + k as u64) & 0xffff_ffff;
            let byte = self
                .pages
                .get(&((x / PAGE_SIZE) as u32))
                .map_or(0, |p| p.data[(x % PAGE_SIZE) as usize]);
            v |= (byte as u64) << (8 * k);
        }
        v
    }

    fn write(&mut self, addr: u64, len: usize, value: u64) {
        for k in 0..len {
            let x = (addr + k as u64) & 0xffff_ffff;
            if let Some(p) = self.pages.get_mut(&((x / PAGE_SIZE) as u32)) {
                p.data[(x % PAGE_SIZE) as usize] = (value >> (8 * k)) as u8;
            }
        }
    }

    /// Non-zero bytes across accessible pages, as `(address, byte)` pairs.
    pub fn nonzero(&self) -> Vec<(u32, u8)> {
        let mut out = Vec::new();
        for (&page, p) in &self.pages {
            for (i, &b) in p.data.iter().enumerate() {
                if b != 0 {
                    out.push((page * PAGE_SIZE as u32 + i as u32, b));
                }
            }
        }
        out
    }
}

/// Final machine state after a run.
pub struct Outcome {
    pub status: ExitStatus,
    pub pc: u32,
    pub gas: i64,
    pub regs: [u64; REG_COUNT],
    pub memory: Memory,
}

/// A decoded program blob: instruction data, opcode bitmask, jump table, and
/// the set of basic-block start indices.
struct Program {
    code: Vec<u8>,
    bitmask: Vec<bool>,
    jump_table: Vec<u64>,
    blocks: BTreeSet<usize>,
}

/// Decode a program blob (GP `deblob`, lenient: a final non-terminated block
/// simply traps on out-of-bounds rather than rejecting the blob).
fn deblob(blob: &[u8]) -> Option<Program> {
    let mut off = 0usize;
    let n_jump = read_compact(blob, &mut off)? as usize;
    let z = *blob.get(off)? as usize;
    off += 1;
    let n_code = read_compact(blob, &mut off)? as usize;

    let mut jump_table = Vec::with_capacity(n_jump);
    for _ in 0..n_jump {
        let mut v = 0u64;
        for k in 0..z {
            v |= (*blob.get(off + k)? as u64) << (8 * k);
        }
        off += z;
        jump_table.push(v);
    }

    let code = blob.get(off..off + n_code)?.to_vec();
    off += n_code;

    let mask_bytes = n_code.div_ceil(8);
    let mask_raw = blob.get(off..off + mask_bytes)?;
    let mut bitmask = Vec::with_capacity(n_code);
    for i in 0..n_code {
        bitmask.push(mask_raw[i / 8] & (1 << (i % 8)) != 0);
    }

    let blocks = basic_blocks(&code, &bitmask);
    Some(Program {
        code,
        bitmask,
        jump_table,
        blocks,
    })
}

/// General-natural (compact) integer decode (GP Appendix C).
fn read_compact(blob: &[u8], off: &mut usize) -> Option<u64> {
    let first = *blob.get(*off)? as u64;
    *off += 1;
    if first < 128 {
        return Some(first);
    }
    // Count leading 1 bits of the prefix byte to find the extra-byte count.
    let extra = (first as u8).leading_ones() as usize;
    let mut value = 0u64;
    for k in 0..extra {
        value |= (*blob.get(*off + k)? as u64) << (8 * k);
    }
    *off += extra;
    if extra < 8 {
        let high = first & ((1 << (8 - extra)) - 1);
        value |= high << (8 * extra);
    }
    Some(value)
}

/// Skip distance (octets to next opcode, minus one), capped at 24.
fn skip(bitmask: &[bool], i: usize) -> usize {
    let mut j = 0usize;
    while j < 24 {
        match bitmask.get(i + 1 + j) {
            Some(true) => return j,
            Some(false) => j += 1,
            None => return j, // padded with set bits
        }
    }
    24
}

/// Basic-block termination opcodes (`T`).
fn is_terminator(op: u8) -> bool {
    matches!(op, 0 | 1 | 40 | 50 | 80 | 180) || (81..=90).contains(&op) || (170..=175).contains(&op)
}

/// Compute the set of basic-block start indices. A start beyond the code
/// (a trap position) is valid, so falling/jumping off the end lands and traps.
fn basic_blocks(code: &[u8], bitmask: &[bool]) -> BTreeSet<usize> {
    let n = code.len();
    let mut starts = BTreeSet::new();
    let mark = |idx: usize, starts: &mut BTreeSet<usize>| {
        if idx >= n || (bitmask[idx] && is_valid_opcode(code[idx])) {
            starts.insert(idx);
        }
    };
    if n > 0 {
        mark(0, &mut starts);
    }
    for i in 0..n {
        if bitmask[i] && is_terminator(code[i]) {
            let next = i + 1 + skip(bitmask, i);
            mark(next, &mut starts);
        }
    }
    starts
}

fn is_block_start(prog: &Program, idx: i64) -> bool {
    idx >= 0 && prog.blocks.contains(&(idx as usize))
}

fn block_start_of(prog: &Program, pc: usize) -> usize {
    prog.blocks.range(..=pc).next_back().copied().unwrap_or(0)
}

/// Instruction count (= gas cost) of the block beginning at `start`.
fn block_gas_cost(prog: &Program, start: usize) -> i64 {
    let mut pc = start;
    let mut count = 0i64;
    loop {
        count += 1;
        let op = zeta(&prog.code, pc);
        if is_terminator(op) {
            return count;
        }
        pc = pc + 1 + skip(&prog.bitmask, pc);
        if count > 1_000_000 {
            return count;
        }
    }
}

/// Instruction byte at `i`, with an implicit zero (trap) suffix.
fn zeta(code: &[u8], i: usize) -> u8 {
    code.get(i).copied().unwrap_or(0)
}

/// Execute a program blob to a halting condition.
pub fn run(
    program: &[u8],
    pc: u32,
    gas: i64,
    regs: [u64; REG_COUNT],
    page_map: &[PageMapEntry],
    memory_init: &[MemoryChunk],
) -> Outcome {
    let mut memory = Memory::default();
    for e in page_map {
        let first = e.address / PAGE_SIZE as u32;
        let last = (e.address as u64 + e.length as u64).div_ceil(PAGE_SIZE) as u32;
        for p in first..last {
            memory.ensure(p, e.writable);
        }
    }
    for c in memory_init {
        for (k, &b) in c.contents.iter().enumerate() {
            let x = c.address as u64 + k as u64;
            let page = (x / PAGE_SIZE) as u32;
            if let Some(p) = memory.pages.get_mut(&page) {
                p.data[(x % PAGE_SIZE) as usize] = b;
            }
        }
    }

    let Some(prog) = deblob(program) else {
        return Outcome { status: ExitStatus::Panic, pc, gas, regs, memory };
    };

    interpret(&prog, pc, gas, regs, memory)
}

fn interpret(
    prog: &Program,
    mut pc: u32,
    mut gas: i64,
    mut regs: [u64; REG_COUNT],
    mut memory: Memory,
) -> Outcome {
    let mut gas_charged = false;
    loop {
        let i = pc as usize;

        // Charge the whole basic block's gas on entry.
        if !gas_charged {
            let cost = block_gas_cost(prog, block_start_of(prog, i));
            if gas < cost {
                return Outcome { status: ExitStatus::OutOfGas, pc, gas, regs, memory };
            }
            gas -= cost;
            gas_charged = true;
        }
        let op = zeta(&prog.code, i);
        let ell = skip(&prog.bitmask, i);
        let next = (i + 1 + ell) as u32;

        let action = execute(prog, op, i, ell, &mut regs, &mut memory);

        match action {
            Action::Next => {
                pc = next;
                if is_terminator(op) {
                    gas_charged = false;
                }
            }
            Action::Jump(target) => {
                pc = target;
                gas_charged = false;
            }
            Action::Halt => {
                return Outcome { status: ExitStatus::Halt, pc, gas, regs, memory };
            }
            Action::Panic => {
                return Outcome { status: ExitStatus::Panic, pc, gas, regs, memory };
            }
            Action::PageFault(a) => {
                return Outcome { status: ExitStatus::PageFault(a), pc, gas, regs, memory };
            }
            Action::HostCall(id) => {
                return Outcome { status: ExitStatus::HostCall(id), pc, gas, regs, memory };
            }
        }
    }
}

enum Action {
    Next,
    Jump(u32),
    Halt,
    Panic,
    PageFault(u32),
    HostCall(u64),
}

/// Sign-extend an `n`-octet value to 64 bits.
fn sext(n: usize, x: u64) -> u64 {
    if n == 0 || n >= 8 {
        return x;
    }
    let bits = 8 * n;
    if x & (1 << (bits - 1)) != 0 {
        x | (!0u64 << bits)
    } else {
        x & ((1u64 << bits) - 1)
    }
}

/// Little-endian decode of `len` octets from the code (implicit zero suffix).
fn decode(code: &[u8], start: usize, len: usize) -> u64 {
    let mut v = 0u64;
    for k in 0..len {
        v |= (zeta(code, start + k) as u64) << (8 * k);
    }
    v
}

fn reg(regs: &[u64; REG_COUNT], idx: usize) -> u64 {
    regs[idx.min(12)]
}

fn jump(prog: &Program, target: i64) -> Action {
    if is_block_start(prog, target) {
        Action::Jump(target as u32)
    } else {
        Action::Panic
    }
}

fn branch(prog: &Program, i: usize, ell: usize, target: i64, cond: bool) -> Action {
    let fallthrough = (i + 1 + ell) as i64;
    if !is_block_start(prog, target) || !is_block_start(prog, fallthrough) {
        Action::Panic
    } else if cond {
        Action::Jump(target as u32)
    } else {
        Action::Next
    }
}

fn djump(prog: &Program, a: u64) -> Action {
    if a == HALT_ADDR {
        return Action::Halt;
    }
    if a == 0
        || a > prog.jump_table.len() as u64 * DYN_ALIGN
        || a % DYN_ALIGN != 0
    {
        return Action::Panic;
    }
    let target = prog.jump_table[(a / DYN_ALIGN - 1) as usize] as i64;
    if is_block_start(prog, target) {
        Action::Jump(target as u32)
    } else {
        Action::Panic
    }
}

include!("pvm_exec.rs");
