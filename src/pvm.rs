//! PolkaVM interpreter — the JAM PVM function Ψ (GP Appendix A).
//!
//! A 64-bit register machine with 13 registers, paged 2³²-byte memory, and
//! per-basic-block gas charging. `run` executes a program blob to a halting
//! condition (halt, panic, out-of-gas, page-fault, or host-call).

use std::collections::{BTreeMap, BTreeSet};

const PAGE_SIZE: u64 = 4096;
const DYN_ALIGN: u64 = 2;
const HALT_ADDR: u64 = 0xffff_0000;
pub const REG_COUNT: usize = 13;

/// Reason a PVM execution stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    Halt,
    Panic,
    OutOfGas,
    PageFault(u32),
    HostCall(u64),
    /// Emitted only by `step`: a normal instruction completed, keep stepping.
    Running,
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
    /// Current program break (heap top) for `sbrk`; 0 when unused.
    pub heap_top: u32,
    /// Upper bound the heap may `sbrk` to (reserved heap-zone end).
    pub heap_max: u32,
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

    /// Map an accessible region (rounding to whole pages), for the page map and
    /// standard-program initialization.
    pub fn map(&mut self, address: u32, length: u32, writable: bool) {
        let first = address / PAGE_SIZE as u32;
        let last = (address as u64 + length as u64).div_ceil(PAGE_SIZE) as u32;
        for p in first..last {
            self.ensure(p, writable);
        }
    }

    /// Grow the heap by `size` bytes (polkavm `sbrk`). Returns the previous
    /// program break (the start of the newly mapped region), or the current
    /// break when `size == 0` (query). Returns 0 if the growth would exceed
    /// `heap_max`.
    pub fn sbrk(&mut self, size: u32) -> u32 {
        if size == 0 {
            return self.heap_top;
        }
        let old = self.heap_top;
        let new = match old.checked_add(size) {
            Some(n) if n <= self.heap_max => n,
            _ => return 0,
        };
        self.map(old, size, true);
        self.heap_top = new;
        old
    }

    /// Write bytes into already-mapped pages (initial memory / SPI data).
    pub fn store(&mut self, address: u32, bytes: &[u8]) {
        for (k, &b) in bytes.iter().enumerate() {
            let x = address as u64 + k as u64;
            if let Some(p) = self.pages.get_mut(&((x / PAGE_SIZE) as u32)) {
                p.data[(x % PAGE_SIZE) as usize] = b;
            }
        }
    }

    /// Read `len` bytes from `address` (zero for unmapped bytes). Caller must
    /// have validated the range with [`readable_range`]; capped defensively.
    pub fn load(&self, address: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|k| {
                let x = address as u64 + k as u64;
                self.pages
                    .get(&((x / PAGE_SIZE) as u32))
                    .map_or(0, |p| p.data[(x % PAGE_SIZE) as usize])
            })
            .collect()
    }

    /// Whether `[address, address+len)` is entirely readable. Page-based and
    /// capped so an absurd `len` returns `false` immediately (no huge loop).
    pub fn readable_range(&self, address: u32, len: u64) -> bool {
        self.range_ok(address, len, false)
    }

    /// Whether `[address, address+len)` is entirely writable (capped).
    pub fn writable_range(&self, address: u32, len: u64) -> bool {
        self.range_ok(address, len, true)
    }

    fn range_ok(&self, address: u32, len: u64, write: bool) -> bool {
        if len == 0 {
            return true;
        }
        let first = address as u64 / PAGE_SIZE;
        let last = (address as u64 + len - 1) / PAGE_SIZE;
        // A range spanning more pages than exist can't be fully mapped.
        if last - first + 1 > self.pages.len() as u64 {
            return false;
        }
        (first..=last).all(|p| {
            let addr = p * PAGE_SIZE;
            if write {
                self.writable(addr)
            } else {
                self.readable(addr)
            }
        })
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

    /// Whether page `page` is mapped and writable.
    pub fn page_writable(&self, page: u32) -> bool {
        self.pages.get(&page).is_some_and(|p| p.writable)
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

/// A resumable PVM instance: run to an exit, handle a host call externally,
/// then resume. Used by the accumulate invocation (`Ψ_H`).
pub struct Vm {
    program: Program,
    pub pc: u32,
    pub gas: i64,
    pub regs: [u64; REG_COUNT],
    pub memory: Memory,
    gas_charged: bool,
    /// Total instruction gas of the current basic block, and how much of it has
    /// been charged so far (per instruction). On a mid-block trap the untouched
    /// remainder is charged, so a trap consumes the whole block.
    blk_cost: i64,
    blk_spent: i64,
}

impl Vm {
    /// Build a VM over a program blob with pre-initialized memory.
    pub fn new(program: &[u8], pc: u32, gas: i64, regs: [u64; REG_COUNT], memory: Memory) -> Option<Self> {
        Some(Vm {
            program: deblob(program)?,
            pc,
            gas,
            regs,
            memory,
            gas_charged: false,
            blk_cost: 0,
            blk_spent: 0,
        })
    }

    /// Execute until a halting condition. On a host call the pc is left at the
    /// `ecalli`; call `advance_host` after handling it, then resume.
    pub fn run(&mut self) -> ExitStatus {
        loop {
            match self.step() {
                (_, ExitStatus::Running) => {}
                (_, status) => return status,
            }
        }
    }

    /// Advance the pc past the current `ecalli` (same basic block, gas already
    /// charged) so execution can resume after a handled host call.
    pub fn advance_host(&mut self) {
        let i = self.pc as usize;
        self.pc = (i + 1 + skip(&self.program.bitmask, i)) as u32;
    }

    /// Execute exactly one instruction. Returns the opcode that ran and the
    /// resulting status. On `HostCall`/`Halt`/`Panic`/`PageFault` the pc is left
    /// at the current instruction (as in `run`); on a normal step pc/regs are
    /// already advanced. Used by the golden per-instruction trace harness.
    pub fn step(&mut self) -> (u8, ExitStatus) {
        let i = self.pc as usize;
        if !self.gas_charged {
            // Basic-block gas gate (GP Appendix A): the whole block must be
            // affordable before any of it runs. Gas is deducted per instruction
            // below (so the counter matches the reference step by step); a trap
            // charges the block's untouched remainder so the total still equals
            // the block cost, matching the PVM conformance vectors.
            let cost = block_gas_cost(&self.program, block_start_of(&self.program, i));
            if self.gas < cost {
                return (0, ExitStatus::OutOfGas);
            }
            self.blk_cost = cost;
            self.blk_spent = 0;
            self.gas_charged = true;
        }
        self.gas -= 1;
        self.blk_spent += 1;
        let op = zeta(&self.program.code, i);
        let ell = skip(&self.program.bitmask, i);
        let next = (i + 1 + ell) as u32;
        let charge_block_remainder = |vm: &mut Vm| vm.gas -= vm.blk_cost - vm.blk_spent;
        match execute(&self.program, op, i, ell, &mut self.regs, &mut self.memory) {
            Action::Next => {
                self.pc = next;
                if is_terminator(op) {
                    self.gas_charged = false;
                }
                (op, ExitStatus::Running)
            }
            Action::Jump(target) => {
                self.pc = target;
                self.gas_charged = false;
                (op, ExitStatus::Running)
            }
            Action::Halt => (op, ExitStatus::Halt),
            Action::Panic => {
                charge_block_remainder(self);
                (op, ExitStatus::Panic)
            }
            Action::PageFault(a) => {
                charge_block_remainder(self);
                (op, ExitStatus::PageFault(a))
            }
            Action::HostCall(id) => (op, ExitStatus::HostCall(id)),
        }
    }
}

/// Execute a program blob to a halting condition (one-shot, no host calls).
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
        memory.map(e.address, e.length, e.writable);
    }
    for c in memory_init {
        memory.store(c.address, &c.contents);
    }
    let Some(mut vm) = Vm::new(program, pc, gas, regs, memory) else {
        return Outcome { status: ExitStatus::Panic, pc, gas, regs, memory: Memory::default() };
    };
    let status = vm.run();
    Outcome { status, pc: vm.pc, gas: vm.gas, regs: vm.regs, memory: vm.memory }
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
