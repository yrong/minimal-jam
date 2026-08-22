// Instruction execution for the PVM interpreter. Included into `pvm.rs`.

fn exit_action(e: ExitStatus) -> Action {
    match e {
        ExitStatus::Panic => Action::Panic,
        ExitStatus::PageFault(a) => Action::PageFault(a),
        ExitStatus::OutOfGas => Action::Panic,
        ExitStatus::Halt => Action::Halt,
        ExitStatus::HostCall(id) => Action::HostCall(id),
        // `Running` is produced only by `Vm::step`; `execute` never yields it.
        ExitStatus::Running => Action::Panic,
    }
}

/// Whether `op` is a defined opcode (`U`).
fn is_valid_opcode(op: u8) -> bool {
    matches!(op,
        0..=2 | 10 | 20 | 30..=33 | 40 | 50..=62 | 70..=73 | 80..=90
        | 100..=111 | 120..=161 | 170..=175 | 180 | 190..=230)
}

#[allow(clippy::too_many_lines)]
fn execute(
    prog: &Program,
    op: u8,
    i: usize,
    ell: usize,
    regs: &mut [u64; REG_COUNT],
    memory: &mut Memory,
) -> Action {
    let code = &prog.code;

    macro_rules! load {
        ($addr:expr, $len:expr, $ra:expr, $f:expr) => {{
            let addr = ($addr) & 0xffff_ffff;
            if let Err(e) = memory.check(addr, $len, false) {
                return exit_action(e);
            }
            let raw = memory.read(addr, $len);
            regs[$ra] = $f(raw);
            Action::Next
        }};
    }
    macro_rules! store {
        ($addr:expr, $len:expr, $val:expr) => {{
            let addr = ($addr) & 0xffff_ffff;
            if let Err(e) = memory.check(addr, $len, true) {
                return exit_action(e);
            }
            memory.write(addr, $len, $val);
            Action::Next
        }};
    }

    // Common operand decodes (only those valid for the matched class are used).
    let ra = (zeta(code, i + 1) % 16).min(12) as usize;
    let rb = (zeta(code, i + 1) / 16).min(12) as usize;
    let rd = zeta(code, i + 2).min(12) as usize;

    match op {
        // --- No arguments ---
        0 => Action::Panic,                                   // trap
        1 => jump(prog, (i + 1 + ell) as i64),                // fallthrough
        2 => Action::Next,                                    // unlikely (hint)

        // --- One immediate ---
        10 => {
            let lx = ell.min(4);
            let id = sext(lx, decode(code, i + 1, lx));
            Action::HostCall(id)
        }

        // --- One register & extended-width immediate ---
        20 => {
            regs[ra] = decode(code, i + 2, 8);
            Action::Next
        }

        // --- Two immediates (store imm at absolute address) ---
        30..=33 => {
            let lx = (zeta(code, i + 1) % 8).min(4) as usize;
            let imm_x = sext(lx, decode(code, i + 2, lx));
            let ly = (ell.saturating_sub(lx + 1)).min(4);
            let imm_y = sext(ly, decode(code, i + 2 + lx, ly));
            let len = 1 << (op - 30);
            store!(imm_x, len, imm_y)
        }

        // --- One offset ---
        40 => {
            let lx = ell.min(4);
            let target = i as i64 + sext(lx, decode(code, i + 1, lx)) as i64;
            jump(prog, target)
        }

        // --- One register & one immediate ---
        50..=62 => {
            let lx = ell.saturating_sub(1).min(4);
            let imm = sext(lx, decode(code, i + 2, lx));
            match op {
                50 => djump(prog, (reg(regs, ra).wrapping_add(imm)) & 0xffff_ffff),
                51 => {
                    regs[ra] = imm;
                    Action::Next
                }
                52 => load!(imm, 1, ra, |v| v),
                53 => load!(imm, 1, ra, |v| sext(1, v)),
                54 => load!(imm, 2, ra, |v| v),
                55 => load!(imm, 2, ra, |v| sext(2, v)),
                56 => load!(imm, 4, ra, |v| v),
                57 => load!(imm, 4, ra, |v| sext(4, v)),
                58 => load!(imm, 8, ra, |v| v),
                59 => store!(imm, 1, reg(regs, ra)),
                60 => store!(imm, 2, reg(regs, ra)),
                61 => store!(imm, 4, reg(regs, ra)),
                62 => store!(imm, 8, reg(regs, ra)),
                _ => unreachable!(),
            }
        }

        // --- One register & two immediates (store imm indirect) ---
        70..=73 => {
            let lx = ((zeta(code, i + 1) / 16) % 8).min(4) as usize;
            let imm_x = sext(lx, decode(code, i + 2, lx));
            let ly = (ell.saturating_sub(lx + 1)).min(4);
            let imm_y = sext(ly, decode(code, i + 2 + lx, ly));
            let len = 1 << (op - 70);
            store!(reg(regs, ra).wrapping_add(imm_x), len, imm_y)
        }

        // --- One register, one immediate, one offset ---
        80..=90 => {
            let lx = ((zeta(code, i + 1) / 16) % 8).min(4) as usize;
            let imm_x = sext(lx, decode(code, i + 2, lx));
            let ly = (ell.saturating_sub(lx + 1)).min(4);
            let target = i as i64 + sext(ly, decode(code, i + 2 + lx, ly)) as i64;
            let a = reg(regs, ra);
            match op {
                80 => {
                    regs[ra] = imm_x;
                    jump(prog, target)
                }
                81 => branch(prog, i, ell, target, a == imm_x),
                82 => branch(prog, i, ell, target, a != imm_x),
                83 => branch(prog, i, ell, target, a < imm_x),
                84 => branch(prog, i, ell, target, a <= imm_x),
                85 => branch(prog, i, ell, target, a >= imm_x),
                86 => branch(prog, i, ell, target, a > imm_x),
                87 => branch(prog, i, ell, target, (a as i64) < (imm_x as i64)),
                88 => branch(prog, i, ell, target, (a as i64) <= (imm_x as i64)),
                89 => branch(prog, i, ell, target, (a as i64) >= (imm_x as i64)),
                90 => branch(prog, i, ell, target, (a as i64) > (imm_x as i64)),
                _ => unreachable!(),
            }
        }

        // --- Two registers ---
        // Vectors use GP 0.5.4 numbering (sbrk at 101 shifts the cluster +1).
        100..=111 => {
            // r_D = low nibble, r_A = high nibble.
            let d = (zeta(code, i + 1) % 16).min(12) as usize;
            let a = reg(regs, (zeta(code, i + 1) / 16).min(12) as usize);
            if op == 101 {
                // sbrk: grow the heap by `a` bytes, return the previous break.
                regs[d] = memory.sbrk(a as u32) as u64;
                return Action::Next;
            }
            regs[d] = match op {
                100 => a,                              // move_reg
                102 => a.count_ones() as u64,          // count_set_bits_64
                103 => (a as u32).count_ones() as u64, // count_set_bits_32
                104 => a.leading_zeros() as u64,       // leading_zero_bits_64
                105 => (a as u32).leading_zeros() as u64, // leading_zero_bits_32
                106 => a.trailing_zeros() as u64,      // trailing_zero_bits_64
                107 => (a as u32).trailing_zeros() as u64, // trailing_zero_bits_32
                108 => sext(1, a & 0xff),              // sign_extend_8
                109 => sext(2, a & 0xffff),            // sign_extend_16
                110 => a & 0xffff,                     // zero_extend_16
                111 => a.swap_bytes(),                 // reverse_bytes
                _ => unreachable!(),
            };
            Action::Next
        }

        // --- Two registers & one immediate ---
        120..=161 => {
            let lx = ell.saturating_sub(1).min(4);
            let imm = sext(lx, decode(code, i + 2, lx));
            let a = reg(regs, ra);
            let b = reg(regs, rb);
            match op {
                120 => return store!(b.wrapping_add(imm), 1, a),
                121 => return store!(b.wrapping_add(imm), 2, a),
                122 => return store!(b.wrapping_add(imm), 4, a),
                123 => return store!(b.wrapping_add(imm), 8, a),
                124 => return load!(b.wrapping_add(imm), 1, ra, |v| v),
                125 => return load!(b.wrapping_add(imm), 1, ra, |v| sext(1, v)),
                126 => return load!(b.wrapping_add(imm), 2, ra, |v| v),
                127 => return load!(b.wrapping_add(imm), 2, ra, |v| sext(2, v)),
                128 => return load!(b.wrapping_add(imm), 4, ra, |v| v),
                129 => return load!(b.wrapping_add(imm), 4, ra, |v| sext(4, v)),
                130 => return load!(b.wrapping_add(imm), 8, ra, |v| v),
                _ => {}
            }
            regs[ra] = match op {
                131 => sext(4, (b.wrapping_add(imm)) & 0xffff_ffff),
                132 => b & imm,
                133 => b ^ imm,
                134 => b | imm,
                135 => sext(4, (b.wrapping_mul(imm)) & 0xffff_ffff),
                136 => (b < imm) as u64,
                137 => ((b as i64) < (imm as i64)) as u64,
                138 => sext(4, ((b & 0xffff_ffff) << (imm % 32)) & 0xffff_ffff),
                139 => sext(4, (b & 0xffff_ffff) >> (imm % 32)),
                140 => sext(4, (((b as u32) as i32 >> (imm % 32)) as u32) as u64),
                141 => sext(4, (imm.wrapping_sub(b)) & 0xffff_ffff),
                142 => (b > imm) as u64,
                143 => ((b as i64) > (imm as i64)) as u64,
                144 => sext(4, ((imm & 0xffff_ffff) << (b % 32)) & 0xffff_ffff),
                145 => sext(4, (imm & 0xffff_ffff) >> (b % 32)),
                146 => sext(4, (((imm as u32) as i32 >> (b % 32)) as u32) as u64),
                147 => {
                    if b == 0 {
                        imm
                    } else {
                        reg(regs, ra)
                    }
                }
                148 => {
                    if b != 0 {
                        imm
                    } else {
                        reg(regs, ra)
                    }
                }
                149 => b.wrapping_add(imm),
                150 => b.wrapping_mul(imm),
                151 => b << (imm % 64),
                152 => b >> (imm % 64),
                153 => ((b as i64) >> (imm % 64)) as u64,
                154 => imm.wrapping_sub(b),
                155 => imm << (b % 64),
                156 => imm >> (b % 64),
                157 => ((imm as i64) >> (b % 64)) as u64,
                158 => b.rotate_right((imm % 64) as u32),
                159 => imm.rotate_right((b % 64) as u32),
                160 => sext(4, (b as u32).rotate_right((imm % 32) as u32) as u64),
                161 => sext(4, (imm as u32).rotate_right((b % 32) as u32) as u64),
                _ => unreachable!(),
            };
            Action::Next
        }

        // --- Two registers & one offset ---
        170..=175 => {
            let lx = ell.saturating_sub(1).min(4);
            let target = i as i64 + sext(lx, decode(code, i + 2, lx)) as i64;
            let a = reg(regs, ra);
            let b = reg(regs, rb);
            let cond = match op {
                170 => a == b,
                171 => a != b,
                172 => a < b,
                173 => (a as i64) < (b as i64),
                174 => a >= b,
                175 => (a as i64) >= (b as i64),
                _ => unreachable!(),
            };
            branch(prog, i, ell, target, cond)
        }

        // --- Two registers & two immediates ---
        180 => {
            let lx = (zeta(code, i + 2) % 8).min(4) as usize;
            let imm_x = sext(lx, decode(code, i + 3, lx));
            let ly = (ell.saturating_sub(lx + 2)).min(4);
            let imm_y = sext(ly, decode(code, i + 3 + lx, ly));
            let target = (reg(regs, rb).wrapping_add(imm_y)) & 0xffff_ffff;
            regs[ra] = imm_x;
            djump(prog, target)
        }

        // --- Three registers ---
        190..=230 => {
            let a = reg(regs, ra);
            let b = reg(regs, rb);
            regs[rd] = match op {
                190 => sext(4, (a.wrapping_add(b)) & 0xffff_ffff),
                191 => sext(4, (a.wrapping_sub(b)) & 0xffff_ffff),
                192 => sext(4, (a.wrapping_mul(b)) & 0xffff_ffff),
                193 => {
                    let bb = b & 0xffff_ffff;
                    if bb == 0 {
                        u64::MAX
                    } else {
                        sext(4, (a & 0xffff_ffff) / bb)
                    }
                }
                194 => {
                    let x = (a as u32) as i32;
                    let y = (b as u32) as i32;
                    if y == 0 {
                        u64::MAX
                    } else if x == i32::MIN && y == -1 {
                        sext(4, x as u32 as u64)
                    } else {
                        sext(4, (x.wrapping_div(y)) as u32 as u64)
                    }
                }
                195 => {
                    let bb = b & 0xffff_ffff;
                    if bb == 0 {
                        sext(4, a & 0xffff_ffff)
                    } else {
                        sext(4, (a & 0xffff_ffff) % bb)
                    }
                }
                196 => {
                    let x = (a as u32) as i32;
                    let y = (b as u32) as i32;
                    if y == 0 {
                        sext(4, x as u32 as u64)
                    } else if x == i32::MIN && y == -1 {
                        0
                    } else {
                        sext(4, (x.wrapping_rem(y)) as u32 as u64)
                    }
                }
                197 => sext(4, ((a & 0xffff_ffff) << (b % 32)) & 0xffff_ffff),
                198 => sext(4, (a & 0xffff_ffff) >> (b % 32)),
                199 => sext(4, (((a as u32) as i32 >> (b % 32)) as u32) as u64),
                200 => a.wrapping_add(b),
                201 => a.wrapping_sub(b),
                202 => a.wrapping_mul(b),
                203 => {
                    if b == 0 {
                        u64::MAX
                    } else {
                        a / b
                    }
                }
                204 => {
                    let x = a as i64;
                    let y = b as i64;
                    if y == 0 {
                        u64::MAX
                    } else if x == i64::MIN && y == -1 {
                        a
                    } else {
                        x.wrapping_div(y) as u64
                    }
                }
                205 => {
                    if b == 0 {
                        a
                    } else {
                        a % b
                    }
                }
                206 => {
                    let x = a as i64;
                    let y = b as i64;
                    if y == 0 {
                        a
                    } else if x == i64::MIN && y == -1 {
                        0
                    } else {
                        x.wrapping_rem(y) as u64
                    }
                }
                207 => a << (b % 64),
                208 => a >> (b % 64),
                209 => ((a as i64) >> (b % 64)) as u64,
                210 => a & b,
                211 => a ^ b,
                212 => a | b,
                213 => (((a as i64 as i128) * (b as i64 as i128)) >> 64) as u64,
                214 => (((a as u128) * (b as u128)) >> 64) as u64,
                215 => (((a as i64 as i128) * (b as u128 as i128)) >> 64) as u64,
                216 => (a < b) as u64,
                217 => ((a as i64) < (b as i64)) as u64,
                218 => {
                    if b == 0 {
                        a
                    } else {
                        reg(regs, rd)
                    }
                }
                219 => {
                    if b != 0 {
                        a
                    } else {
                        reg(regs, rd)
                    }
                }
                220 => a.rotate_left((b % 64) as u32),
                221 => sext(4, (a as u32).rotate_left((b % 32) as u32) as u64),
                222 => a.rotate_right((b % 64) as u32),
                223 => sext(4, (a as u32).rotate_right((b % 32) as u32) as u64),
                224 => a & !b,
                225 => a | !b,
                226 => !(a ^ b),
                227 => (a as i64).max(b as i64) as u64,
                228 => a.max(b),
                229 => (a as i64).min(b as i64) as u64,
                230 => a.min(b),
                _ => unreachable!(),
            };
            Action::Next
        }

        _ => Action::Panic, // undefined opcode
    }
}
