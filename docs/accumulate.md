# Accumulate STF —— 灰皮书 §12 详解与 minimal-jam 实现分析

本文分两部分:

- **第一部分**:灰皮书(Gray Paper,以下简称 GP)§12 *Accumulation* 及其依赖的
  Appendix A(PVM `Ψ`)、Merklization 章节的详细说明。
- **第二部分**:`minimal-jam` 中对应实现的逐处剖析(`src/accumulate.rs`、
  `src/accumulate_exec.rs`、`src/pvm.rs`),并标注与 GP 的差异 / 简化。

覆盖范围:`davxy/jam-test-vectors` 的 `stf/accumulate/tiny` 全部 30 个向量,
逐字节通过(账户 δ、统计 π_S、输出根、两个环形缓冲)。

---

# 第一部分:灰皮书 §12 详解

## 1.1 累积在协议中的位置

一个 work-report 经过 **guarantee → assurance** 后成为"可用"(available);随后进入
**accumulation**:把每个 work-digest 的 refine 输出喂给其目标服务的 `accumulate`
逻辑,在链上状态里产生副作用(改服务账户、转账、增删服务等)。累积是唯一能
**修改链上状态**的服务执行阶段(refine 是无状态的、在 core 上做的)。

累积有三个复杂点(GP §Accumulation 引言):

1. **执行环境**:每个服务的 `accumulate` 代码在 PVM 里跑,并能通过 host 函数
   读写状态。
2. **gas 配额**:必须给每个服务的执行定 gas 上限。
3. **转账**:累积过程中服务间的余额转移(延迟转账)。

## 1.2 状态项(与累积相关)

| GP 符号 | 名称 | 含义 |
|---|---|---|
| `δ` | service accounts | 服务账户字典 `serviceid → account` |
| `ϑ` (theta) | ready queue | 每个 epoch-slot 一个桶,存**带未决依赖**的报告 `(report, deps)` |
| `ξ` (xi) | accumulated | 每个 epoch-slot 一个桶,存**已累积**的 work-package 哈希 |
| `χ` (chi) | privileges | 特权服务索引(manager/assigners/delegator/registrar/always-accers) |
| `π_S` | service statistics | 本块各服务累积的 `(items, transfers, gas)` |
| `θ` / `lastaccout` | accumulation output log | 本块各服务的 `(serviceid, hash)` 输出承诺序列 |

服务账户 `a`(GP `ServiceAccount`)含:`codehash`、`storage`(k/v)、`preimages`、
`balance`、`minaccgas`/`minmemogas`、`octets`(存储字节)、`items`(存储项数)、
`created`/`lastacc`/`parent` 等元数据。

> 注:GP 主网版本还有 `supervisor`/`supervisorbalance`/`gratis` 等字段;
> 0.7.2 tiny 向量的账户**没有** supervisor 相关字段(见第二部分)。

## 1.3 报告可用性、依赖与队列编辑

一个报告的**依赖集** = `context.prerequisites`(前置 work-package 哈希)∪
`segment_root_lookup` 里引用的 work-package 哈希。依赖全部"已累积"后,报告才可累积。

- **队列编辑 `E`**(GP eq. `editqueue`):给定"已累积哈希集",从队列里
  (a) 删除自身已被累积的报告;(b) 从每个报告的依赖集里删掉已满足的哈希。
- **优先队列 `Q`**(GP eq. `priorityqueue`):反复取出"依赖已空"的报告,
  形成一个**拓扑顺序**的可累积序列。它天然支持**同块级联**:若 A 本块被累积,
  依赖 A 的报告本块即可解锁。

## 1.4 累积候选序列 `W*` 的装配

本块可累积集 = **本块立即可累积报告**(依赖空)+ 对
`ϑ`(从 `slot mod E` 起环形展开)与本块延迟报告做 `E`(用立即报告哈希解依赖)后
再 `Q` 出来的报告。

## 1.5 累积执行:accseq / accpar / accone

GP 用三层函数描述执行:

- **`accone`**(单服务,GP eq. `accseq`/`accone` 附近):把某服务的所有 work-digest
  聚成操作数序列 `i^U`,一次性调用其 `accumulate`(PVM `Ψ_A`),返回:变更后的
  状态上下文、被修改服务集、**延迟转账序列**、可能的**输出承诺** `(s, h)`、
  实际 gas、以及 preimage 供给。
- **`accpar`**(并行):对一组服务并行跑 `accone`,并用函数 `R` 处理特权服务
  的"所有权"迁移。为避免并发写冲突,一个服务的 `accumulate` 与其
  supervisor 的 `accumulate` 若都改到同一账户,则**丢弃前者结果**(除已供给的
  preimage);而**延迟转账绝不与 supervisor 的 accumulate 并行**(否则可能丢币)。
- **`accseq`**(外层):在一个 gas 预算内,按序推进 `accpar`,产出:累积报告数
  `n`、后置状态、输出配对 `b`、各服务 gas、已处理转账。

**块级 gas 预算**(GP eq. `finalstateaccumulation`):

```
g = max(C_blockaccgas,  C_reportaccgas · C_corecount + Σ_{x∈alwaysaccers} x)
```

## 1.6 PVM 调用:Ψ_A / Ψ_M / Ψ_H

- **`Ψ_A`**(accumulate 调用):把服务代码接到 PVM 的 5 号入口,操作数
  `E(t, s, i^U)`(时隙、服务号、操作数序列)作为 args,并挂上 accumulate 的
  host 函数分发器 `f`。
- **`Ψ_M`**(GP eq. `Ψ_M`,通用 arg 调用):先做**标准程序初始化 `Y`**;
  失败 → `panic`;否则以初值跑 `Ψ_H`,`halt` 时按 `r7..r7+r8` 从内存取返回。
- **`Ψ_H`**:可恢复执行——跑到退出;`ecalli`(host-call)时外部处理再续跑;
  直到 `halt`/`panic`/`oog`/`fault`。

## 1.7 标准程序初始化 `Y`(内存布局)

GP §Standard Program Initialization 定义:jam-blob 编码为

```
E3(|o|) ‖ E3(|w|) ‖ E2(z) ‖ E3(s) ‖ o ‖ w ‖ E4(|pvm|) ‖ pvm
```

其中 `o`=只读数据、`w`=读写(堆)初值、`z`=额外堆页数、`s`=栈字节数。

常量:`Z_Z`(init zone)= 2^16,`Z_I`(init input)= 2^24,`Z_P`(page)= 4096。
取整:`rnp(x)=P·⌈x/P⌉`(页对齐),`rnq(x)=Z·⌈x/Z⌉`(区对齐)。

**存在性条件**(GP eq. `conditions`):

```
5Z + rnq(|o|) + rnq(|w| + z·P) + rnq(s) + I ≤ 2^32
```

**内存映射**(GP eq. `memlayout`,`R`=只读、`W`=读写、其余不可访问):

```
[Z,                         Z+|o|)                     ← o          R
[Z+|o|,                     Z+rnp(|o|))                ← 0(页补齐)  R
[2Z+rnq(|o|),               2Z+rnq(|o|)+|w|)           ← w          W
[..,                        2Z+rnq(|o|)+rnp(|w|)+z·P)  ← 0(堆)     W
[2^32-2Z-I-rnp(s),          2^32-2Z-I)                 ← 0(栈)     W
[2^32-Z-I,                  2^32-Z-I+|a|)              ← a(参数)   R
[..,                        2^32-Z-I+rnp(|a|))         ← 0(页补齐)  R
```

段之间**刻意留一个空区**(zone)以减小越界溢出。注意两个"堆末端":

- **可访问堆末端** = `2Z+rnq(|o|)+rnp(|w|)+z·P`(memlayout);
- **保留堆区末端** = `2Z+rnq(|o|)+rnq(|w|+z·P)`(conditions,整堆区按 `rnq` 对齐)。

二者之间的空隙是分配器用 `sbrk` 指令按需扩堆的空间。

**寄存器初值**(GP eq. `registers`):

```
r0 = 2^32 - 2^16       (返回地址哨兵)
r1 = 2^32 - 2Z - I     (栈指针 / 栈区末端)
r7 = 2^32 - Z - I      (参数指针)
r8 = |a|               (参数长度)
其余 = 0
```

## 1.8 Host 函数与 gas

所有 host 函数形如
`(ε*, gas*, regs*, mem*, ctx*) = Ω_□(gas, regs, mem, ctx, …)`。
gas 不足以覆盖基础成本 `g` 时返回 `oog` 并消耗全部 gas。含内存的调用
gas = `c + fnmemgas(L, ℓ)`(基础成本 + 每 1024 字节速率 × 字节数)。

累积相关 host 函数(GP 主网编号 / 基础 gas 常量):

| Ω | 名称 | GP 编号 | 基础 gas | 作用 |
|---|---|---|---|---|
| Ω_G | gas | — | 48 | 返回剩余 gas |
| Ω_Y | fetch | — | 按 kind(如 case0=390) | 取协议参数/操作数/上下文等 |
| Ω_L | lookup | 3 | 600 | 查 preimage |
| Ω_R | read | 4 | 2407 | 读服务存储 |
| Ω_W | write | 5 | 2442 | 写调用者存储 |
| Ω_I | info | 6 | 703 | 服务元数据 |
| Ω_B | bless | 15 | 422 | 设特权 |
| Ω_T | transfer | 21 | 575 (+l) | 延迟转账 |
| Ω_J | eject | 22 | 458 | 删服务、并入余额 |
| Ω_Taurus | yield | — | 98 | 记录输出承诺 |

**转账 `Ω_T`**(GP eq. 附近):`source`(默认 self)、`dest`、`x`(标志)、
`amount`、`l`(为 dest 的 `on_transfer` 预留的 gas)、`o`(memo 指针)。
即时从 source 扣款,登记一条**延迟转账** `defxfer = (source, dest, dest_supervisor,
amount, memo, gas)`;dest 侧的入账是延迟的。含 memo 时 `g = CgasT + l`。

**弹出 `Ω_J`**:删除目标 `d`,把 `d` 的余额(+ supervisorbalance)并入调用者。
条件:`d≠self`、`self` 是 `d` 的有效 supervisor、`d.created≠t`、`d.items=0` 等。

## 1.9 延迟转账的应用与 on_transfer

累积产出的延迟转账 `t`,在后续用**目的服务的 `on_transfer`** 逻辑处理(仍是 PVM
执行,消耗为其预留的 gas)。若目的服务已不存在(如同块被弹出),转账作废、
**资金销毁**(GP 明确:deferred transfer may be discarded and funds burnt)。
`fnpartitionxfers` 决定哪些转账可与本轮 accumulate 并行、哪些延后。

## 1.10 最终状态整合(GP eq. `finalstateaccumulation`)

给定 `accseq` 的产出:

- `δ`(账户)= 累积后的服务账户(再叠加延迟转账、preimage 供给);
- `π_S`(统计,GP eq. `accumulationstatistics`)= 累积服务 → `(items, transfers, gas)`;
- `θ`/`lastaccout' = ⟨(s,h) ∈ b⟩` = 本块输出承诺序列;
- `ξ`、`ϑ` 环形缓冲移位:最新 slot(`slot mod E`)放本块累积包哈希;
  gap slot 清空;其余用最新哈希再 `E`。

## 1.11 累积输出根:Merkle 函数

`lastaccout` 会被 Merkle 化成一个根(GP §Merklization)。

**节点函数 `N`**(GP eq. `merklenode`):

```
N(v, H) = zerohash                      当 |v|=0
        = v[0]                          当 |v|=1   （原样返回，可宽于 32 字节）
        = H("$node" ‖ N(左半) ‖ N(右半))  否则
```

**良平衡二叉 Merkle `M_B`**(`merklizewb`,GP eq. `simplemerkleroot`):

```
M_B(v, H) = H(v[0])   当 |v|=1
          = N(v, H)   否则（含 |v|=0 → zerohash）
```

叶子编码(GP eq. 状态序列化 C(16) 用同一形态):每个 `(s, h)` → `E4(s) ‖ E(h)`。
累积输出根使用 **keccak** 作为 `H`。

---

# 第二部分:minimal-jam 实现分析

## 2.1 文件与职责

| 文件 | 职责 |
|---|---|
| `src/accumulate.rs` | 状态/类型定义、队列管理(`E`/`Q`/分区/环形缓冲)、`transition` 主流程、输出根 |
| `src/accumulate_exec.rs` | 执行引擎:标准程序初始化 `Y`、`run_service`、host-call ABI、延迟转账、编码器 |
| `src/pvm.rs` | 可恢复 PVM `Vm`、每基本块 gas、`Memory` + `sbrk` |
| `src/pvm_exec.rs` | 指令执行(含 `sbrk` 指令) |
| `tests/accumulate.rs` | 数据驱动:跑目录下全部向量,断言 `(output, post_state)` 逐字节相等 |

## 2.2 状态类型映射(`accumulate.rs`)

| GP | 代码 | 行 |
|---|---|---|
| `δ` | `State.accounts: Vec<AccountsMapEntry>` | `:85` |
| `ϑ` | `State.ready_queue: ReadyQueue`(`FixedSeq<_, EPOCH>`) | |
| `ξ` | `State.accumulated: AccumulatedQueue` | |
| `χ` | `State.privileges: Privileges` | `:76` |
| `π_S` | `State.statistics: Vec<ServiceStatEntry>` | |
| `a` | `ServiceAccount`{ service, storage, preimage_blobs, preimage_requests } | `:52` |
| `(report, deps)` | `type Pending = (WorkReport, Vec<[u8;32]>)` | `:113` |

`Outcome`(`:105`)序列化成向量的 `output`(`ok` = 32 字节累积输出根)。

## 2.3 依赖与队列编辑

- `dependencies(r)`(`:119`)= `context.prerequisites` ∪
  `segment_root_lookup[*].work_package_hash`。对应 GP 的依赖集。
- `edit(records, accumulated)`(`:126`)= GP `E`:`filter` 掉自身已累积的报告,
  再从每个 `deps` 里 `filter` 掉已满足哈希。
- `priority(records)`(`:138`)= GP `Q`:取 `deps` 为空的报告,若非空则对剩余
  用其哈希再 `edit` 并**递归**——实现拓扑顺序 + 同块级联。

## 2.4 `transition` 主流程(`:155`)

1. `m = slot % EPOCH`,`accumulated_cup` = `ξ` 全展平(`:156-157`)。
2. **分区**(`:160-172`):`immediate`(prereq 空且 srl 空)、`queued_raw`
   (带依赖),`queued = edit(queued_raw, accumulated_cup)`。
3. **`W*` 装配**(`:174-183`):`ϑ` 从 `m` 起环形展开 + `queued`,用
   `immediate_hashes` 再 `edit`,`accumulatable = immediate + priority(...)`。
4. **块级 gas 门控**(`:185-197`):`BLOCK_ACC_GAS = 20_000_000`(tiny),按序
   累加报告的 `accumulate_gas`,超限则停,得 `acc_reports`。
   > 对应 GP 的 `g = max(blockaccgas, reportaccgas·corecount + Σ alwaysacc)`;
   > tiny 下退化为常量 20M。
5. **按服务分组执行**(`:199-246`):收集去重的 `service_id`,每服务把其
   work-digest 聚成 `Operand` 序列(`:220`),取其代码(从账户的 preimage 里按
   `code_hash` 找,`:232`),调 `run_service`,回收 `accounts`/`gas_used`/`yielded`,
   并累积 `deferred`(延迟转账)。
6. **延迟转账应用**(`:247-253`):目的地存在→加余额;不存在→**销毁**。
7. **`last_accumulation_slot`**(`:254-259`):每个累积服务置为本块 slot。
8. **写回**:`post.accounts`(`:262-267`)、`post.statistics`(`π_S`,`:268-278`)。
9. **`ξ` 移位**(`:280-289`):前移一格,最新槽放本块累积包哈希(按哈希排序)。
10. **`ϑ` 重建**(`:292-306`,GP `finalstateaccumulation`):`i==0` 放本块未累积
    的排队报告;`i<gap` 清空;否则旧内容再 `edit`。`gap = slot - pre.slot`。
11. **输出根**(`:308-314`):有 yield → `accumulation_root`,否则 32 零字节。

## 2.5 执行引擎 `accumulate_exec.rs`

### 2.5.1 剥离 jam-pvm 容器:`program_offset`(`:49`)

测试服务是 **jam-pvm-build 容器**(前缀有 magic/name/version/license 元数据),
不是裸 GP blob。`program_offset` 在前 256 字节里找一个偏移,使
`|o|`/`|w|`/`|pvm|` 三个长度头**恰好消费到 blob 末端**(`:61`),即内嵌 GP
标准程序 blob 起点。属 jam-pvm 适配层,非 GP。

### 2.5.2 标准程序初始化 `Y`:`spi`(`:70`)——内存布局深挖

常量:`Z=1<<16`、`I=1<<24`、`P=4096`(`:12-14`);`pq=|x| P*⌈x/P⌉`(`:89`)、
`qq=|x| Z*⌈x/Z⌉`(`:90`)。头解析 `:73-87`(olen/wlen/z/s/ro/rw/plen/pvm)。

映射(逐段对照 GP eq. `memlayout`):

| 段 | 代码 | GP 边界 |
|---|---|---|
| 只读 `o`(R) | `map(Z, pq(olen), false)`+`store` `:92-93` | `[Z, Z+rnp(|o|))` |
| 堆 `w`+额外页(W) | `wbase=2Z+qq(olen)`;`map(wbase, pq(wlen)+z·P, true)`+`store` `:94-96` | `[2Z+rnq(|o|), +rnp(|w|)+z·P)` |
| 栈(W) | `stack_lo=2^32-2Z-I-pq(s)`;`map(stack_lo, pq(s), true)` `:101-102` | `[2^32-2Z-I-rnp(s), 2^32-2Z-I)` |
| 参数 `a`(R) | `abase=2^32-Z-I`;`map(abase, pq(len), false)`+`store` `:103-105` | `[2^32-Z-I, +rnp(|a|))` |

**两个堆末端**(关键):

- `heap_top = wbase + pq(wlen) + z·P`(`:99`)= GP 可访问堆末端 = **初始 break**;
- `heap_max = wbase + qq(wlen + z·P)`(`:100`)= GP 保留堆区末端 = **`sbrk` 上限**。

> **修过的 bug**:多操作数向量(如 9 个 operand)fetch 缓冲增大,服务用 `sbrk`
> 把 break 从 `heap_top` 推向 `heap_max`;早先 `sbrk` 是占位、不扩堆,导致越过
> `heap_top` 即 page-fault。修正后两条边界精确对齐 GP。

**寄存器**(`:107-111`,逐条对齐 GP eq. `registers`):
`r0=2^32-2^16`、`r1=2^32-2Z-I`、`r7=abase`、`r8=|a|`、其余 0。

**遗留**:`spi` 末尾返回的 `(a, b)`(`:113-114`,旧的堆页边界)现已被
`heap_top/heap_max` 取代,调用点写作 `_a,_b`(`:237`)未用,可清理。

### 2.5.3 入口 pc 与 `Ψ_H`

`run_service`(`:228`)`Vm::new(&pvm, 5, gas, regs, mem)`:入口 **pc=5** 是
jam-pvm 分发表里 `accumulate` 处理器(对应 `Ψ_A` 选 5 号入口),非 `Y` 的一部分。
随后 `:245` 扣 **+10** 一次性启动溢价(见 gas 模型),再进入 host-call 循环
(`:253-266`,即 `Ψ_H`):`HostCall`→`host()`→`advance_host()` 越过 `ecalli` 续跑;
`Halt` 结束;`Panic/OutOfGas/PageFault`→**回滚 `orig` 账户**(GP 异常维度:常规
上下文变更丢弃;此处未实现 `checkpoint` 半提交)。

### 2.5.4 可恢复 PVM 与每基本块 gas(`pvm.rs`)

- `Vm`(`:370`)保存 `program/pc/gas/regs/memory/gas_charged`。
- `run`(`:394`)循环:进入新基本块(`!gas_charged`)时按
  `block_gas_cost(block_start_of(pc))`(`:347`)**一次性扣该块指令数**(含 `ecalli`);
  gas 不足→`OutOfGas`;执行到 terminator 时 `gas_charged=false`(下个块再计费)。
- `advance_host`:host-call 后把 pc 越过 `ecalli` 续跑(同块,不重复计费)。
- `block_gas_cost`(`:347`):从块首数指令到 terminator。

### 2.5.5 `Memory` 与 `sbrk`(`pvm.rs:41,77`)

- `Memory`{ `pages: BTreeMap<u32,Page>`, `heap_top`, `heap_max` }。按页惰性映射。
- `sbrk(size)`(`:77`):`size==0`→返回当前 break(查询);否则
  `new=old+size`,若 `≤heap_max` 则 `map(old,size,true)`、`heap_top=new`、返回
  **旧 break**(PolkaVM 语义);超限返回 0。
- `readable_range`/`writable_range` 带页数上限,防超大 `len` 触发巨型分配(早先
  一处 host-side 无界分配导致挂起,已加固)。

### 2.5.6 Host-call ABI:`host`(`:271`)——逐条

编号用 **jam-pvm 的 ecalli 号**(= GP 主网号 −1 的偏移,经向量校准):

| n | 调用 | 行 | 语义(实现) |
|---|---|---|---|
| 0 | gas | `:295` | `r7 = 剩余 gas` |
| 1 | fetch | `:299` | kind 0=`protocol_params`;14=全部操作数(compact 前缀+拼接);15=按 `r11` 索引单操作数;写入 `r7/r8/r9` 指定缓冲 |
| 3 | read | `:315` | 读服务(`r7`,`NONE`=self)存储 key(`r8/r9`)→ 写 `r10`,`r7`=值长/`NONE` |
| 4 | write | `:336` | 写 caller 存储:`r10==0` 删项(减 `items/bytes`);存在则改值(调 `bytes`);否则新增并按 key 排序;`r7`=旧值长/`NONE` |
| 5 | info | `:374` | `encode_info`(codehash+balance+min_item_gas+min_memo_gas+bytes+items)写 `r8` |
| 20 | transfer | `:414` | dest=`r7`,amount=`r8`:扣 caller 余额、记 `Transfer{dest,amount}`;dest 不存在→`WHO`,余额不足→`CASH` |
| 21 | eject | `:397` | target=`r7`:删目标、余额并入 caller;不存在→`WHO`,`=self`→`HUH` |
| 25 | yield | `:389` | 读 `r7` 处 32 字节为本服务输出承诺 |
| 100 | log | `:432` | JIP-1 调试,空操作 |
| 其它 | — | `:433` | `r7=HUH`(未实现) |

返回码常量:`NONE=2^64-1`、`WHO=-2`、`HUH=-4`、`CASH=-6`(`:17-20`)。
`write_out`(`:440`)统一处理 fetch 的"写缓冲 + 返回总长/`NONE`"。

### 2.5.7 操作数与参数编码

- `acc_args(slot, service, n)`(`:119`)= `compact(slot)‖compact(service)‖compact(n)`,
  即 `Ψ_A` 的 `AccumulateParams`(注意 slot/service **是 compact,不是定宽**)。
- `compact(n)`(`:128`)= GP 通用自然数(general-natural)变长编码(用于序列长度前缀)。
- `encode_operand`(`:148`)= jam-types `AccumulateItem::WorkItem(WorkItemRecord)`
  的 SCALE 布局:tag 0 ‖ package_hash ‖ seg_root ‖ authorizer ‖ payload_hash ‖
  `compact(gas_limit)` ‖ `CompactRefineResult`(Ok→`0‖compact-len‖blob`;Err→code)
  ‖ `compact(len)‖auth_trace`。
- `protocol_params`(`:173`)= jam-types `tiny()` 的 `ProtocolParameters` 定宽布局
  (34 个字段,Balance/Gas u64、Slot/u32 4B、index/u16 2B),供 `fetch(kind=0)`。

### 2.5.8 延迟转账 + 弹出

- `AccOut.transfers: Vec<Transfer>`(`:32/36`)把每服务产生的延迟转账带出。
- `transfer`(`:414`)只扣款 + 记账;`transition:247-253` 在所有服务累积后统一
  入账,目的地不存在则销毁——实现 `transfer_for_ejected`(100 被销毁)。
- `eject`(`:397`)即时删服务、并入余额;顺序上先于延迟转账应用,故"先弹出、
  后转账作废"链条正确。

> **简化**:延迟转账**未运行目的地的 `on_transfer` PVM 逻辑**(当前向量目的地
> 均被弹出→销毁,不触发);GP 主网的 supervisor 余额、`fnpartitionxfers`
> 并行划分未实现。

### 2.5.9 累积输出根:`accumulation_root` / `merkle_node`(`accumulate.rs:349,374`)

- `accumulation_root`(`:349`):对各 yield 的叶子 `E4(s)‖h`(**按服务排序**)做
  keccak `M_B`:0 叶→32 零字节;1 叶→`keccak(leaf)`;否则 `merkle_node`。
- `merkle_node`(`:374`)= GP `N`:0→零哈希;1→**原样返回叶**(可 >32 字节);
  否则 `keccak("$node" ‖ N(左) ‖ N(右))`。
  > 单叶原样返回、由父节点整块哈希,正是 GP `N` 的定义(叶宽 36 字节时也正确)。

## 2.6 Gas 模型(经验校准,非 GP 主网常量)

tiny 测试服务的 gas 不用 GP 主网常量(那些是 read=2407、info=703 等,与向量不符),
而是一套小模型,对着向量的 `accumulate_gas_used` 逐字节反推:

| 项 | 值 | 位置 |
|---|---|---|
| 每基本块 | 指令条数(含 `ecalli`) | `pvm.rs:347` `block_gas_cost` |
| 一般 host-call | 10 | `accumulate_exec.rs:285` |
| `log`(100) | 0 | `:286` |
| `yield`(25) | 30 | `:287` |
| `eject`(21) | 40 | `:288` |
| `transfer`(20) | `50 + 预留 gas 上限(r9)` | `:289`(GP `g = CgasT + l`) |
| 每次 `Ψ_H` 调用 | +10 一次性启动溢价 | `run_service:245` |

**推导要点**(供后续维护):由多个向量的 host-call 序列 + 块 gas 建方程,得
`info+eject=50`、`info+yield=40`;取 `info=10` → `eject=40`、`yield=30`。
`transfer` 的 +10040 ≈ `base(50) + gas_limit(10000)`,对齐 GP 的 `CgasT + l`。
启动溢价 +10 = 协议参数取用 + 分配器初始化的固定开销。

## 2.7 统计 `π_S`(`transition:268-278`)

每个被累积服务写 `accumulate_count`(操作数个数)与 `accumulate_gas_used`;其余
维度(refine/extrinsic/exports…)在本 STF 置 0(`zero_service_record` `:331`)。
**账户不存在但被排队报告触发的服务**(依赖本块解开、账户从未创建)也以 0 gas
累积并产生 `π_S` 条目(如 `work_for_ejected-3` 的 `(2,1,0)`)。

---

# 第三部分:已知简化与未实现

- host-call gas 用小经验模型,非 GP 基础常量。
- 延迟转账只 credit/burn 余额,**不跑目的地 `on_transfer`**(无覆盖向量需要)。
- 未实现 host-call:`new`/`upgrade`/`bless`/`designate`/`assign`/`solicit`/
  `forget`/`query`/`lookup`/`checkpoint`/`provide` 等 → 返回 `HUH`。
- 异常维度:panic/OOG/fault 直接回滚 `orig` 账户,无 `checkpoint` 半提交。
- 特权 `χ`、always-accumulate、supervisor 余额、`fnpartitionxfers` 并行划分未参与
  (0.7.2 账户无 supervisor 字段)。
- 只覆盖 `stf/accumulate/tiny`;full 规模、erasure-coding、网络等不在此列。
- `spi` 返回的 `(a,b)` 为遗留、未用。

---

# 第四部分:测试与验证

- `tests/accumulate.rs`:数据驱动,遍历 `tests/vectors/accumulate/*.json`,对每个
  向量跑 `transition(pre, input)` 并断言 `output` 与 `post_state` 逐字节相等。
- 结果:**30/30** 通过(队列-only、立即累积、ready-queue 级联、多操作数、
  自引用链、账户弹出、向已弹出目的地的延迟转账)。
- 全套件:16 个测试二进制全绿,0 warning。

## 参考(GP 章节)

- §12 Accumulation:`acc.tex`(accseq/accpar/accone、finalstateaccumulation、
  accumulationstatistics、fnservouts/fnpartitionxfers)。
- Appendix A PVM `Ψ`:`pvm.tex`(标准程序初始化 `Y`:eq. conditions/memlayout/
  registers;`Ψ_M`)、`pvi.tex`(host 函数表)、`definitions.tex`(gas 常量)。
- Merklization:`mrk.tex`(节点 `N`、良平衡 `M_B`=`merklizewb`)。
