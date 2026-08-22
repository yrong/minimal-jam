# Work-Package 流水线:Guarantee 与 Assurance(JAM ↔ Polkadot)

基础 note:一个 work-package 在 JAM 中如何变为*可用(available)*、再被*累积
(accumulated)*,为什么需要 guarantee 与 assurance 两步,以及它们如何对应到原
Polkadot(ELVES)的 parachain 共识阶段。

> 英文版:[`work-package-pipeline.md`](./work-package-pipeline.md)

## 1. 完整流水线

```
refine(核内) → guarantee(担保) → assurance(可用性) → audit/approval(审计) → accumulate(累积上链)
   "算"          "算得对"          "数据拿得到"          "复算无误"           "改链上状态"
```

一个 **work-package** 被分到某个 **core**,由该 core 的验证者做 **refine**(无状态
的重活,如执行一个 parachain 块),产出 **work-report**。之后是关注的两步。

- 本仓库对应 STF:`src/reports.rs`(guarantee)、`src/assurances.rs`(assurance)、
  `src/accumulate.rs` + `src/accumulate_exec.rs`(accumulate)。

## 2. guarantee(担保)——"这份计算是对的"

- **谁**:分到该 core 的一组 **guarantor**(担保人;需该组 ≥2/3 签名)。
- **做什么**:重跑/检查 refine,给 work-report 附上 **Ed25519 签名**,担保结果。
- **上链**:`guarantees` extrinsic(`E_G`)进块;通过校验的报告被分配到 core,
  进入"待可用"`ρ`。
- **代码(`reports.rs`)**:担保人分配(熵洗牌 + 轮换)、Ed25519 凭证校验、报告
  **上下文有效性**(anchor 时效、依赖、gas、授权),再写 `ρ` 与 core/service 统计。

**为什么需要**:担保是**廉价的正确性背书**,让报告被乐观接受;有人质疑再走
dispute。它把"计算"与"共识"解耦——只需一小组重算,而非全网。

## 3. assurance(可用性)——"支撑数据全网拿得到"

- **谁**:全体活跃验证者。
- **做什么**:work-package 被**纠删编码**成碎片分发;每个验证者签一个 **bitfield**,
  声明"我持有 core X 的那份碎片"。
- **变可用**:某 core 得到**严格 2/3 超多数** assurance 时,报告 *available*,从
  `ρ` 移除并返回累积。超时(`ASSURANCE_TIMEOUT`=5)仍不可用则清除(不累积)。
- **代码(`assurances.rs`)**:per-core 2/3 超多数标记 + 超时清理。

**为什么需要**:这是**乐观 rollup 式安全的命门**。只有支撑数据"全网可重建",后续
**审计/审批**与**争议**才有据可查。数据不可得就无人能复核 refine 是否作弊——所以
**数据不可用绝不能最终确认**。纠删编码保证只要约 1/3 验证者在线即可重建全部数据。

### 纠删编码:两个不同的阈值(每个验证者一份碎片)

分发是**每个验证者一份碎片**:work-package 数据(及其导出 segment)被纠删编码成
**V 份**(V=验证者数),验证者 `i` 持有第 `i` 份;bitfield 里某 core 的那一位=1,
表示"我持有该 core 上那份报告的碎片"。

常见误解是"要 2/3 的碎片才能重组"——**并非如此,这是两个独立阈值**:

| 阈值 | 数值 | 含义 |
|---|---|---|
| assurance 签名门槛 | **> 2/3 验证者** | 声明报告*可用*(`assurances.rs`,`3·count > 2·V`) |
| 纠删码重组门槛 | **~1/3 碎片**(⌈V/3⌉) | 拿到这么多碎片即可还原全部数据(系统性 Reed-Solomon,约 3× 冗余) |

- full:V=1023 → 约 342 ≈ V/3 份即可重组;`core_count = 341 = V/3`。
- tiny:V=6 → 2 份即可重组;可用性需 ≥5 个签名。

**为什么"2/3 签名、1/3 重组"(拜占庭 1/3 容错):** 假设至多 1/3 验证者作恶,
若 >2/3 诚实地 assure 持有碎片,则即使事后其中 1/3 消失/撒谎,仍剩 >1/3 的诚实
碎片可取回——恰好等于重组门槛。所以 2/3 签名是*安全余量*,保证"扣掉 1/3 坏人后
仍够重组";而重组本身只要 1/3。重组用于 **audit/approval(审计)与 dispute(争议)**:
审计者从少数验证者拉碎片、重组数据、复跑 refine 检查担保者是否作弊。

> minimal-jam 是"解码后 JSON 上的 STF",**不实现纠删编码/碎片分发**(那是网络层);
> `assurances.rs` 只校验 bitfield 的 2/3 超多数。

## 4. 为什么拆成两步

| | guarantee | assurance |
|---|---|---|
| 断言 | 计算**正确** | 数据**可得** |
| 参与者 | 少数担保组 | 全体验证者 |
| 阈值 | 组内 2/3 | 全网 2/3 |
| 抵御 | 无效状态转移(dispute 兜底) | 数据扣留(data withholding) |

两者正交:正确但被扣 = 无法审计;可得但算错 = dispute 打掉。**都满足**才安全累积。

## 5. 对应 Polkadot(ELVES/parachain 共识)

| JAM | Polkadot | 说明 |
|---|---|---|
| work-package / work-report | candidate / **candidate receipt** | 待上链候选 |
| refine | **`validate_block` / PVF 执行** | 核内验证逻辑 |
| guarantor(担保组) | **backing group** | 分到 core/para 的验证者子集 |
| **guarantee**(担保签名) | **backing**(backing statements → "backed candidate") | 背书 |
| **assurance**(可用性 bitfield) | **availability bitfields / availability distribution** | 同构;纠删编码一致 |
| "available" → accumulate | **inclusion**(候选写入 relay 块) | |
| audit / approval | **approval checking**(二级审批检查者) | 事后随机复算 |
| disputes | **disputes** | 争议裁决 |
| accumulate | (Polkadot 无直接对应) | 结果**整合进链上状态**,泛化到任意服务 |

一句话:**guarantee ≈ Polkadot 的 backing,assurance ≈ Polkadot 的 availability**。

## 6. 关键差异(JAM 的泛化)

- Polkadot 专为 **parachain**:refine = 跑 parachain 块(PVF)。
- JAM 泛化为**任意 service**:refine 是通用核内计算;新增 **accumulate** 把 refine
  结果**同步进链上状态**(Polkadot 里 parachain 状态根的应用是隐式、专用的,JAM
  显式化、通用化)。
- 因此称"去中心化超级计算机":保留 Polkadot 已验证的 backing/availability 安全机制
  (改名 guarantee/assurance),但计算与状态整合被通用化。

## 7. 谁被选中:担保组 vs 审计组

两组验证者的选取机制**根本不同**:担保组是**确定性分配**(entropy 洗牌 → 固定
core 组,轮换),审计组是 **VRF 抽签自选**(不可预测)。

### guarantor(担保组)——确定性分配

代码在 `reports.rs`:
- **基础分组**(`:131`):验证者 `i` 的基核 = `⌊i/3⌋` —— 即每 core **3 个验证者**
  (V/C=3)。
- **entropy 洗牌**(`:132`,`fisher_yates` `:139`):用链上随机数 `η[2]`(`:418`)做
  Fisher-Yates 打乱,决定"哪 3 个"分到哪个 core。
- **轮换**(`:134-135`):每 `ROTATION` 槽(tiny 4,full 10)给 core 索引加偏移
  `⌊(t mod E)/ROTATION⌋` 再取模,周期性换岗。
- **跨轮换/跨 epoch**(`assignment_for` `:409`):担保 slot 必须落在当前或上一轮换内
  (`:208-215`);跨 epoch 边界用 `prev_validators` + `η[3]`(`:431`)。
- **签名门槛**:一份 report 需该 core 的 3 个担保人里 **≥2 个** 的 Ed25519 签名。

即 η 洗牌当前映射到该 core 的那 ≈3 个验证者。**为什么确定性 + 轮换**:担保人要
**协同**产出并签署报告,必须知道"谁在这个 core"(一个轮换内可预测);定期换岗
限制长期合谋。

### auditor(审计/审批)——不可预测的 VRF 抽签

从**全体验证者**里抽(不是该 core 的担保子集)。目标是**独立**检查者:担保人在
backing 阶段已经查过,所以 approval 提供的是新的、独立的复核(强调的是*独立性*,
不一定是协议层对 backers 的硬性排除)。

- **VRF 自选(没有人指派你)**:每个验证者用自己的 VRF 输出算出"我要审计*哪些
  候选、各在第几档*"。没有协调者;揭示 VRF 证明前,谁都不知道被选中的是谁。
- **档(tranche)= 按需扩招,不是投票回合**:第 0 档、第 1 档…是同一候选内的
  逐级*层级*。第 0 档的 VRF 中签者先查;**只有赞成票还不够(有 no-show,或该档
  中签人手不足)才激活下一档**(不是"够阈值再进下一档")。落在第 0 档 = "你是该
  候选的一个初始 approval 检查者"。档也不同于流水线的**先后阶段**(backing → approval)。
- **做什么**:从少数验证者拉纠删碎片(~1/3 即可重组)→ 复跑 refine → 投
  valid/invalid。
- **何时算 approved**:需集齐 `needed_approvals` 条**有效 approval 票**——来自被
  指派、真的重跑了 refine 并投 valid 的检查者(**不是** backing/担保签名)——**且**
  无未决 no-show。若被指派者超时未出票(no-show),更高档激活更多检查者;必须在
  没有悬而未决 no-show 的前提下凑够票数。
  - `needed_approvals` 是 **Polkadot** 参数(主网默认 **30**);JAM 未在链上固定该
    值(见下方说明)。

**为什么用 VRF、要不可预测**:审计的价值在于**攻击者无法提前知道谁会查**,因而
无法事先贿赂/攻陷检查者。若像担保组那样可预测,只需搞定那几个人即可蒙混过关。

### 对照

| | guarantor(担保) | auditor(审计/审批) |
|---|---|---|
| 从哪选 | 分到该 core 的子集(≈3 人) | 全体验证者 |
| 机制 | entropy 洗牌 + 轮换(**确定性**) | VRF 抽签(**不可预测**) |
| 可预测性 | 一个轮换内可知 | 揭示前保密 |
| 规模 | 每 core 固定 3 | 按档动态放大 |
| 目的 | 高效协同产出报告 | 抗合谋、事后随机复核 |
| Polkadot | backing group | approval checking(relay-vrf assignment + tranches + no-show) |

> 本仓库:**担保组分配已实现**(`reports.rs` 的 `assignment`/`assignment_for`:
> η 洗牌 + 轮换 + 跨 epoch)。**审计/审批未实现** —— 它是共识/网络层过程(VRF
> 抽签、分档、纠删码重组),不在 tiny STF 向量范围内。
>
> JAM 只把 **disputes/judgements** 形式化上链(`disp.tex`);审计的档大小与票数属
> 链下协议,主 GP 未固定。上文 `needed_approvals = 30`、RelayVRFModulo/Delay 是
> **Polkadot** 的具体实现,作为 JAM 继承设计的参照。

## 8. 审计结果:no-show 与争议(dispute)

### no-show ——"被指派却没按时投票"(不是泛指"没投票")

- **no-show = 被 VRF 指派(中签要查某候选)、却在超时窗口内没交出 approval 票的
  检查者。** 没被指派的验证者本来就不用投,不算 no-show。
- 它是**暂时/未决**态:票可能晚到(到了即"解决"),或被替补检查者覆盖。
- **为什么在意**:no-show 可疑——检查者可能查出问题在拖延,或攻击者故意拖延、
  阻止凑够诚实检查。所以**每个 no-show 都激活下一档**,拉更多替补检查者。
- **"无未决 no-show"** = 每个被指派者要么已出票,要么其缺席已被更高档替补出票覆盖。
  只有"够 `needed_approvals` 有效票 **且** 无悬空缺席"才算 approved。
- (no-show / 分档是 Polkadot 链下 approval 概念,本仓库未实现。)

### 单个 invalid 就触发 dispute ——但"触发 ≠ 裁决"

- **触发**:乐观模型核心是"**只要一个诚实检查者发现不对就能揭发**"。哪怕其他人都
  赞同,任一被指派者复核出 *invalid*,就**升级为 dispute**(不走普通 approval 票)。
  揭发门槛低到 1 票。
- **裁决**:随后升级到**全体验证者**,由 **2/3 超多数**定夺,**不是那一票说了算**。
  仓库 `disputes.rs`(GP §10,已实现,28/28)里:
  - **verdict** `ψ` ∈ {good / bad / wonky}:≥2/3 valid → **good**(报告保留);
    ≥2/3 invalid → **bad**(报告被拒,清除可用性 `ρ`);约 `⌊V/3⌋` 分歧
    (`WONKY_VOTES`)→ **wonky**(无共识)。
  - **culprits(祸首)**:一个 *bad* 报告的**担保人**(≥ `MIN_CULPRITS` = 2)——担保了
    错报告 → slash。
  - **faults(错判)**:投票**与最终 verdict 相反**的人 → slash。
- **所以"大家都赞同、只有一人投 invalid"的场景**:那一票*触发* dispute、逼全体复核;
  若报告确实有效,verdict = good(2/3 valid),那个孤立的 invalid 投票者作为
  **fault 被 slash**。单票只能"逼大家查",无法独自把报告否掉。

**这套非对称正是要点**:揭发廉价(1 票),但诬告有罚(fault slash)防 griefing,担保
错报告要担责(culprit slash)。只要 ≤1/3 作恶,诚实方总能把真相顶成 2/3 超多数。

### 三者都不是"多轮攒票"

一个常见误解:backing/approval 是"分多轮、每轮攒票、够阈值再进下一轮"。**并非如此**:

- **backing**:一次性 2-of-3 组内阈值(担保签名收齐即可)。
- **approval**:所有已激活档的票**汇入同一池**,只有**一个全局完成条件**
  (`needed_approvals` 有效票 + 无未决 no-show),不是每档一道门。**票不够(no-show
  或人手不足)才扩招下一档,够票即停**——理想情况第 0 档就完成。
- **dispute**:一次性升级全体,由 2/3 超多数定夺。

JAM 里真正的"轮/周期"在别处、与这条投票流无关:**epoch(纪元)**、担保人的
**rotation 轮换周期**(`reports.rs` 的 `ROTATION`),以及出块/最终性共识——那是另一个
子系统。

## 9. 在 minimal-jam 中的实现对应与缺失

本仓库实现的是这条流程的**链上 STF 校验**那半(对 tiny 向量 byte-exact)。
**核内(refine)**与**链下**过程(audit/approval、纠删码、担保/可用性 P2P)
**按设计不在范围内**——这是"解码 JSON 上的状态转移",不是完整节点。

| 阶段 | 对应代码 | 状态 | 缺失/未做 |
|---|---|---|---|
| **refine(核内"算")** | `pvm.rs` / `pvm_exec.rs`(PVM 引擎,311/311) | 🟡 引擎在,阶段未接 | refine 调用 `Ψ_R` + refine host ABI(段导入导出、historical_lookup…)、真正跑 work-package。向量只喂 refine 的**输出**(`work-report.results` + `refine_load`),不重跑 refine |
| **guarantee(担保"算得对")** | `reports.rs`(42/42) | ✅ 链上 STF | 链下担保**网络协议**:报告产出/分发、担保组 gossip、签名收集(仅校验 extrinsic) |
| **assurance(可用性"拿得到")** | `assurances.rs`(10/10) | ✅ 链上 STF | **纠删编码 + 碎片分发/取回**(网络层) |
| **audit / approval(审计"复算无误")** | —(无) | ❌ 未实现 | 全部:VRF 抽签、tranche、no-show、重下碎片复跑 refine、投票 |
| ↳ audit 的链上**后果** dispute | `disputes.rs`(28/28) | ✅ 链上 STF | dispute 的**链上裁决**已做;**触发它的链下 approval 未做** |
| **accumulate(累积"改链上状态")** | `accumulate.rs` + `accumulate_exec.rs`(30/30) | ✅ 链上 STF | 少数 host-call、`on_transfer` PVM、非 tiny 参数(见 `docs/accumulate.md` §二/三) |

**缺失标记(汇总):**
- ❌ **refine 执行**(核内):`Ψ_R` + refine host ABI + 段导入导出。
- ❌ **audit / approval**(链下):VRF 抽签、tranche、no-show、复核投票。
- ❌ **纠删编码 / 碎片分发取回**(网络)。
- ❌ **P2P 网络层**(担保 / 可用性 / 审计)。
- ❌ **区块生产 / 最终性共识**(SAFROLE 出块 VRF;注:`safrole.rs` 只做**票据处理
  STF**,13/14——`bad_ticket_proof` 环证明尚缺)。
- 🟡 accumulate:少量 host-call、`on_transfer`、full 参数。

**一句话:** 链上**状态转移**(guarantee / assurance / accumulate,加 audit 的链上
后果 disputes)已 byte-exact 实现;**refine 执行**与 **audit/approval + 纠删码 + P2P
 + 出块共识**等**链下/核内**部分未实现——这就是"minimal JAM STF"的边界。

## 参考

- GP §11:`guaranteeing.tex` / `reporting_assurance.tex`、`assur.tex`
  (`availassignmentspostguarantees`、`availassignmentspostassurances`)。
- 仓库:`src/reports.rs`、`src/assurances.rs`、`src/accumulate.rs`。
- Polkadot:parachain 共识(ELVES)—— backing、availability distribution、
  approval checking、disputes。
