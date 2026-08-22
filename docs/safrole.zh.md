# Safrole:出块共识及其在区块导入中的角色

为什么区块导入 STF(`import_block`)把一整组状态章节委托给
`safrole::transition`、Safrole 到底*是什么*,以及它如何对应 Polkadot。

> 英文版:[`safrole.md`](./safrole.md)

## 1. Safrole 是什么

**Safrole**(**Sassafras** 的生产化变体)是 JAM 的**出块共识**:决定*每个 slot
的区块由谁封装(seal)*,并为链提供*随机数*。它是一个 **ring-VRF 抽签(ticket
lottery)**:

- 每个 epoch 之前,验证者私下生成 **ticket**(ring-VRF 输出)并上链提交。ticket
  通过环签名证明"某个(匿名的)验证者有权出某个 slot",但不暴露是谁。
- 中签的 ticket 被排成**逐 slot 的封装序列**;slot *n* 的 ticket 持有者是唯一
  被允许出该块的验证者。
- 由此得到**匿名、抗抢跑**的出块人选择:在他封装出块前,没人知道下一个作者是谁。
- 若 ticket 攒得不够,该 epoch 回退到由熵派生的**确定性密钥序列**
  (`fallback_keys(η, κ)`)。

## 2. Safrole 拥有的状态

Safrole 是这些 σ 章节的唯一写入者(括号为 GP 记号):

| 章节 | 状态 | 含义 |
|---|---|---|
| C11 (τ) | `timeslot` | 最近 slot |
| C6 (η) | `entropy`(4 个缓冲) | 随机数信标(每块 VRF 折入 + epoch 轮换) |
| C7/C8/C9 (ι/κ/λ) | staging / active / previous 验证者 | 验证者集,每 epoch 轮换 |
| C4 (γ) | `safrole` = { `pending` γ_k、`ring_commitment` γ_z、`tickets_or_keys` γ_s、`accumulator` γ_a } | ticket 竞赛 + 封装来源 |

常量(tiny):epoch `E = 12`,ticket 提交尾段起点 `TAIL_START = 10`,
`tickets_per_validator = 3`。

## 3. Safrole 每个区块做什么

1. **推进 τ** 到该块 slot(必须严格单调递增)。
2. **折入熵:** `η₀' = blake2b(η₀ ‖ VRF_output(seal))`——每块都喂信标。
3. **累积 ticket:** 尾段之前的块(`slot mod E < 10`)可携带 tickets extrinsic;
   有效 ticket 加入 `γ_a`,按 id 排序,截断到 `E`。
4. **epoch 边界**(`slot/E` 递增)时:
   - 轮换验证者 `λ'=κ, κ'=γ_k, γ_k'=Φ(ι)`(Φ 把作恶者密钥清零);
   - 重算环承诺 `γ_z' = ring_commitment(γ_k')`(bandersnatch);
   - 轮换 `η`;
   - 选定本 epoch 的**封装来源** `γ_s'`:竞赛饱和则用中签 ticket `Z(γ_a)`,
     否则 `Keys(fallback_keys(η₂', κ'))`;
   - 重置 `γ_a`——**并仍然接纳这个边界块自己的 tickets**(新竞赛可立即开始)。

## 4. 为什么区块导入需要它

导入一个区块就是一次**状态转移**;Safrole 的章节必须演进,才能:

- 校验**下一个**块的作者(seal 依据 `γ_s` 验证);
- 推进**随机数信标** `η`(它给担保人分配、ticket 抽签、fallback 密钥提供种子);
- 让**验证者集**跨 epoch 正确轮换。

所以*每个*块都会碰 Safrole——即使是没有 ticket 的 `fallback` 块也要推进 τ 和 η,
epoch 边界块还要轮换。跳过 Safrole 会让第一个块的状态根就错。

## 5. 在 `import_block` 中的角色

`import_block(pre, block)` 把 **Safrole 拥有的章节**(τ/η/ι/κ/λ/γ)**委托**给
经过测试的 `safrole::transition`,在统一 `State` 与 safrole STF 状态之间做映射;
其余章节(π 统计、α 授权池、β 近期区块)自己算。由此 `fallback` 与 `safrole`
两个 trace 类别都 byte-exact 复现。

接入 `safrole` traces 时也暴露并修复了一个潜伏 bug:epoch 转换分支此前**丢弃了
边界块的 tickets extrinsic**(把 `γ_a` 置空并忽略新 ticket)。safrole STF 向量
从未把 epoch 边界与 ticket 提交组合在一起,直到某条真实 trace 在 slot 12 同时
做这两件事才暴露。

## 6. 对应 Polkadot

| JAM | Polkadot |
|---|---|
| Safrole(Sassafras ring-VRF ticketing) | **BABE**(slot/epoch 出块),正演进到 **Sassafras** |
| `η` 随机数信标 | BABE VRF 随机数 / epoch 随机数 |
| ticket 抽签 → 逐 slot 作者 | BABE 主/次 slot 的 VRF 认领 |
| 验证者集 epoch 轮换 | session / epoch 验证者轮换 |

Safrole 相对 BABE 的优势:ticket 让作者序列**有序但在封装前匿名**,消除了暴露式
VRF slot 认领的"最后行动者/研磨(grinding)"与定向 DoS 弱点。

## 7. 在 minimal-jam 中的状态

- 已实现:`safrole.rs` STF(epoch 内推进、ticket 累积、epoch 转换、fallback/中签
  封装、`γ_z` 环承诺,**以及 Bandersnatch RingVRF 证明验证**——均经
  `ark-vrf` 0.1.0 + Zcash SRS)。通过 `safrole` STF 向量 **14/14**(含
  `bad_ticket_proof`)与 100 条 `safrole` 区块导入 traces。
- Ticket 验证:每个证明针对本 epoch 的环承诺 `γ_z`、VRF 输入
  `jam_ticket_seal ‖ η'₂ ‖ attempt` 校验(注意:GP 用带 `$` 的记号书写上下文,
  但实际字节是不含 `$` 的 `jam_ticket_seal`);证明无效则返回 `bad_ticket_proof`。
