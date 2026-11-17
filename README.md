# 死信离线恢复工具（dlq-recovery）

从队列**死信导出文件**恢复未成功处理的业务事件，判定「可重投 / 需隔离 / 已被后续事件取代」，
再生成**按原业务分区排序**的重投包交给下游。全程只读写本地文件，**不连接任何生产队列**。

## 快速开始

```bash
# 1) 只读预览（不改任何文件）
python3 -m dlq_recovery preview \
    --dead-letter examples/dead_letter.jsonl \
    --dispositions examples/dispositions.jsonl \
    --policy examples/policy.json

# 2) 逐事件版本批准（批准人、审计信息写入账本）
python3 -m dlq_recovery approve --event-id ev-xxxx --by alice \
    --dead-letter ... --dispositions ... --policy ... --approvals approvals.jsonl

# 3) 导出重投包（仅含有效批准版本）
python3 -m dlq_recovery export --out ./replay-pkg ...

# 4) 校验
python3 -m dlq_recovery verify --package ./replay-pkg

# 5) 交付后对账：登记 → 导入回执 → 对账预览 → 签发补投 → 校验补投包
python3 -m dlq_recovery register --store ./recon-store --package ./replay-pkg --by alice
python3 -m dlq_recovery import-receipts --store ./recon-store \
    --receipts ./receipts/batch-a.jsonl --by alice
python3 -m dlq_recovery reconcile --store ./recon-store --text
python3 -m dlq_recovery issue-replay --store ./recon-store --by alice
python3 -m dlq_recovery verify-replay --store ./recon-store --package <补投包目录>
```

运行测试：

```bash
python3 -m unittest discover -s tests -t .
```

生成对账夹具（含回执样例与逐步手册）：

```bash
python3 -I examples/reconciliation/build_fixtures.py
```

## 输入格式

### 死信文件（JSONL，逐行一条记录）

```json
{
  "message": {
    "message_id": "msg-1",
    "business_key": "order-1001",
    "partition": "p2",
    "offset": 5,
    "payload": {"order_id": "order-1001", "amount": 120.5},
    "event_type": "order.created",
    "status": "active",
    "occurred_at": 1000,
    "source_attempt": "upstream-1"
  },
  "failure": {
    "delivery_count": 3,
    "reason": "db_timeout",
    "evidence": "2026-11-16T10:00:03Z timeout after 30s (trace=abc123)"
  }
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `message_id` | 是 | 消息身份。同一 `message_id` 指向不同内容会被拒绝 |
| `business_key` | 是 | 业务键。相同**不代表**载荷可互换 |
| `partition` / `offset` | 是 | 原队列位置；`offset` 为 ≥0 整数 |
| `payload` | 是 | 任意 JSON；指纹对键顺序不敏感 |
| `event_type` / `status` | 是 | 事件类型与业务状态 |
| `occurred_at` | 是 | 业务时间（整数）。用于判定"后续状态事件取代旧事件" |
| `source_attempt` | 否 | 上游重发来源，便于追溯 |
| `delivery_count` | 是 | 投递次数，≥1 |
| `reason` / `evidence` | 是 / 否 | 失败原因与证据原文 |

解析是**严格 JSON**：拒绝重复键、`NaN`/`Infinity`、未知字段、负数偏移。
跨分区交错、同分区乱序都可以，工具自己排序。

### 人工处置（JSONL）

```json
{"message_id": "msg-1", "action": "retry", "operator": "alice", "note": "已定位为缓存残留"}
```

`action` 只允许 `retry` / `quarantine`。人工处置是**分诊建议**，不是批准：
它不会让事件变得可导出，真正的放行只来自批准账本里针对 `event_id` 的批准。

### 业务配置（JSON，可选）

```json
{
  "problem_statuses": ["needs_review"],
  "final_statuses": ["cancelled", "deleted", "closed", "completed"]
}
```

- `problem_statuses`：这些状态的版本默认隔离（软隔离，可由逐版本批准放行）；
- `final_statuses`：终态。同业务键出现更晚的终态事件时，旧版本判为「已被取代」。

## 判定规则

| 判定 | 含义 |
| --- | --- |
| `retryable` | 可进入批准/重投环节 |
| `quarantined` | 需隔离。`releasable=true` 表示软隔离（问题状态/人工 retry 建议），可由批准放行；否则为硬隔离 |
| `superseded` | 已被后续状态事件取代，永不重投 |

执行顺序：

1. **身份校验**：同一 `message_id` 不能指向不同内容；同一 `(partition, offset)` 不能出现不同事件。
2. **重复合并**：业务键 + 载荷指纹 + 事件类型 + 状态 + 业务时间完全一致 → 视为上游重发，
   合并成一个事件版本（规范位置取最早偏移），保留全部来源身份与失败证据。
3. **后续事件替代**：同业务键存在业务时间更晚的终态事件 → 旧版本 `superseded`。
   业务时间相同不构成替代。
4. **冲突隔离**：同业务键 + 同事件类型但载荷指纹不同 → 所有版本硬隔离，
   冲突载荷**完整保留**在 `quarantine/conflicts.ndjson`。不同事件类型（created vs cancelled）
   载荷天然不同，不算冲突。
5. **歧义隔离**：同载荷但状态/业务时间不一致、或同一内容出现在多个分区 → 硬隔离。
6. **人工处置**：`quarantine` → 硬隔离；`retry` → 仅作为建议记录；处置互相矛盾 → 硬隔离。
7. **状态策略**：`problem_statuses` 中的版本软隔离。

**硬隔离无法通过任何批准放行**，必须修正输入、重新生成计划。

## 批准语义

- 批准绑定 `event_id`。`event_id` 由业务键 + 分区 + 偏移 + **载荷指纹**推导：
  载荷或位置变化，`event_id` 就变化，旧批准自然失效。
- 批准还绑定 `version_digest`（该版本的队列位置、载荷、失败证据、判定原因）。
  本事件证据变化 → 批准失效；**无关记录**变化 → 批准继续有效，并标记 `plan_drift`。
- 同一业务键的其他版本不会被连带批准。
- 已在账本中的批准需先 `withdraw` 才能重新批准；撤回是追加记录，历史可审计。

## 重投包结构

```
replay-pkg/
  manifest.json              元数据、计划摘要、逐文件 sha256
  plan.json                  完整判定计划与证据
  README.txt                 下游说明
  checksums.sha256           逐文件校验和
  partitions/p-<分区>.ndjson 仅含有效批准版本，分区内按原偏移升序
  quarantine/items.ndjson    未放行的隔离版本（下游不得重放）
  quarantine/conflicts.ndjson 冲突组与全部载荷版本
  .complete                  完成标记（缺此标记视为导出中断）
```

每条重投记录携带 `event_id`、`payload_sha256`、`partition_sequence`、
`source_records`（原始偏移、投递次数、失败原因、证据）与 `approval`，
可完整追溯回原偏移与失败证据。

导出顺序：分区文件各自独立排序，跨分区在 manifest 中按分区名列出，
下游可按分区并行消费，互不阻塞。

## 导出中断

- 打包在**临时目录**内完成，全部文件 fsync 后整体 `os.replace` 到目标目录；
- 中途失败会清理临时目录，目标目录不会出现半成品；
- `.complete` 标记缺失、文件缺失、哈希不符、分区内偏移乱序、隔离件混入重投包
  —— `verify` 都会以退出码 7 报告，并给出结构化的 `problems` 列表。

## 交付后对账与补投

下游只能拿回**分批、乱序的离线回执**时，用对账存储（`--store` 目录，全程本地
文件）完成登记、收敛、补投签发与恢复。一次交付对应一个独立的 `attempt_id`：
首次登记生成原包尝试（`origin`），每次补投生成新的补投尝试（`replay`）。

### 回执格式（JSONL，每行一条）

```json
{
  "attempt_id": "attempt-0001",
  "package_digest": "00389b07…（64 位 sha256，登记时由包内容计算）",
  "event_id": "ev-c26fb572b7caaf0460c4",
  "payload_sha256": "…（包内该事件版本的载荷摘要）",
  "result": "not_executed",
  "reported_at": "2026-11-17T10:00:00Z",
  "reported_by": "downstream-batch-a",
  "receipt_id": "下游自带的去重键（可选）",
  "detail": "可选原文说明"
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `attempt_id` | 是 | 回执所属的交付尝试；迟到旧回执仍必须指向原尝试 |
| `package_digest` | 是 | 包**内容身份**。与登记不符直接拒收，业务键相同的包不能顶替 |
| `event_id` / `payload_sha256` | 是 | 绑定包内具体事件版本，回执不能挂到别的载荷上 |
| `result` | 是 | `success`（已成功执行）/ `not_executed`（明确未执行，可再试）/ `unknown`（无法确认） |
| `reported_at` / `reported_by` | 是 | 下游报告时间与来源 |
| `receipt_id` / `detail` | 否 | 下游去重键与说明原文 |

关键语义：

- **未知不是失败，缺回执也不是失败**。`unknown` 与无回执（派生态 `missing`）
  都不能当作 `not_executed` 自动补投，只能被**同次尝试**后续的确定结果消解。
- 同次尝试同时出现 `success` 与 `not_executed` 是**矛盾证据**（派生态
  `conflict`），不按文件顺序覆盖，永久阻断该事件自动补投并在对账视图展示。
- 解析采用严格 JSON（拒绝重复键、`NaN`/`Infinity`、未知字段）；一份文件只
  允许一个 `attempt_id`。任何格式或身份绑定错误都会让**整份文件原子拒收**，
  存储不留下部分状态。

### 持久化对账存储

```
recon-store/
  log/
    events.log              哈希链只追加日志（唯一事实源）
    receipts/0001-*.jsonl   原始回执归档（按导入序号保留）
  packages/<chain>/
    origin/                 登记时复制的原始交付包（不可变）
    attempts/attempt-0002/package/   每次补投签发的补投包
  state.json                可重建的物化快照（缓存，落后即按日志重放）
  .lock                     进程间文件锁
```

- **哈希链日志**：每条记录带 `seq`、`prev_hash`、`entry_hash`，篡改或断链在
  `verify-store` / 下次打开时即被发现。
- **证据幂等**：证据按回执内容哈希 `(attempt, event, evidence_hash)` 去重；
  重复文件、拆分文件、乱序导入收敛到同一结果，但每条证据的全部导入来源
  （文件、行号、导入人、序号）都作为 provenance 保留，可追溯。
- **原包不可变**：载荷、批准、来源证据保存在登记快照里，回执无法修改；
  补投记录通过 `origin` 块原样携带它们。
- 相同有效证据的导入顺序与文件分块不影响最终对账结果（收敛是纯函数）。

### 派生态与补投选批

每个 `(尝试, 事件)` 的派生态：`success` / `not_executed` / `unknown` /
`missing` / `conflict`。补投候选按**原包单分区顺序**从前向后检查：

- 已成功事件：跳过，且**任何已确认成功都禁止再次补投**；
- 明确未执行且未成功：可加入新批次；
- 遇到未知 / 缺回执 / 矛盾 / 尚在未完成补投尝试中的事件：成为本分区**阻塞点**，
  其后事件一律截留；**其他分区不受牵连**。

新尝试只允许包含上一次**明确未执行且尚未成功**的事件；每条补投记录带
`replay.attempt_id`（本次尝试）、`replay.prev_attempt_id` 与
`replay.basis`（前次失败尝试、派生态与全部失败证据哈希）。

### 可恢复发布协议

`issue-replay` 不要求数据库与文件系统跨介质事务，分两阶段：

1. 先在内存确定包内容与确定性 `package_digest`，再落 `attempt_publishing`
   日志意图——此刻事件已被占用，预览不会占用事件；
2. 在临时目录构建包、fsync 后原子替换到目标目录，再落 `attempt_published`。

重新打开存储时自动恢复：存在完整包（`.complete` + 摘要匹配）则**追认已签发**，
事件保持占用、禁止再签；没有可用包则**中止意图并释放事件**，允许重新签发。
因此不会出现"没有可用包却永久占用事件"或"旧包已可执行却能再次签发"。
已发出的补投尝试在未完成对账前不能重复签发；操作员可用 `seal-attempt`
宣告一轮对账结束后再签发下一轮。

### 跨尝试异常

- 早先尝试的迟到回执只能挂回原尝试；指向新尝试的旧摘要回执被拒收。
- 成功（或矛盾）证据到达时事件已进入后续补投尝试 → 展示
  `late_success_after_reissue`；不同尝试出现成功/未执行分歧 → 展示
  `cross_attempt_contradiction`。异常只展示、不抹掉任何交付历史。

### 补投包校验（verify-replay）

以日志中的签发意图为权威，拒绝：替换源包载荷/批准/来源证据、批次内重复
事件、越过分区阻塞位置、事件集合或前次失败依据与登记内容不符、缺少完成
标记、来源不明的包。

### 对账相关命令

| 命令 | 作用 |
| --- | --- |
| `register` | 登记已通过 `verify` 的交付包，形成首次尝试并复制不可变快照 |
| `import-receipts` | 导入回执（整文件解析 + 绑定校验通过后原子生效） |
| `reconcile` | 对账预览：每事件派生态、证据来源、分区阻塞点、补投候选、异常（`--text` 文本视图） |
| `issue-replay` | 签发下一次补投批次（新 `attempt_id`，两阶段可恢复发布） |
| `verify-replay` | 校验补投包与对账登记逐字一致 |
| `seal-attempt` / `abort-attempt` | 封存一轮尝试 / 中止无可用包的尝试并释放占用 |
| `verify-store` | 校验哈希链与物化快照（快照落后自动重建） |

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 4 | 输入文件格式/内容非法 |
| 5 | 语义校验失败（如 event_id 不存在） |
| 6 | 策略阻止（无批准、失效批准、非空输出目录） |
| 7 | 完整性校验失败（包缺文件/被篡改/未完成） |
| 8 | 工作流状态不允许（重复批准、撤回不存在的批准） |

## 离线保证

- 源码不含 `socket`/`http`/`urllib`/`kafka`/`pika` 等任何网络或队列客户端导入；
- `dlq_recovery.offline` 提供 AST 静态扫描与运行时模块检查；
- 测试 `test_offline.py` 强制校验工具包内无网络依赖；
- 所有阶段（预览、批准、导出、校验）均只操作本地文件。
