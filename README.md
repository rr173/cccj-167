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
```

运行测试：

```bash
python3 -m unittest discover -s tests -t .
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
