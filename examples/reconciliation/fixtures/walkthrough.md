# 对账与补投操作手册（夹具演示）

所有命令只读写本地文件。设 `$W` 为仓库根目录，`$F` 为本夹具目录。

## 0. 原始交付包已经过原有校验

```bash
python3 -m dlq_recovery verify --package "$F/origin-pkg"
```

## 1. 登记交付包（形成首次交付尝试 attempt-0001）

```bash
python3 -m dlq_recovery register --store "$F/store" \
    --package "$F/origin-pkg" --by alice --note "首批交付"
```

登记后包被复制进对账存储，内容身份 `package_digest`（见
`origin-pkg/manifest.json`，本次为 `e953480d6848af06d2efefca072163c792751c1273026f26d8675aed6e017ca1`）与
`attempt_id`、每个事件的 `event_id + payload_sha256` 绑定，业务键相同的
另一个包无法顶替。

## 2. 导入回执（整文件原子生效，坏文件不留部分状态）

```bash
python3 -m dlq_recovery import-receipts --store "$F/store" \
    --receipts "$F/receipts/01-pa-definite-pb-missing.jsonl" --by alice
```

重复导入同一文件、或导入内容重叠的 `04-duplicate-split-out-of-order.jsonl`
都是幂等的：证据按内容哈希去重，全部导入来源仍保留可追溯。

## 3. 对账预览

```bash
python3 -m dlq_recovery reconcile --store "$F/store" --text
```

`p-b` 第一个事件缺回执，是本分区阻塞点：`p-b-2/p-b-3` 即便明确未执行也被
截留；`p-a` 不受牵连。

## 4. 未知转成功

```bash
python3 -m dlq_recovery import-receipts --store "$F/store" \
    --receipts "$F/receipts/02a-unknown-first.jsonl" --by alice
python3 -m dlq_recovery import-receipts --store "$F/store" \
    --receipts "$F/receipts/02b-success-resolves-unknown.jsonl" --by alice
```

未知不是失败：它只在确定结果到达前阻塞补投；成功回执到达后被消解。

## 5. 矛盾证据阻断自动补投

```bash
python3 -m dlq_recovery import-receipts --store "$F/store" \
    --receipts "$F/receipts/03a-conflict-success.jsonl" --by alice
python3 -m dlq_recovery import-receipts --store "$F/store" \
    --receipts "$F/receipts/03b-conflict-not-executed.jsonl" --by alice
```

同次尝试同时出现成功与明确未执行时，派生态为 `conflict`，不会按文件顺序
覆盖；该事件永久退出自动补投，并在 `reconcile` 的 anomalies 中展示。

## 6. 签发补投与校验

```bash
python3 -m dlq_recovery issue-replay --store "$F/store" --by alice
python3 -m dlq_recovery verify-replay --store "$F/store" --package <输出的 package_dir>
```

补投尝试获得新的 `attempt_id`，只包含上一次明确未执行且尚未成功的事件；
每条记录带本次尝试、前次尝试与失败依据。未完成对账前再次 `issue-replay`
会被拒绝（退出码 8）。

## 7. 错误回执与迟到回执

```bash
# 身份绑定错误：整文件拒收（退出码 5），存储状态不变
python3 -m dlq_recovery import-receipts --store "$F/store" \
    --receipts "$F/receipts/05-invalid-wrong-package-digest.jsonl" --by alice
```

迟到的旧尝试回执必须仍指向原 `attempt_id`；指向新尝试的旧 digest 回执同样
被拒。已确认成功的事件禁止再次补投，与后续登记尝试矛盾时只展示异常，
不抹掉交付历史。

## 8. 存储自检

```bash
python3 -m dlq_recovery verify-store --store "$F/store"
```

哈希链日志是唯一事实源，`state.json` 只是可重建的物化快照。
