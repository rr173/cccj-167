dlq-recovery 1.0.0 离线重投包
计划摘要: a95aa3101e699c7e382712bbf623eeb5a0c4cfbc31fd2846829f21a2866728e3
生成时间(UTC): 2026-11-17T07:09:48Z

记录数=6 版本数=6 已批准重投=6 隔离=0 被替代=0

partitions/*.ndjson: 仅含有效批准的事件版本，分区内按原队列偏移升序；
  每条记录带 event_id / payload_sha256 / source_records，可追溯回原偏移与失败证据。
quarantine/items.ndjson: 需隔离版本，下游不得重放。
quarantine/conflicts.ndjson: 同业务键冲突载荷的完整保留件。
本包由离线工具生成，不包含任何队列连接动作。
