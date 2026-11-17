"""错误类型与稳定错误码。

所有面向操作员的失败都使用 :class:`RecoveryError` 及其子类，并带有稳定的
``code``，便于在 CLI / 校验结果中做机器可读判断。
"""

from __future__ import annotations


class RecoveryError(Exception):
    """恢复工具的可预期错误基类。"""

    code = "RECOVERY_ERROR"
    exit_code = 3

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        out = {"code": self.code, "message": self.message}
        if self.details:
            out["details"] = self.details
        return out


class InputError(RecoveryError):
    """输入文件无法读取或格式不合法。"""

    code = "INPUT_INVALID"
    exit_code = 4


class ValidationError(RecoveryError):
    """业务语义校验失败（例如需要人工处置却无记录）。"""

    code = "VALIDATION_FAILED"
    exit_code = 5


class PolicyError(RecoveryError):
    """操作在当前阶段被策略禁止。"""

    code = "POLICY_BLOCKED"
    exit_code = 6


class IntegrityError(RecoveryError):
    """产物与输入/计划不一致，或被篡改/中断。"""

    code = "INTEGRITY_FAILED"
    exit_code = 7


class WorkflowError(RecoveryError):
    """批准/导出流程状态不允许当前操作。"""

    code = "WORKFLOW_INVALID"
    exit_code = 8


class DisclosureError(RecoveryError):
    """字段显隐等级不足，无法披露证据。"""

    code = "DISCLOSURE_DENIED"
    exit_code = 9


class ConflictError(RecoveryError):
    """同一业务键下存在不可自动合并的冲突版本。"""

    code = "CONFLICT_BLOCKED"
    exit_code = 10
