"""离线守卫：静态扫描与运行时防护。

工具本身只读写本地文件。``assert_no_network_modules`` 用于防止未来误引入
网络/队列客户端；测试也会扫描源码确认没有任何 socket/broker 依赖。
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

FORBIDDEN_MODULES = frozenset(
    {
        "socket",
        "ssl",
        "http",
        "urllib",
        "urllib3",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "telnetlib",
        "xmlrpc",
        "asyncio",
        "multiprocessing.connection",
        "kafka",
        "confluent_kafka",
        "pika",
        "kombu",
        "boto3",
        "botocore",
        "redis",
        "pymongo",
        "psycopg2",
        "amqp",
    }
)

# 明确禁止的调用/属性（即使模块名被别名导入）
FORBIDDEN_NAMES = frozenset(
    {
        "connect",
        "create_connection",
        "urlopen",
        "socketpair",
        "fromfd",
    }
)


class OfflineViolation(RuntimeError):
    pass


def scan_source(path: str | Path) -> list[str]:
    """扫描单个 Python 文件，返回违规描述列表。"""

    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_MODULES or alias.name in FORBIDDEN_MODULES:
                    violations.append(f"line {node.lineno}: 禁止导入 {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".")[0]
            if root in FORBIDDEN_MODULES or module in FORBIDDEN_MODULES:
                violations.append(f"line {node.lineno}: 禁止从 {module} 导入")
        elif isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in FORBIDDEN_NAMES:
                violations.append(f"line {node.lineno}: 禁止调用 {name}()（可能连接外部服务）")
    return violations


def assert_offline_package(package_dir: str | Path) -> list[str]:
    root = Path(package_dir)
    problems: list[str] = []
    for path in sorted(root.rglob("*.py")):
        problems.extend(f"{path}: {v}" for v in scan_source(path))
    return problems


def ensure_offline_runtime() -> None:
    """运行时二次确认：本进程没有加载任何网络 I/O 客户端。

    这里只检查真正具备网络能力的模块；``urllib.parse`` 会被 pathlib 间接
    加载（仅用于 file:// 路径格式化），因此不在运行时清单内，但仍禁止
    本项目源码直接 import urllib。
    """

    loaded = {name.split(".")[0] for name in sys.modules}
    runtime_forbidden = FORBIDDEN_MODULES - {"urllib", "asyncio", "xmlrpc"}
    hits = sorted(loaded & runtime_forbidden)
    if hits:
        raise OfflineViolation(f"检测到已加载的网络模块: {hits}")
