#!/usr/bin/env python3
"""fanalyzer —— 固件镜像分析工具

在固件里扫描文件系统与压缩流签名、计算熵分布、提取字符串、查找敏感信息。

只用 Python 标准库，无三方依赖。

用法：
    python fanalyzer.py scan     firmware.bin
    python fanalyzer.py entropy  firmware.bin
    python fanalyzer.py strings  firmware.bin -n 6
    python fanalyzer.py secrets  firmware.bin
    python fanalyzer.py extract  firmware.bin -o out/
    python fanalyzer.py info     firmware.bin        # 全部跑一遍

"""

from __future__ import annotations

import argparse
import math
import os
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Windows 控制台默认 GBK，强制 utf-8，否则输出中文会崩
# ---------------------------------------------------------------------------
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 签名表
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Signature:
    magic: bytes
    name: str
    kind: str          # filesystem / compression / bootloader / container / crypto
    offset_hint: int = 0   # magic 相对结构起点的偏移


SIGNATURES: tuple[Signature, ...] = (
    # 文件系统
    Signature(b"hsqs", "SquashFS (小端)", "filesystem"),
    Signature(b"sqsh", "SquashFS (大端)", "filesystem"),
    Signature(b"\x45\x3d\xcd\x28", "CramFS", "filesystem"),
    Signature(b"UBI#", "UBIFS / UBI", "filesystem"),
    Signature(b"-rom1fs-", "RomFS", "filesystem"),
    Signature(b"070701", "CPIO (newc)", "filesystem"),
    Signature(b"070702", "CPIO (crc)", "filesystem"),
    # 压缩
    Signature(b"\x1f\x8b\x08", "GZIP", "compression"),
    Signature(b"\xfd7zXZ\x00", "XZ", "compression"),
    Signature(b"BZh9", "BZIP2", "compression"),
    Signature(b"\x28\xb5\x2f\xfd", "ZSTD", "compression"),
    Signature(b"\x04\x22\x4d\x18", "LZ4 (legacy)", "compression"),
    Signature(b"\x5d\x00\x00", "LZMA (raw)", "compression"),
    # 容器 / 镜像
    Signature(b"PK\x03\x04", "ZIP", "container"),
    Signature(b"ANDROID!", "Android boot image", "container"),
    Signature(b"\xd0\x0d\xfe\xed", "Device Tree Blob (DTB)", "container"),
    Signature(b"\x7fELF", "ELF 可执行文件", "container"),
    # 引导
    Signature(b"\x27\x05\x19\x56", "U-Boot Legacy uImage", "bootloader"),
    Signature(b"U-Boot ", "U-Boot 版本字符串", "bootloader"),
    # 密钥 / 证书
    Signature(b"-----BEGIN ", "PEM 私钥/证书", "crypto"),
)

# ext 家族：superblock 在 0x438，magic 0x53EF
EXT_MAGIC = b"\x53\xef"
EXT_OFFSET = 0x438

# 扫描时的最小命中偏移间隔，避免同一个压缩流里重复报告
DEDUP_WINDOW = 64


@dataclass
class Hit:
    offset: int
    name: str
    kind: str

    def __str__(self) -> str:
        return f"0x{self.offset:08X}  {self.kind:<12} {self.name}"


# ---------------------------------------------------------------------------
# 1. 签名扫描
# ---------------------------------------------------------------------------
def scan_signatures(data: bytes, dedup: int = DEDUP_WINDOW) -> list[Hit]:
    """一次遍历，用首字节建索引后再比对，避免 O(n*m) 的重复扫描。"""
    by_first: dict[int, list[Signature]] = {}
    for sig in SIGNATURES:
        by_first.setdefault(sig.magic[0], []).append(sig)

    hits: list[Hit] = []
    n = len(data)
    for i in range(n):
        cands = by_first.get(data[i])
        if not cands:
            continue
        for sig in cands:
            m = sig.magic
            if data[i:i + len(m)] == m:
                hits.append(Hit(i, sig.name, sig.kind))

    # ext2/3/4 单独判定
    if len(data) > EXT_OFFSET + 2 and data[EXT_OFFSET:EXT_OFFSET + 2] == EXT_MAGIC:
        hits.append(Hit(EXT_OFFSET - 0x400, "ext2/3/4 文件系统", "filesystem"))

    hits.sort(key=lambda h: h.offset)

    # 去重：同一名字在 dedup 窗口内只留一个
    out: list[Hit] = []
    last: dict[str, int] = {}
    for h in hits:
        prev = last.get(h.name)
        if prev is not None and h.offset - prev < dedup:
            continue
        last[h.name] = h.offset
        out.append(h)
    return out


# ---------------------------------------------------------------------------
# 2. 熵分析
# ---------------------------------------------------------------------------
def shannon_entropy(block: bytes) -> float:
    """香农熵，单位 bit/byte，范围 0~8。"""
    if not block:
        return 0.0
    counts = Counter(block)
    total = len(block)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


@dataclass
class EntropyBlock:
    offset: int
    entropy: float
    sample: bytes = field(repr=False, default=b"")

    @property
    def tag(self) -> str:
        if self.entropy >= 7.5:
            return "压缩/加密"
        if self.entropy >= 6.0:
            return "疑似压缩"
        if self.entropy >= 3.0:
            return "混合数据"
        return "空洞/填充"


def entropy_profile(data: bytes, block_size: int = 4096, max_blocks: int = 0) -> list[EntropyBlock]:
    blocks: list[EntropyBlock] = []
    limit = len(data) if not max_blocks else min(len(data), max_blocks * block_size)
    for off in range(0, limit, block_size):
        chunk = data[off:off + block_size]
        if not chunk:
            break
        blocks.append(EntropyBlock(off, shannon_entropy(chunk)))
    return blocks


def render_entropy_bars(blocks: list[EntropyBlock], width: int = 40) -> str:
    lines = []
    for b in blocks:
        filled = int(round(b.entropy / 8.0 * width))
        bar = "#" * filled + "." * (width - filled)
        lines.append(f"0x{b.offset:08X}  {b.entropy:5.2f}  [{bar}]  {b.tag}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3. 字符串提取
# ---------------------------------------------------------------------------
PRINTABLE = bytes(range(0x20, 0x7F))


def extract_strings(data: bytes, min_len: int = 6, utf16: bool = True) -> list[tuple[int, str, str]]:
    """返回 [(offset, encoding, text)]。utf16=False 时只看 ASCII。"""
    results: list[tuple[int, str, str]] = []

    # ASCII / UTF-8 可打印串
    cur: list[int] = []
    start = 0
    for i, byte in enumerate(data):
        if byte in PRINTABLE or byte == 0x09:
            if not cur:
                start = i
            cur.append(byte)
        else:
            if len(cur) >= min_len:
                results.append((start, "ascii", bytes(cur).decode("ascii", "replace")))
            cur = []

    if len(cur) >= min_len:  # 文件尾部的串
        results.append((start, "ascii", bytes(cur).decode("ascii", "replace")))

    # UTF-16LE：按 2 字节码元解码，支持 ASCII 与中文等 BMP 字符。
    # 早期版本只判断「可打印 ASCII + \x00」，会漏掉中文串，所以改成按码元解码。
    if utf16:
        results.extend(_extract_utf16le(data, min_len))

    results.sort(key=lambda r: r[0])
    return results


def _extract_utf16le(data: bytes, min_len: int) -> list[tuple[int, str, str]]:
    results: list[tuple[int, str, str]] = []
    n = len(data) - 1
    i = 0
    while i < n:
        j = i
        chars: list[str] = []
        while j < n:
            unit = data[j] | (data[j + 1] << 8)
            if unit == 0 or unit < 0x20 and unit != 0x09:
                break
            if 0xD800 <= unit <= 0xDFFF:      # 代理区，跳过（本工具不做完整 UTF-16 解码）
                break
            ch = chr(unit)
            if not ch.isprintable() and ch != "\t":
                break
            chars.append(ch)
            j += 2
        if len(chars) >= min_len:
            results.append((i, "utf16le", "".join(chars)))
            i = j if j > i else i + 2
        else:
            i += 2 if not chars else j + 2
    return results


# ---------------------------------------------------------------------------
# 4. 敏感信息扫描
# ---------------------------------------------------------------------------
SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("私钥",           r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "high"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}",                   "high"),
    ("硬编码口令",     r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"&]{3,}", "high"),
    ("API Key/Token",  r"(?i)(api[_-]?key|secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{8,}", "medium"),
    ("HTTP 地址",      r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", "low"),
    ("邮箱",           r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "low"),
    ("IPv4",           r"\b(?:\d{1,3}\.){3}\d{1,3}\b",         "low"),
    ("内网地址",       r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "medium"),
)


@dataclass
class Secret:
    offset: int
    rule: str
    value: str
    level: str


def scan_secrets(data: bytes, max_len: int = 4000) -> list[Secret]:
    """在 ASCII 可打印区域上跑正则，避免匹配到二进制噪音。"""
    found: list[Secret] = []
    seen: set[tuple[str, str]] = set()

    for off, encoding, text in extract_strings(data, min_len=4, utf16=False):
        if len(text) > max_len:
            continue
        for rule, pattern, level in SECRET_PATTERNS:
            for m in re.finditer(pattern, text):
                value = m.group(0)
                key = (rule, value)
                if key in seen:
                    continue
                seen.add(key)
                found.append(Secret(off + m.start(), rule, value[:120], level))
    found.sort(key=lambda s: s.offset)
    return found


# ---------------------------------------------------------------------------
# 5. 按签名切分提取
# ---------------------------------------------------------------------------
def extract_segments(data: bytes, hits: list[Hit], out_dir: Path, limit: int = 32) -> list[Path]:
    """把每个命中点之后的数据切一段出来，便于后续用专用工具分析。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for idx, h in enumerate(hits[:limit]):
        if h.kind in ("crypto",):
            continue
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", h.name)
        target = out_dir / f"{idx:02d}_{h.offset:08X}_{safe}.bin"
        target.write_bytes(data[h.offset:h.offset + 4 * 1024 * 1024])
        written.append(target)
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _load(path: str) -> bytes:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"文件不存在：{path}")
    return p.read_bytes()


def cmd_scan(args) -> int:
    data = _load(args.file)
    hits = scan_signatures(data)
    print(f"文件：{args.file}   大小：{len(data)} 字节\n")
    if not hits:
        print("未识别到已知签名。（可能是加密固件、未知格式，或需要先解包外层容器）")
        return 0
    print(f"识别到 {len(hits)} 处签名：\n")
    for h in hits:
        print("  " + str(h))
    return 0


def cmd_entropy(args) -> int:
    data = _load(args.file)
    blocks = entropy_profile(data, block_size=args.block)
    print(f"文件：{args.file}   块大小：{args.block} 字节   共 {len(blocks)} 块\n")
    print(render_entropy_bars(blocks))
    if blocks:
        avg = sum(b.entropy for b in blocks) / len(blocks)
        print(f"\n平均熵：{avg:.2f} bit/byte")
        if avg > 7.5:
            print("结论：整体接近随机 —— 固件很可能被整体加密或压缩。")
        elif avg > 6.0:
            print("结论：多块熵偏高 —— 存在压缩的根文件系统。")
        else:
            print("结论：存在明显的非压缩区域 —— 可能能直接提取到文件系统。")
    return 0


def cmd_strings(args) -> int:
    data = _load(args.file)
    items = extract_strings(data, min_len=args.number)
    for off, enc, text in items:
        print(f"0x{off:08X}  [{enc}] {text}")
    print(f"\n共 {len(items)} 条（最短 {args.number} 字符）")
    return 0


def cmd_secrets(args) -> int:
    data = _load(args.file)
    found = scan_secrets(data)
    if not found:
        print("未发现敏感信息。")
        return 0
    order = {"high": 0, "medium": 1, "low": 2}
    for s in sorted(found, key=lambda x: (order.get(x.level, 9), x.offset)):
        print(f"[{s.level:<6}] 0x{s.offset:08X}  {s.rule:<14} {s.value}")
    print(f"\n共 {len(found)} 条")
    high = sum(1 for s in found if s.level == "high")
    if high:
        print(f"其中 {high} 条为高风险（密钥/口令），建议优先处理。")
    return 0


def cmd_extract(args) -> int:
    data = _load(args.file)
    hits = scan_signatures(data)
    written = extract_segments(data, hits, Path(args.out))
    print(f"已切出 {len(written)} 个片段到 {args.out}/")
    for w in written:
        print("  " + w.name)
    return 0


def cmd_info(args) -> int:
    cmd_scan(args)
    print("\n" + "=" * 60 + "\n")
    cmd_entropy(args)
    print("\n" + "=" * 60 + "\n")
    cmd_secrets(args)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="fanalyzer",
        description="固件镜像分析：签名扫描 / 熵分析 / 字符串 / 敏感信息",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="扫描文件系统与压缩流签名")
    p.add_argument("file")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("entropy", help="分块熵分析（判断压缩/加密）")
    p.add_argument("file")
    p.add_argument("--block", type=int, default=4096, help="块大小，默认 4096")
    p.set_defaults(func=cmd_entropy)

    p = sub.add_parser("strings", help="提取可打印字符串")
    p.add_argument("file")
    p.add_argument("-n", "--number", type=int, default=6, help="最短长度，默认 6")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("secrets", help="扫描密钥、口令、内网地址等敏感信息")
    p.add_argument("file")
    p.set_defaults(func=cmd_secrets)

    p = sub.add_parser("extract", help="按签名切分并导出片段")
    p.add_argument("file")
    p.add_argument("-o", "--out", default="out", help="输出目录")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("info", help="一次跑完 scan + entropy + secrets")
    p.add_argument("file")
    p.add_argument("--block", type=int, default=4096)
    p.set_defaults(func=cmd_info)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
