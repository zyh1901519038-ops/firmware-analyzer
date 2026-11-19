#!/usr/bin/env python3
"""fanalyzer 自检：不依赖外部样本，自己合成一个假固件来验证各功能。

运行：python test_fanalyzer.py
"""
from __future__ import annotations

import gzip
import struct
import tempfile
import unittest
from pathlib import Path

import fanalyzer as fa


def build_fake_firmware() -> bytes:
    """拼一个包含多种特征的假固件：
    U-Boot 头 -> gzip 压缩的根文件系统 -> 随机数据(高熵) -> 明文口令/URL -> 填充(低熵)
    """
    parts: list[bytes] = []

    # 1) U-Boot legacy uImage 头（64 字节，magic 0x27051956 大端）
    header = struct.pack(">IIIIIII", 0x27051956, 0, 0, 0x1A2B3C4D, 0, 0, 0)
    header += b"\x00" * (64 - len(header))
    parts.append(header)

    # 2) gzip 数据
    parts.append(gzip.compress(b"/etc/init.d/rcS\0/bin/busybox\0" * 8))

    # 3) 高熵随机数据（模拟加密/压缩区）
    parts.append(bytes((i * 73 + 151) % 256 for i in range(4096)))

    # 4) 明文敏感信息
    parts.append(b'\npassword="admin123"\n')
    parts.append(b"broker=mqtt://192.168.10.20:1883\n")
    parts.append(b"https://ota.example.com/api/v1/check\n")
    parts.append(b"AKIAABCDEFGHIJKLMNOP\n")

    # 5) 低熵填充（模拟未使用的 flash 空洞）
    parts.append(b"\xff" * 8192)

    return b"".join(parts)


class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.data = build_fake_firmware()
        self.hits = fa.scan_signatures(self.data)

    def test_detects_uimage(self):
        names = [h.name for h in self.hits]
        self.assertTrue(any("uImage" in n for n in names), names)

    def test_detects_gzip(self):
        names = [h.name for h in self.hits]
        self.assertIn("GZIP", names)

    def test_offsets_ascending(self):
        offsets = [h.offset for h in self.hits]
        self.assertEqual(offsets, sorted(offsets))

    def test_empty_input(self):
        self.assertEqual(fa.scan_signatures(b""), [])


class TestEntropy(unittest.TestCase):
    def test_all_zero_is_zero(self):
        self.assertLess(fa.shannon_entropy(b"\x00" * 4096), 0.01)

    def test_all_ff_is_zero(self):
        self.assertLess(fa.shannon_entropy(b"\xff" * 4096), 0.01)

    def test_sequence_high(self):
        data = bytes(range(256)) * 16   # 256 个符号均匀出现 → 熵 = 8
        self.assertAlmostEqual(fa.shannon_entropy(data), 8.0, places=3)

    def test_two_symbols_is_one_bit(self):
        data = b"\x00\x01" * 2048
        self.assertAlmostEqual(fa.shannon_entropy(data), 1.0, places=3)

    def test_profile_block_count(self):
        for n in (fa.entropy_profile(b"A" * 10000, block_size=4096),
                  fa.entropy_profile(b"A" * 10000, block_size=4096, max_blocks=2)):
            self.assertTrue(n)
        blocks = fa.entropy_profile(b"A" * 10000, block_size=4096)
        self.assertEqual(len(blocks), 3)          # 10000 / 4096 → 3 块
        self.assertTrue(all(b.entropy < 0.01 for b in blocks))

    def test_tag_high_entropy(self):
        data = bytes((i * 73 + 151) % 256 for i in range(4096))
        b = fa.entropy_profile(data, block_size=4096)[0]
        self.assertGreater(b.entropy, 7.5)
        self.assertEqual(b.tag, "压缩/加密")


class TestStrings(unittest.TestCase):
    def test_finds_ascii(self):
        text = [t for _, _, t in fa.extract_strings(build_fake_firmware(), min_len=6)]
        joined = "\n".join(text)
        self.assertIn("password=\"admin123\"", joined)
        self.assertIn("ota.example.com", joined)

    def test_min_length_respected(self):
        data = b"\x00abc\x00abcde\x00abcdefgh\x00"
        texts = [t for _, _, t in fa.extract_strings(data, min_len=5, utf16=False)]
        self.assertEqual(texts, ["abcde", "abcdefgh"])

    def test_utf16_detected(self):
        data = "固件版本".encode("utf-16le") + b"\x00" * 4
        encs = [e for _, e, _ in fa.extract_strings(data, min_len=2)]
        self.assertIn("utf16le", encs)


class TestSecrets(unittest.TestCase):
    def setUp(self):
        self.found = fa.scan_secrets(build_fake_firmware())

    def test_finds_password(self):
        self.assertTrue(any(s.rule == "硬编码口令" for s in self.found))

    def test_finds_aws_key(self):
        self.assertTrue(any(s.rule == "AWS Access Key" for s in self.found))

    def test_finds_intranet_ip(self):
        self.assertTrue(any(s.rule == "内网地址" for s in self.found))

    def test_levels_valid(self):
        for s in self.found:
            self.assertIn(s.level, ("high", "medium", "low"))

    def test_no_duplicate_rule_value_pairs(self):
        keys = [(s.rule, s.value) for s in self.found]
        self.assertEqual(len(keys), len(set(keys)))


class TestExtract(unittest.TestCase):
    def test_writes_segments(self):
        data = build_fake_firmware()
        hits = fa.scan_signatures(data)
        with tempfile.TemporaryDirectory() as td:
            written = fa.extract_segments(data, hits, Path(td))
            self.assertTrue(written)
            for w in written:
                self.assertTrue(w.is_file())
                self.assertGreater(w.stat().st_size, 0)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        self.tmp.write(build_fake_firmware())
        self.tmp.close()

    def tearDown(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_scan_runs(self):
        self.assertEqual(fa.main(["scan", self.tmp.name]), 0)

    def test_all_subcommands_run(self):
        for argv in (
            ["entropy", self.tmp.name, "--block", "1024"],
            ["strings", self.tmp.name, "-n", "8"],
            ["secrets", self.tmp.name],
            ["info", self.tmp.name],
        ):
            self.assertEqual(fa.main(argv), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
