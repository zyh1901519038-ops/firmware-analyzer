# fanalyzer

[![tests](https://github.com/zyh1901519038-ops/firmware-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/zyh1901519038-ops/firmware-analyzer/actions/workflows/tests.yml)

一个固件镜像分析的小工具，纯 Python 标准库，不装任何依赖。

能做的事：在固件里找出文件系统和压缩流的位置、按块算熵判断哪段被压缩或加密、提取字符串、扫硬编码的口令和密钥。

## 功能

- `scan` 扫签名，认 20 种左右：SquashFS、CramFS、UBIFS、RomFS、CPIO、GZIP、XZ、ZSTD、LZ4、LZMA、ZIP、ELF、DTB、Android boot、uImage、PEM
- `entropy` 分块算香农熵，画条形图，末尾给一句结论
- `strings` 提取 ASCII 和 UTF-16LE 字符串（中文也能出来）
- `secrets` 扫私钥、AWS Key、硬编码口令、Token、URL、邮箱、IPv4、内网地址，按高/中/低分级
- `extract` 按签名位置切子镜像，方便再拿别的工具分析
- `info` 把 scan/entropy/secrets 一起跑

## 用法

```bash
python fanalyzer.py info firmware.bin
```

跑一个测试镜像（uImage 头 + gzip + 随机块 + 明文口令）的输出：

```
识别到 2 处签名：

  0x00000000  bootloader   U-Boot Legacy uImage
  0x00000040  compression  GZIP

============================================================

文件：firmware.bin   块大小：4096 字节   共 4 块

0x00000000   7.98  [########################################]  压缩/加密
0x00001000   0.69  [###.....................................]  空洞/填充
0x00002000   0.00  [........................................]  空洞/填充
0x00003000   0.00  [........................................]  空洞/填充

平均熵：2.17 bit/byte
结论：存在明显的非压缩区域 —— 可能能直接提取到文件系统。

============================================================

[high  ] 0x00001075  硬编码口令          password="admin123
[high  ] 0x000010CF  AWS Access Key     AKIAABCDEFGHIJKLMNOP
[medium] 0x00001097  内网地址            192.168.10.20
[low   ] 0x000010AA  HTTP 地址           https://ota.example.com/api/v1/check
```

## 测试

```bash
python test_fanalyzer.py
```

21 个用例。测试不依赖真实固件，自己拼一个：uImage 头 + gzip 数据 + 高熵随机块 + 明文口令 + 0xFF 填充，然后验证识别、熵值、字符串、敏感信息、切片，以及每个子命令能不能跑。

## 实现上几个点

**签名扫描没有按签名逐个扫全文件**。那样是 O(签名数 × 文件大小)，几百 MB 的固件会很慢。这里先按 magic 的首字节建索引，遍历一次文件，每个位置只比对首字节相同的少数几个签名。

**ext2/3/4 靠 0x438 判断**。它的 superblock 在偏移 0x438 而不是文件开头，magic 是 0x53EF。固件开头通常是引导代码，没有任何特征，所以只看头部会漏掉 ext。这个偏移量是从 ext2 的磁盘结构里查的。

**熵用来区分压缩和填充**。香农熵单位 bit/byte，8 表示完全随机，0 表示单一字节。实际用的时候大概是：

| 熵 | 大概是什么 |
|---|---|
| 7.5 以上 | 压缩过或加密了 |
| 6 到 7.5 | 疑似压缩数据 |
| 3 到 6 | 混合内容 |
| 接近 0 | 0x00 或 0xFF 填充，flash 没用到的区域 |

一条命令就能看出固件有没有加密、根文件系统在哪一段。

## 踩过的坑

写的时候测试挂过两次，两次都是改代码而不是改测试。

**UTF-16 一开始只认 ASCII**。原始实现判断的是「可打印 ASCII 后面跟 \x00」，中文串比如 `固件版本`，每个字节能取到大于 0x7F，条件不成立，一个都提不出来。后来改成按 2 字节码元解码再判断 printable，中文就正常了。

## 目录

```
fanalyzer.py        主体：签名表、扫描、熵、字符串、敏感信息、CLI
test_fanalyzer.py   测试，自带镜像合成
```

## 许可

MIT
