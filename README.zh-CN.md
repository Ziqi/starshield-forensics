# `starshield-forensics`（`v0.4.1` · 纯离线 LevelDB `.log`/`.ldb`/`MANIFEST` 与容器结构初筛工具包）

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16602/badge)](https://www.bestpractices.dev/projects/16602)
[![OpenSSF Scorecard](https://img.shields.io/endpoint?url=https%3A%2F%2Fziqi.github.io%2Fstarshield%2Fscorecard.json)](https://github.com/Ziqi/starshield-forensics/actions/workflows/scorecard.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/starshield-forensics/attestations)
[![PyPI](https://img.shields.io/pypi/v/starshield-forensics?label=PyPI%20%28PEP%20740%29&color=blue)](https://pypi.org/project/starshield-forensics/)

> **[English (`README.md`)](./README.md)** | **简体中文**

**面向数字取证与应急响应（DFIR）人员的纯离线、只读、零第三方运行依赖（Python >= 3.10 纯标准库）终端缓存与二进制容器初筛工具包（`<= v0.4.x` 各版本均为独立自研开源工程基线）：**
- **工程与分发：** PyPI [`starshield-forensics 0.4.1`](https://pypi.org/project/starshield-forensics/)（GitHub Actions 源码可重现构建 + 离线 `Ed25519` 双重校验 + PyPI PEP 740 发布证明）· Homebrew `brew install Ziqi/tap/starshield-forensics`（独立 `libexec` 公式）· 可重现 `starshield.pyz` / `wheel` / `sdist`（SLSA Build Level 3 [`/attestations`](https://github.com/Ziqi/starshield-forensics/attestations)）· Zenodo Concept DOI [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804)（当前解析至已归档的 `v0.3.7`）
- **在线文档门户：** [`https://ziqi.github.io/starshield/`](https://ziqi.github.io/starshield/)

---

## 核心定位与适用边界（`v0.4.1`）

1. **终端 LevelDB `.log` 预写日志、纯标准库 Snappy `.ldb` SSTable 与 `MANIFEST` 墓碑融合（`precheck`、`parse-leveldb-log` & `parse-leveldb-store`）**：只读检测本地 Chromium 浏览器（`Chrome / Edge / Brave` Local Storage、既有 LevelDB 型 IndexedDB、浏览器扩展 `Local Extension Settings`）及 `Microsoft Teams / Slack / WhatsApp Web` 本地缓存，支持 32 KiB `.log` 帧与纯标准库 Snappy（`0x01`）/ 未压缩（`0x00`）`.ldb` 数据块的 Castagnoli `CRC32C`（多项式 `0x82F63B78`，LevelDB 掩码加数 `0xA282EAD8`）逐块校验、坏块隔离、多记录 `MANIFEST-*` `VersionEdit` 状态机重放及 `0x00` 物理删除墓碑对比，精确区分 `LIVE_ACTIVE`（现存记录）、`UI_SOFT_DELETED`（应用层软删除）、`LIVENESS_INDETERMINATE`（由于活跃区截断或 `MANIFEST` 损坏导致存活态待定）与 `TOMBSTONED_HISTORICAL_RECOVERED`（已被墓碑或覆写取代但从底层块成功寻回的历史记录）。
2. **PNG / JPEG / PDF 容器结构观察（`inspect-image` & `inspect-pdf`）**：纯标准库解析 PNG `IHDR/IDAT/IEND` CRC32 与 `iCCP`（单块 `16 MiB` / 单文件累计 `32 MiB` 上限）、多段 JPEG `APP2 ICC_PROFILE` / `APP13 (8BIM)`，以及 ISO 32000 PDF 增量保存修订历史（跳过流跨度、字符串字面量及 `obj..endobj`/`<<..>>`/`[..]` 嵌套内部伪标记的结构化 `%%EOF` / `xref` / `startxref`、`/FlateDecode` `/Type /ObjStm` 元数据与 `/JavaScript` `/Launch` 结构线索），强制附带操作系统重存、电子签章与表单填写等良性成因提示——**仅作容器结构观察，绝不构成图像篡改或文档伪造鉴定**。
3. **编码校验位语法核验与双模式脱敏（`starshield mcp` + `detokenize` + `shred-vault`）**：离线核验 `ISO/IEC 7812` 银行卡 `Luhn`、89 国 `ISO 13616 IBAN Mod-97`、250 地区 `ISO 9362 SWIFT/BIC`、美国 `ABA`、`ISO 11649 RF`、`ISO 17442 LEI`、`TRON TRC-20` Base58Check 及 `Ethereum EIP-55` 地址以排除 OCR 或抄录笔误。**校验位通过仅证明字符串符合数学编码格式，绝不代表存在欺诈，亦不证明任何交易实际发生。** `starshield mcp` 不是提示注入过滤器：其 `parse/triage` 工具默认扣留自由聊天正文并输出带 8 位十六进制会话指纹的代号（如 `<IBAN_GB_9F3AC41D_01>`，还原时向后兼容 4–8 位标签；单类别超 `10,000` 条退化为不可逆单向 `_OVR_` 溢出标记；**注意：结构化代号保留两位国家码，且明文保留数值金额如 `USD 9,500.00`、`€1.000,00`**；而 CLI 默认模式使用 `[REDACTED_HMAC:...]` 与 `[REDACTED_CONTENT]`）。还原命令 `detokenize` 与销毁命令 `shred-vault`（销毁前强制校验 `starshield-token-vault/v1` 头防误删检材）仅为本地 CLI 子命令，未注册为 `MCP` 工具。

---

## 四级认知确定性分层与存储格式边界

每条输出均携带机器可读的认知等级（`OBSERVED` 物理观测 / `DERIVED` 确定性推算 / `INFERRED` 待外部印证线索 / `UNKNOWN` 本地证据边界外未知），并严格声明以下 `v0.4.1` 格式边界：

| 目标检材与应用 | 底层存储格式 | `v0.4.1` 支持状态与边界 |
| :--- | :--- | :--- |
| **`Chrome / Edge / Brave` Local Storage、既有 LevelDB IndexedDB、浏览器扩展 `Local Extension Settings`、`Teams / Slack / WhatsApp Web` JSON 与 KV 缓存** | LevelDB `.log` WAL + Snappy `.ldb` SSTable + `MANIFEST-*` | **原生支持（`.log` + Snappy `.ldb` + `MANIFEST`）**：通过 `precheck`、`parse-leveldb-log` 与 `parse-leveldb-store` 实现坏块隔离、孤儿表识别、UTF-8 / 奇偶偏移 UTF-16LE JSON 与 LocalStorage KV 文本提取及墓碑历史对账 |
| **Zstandard (`0x02`) 压缩块、纯二进制 Blink V8 `StructuredClone` 与外部 `.blob` 目录** | Zstd 压缩块 / V8 二进制 AST (`0xFF`) / IndexedDB `.blob` | 诚实统计 `zstd_unsupported_blocks_count`、`blink_v8_non_json_values_skipped` 与 `external_blob_warning`；`v0.4.1` **不解压** `0x02` Zstd 块、**不重组**外部 `.blob` 大对象，亦**不反序列化**非 JSON 的纯二进制 V8 对象 |
| **`Chrome 156+` 新建站点 IndexedDB、`VS Code / Cursor state.vscdb`、原生加密 `WhatsApp Desktop messages.db`、`Discord SimpleCache`** | SQLite B-Tree / SQLCipher / `SimpleCache` | **不在 LevelDB 解析范围内**（`precheck` 支持 16 字节 `SQLite format 3\x00` 魔数无后缀文件分流识别；既有旧站点库仍留在 LevelDB，Chrome 156+ 新建库使用 SQLite，请使用 `sqlite3` 检查） |
| **本地会话代号金库与销毁（`--vault-file` / `shred-vault`）** | 同机 `0600` 明文映射 JSON | Python 标准库不含原生 AEAD，Linux 建议置于内存盘 `/dev/shm`，macOS 建议置于 `0700` 私有目录（如 `~/.starshield/vault.json`）；`shred-vault` 仅对验证通过的金库文件执行尽力而为双遍逻辑覆写与 `unlink`，在 SSD/NVMe 或 APFS/Btrfs/ZFS CoW 卷上不承诺底层闪存块不可恢复擦除 |

---

## 快速体验与 `MCP` 挂载

```bash
# 免克隆零安装体验内置 100% 净室合成样本（零网络外联）：
uvx --from starshield-forensics starshield demo

# 或通过官方 PyPI / macOS & Linux Homebrew Tap 安装：
pip install starshield-forensics
# 或：brew install Ziqi/tap/starshield-forensics
starshield demo

# 克隆源码实测内置 < 16 KB 损坏 LevelDB 靶场样本与全部测试套件（详见 examples/README.md）：
git clone https://github.com/Ziqi/starshield-forensics.git
cd starshield-forensics
python3 -m starshield precheck examples/corrupted_leveldb_challenge
python3 -m starshield parse-leveldb-store examples/corrupted_leveldb_challenge
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -W error tests/fuzz_parsers.py --stdlib --iterations 3000
PYTHONDONTWRITEBYTECODE=1 python3 benchmark/benchmark_suite.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_cross_tool_forensics.py
```

在 Claude Desktop / Cursor / Antigravity / Windsurf 中挂载 8 项只读确定性 `MCP` 工具（不传 `--vault-file` 时纯驻留内存；需跨会话还原时按平台配置）：

- **Linux（`tmpfs` 内存盘）：**
```json
{
  "mcpServers": {
    "starshield-forensics": {
      "command": "uvx",
      "args": ["--from", "starshield-forensics==0.4.1", "starshield", "--vault-file", "/dev/shm/starshield_vault.json", "mcp"]
    }
  }
}
```

- **macOS（`0700` 私有用户目录，macOS 无 `/dev/shm`）：**
```json
{
  "mcpServers": {
    "starshield-forensics": {
      "command": "uvx",
      "args": ["--from", "starshield-forensics==0.4.1", "starshield", "--vault-file", "/Users/<you>/.starshield/vault.json", "mcp"]
    }
  }
}
```

完整英文规格说明、双模式脱敏示例、损坏靶场指南（[`examples/README.md`](./examples/README.md)）、611 项向量验证脚本（[`scripts/verify_cross_tool_forensics.py`](./scripts/verify_cross_tool_forensics.py)，含 13 项外部工具差分对比 + 598 项规范与校验位核验）与签名验证步骤请参见 **[`README.md`](./README.md)**。
