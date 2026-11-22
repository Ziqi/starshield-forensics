# `starshield-forensics`（`v0.3.10` · 纯离线 LevelDB `.log` 与容器结构初筛工具包）

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16602/badge)](https://www.bestpractices.dev/projects/16602)
[![OpenSSF Scorecard](https://img.shields.io/endpoint?url=https%3A%2F%2Fziqi.github.io%2Fstarshield%2Fscorecard.json)](https://github.com/Ziqi/starshield-forensics/actions/workflows/scorecard.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/starshield-forensics/attestations)
[![PyPI](https://img.shields.io/pypi/v/starshield-forensics?label=PyPI%20%28PEP%20740%29&color=blue)](https://pypi.org/project/starshield-forensics/)

> **[English (`README.md`)](./README.md)** | **简体中文**

**面向数字取证与应急响应（DFIR）人员的纯离线、只读、零第三方运行依赖（Python >= 3.10 纯标准库）终端缓存与二进制容器初筛工具包：**
- **工程与分发：** PyPI [`starshield-forensics 0.3.10`](https://pypi.org/project/starshield-forensics/)（离线 `Ed25519` 签名 + PyPI PEP 740 发布证明）· Homebrew `brew install Ziqi/tap/starshield-forensics`（独立 `libexec` 公式）· 可重现 `starshield.pyz`（GitHub Actions 源码构建 + SLSA Build Level 3 [`/attestations`](https://github.com/Ziqi/starshield-forensics/attestations)）· Zenodo Concept DOI [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804)（当前解析至已归档的 `v0.3.7`）
- **在线文档门户：** [`https://ziqi.github.io/starshield/`](https://ziqi.github.io/starshield/)

---

## 核心定位与适用边界（`v0.3.10`）

1. **终端未压实 LevelDB `.log` 预写日志初筛（`precheck` & `parse-leveldb-log`）**：只读检测本地 Chromium 浏览器（`Chrome / Edge / Brave` Local Storage、既有 LevelDB 型 IndexedDB、浏览器扩展 `Local Extension Settings`）及 `Microsoft Teams / Slack / WhatsApp Web` 本地缓存的未压实 `.log` 帧，执行 32 KiB 物理块 Castagnoli `CRC32C`（多项式 `0x82F63B78`，LevelDB 掩码加数 `0xA282EAD8`）逐帧校验、坏帧隔离与 `WriteBatch` 逐操作序号还原，提取带字节偏移量的 JSON 记录。
2. **PNG / JPEG / PDF 容器结构观察（`inspect-image` & `inspect-pdf`）**：纯标准库解析 PNG `IHDR/IDAT/IEND` CRC32 与 `iCCP`（单块 `16 MiB` / 单文件累计 `32 MiB` 上限）、多段 JPEG `APP2 ICC_PROFILE` / `APP13 (8BIM)`，以及 ISO 32000 PDF 增量保存修订历史（跳过流跨度与字符串字面量的结构化 `%%EOF` / `xref` / `startxref`、`/FlateDecode` `/Type /ObjStm` 元数据与 `/JavaScript` `/Launch` 结构线索），强制附带操作系统重存、电子签章与表单填写等良性成因提示——**仅作容器结构观察，绝不构成图像篡改或文档伪造鉴定**。
3. **编码校验位语法核验与双模式脱敏（`starshield mcp` + `detokenize` + `shred-vault`）**：离线核验 `ISO/IEC 7812` 银行卡 `Luhn`、89 国 `ISO 13616 IBAN Mod-97`、250 地区 `ISO 9362 SWIFT/BIC`、美国 `ABA`、`ISO 11649 RF`、`ISO 17442 LEI`、`TRON TRC-20` Base58Check 及 `Ethereum EIP-55` 地址以排除 OCR 或抄录笔误。**校验位通过仅证明字符串符合数学编码格式，绝不代表存在欺诈，亦不证明任何交易实际发生。** `starshield mcp` 不是提示注入过滤器：其 `parse/triage` 工具默认扣留自由聊天正文并输出带会话指纹的代号（如 `<IBAN_GB_9F3A_01>`，**注意：结构化代号保留两位国家码，且明文保留数值金额如 `USD 9,500.00`、`€1.000,00`**；而 CLI 默认模式使用 `[REDACTED_HMAC:...]` 与 `[REDACTED_CONTENT]`）。还原命令 `detokenize` 与销毁命令 `shred-vault`（销毁前强制校验 `starshield-token-vault/v1` 头防误删检材）仅为本地 CLI 子命令，未注册为 `MCP` 工具。

---

## 四级认知确定性分层与存储格式边界

每条输出均携带机器可读的认知等级（`OBSERVED` 物理观测 / `DERIVED` 确定性推算 / `INFERRED` 待外部印证线索 / `UNKNOWN` 本地证据边界外未知），并严格声明以下 `v0.3.10` 格式边界：

| 目标检材与应用 | 底层存储格式 | `v0.3.10` 支持状态与边界 |
| :--- | :--- | :--- |
| **`Chrome / Edge / Brave` Local Storage、既有 LevelDB IndexedDB、浏览器扩展 `Local Extension Settings`、`Teams / Slack / WhatsApp Web` JSON 缓存** | LevelDB `.log` WAL（32 KiB `CRC32C`） | **原生支持（未压实 `.log`）**：通过 `precheck` 与 `parse-leveldb-log` 坏帧续扫提取 UTF-8 / UTF-16LE JSON 记录 |
| **已压实的 LevelDB `.ldb` SSTable 与外部 `.blob` 目录** | Snappy 压缩块（`0xdb4775248b80fb57`） / IndexedDB `.blob` | `precheck` 只要检出任意 `.ldb`/`.sst` 或 `.blob` 文件即输出 `PARTIAL` 或 `NO_GO_COMPACTED_OR_UNSUPPORTED`（绝不误判 `GO`）；`v0.3.10` **不解码** `.ldb` 数据块、**不跟随**外部 `.blob` 文件，亦**不解码**非 JSON 的 Blink `StructuredClone` 对象（请使用 `dfindexeddb` 或 `ccl_chromium_reader`） |
| **`Chrome 156+` 新建站点 IndexedDB、`VS Code / Cursor state.vscdb`、原生加密 `WhatsApp Desktop messages.db`、`Discord SimpleCache`** | SQLite B-Tree / SQLCipher / `SimpleCache` | **不在 LevelDB `.log` 解析范围内**（既有旧站点库仍留在 LevelDB，Chrome 156+ 新建库使用 SQLite，Electron 升级滞后于上游 Chromium；SQLite 库请使用 `sqlite3` 检查） |
| **本地会话代号金库与销毁（`--vault-file` / `shred-vault`）** | 同机 `0600` 明文映射 JSON | Python 标准库不含原生 AEAD，Linux 建议置于内存盘 `/dev/shm`，macOS 建议置于 `0700` 私有目录（如 `~/.starshield/vault.json`）；`shred-vault` 仅对验证通过的金库文件执行尽力而为双遍逻辑覆写与 `unlink`，在 SSD/NVMe 或 APFS/Btrfs/ZFS CoW 卷上不承诺物理块不可恢复擦除 |

---

## 快速体验与 `MCP` 挂载

```bash
# 免克隆零安装体验内置 100% 净室合成样本（零网络外联）：
uvx --from starshield-forensics starshield demo

# 或通过官方 PyPI / macOS & Linux Homebrew Tap 安装：
pip install starshield-forensics
# 或：brew install Ziqi/tap/starshield-forensics
starshield demo

# 克隆源码运行全部单元测试、模糊测试、基准与自检脚本（无需手动指定 PYTHONPATH）：
git clone https://github.com/Ziqi/starshield-forensics.git
cd starshield-forensics
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -W error tests/fuzz_parsers.py --stdlib --iterations 2500
PYTHONDONTWRITEBYTECODE=1 python3 benchmark/benchmark_suite.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_cross_tool_forensics.py
```

在 Claude Desktop / Cursor / Antigravity / Windsurf 中挂载 7 项只读确定性 `MCP` 工具（不传 `--vault-file` 时纯驻留内存；需跨会话还原时按平台配置）：

- **Linux（`tmpfs` 内存盘）：**
```json
{
  "mcpServers": {
    "starshield-forensics": {
      "command": "uvx",
      "args": ["--from", "starshield-forensics", "starshield", "--vault-file", "/dev/shm/starshield_vault.json", "mcp"]
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
      "args": ["--from", "starshield-forensics", "starshield", "--vault-file", "/Users/<you>/.starshield/vault.json", "mcp"]
    }
  }
}
```

完整英文规格说明、双模式脱敏示例、538 项向量验证脚本（[`scripts/verify_cross_tool_forensics.py`](./scripts/verify_cross_tool_forensics.py)）与签名验证步骤请参见 **[`README.md`](./README.md)**。
