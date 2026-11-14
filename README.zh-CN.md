# `starshield-forensics`（`v0.3.8` · 纯离线确定性电子数据取证、截图容器核验与 `MCP` 工具包）

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16602/badge)](https://www.bestpractices.dev/projects/16602)
[![OpenSSF Scorecard](https://img.shields.io/endpoint?url=https%3A%2F%2Fziqi.github.io%2Fstarshield%2Fscorecard.json)](https://github.com/Ziqi/starshield-forensics/actions/workflows/scorecard.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/starshield-forensics/attestations)
[![OSPS Baseline](https://img.shields.io/badge/OpenSSF%20OSPS%20Baseline-Level%203%20%28EU%20CRA%20Aligned%29-brightgreen)](./SECURITY.md#5-openssf-osps-baseline-level-3--eu-cyber-resilience-act-cra-alignment)
[![UK FSR Statutory Code / ISO 17025 Validation](https://img.shields.io/badge/Validation-UK%20FSR%20%28FSA--DIG--100%29%20%26%20ISO%2017025%20Aligned-blue)](./VALIDATION_REPORT_FSR_ISO17025.md)
[![PyPI](https://img.shields.io/pypi/v/starshield-forensics?label=PyPI%20%28PEP%20740%29&color=blue)](https://pypi.org/project/starshield-forensics/0.3.8/)

> **[English (`README.md`)](./README.md)** | **简体中文**

**面向金融风控审计、全栈开发者排障、司法取证官与跨境合规团队的纯离线、只读、零第三方运行依赖（Python >= 3.10 纯标准库）二进制检验与电子证据初筛库（原生覆盖 `Chrome / Edge / Brave` 浏览器及 `VS Code / Microsoft Teams / Slack / WhatsApp Desktop / Discord` 等 Electron 桌面端，内置隐私脱敏 `starshield mcp` 服务端）：**
- **获颁 Linux 基金会 OpenSSF Best Practices `Silver` 银牌认证（[`#16602` · 226%](https://www.bestpractices.dev/projects/16602)）并对齐 [`OpenSSF OSPS Baseline Level 3 / 欧盟 CRA`](./SECURITY.md#5-openssf-osps-baseline-level-3--eu-cyber-resilience-act-cra-alignment)**
- **供应链安全评分与持续模糊测试：** **OpenSSF Scorecard [`8.0 / 10`](https://github.com/Ziqi/starshield-forensics/actions/workflows/scorecard.yml)**（含 `ClusterFuzzLite / Atheris` 持续模糊测试 **`Fuzzing: 10 / 10` 满分**，共 `11` 项核心指标满分）+ **SLSA Build Level 3** 构建溯源证明（[`/attestations`](https://github.com/Ziqi/starshield-forensics/attestations)）
- **PyPI 官方受信发布（PEP 740 数字证明）：** [`pip install starshield-forensics`](https://pypi.org/project/starshield-forensics/0.3.8/)
- **学术永久 DOI 与 UNESCO 源码存证：** Zenodo [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804)（`v0.3.7`：[`10.5281/zenodo.24156262`](https://doi.org/10.5281/zenodo.24156262)）· Software Heritage [`swh:1:snp:4ed5efecab5e40975e75a5c5107b63121b1df60a`](https://archive.softwareheritage.org/swh:1:snp:4ed5efecab5e40975e75a5c5107b63121b1df60a;origin=https://github.com/Ziqi/starshield-forensics)
- **双工具方法学验证：** 对齐英国法医科学监管机构现行法定守则 **UK FSR Statutory Code (`FSA – DIG 100`，承接并替代原 `FSR-C-107`) & ISO/IEC 17025** 验证框架（见 [`VALIDATION_REPORT_FSR_ISO17025.md`](./VALIDATION_REPORT_FSR_ISO17025.md)）
- **在线文档与净室合成基准底稿门户：** [`https://ziqi.github.io/starshield/`](https://ziqi.github.io/starshield/)

---

## 三大高频使用场景

1. **金融风控、电商售后与财务报销截图毫秒级初筛（`starshield inspect-image`）**：离线核验付款回单、转账截图与争议附件的 PNG `IHDR/IDAT/IEND/iCCP` CRC32 完整性、JPEG `APP2 ICC_PROFILE` 色彩配置头与 Photoshop `APP13 (8BIM)` 编辑资源段，并同步离线校验银行卡 `Luhn`、全球 89 国 `IBAN Mod-97` 与 `SWIFT/BIC` 校验位。
2. **开发者本地损坏 Electron（`VS Code / Slack / Teams / Discord`）与 Chrome 缓存离线诊断恢复（`starshield precheck` & `parse-leveldb-log`）**：只读校验本地 IndexedDB / LevelDB `.log` 预写日志的掩码 Castagnoli `CRC32C`（`0xA282EAD8`）物理帧并恢复未压缩 JSON 记录，秒级判断底层 Compaction 状态。
3. **涉外争议解决与司法电子取证诉前初筛（`UK FSR FSA – DIG 100 / ISO 17025` 对齐）**：按字节偏移量重组网页端/桌面端撤回（Soft-Delete）与篡改记录，严格遵循四级认知确定性边界并默认启用单次随机密钥 `HMAC-SHA256` 脱敏。

---

## 四级认知确定性分层（Epistemic Tiers）

为杜绝将原始字节与主观推论混为一谈，`starshield-forensics` 的每一条输出均携带机器可读的认知边界标签：

1. **`OBSERVED`（物理观测层）**：直接存在于原始输入字节、块头或 JSON 字段中的物理记录（精确绑定 WAL 帧偏移量或容器 Chunk 偏移量）。
2. **`DERIVED`（确定性推算层）**：由标准确定性算法直接计算得出（Castagnoli `CRC32C`、ISO/IEC 7812 `Luhn`、ISO 13616 `IBAN Mod-97`、UTC 时间差运算）。
3. **`INFERRED`（待印证线索层）**：需结合外部独立证据（如银行服务端流水或运营商协查记录）交叉印证的初筛线索，绝不单独作为定案结论。
4. **`UNKNOWN`（边界外未知层）**：明确标注超出本地客户端存储证据边界的事项（如采集前已被 LevelDB Compaction 物理覆写的记录）。

---

## 核心能力模块（`v0.3.8`）

| 模块 | 核心工程能力 | 严格方法学边界 |
| :--- | :--- | :--- |
| **`starshield precheck`（零明文可行性门禁）** | 离线扫描 Chromium 浏览器与 Electron 桌面端 IndexedDB / Local Storage 目录或 `.log`/`.ldb` 文件，校验 SSTable Footer Magic（`0xdb4775248b80fb57`）与 Blink `0xFF` 头，输出 `GO` / `PARTIAL` / `NO_GO` 评估清单且不泄露任何正文内容。 | 仅用于取证前 Compaction 状态初筛，不解压 `.ldb` Snappy 数据块。 |
| **`leveldb_log.py`（LevelDB `.log` 物理帧重组）** | 解析 32 KiB 物理块、校验掩码 Castagnoli `CRC32C`（`0xA282EAD8`）、重组跨块 `FULL/FIRST/MIDDLE/LAST` WriteBatch 帧，提取 Chromium 浏览器及 Electron 桌面端（`VS Code`、Microsoft Teams/Skype `chatsvc`、Slack、WhatsApp Web/Desktop、Discord 等）的 UTF-8 / UTF-16LE JSON 记录。 | 不虚构已被底层垃圾回收物理清除的历史块。 |
| **`ioc_validators.py`（多法域金融校验位核验）** | 支持银行卡 ISO/IEC 7812 `Luhn`、全球 89 国 SWIFT IBAN 长度与 `Mod-97`、250 个 ISO 3166-1 国家码 `SWIFT/BIC` 校验及 120 字符窗口内英国 `Sort Code` 配对识别。 | 纯数学格式与校验位核验，不联网查询账户实名状态。 |
| **`image_containers.py`（PNG / JPEG 容器结构检验）** | 逐块核验 PNG `IHDR/IDAT/IEND` CRC32 与 `iCCP` 色彩配置，重组多段 JPEG `APP2 ICC_PROFILE` 与 `APP13 (8BIM)`。 | 客观输出容器结构特征与操作系统截图/转存免责说明，绝不武断宣称“伪造铁证”。 |
| **`starshield mcp`（零依赖 AI Agent `MCP` 服务端）** | 通过纯标准库 JSON-RPC 2.0 `stdio` 向 Claude Desktop、Cursor、Google Antigravity、Windsurf 暴露 4 项只读确定性工具（`starshield_demo`、`starshield_precheck_leveldb`、`starshield_inspect_image_tamper`、`starshield_validate_financial_iocs`）。 | 默认强制开启会话级 `HMAC-SHA256` 脱敏，确保原始敏感信息、文件名与文件哈希绝不进入云端大模型上下文。 |
| **默认 HMAC 脱敏模式（`cli.py`）** | 默认启用单次运行随机密钥 `HMAC-SHA256`（可选 `sha384` / `blake2b`）隐去文件名、原始哈希与精确日期，防止屏幕共享或日志外泄。 | 如在授权离线取证工作站需完整哈希，显式传入 `--unredacted`。 |

---

## 10 秒零安装体验与 AI Agent（`MCP`）一键挂载

```bash
# 免克隆免建虚拟环境单行体验内置 100% 净室合成样本（零网络外联）：
uvx --from starshield-forensics starshield demo

# 或通过官方 PyPI（带 PEP 740 数字证明）与 macOS/Linux Homebrew Tap 安装：
pip install starshield-forensics
# 或：brew install Ziqi/tap/starshield-forensics
starshield demo

# 对本地目录执行零明文取证可行性预检
starshield precheck /path/to/IndexedDB_folder
```

在 Claude Desktop / Cursor / Antigravity / Windsurf 中直接粘贴以下 5 行配置即可挂载只读确定性核验工具（默认自动 `HMAC-SHA256` 脱敏）：

```json
{
  "mcpServers": {
    "starshield-forensics": {
      "command": "uvx",
      "args": ["--from", "starshield-forensics", "starshield", "mcp"]
    }
  }
}
```

### 真实确定性输出示例（`starshield demo` 默认 HMAC 脱敏模式）

```json
{
  "epistemic_tier": "OBSERVED",
  "schema_detected": "chatsvc",
  "leveldb_batch_byte_offset": 397,
  "leveldb_sequence_number": 1002,
  "is_soft_deleted_in_ui": true,
  "sender_mri": "[REDACTED_HMAC:1b71a34908e1]",
  "cached_content": "[REDACTED_CONTENT — pass --unredacted to view]",
  "extracted_iocs": {
    "luhn_validated_cards": ["[REDACTED_HMAC:3ec5f5677098]"],
    "mod97_validated_ibans": ["[REDACTED_HMAC:4dad6b1cc0be]", "[REDACTED_HMAC:f21864d3e75c]"]
  }
}
```

### 供应链、模糊测试与永久归档核验矩阵

| 核验与归档维度 | 实时状态与永久存证锚点 |
| :--- | :--- |
| **持续模糊测试（`ClusterFuzzLite / Atheris`）** | [![Fuzzing: 10/10](https://img.shields.io/badge/Scorecard%20Fuzzing-10%2F10%20%28ClusterFuzzLite%29-brightgreen)](https://github.com/Ziqi/starshield-forensics/actions/workflows/cflite.yml) [![Continuous Fuzzing](https://github.com/Ziqi/starshield-forensics/actions/workflows/cflite.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/actions/workflows/cflite.yml) |
| **静态安全扫描（`CodeQL SAST`）与确定性 CI** | [![CodeQL SAST](https://github.com/Ziqi/starshield-forensics/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/actions/workflows/codeql.yml) [![StarShield Deterministic CI](https://github.com/Ziqi/starshield-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/actions/workflows/ci.yml) |
| **构建溯源证明与机器可读版权（`REUSE 3.3`）** | [![Supply-Chain Attestations](https://github.com/Ziqi/starshield-forensics/actions/workflows/attestations.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/attestations) [![REUSE status](https://img.shields.io/badge/REUSE-3.3%20compliant-brightgreen)](./REUSE.toml) |
| **包分发（`Homebrew Tap`）与学术 / UNESCO 源码归档** | [![Homebrew Tap](https://img.shields.io/badge/Homebrew-Ziqi%2Ftap-FBB040.svg?logo=homebrew&logoColor=white)](https://github.com/Ziqi/homebrew-tap) [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24145804.svg)](https://doi.org/10.5281/zenodo.24145804) [![SWHID](https://img.shields.io/badge/SWHID-swh%3A1%3Asnp%3A4ed5efec-e20026)](https://archive.softwareheritage.org/swh:1:snp:4ed5efecab5e40975e75a5c5107b63121b1df60a;origin=https://github.com/Ziqi/starshield-forensics) |

完整英文规格说明、对抗测试集（`StarShield-Bench-24`）与供应链签名验证指南请参见 **[`README.md`](./README.md)**。
