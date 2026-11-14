# `starshield-forensics`（`v0.3.7` · 纯离线确定性电子数据取证与证据初筛工具包）

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16602/badge)](https://www.bestpractices.dev/projects/16602)
[![OpenSSF Scorecard](https://img.shields.io/endpoint?url=https%3A%2F%2Fziqi.github.io%2Fstarshield%2Fscorecard.json)](https://github.com/Ziqi/starshield-forensics/actions/workflows/scorecard.yml)
[![PyPI](https://img.shields.io/pypi/v/starshield-forensics?label=PyPI%20%28PEP%20740%29&color=blue)](https://pypi.org/project/starshield-forensics/0.3.7/)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/starshield-forensics/attestations)
[![REUSE status](https://img.shields.io/badge/REUSE-3.3%20compliant-brightgreen)](./REUSE.toml)
[![FSR / ISO 17025 Validation](https://img.shields.io/badge/Validation-FSR--C--107%20%2F%20ISO%2017025%20Aligned-blue)](./VALIDATION_REPORT_FSR_ISO17025.md)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24145804.svg)](https://doi.org/10.5281/zenodo.24145804)

> **[English (`README.md`)](./README.md)** | **简体中文**

**面向司法取证官、蓝队应急响应与跨境合规团队的纯离线、只读、零第三方运行依赖（Python >= 3.10 纯标准库）电子证据初筛库：**
- **获颁 Linux 基金会 OpenSSF Best Practices `Silver` 银牌认证（[`#16602` · 226%](https://www.bestpractices.dev/projects/16602)）**
- **PyPI 官方受信发布（PEP 740 数字证明）：** [`pip install starshield-forensics`](https://pypi.org/project/starshield-forensics/0.3.7/)
- **学术永久 DOI（Zenodo）：** [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804)
- **双工具方法学验证：** 对齐英国取证科学监管机构 **FSR-C-107 / ISO/IEC 17025** 验证框架（见 [`VALIDATION_REPORT_FSR_ISO17025.md`](./VALIDATION_REPORT_FSR_ISO17025.md)）
- **在线文档与脱敏底稿门户：** [`https://ziqi.github.io/starshield/`](https://ziqi.github.io/starshield/)

---

## 四级认知确定性分层（Epistemic Tiers）

为杜绝将原始字节与主观推论混为一谈，`starshield-forensics` 的每一条输出均携带机器可读的认知边界标签：

1. **`OBSERVED`（物理观测层）**：直接存在于原始输入字节、块头或 JSON 字段中的物理记录（精确绑定 WAL 帧偏移量或容器 Chunk 偏移量）。
2. **`DERIVED`（确定性推算层）**：由标准确定性算法直接计算得出（Castagnoli `CRC32C`、ISO/IEC 7812 `Luhn`、ISO 13616 `IBAN Mod-97`、UTC 时间差运算）。
3. **`INFERRED`（待印证线索层）**：需结合外部独立证据（如银行服务端流水或运营商协查记录）交叉印证的初筛线索，绝不单独作为定案结论。
4. **`UNKNOWN`（边界外未知层）**：明确标注超出本地客户端存储证据边界的事项（如采集前已被 LevelDB Compaction 物理覆写的记录）。

---

## 核心能力模块（`v0.3.7`）

| 模块 | 核心工程能力 | 严格方法学边界 |
| :--- | :--- | :--- |
| **`starshield precheck`（零明文可行性门禁）** | 离线扫描 Chromium IndexedDB / Local Storage 目录或 `.log`/`.ldb` 文件，校验 SSTable Footer Magic（`0xdb4775248b80fb57`）与 Blink `0xFF` 头，输出 `GO` / `PARTIAL` / `NO_GO` 评估清单且不泄露任何正文内容。 | 仅用于取证前 Compaction 状态初筛，不解压 `.ldb` Snappy 数据块。 |
| **`leveldb_log.py`（LevelDB `.log` 物理帧重组）** | 解析 32 KiB 物理块、校验掩码 Castagnoli `CRC32C`（`0xA282EAD8`）、重组跨块 `FULL/FIRST/MIDDLE/LAST` WriteBatch 帧，提取 Teams/Skype `chatsvc`、Slack、WhatsApp Web 等 UTF-8 / UTF-16LE JSON 记录。 | 不虚构已被底层垃圾回收物理清除的历史块。 |
| **`ioc_validators.py`（多法域金融校验位核验）** | 支持银行卡 ISO/IEC 7812 `Luhn`、全球 89 国 SWIFT IBAN 长度与 `Mod-97`、250 个 ISO 3166-1 国家码 `SWIFT/BIC` 校验及 120 字符窗口内英国 `Sort Code` 配对识别。 | 纯数学格式与校验位核验，不联网查询账户实名状态。 |
| **`image_containers.py`（PNG / JPEG 容器结构检验）** | 逐块核验 PNG `IHDR/IDAT/IEND` CRC32 与 `iCCP` 色彩配置，重组多段 JPEG `APP2 ICC_PROFILE` 与 `APP13 (8BIM)`。 | 客观输出容器结构特征与操作系统截图/转存免责说明，绝不武断宣称“伪造铁证”。 |
| **默认 HMAC 脱敏模式（`cli.py`）** | 默认启用单次运行随机密钥 `HMAC-SHA256`（可选 `sha384` / `blake2b`）隐去文件名、原始哈希与精确日期，防止屏幕共享或日志外泄。 | 如在授权离线取证工作站需完整哈希，显式传入 `--unredacted`。 |

---

## 30 秒快速上手

```bash
pip install starshield-forensics

# 运行内置 100% 净室合成样本演示（零网络请求）
starshield demo

# 对本地目录执行零明文取证可行性预检
starshield precheck /path/to/IndexedDB_folder
```

完整英文规格说明、对抗测试集（`StarShield-Bench-24`）与供应链签名验证指南请参见 **[`README.md`](./README.md)**。
