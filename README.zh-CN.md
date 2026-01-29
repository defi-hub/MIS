# 模块化智能空间 (MIS)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18381504.svg)](https://doi.org/10.5281/zenodo.18381504)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Paper](https://img.shields.io/badge/paper-preprint-yellow)](paper/mis_paper.pdf)
[![Language](https://img.shields.io/badge/language-Rust%20%7C%20C-red)]()

**引用格式：** Sergey Defis. (2026). *模块化智能空间 (MIS)：基于 eBPF 的自主 AI 智能体安全执行环境*. Zenodo. https://doi.org/10.5281/zenodo.18381504

---

## 概述

本仓库包含**模块化智能空间 (MIS)** 的**参考实现**和**学术论文** - 这是一种用于部署具有内核级隔离保证的自主 AI 智能体的新型架构。

---

## 扩展说明（设计理念）

学术论文专注于正式架构和参考实现。

有关系统级动机、设计理念以及学术论文范围之外的概念的更多信息，请参阅：

- **配套文章（Telegraph）**：  
  https://telegra.ph/MIS-Polnaya-arhitektura-chto-ostalos-za-kadrom-akademicheskoj-stati-01-27

- **Telegram 频道（开放研究日志）**：  
  https://t.me/def.blog/21

- **扩展白皮书（英文）**：  
  [docs/whitepaper_extended_en.md](docs/whitepaper_extended_en.md)

这些材料提供了关于 MIS 作为自主智能体执行和选择环境的扩展讨论，超出了严格的学术框架。

---

**论文**: [模块化智能空间：基于 eBPF 的自主 AI 智能体安全执行环境](paper/mis_paper.pdf)

**作者**: Sergey Defis (xoomi16@gmail.com)  
(Telegram Direct @def.blog)

---

## 主要贡献

1. **抗 TOCTOU 访问控制**：基于 inode 的检查消除文件系统竞态条件
2. **双布隆过滤器策略**：O(1) 威胁检测，CVE 响应时间低于 30 秒
3. **具身学习**：三流日志记录实现从真实系统交互中进行策略强化学习

---

## 仓库内容

### 学术论文

- **[paper/mis_paper.tex](paper/mis_paper.tex)** - LaTeX 源代码
- **[paper/mis_paper.pdf](paper/mis_paper.pdf)** - 编译的 PDF

包含形式化证明、评估和相关工作的完整论文。

## 架构

有关详细的架构图和攻击缓解示例，请参阅：

**[📐 架构文档](docs/architecture.md)**

主要组件：
- 系统调用流程：智能体 → 内核 → eBPF LSM → 策略引擎
- 信任边界：受信任（内核、策略）vs 不受信任（智能体）
- 攻击场景及缓解措施（TOCTOU、命名空间逃逸、资源耗尽）

### 参考实现

**状态**：概念验证 (PoC)

这是一个展示核心架构的**概念实现**。它**尚未准备好用于生产环境**，需要进一步开发才能部署。

```
- reference_implementation/
  - ebpf/
    - mis_lsm.c  # eBPF LSM 钩子
  - policy_engine/
    - main.rs  # Rust 用户空间策略引擎
  - config/
    - mis_config.toml  # 示例配置
```

**组件**：

1. **eBPF LSM 模块** (`ebpf/mis_lsm.c`)：
   - 内核级文件访问控制
   - 每 CPU LRU 缓存
   - 环形缓冲区事件信号

2. **策略引擎** (`policy_engine/main.rs`)：
   - 双布隆过滤器策略执行
   - 具有 CPU 节流检测的监视器
   - Git 版本化白名单管理

3. **配置** (`config/mis_config.toml`)：
   - 故障安全默认设置
   - 系统调用 TTL 映射
   - 资源限制

---

## 要求（用于 PoC）

- Linux 内核 ≥ 5.7（eBPF LSM 支持）
- Rust（最新稳定版）
- Clang/LLVM（用于 eBPF 编译）

**注意**：此 PoC 在投入生产使用之前需要大量额外工作：
- 完整的 eBPF 映射实现
- 布隆过滤器库集成
- 全面测试
- 生产环境加固

---

## 引用

如果您在研究中使用此工作，请引用：

```bibtex
@article{defis2026mis,
  author    = {Sergey Defis},
  title     = {模块化智能空间 (MIS)：基于 eBPF 的自主 AI 智能体安全执行环境},
  journal   = {预印本},
  year      = {2026},
  month     = {1月},
  url       = {https://github.com/defi-hub/MIS}
}
```

或使用 [CITATION.cff](CITATION.cff)。

---

## 研究状态

- **论文**：已提交同行评审（2026 年 1 月）
- **实现**：概念验证
- **部署**：尚未准备好用于生产环境

这项工作是 AI 安全和操作系统安全领域正在进行的研究的一部分。

---

## 许可证

MIT 许可证 - 请参阅 [LICENSE](LICENSE) 文件。

---

## 联系方式

**作者**：Sergey Defis  
**电子邮件**：xoomi16@gmail.com  
**问题反馈**：[GitHub Issues](https://github.com/defi-hub/MIS/issues)

---

**免责声明**：这是学术研究。参考实现展示了论文中的概念，但如果没有大量额外的工程工作，不适用于生产部署。

---

## 其他语言版本

- [English](README.md)
- [简体中文](README.zh-CN.md)
- [日本語](README.ja.md)
- [한국어](README.ko.md)
