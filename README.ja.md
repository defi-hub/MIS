# モジュラーインテリジェンススペース (MIS)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18381504.svg)](https://doi.org/10.5281/zenodo.18381504)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Paper](https://img.shields.io/badge/paper-preprint-yellow)](paper/mis_paper.pdf)
[![Language](https://img.shields.io/badge/language-Rust%20%7C%20C-red)]()

**引用形式：** Sergey Defis. (2026). *モジュラーインテリジェンススペース (MIS)：eBPF ベースの自律 AI エージェント向け安全実行環境*. Zenodo. https://doi.org/10.5281/zenodo.18381504

---

## 概要

このリポジトリには、**モジュラーインテリジェンススペース (MIS)** の**リファレンス実装**と**学術論文**が含まれています。これは、カーネルレベルの分離保証を持つ自律 AI エージェントを展開するための新しいアーキテクチャです。

---

## 拡張注釈（設計思想）

学術論文は、正式なアーキテクチャとリファレンス実装に焦点を当てています。

システムレベルの動機、設計哲学、および学術論文の範囲外の概念に関する追加情報については、以下を参照してください：

- **補足記事（Telegraph）**：  
  https://telegra.ph/MIS-Polnaya-arhitektura-chto-ostalos-za-kadrom-akademicheskoj-stati-01-27

- **Telegram チャンネル（オープン研究ログ）**：  
  https://t.me/def.blog/21

- **拡張ホワイトペーパー（英語）**：  
  [docs/whitepaper_extended_en.md](docs/whitepaper_extended_en.md)

これらの資料は、厳密な学術的枠組みを超えた、自律エージェントの実行および選択環境としての MIS に関する拡張的な議論を提供します。

---

**論文**: [モジュラーインテリジェンススペース：eBPF ベースの自律 AI エージェント向け安全実行環境](paper/mis_paper.pdf)

**著者**: Sergey Defis (xoomi16@gmail.com)  
(Telegram Direct @def.blog)

---

## 主な貢献

1. **TOCTOU 耐性アクセス制御**：inode ベースのチェックによりファイルシステムの競合状態を排除
2. **デュアルブルームフィルターポリシー**：O(1) 脅威検出、30 秒未満の CVE 応答
3. **エンボディード学習**：実際のシステムインタラクションからのオンポリシー強化学習を可能にする 3 ストリームロギング

---

## リポジトリの内容

### 学術論文

- **[paper/mis_paper.tex](paper/mis_paper.tex)** - LaTeX ソース
- **[paper/mis_paper.pdf](paper/mis_paper.pdf)** - コンパイルされた PDF

形式的証明、評価、関連研究を含む完全な論文。

## アーキテクチャ

詳細なアーキテクチャ図と攻撃緩和の例については、以下を参照してください：

**[📐 アーキテクチャドキュメント](docs/architecture.md)**

主要コンポーネント：
- システムコールフロー：エージェント → カーネル → eBPF LSM → ポリシーエンジン
- 信頼境界：信頼された（カーネル、ポリシー）vs 信頼されない（エージェント）
- 攻撃シナリオと緩和策（TOCTOU、ネームスペースエスケープ、リソース枯渇）

### リファレンス実装

**ステータス**：概念実証 (PoC)

これはコアアーキテクチャを実証する**概念実装**です。**本番環境での使用準備はできておらず**、展開には更なる開発が必要です。

```
- reference_implementation/
  - ebpf/
    - mis_lsm.c  # eBPF LSM フック
  - policy_engine/
    - main.rs  # Rust ユーザースペースポリシーエンジン
  - config/
    - mis_config.toml  # サンプル設定
```

**コンポーネント**：

1. **eBPF LSM モジュール** (`ebpf/mis_lsm.c`)：
   - カーネルレベルのファイルアクセス制御
   - CPU ごとの LRU キャッシュ
   - リングバッファイベントシグナリング

2. **ポリシーエンジン** (`policy_engine/main.rs`)：
   - デュアルブルームフィルターポリシー実行
   - CPU スロットリング検出付きウォッチドッグ
   - Git バージョン管理されたホワイトリスト管理

3. **設定** (`config/mis_config.toml`)：
   - フェイルセキュアデフォルト
   - システムコール TTL マッピング
   - リソース制限

---

## 要件（PoC 用）

- Linux カーネル ≥ 5.7（eBPF LSM サポート）
- Rust（最新安定版）
- Clang/LLVM（eBPF コンパイル用）

**注意**：この PoC は本番使用前に大幅な追加作業が必要です：
- 完全な eBPF マップ実装
- ブルームフィルターライブラリ統合
- 包括的なテスト
- 本番環境への強化

---

## 引用

この研究を使用する場合は、以下のように引用してください：

```bibtex
@article{defis2026mis,
  author    = {Sergey Defis},
  title     = {モジュラーインテリジェンススペース (MIS)：eBPF ベースの
               自律 AI エージェント向け安全実行環境},
  journal   = {プレプリント},
  year      = {2026},
  month     = {1月},
  url       = {https://github.com/defi-hub/MIS}
}
```

または [CITATION.cff](CITATION.cff) を使用してください。

---

## 研究ステータス

- **論文**：査読中（2026 年 1 月）
- **実装**：概念実証
- **展開**：本番環境での使用準備未完了

この研究は、AI 安全性およびオペレーティングシステムセキュリティにおける進行中の研究の一部です。

---

## ライセンス

MIT ライセンス - [LICENSE](LICENSE) ファイルを参照してください。

---

## 連絡先

**著者**：Sergey Defis  
**メール**：xoomi16@gmail.com  
**問題報告**：[GitHub Issues](https://github.com/defi-hub/MIS/issues)

---

**免責事項**：これは学術研究です。リファレンス実装は論文のコンセプトを示していますが、大幅な追加エンジニアリングなしでは本番展開を意図していません。

---

## 他言語版

- [English](README.md)
- [简体中文](README.zh-CN.md)
- [日本語](README.ja.md)
- [한국어](README.ko.md)
