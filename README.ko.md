# 모듈형 인텔리전스 스페이스 (MIS)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18381504.svg)](https://doi.org/10.5281/zenodo.18381504)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Paper](https://img.shields.io/badge/paper-preprint-yellow)](paper/mis_paper.pdf)
[![Language](https://img.shields.io/badge/language-Rust%20%7C%20C-red)]()

**인용 형식:** Sergey Defis. (2026). *모듈형 인텔리전스 스페이스 (MIS): eBPF 기반 자율 AI 에이전트를 위한 안전한 실행 환경*. Zenodo. https://doi.org/10.5281/zenodo.18381504

---

## 개요

이 저장소는 **모듈형 인텔리전스 스페이스 (MIS)** 의 **참조 구현**과 **학술 논문**을 포함합니다. 이는 커널 수준의 격리 보장을 갖춘 자율 AI 에이전트를 배포하기 위한 새로운 아키텍처입니다.

---

## 확장 노트 (설계 근거)

학술 논문은 공식 아키텍처와 참조 구현에 중점을 둡니다.

시스템 수준의 동기, 설계 철학 및 학술 논문 범위 밖의 개념에 대한 추가 정보는 다음을 참조하십시오:

- **보충 기사 (Telegraph)**:  
  https://telegra.ph/MIS-Polnaya-arhitektura-chto-ostalos-za-kadrom-akademicheskoj-stati-01-27

- **Telegram 채널 (공개 연구 로그)**:  
  https://t.me/def.blog/21

- **확장 백서 (영문)**:  
  [docs/whitepaper_extended_en.md](docs/whitepaper_extended_en.md)

이러한 자료는 엄격한 학술적 틀을 넘어 자율 에이전트를 위한 실행 및 선택 환경으로서의 MIS에 대한 확장된 논의를 제공합니다.

---

**논문**: [모듈형 인텔리전스 스페이스: eBPF 기반 자율 AI 에이전트를 위한 안전한 실행 환경](paper/mis_paper.pdf)

**저자**: Sergey Defis (xoomi16@gmail.com)  
(Telegram Direct @def.blog)

---

## 주요 기여

1. **TOCTOU 저항 접근 제어**: inode 기반 검사로 파일시스템 경쟁 조건 제거
2. **이중 블룸 필터 정책**: O(1) 위협 탐지, 30초 미만의 CVE 대응
3. **체화된 학습**: 실제 시스템 상호작용으로부터 온폴리시 강화 학습을 가능하게 하는 3-스트림 로깅

---

## 저장소 내용

### 학술 논문

- **[paper/mis_paper.tex](paper/mis_paper.tex)** - LaTeX 소스
- **[paper/mis_paper.pdf](paper/mis_paper.pdf)** - 컴파일된 PDF

형식적 증명, 평가 및 관련 작업이 포함된 전체 논문.

## 아키텍처

자세한 아키텍처 다이어그램 및 공격 완화 예시는 다음을 참조하십시오:

**[📐 아키텍처 문서](docs/architecture.md)**

주요 구성 요소:
- 시스템 콜 흐름: 에이전트 → 커널 → eBPF LSM → 정책 엔진
- 신뢰 경계: 신뢰됨 (커널, 정책) vs 신뢰 안 됨 (에이전트)
- 공격 시나리오 및 완화 (TOCTOU, 네임스페이스 탈출, 리소스 고갈)

### 참조 구현

**상태**: 개념 증명 (PoC)

이는 핵심 아키텍처를 시연하는 **개념 구현**입니다. **프로덕션 준비가 되지 않았으며** 배포를 위해서는 추가 개발이 필요합니다.

```
- reference_implementation/
  - ebpf/
    - mis_lsm.c  # eBPF LSM 훅
  - policy_engine/
    - main.rs  # Rust 사용자 공간 정책 엔진
  - config/
    - mis_config.toml  # 예제 구성
```

**구성 요소**:

1. **eBPF LSM 모듈** (`ebpf/mis_lsm.c`):
   - 커널 수준 파일 접근 제어
   - CPU당 LRU 캐싱
   - 링버퍼 이벤트 시그널링

2. **정책 엔진** (`policy_engine/main.rs`):
   - 이중 블룸 필터 정책 시행
   - CPU 스로틀링 감지가 있는 워치독
   - Git 버전 관리 화이트리스트 관리

3. **구성** (`config/mis_config.toml`):
   - 장애 안전 기본값
   - 시스템 콜 TTL 매핑
   - 리소스 제한

---

## 요구사항 (PoC용)

- Linux 커널 ≥ 5.7 (eBPF LSM 지원)
- Rust (최신 안정 버전)
- Clang/LLVM (eBPF 컴파일용)

**참고**: 이 PoC는 프로덕션 사용 전에 상당한 추가 작업이 필요합니다:
- 완전한 eBPF 맵 구현
- 블룸 필터 라이브러리 통합
- 포괄적인 테스트
- 프로덕션 강화

---

## 인용

이 연구를 사용하는 경우 다음과 같이 인용하십시오:

```bibtex
@article{defis2026mis,
  author    = {Sergey Defis},
  title     = {모듈형 인텔리전스 스페이스 (MIS): eBPF 기반
               자율 AI 에이전트를 위한 안전한 실행 환경},
  journal   = {사전 인쇄},
  year      = {2026},
  month     = {1월},
  url       = {https://github.com/defi-hub/MIS}
}
```

또는 [CITATION.cff](CITATION.cff)를 사용하십시오.

---

## 연구 상태

- **논문**: 동료 검토 제출됨 (2026년 1월)
- **구현**: 개념 증명
- **배포**: 프로덕션 준비 안 됨

이 작업은 AI 안전 및 운영 체제 보안 분야의 진행 중인 연구의 일부입니다.

---

## 라이선스

MIT 라이선스 - [LICENSE](LICENSE) 파일을 참조하십시오.

---

## 연락처

**저자**: Sergey Defis  
**이메일**: xoomi16@gmail.com  
**이슈**: [GitHub Issues](https://github.com/defi-hub/MIS/issues)

---

**면책 조항**: 이것은 학술 연구입니다. 참조 구현은 논문의 개념을 시연하지만 상당한 추가 엔지니어링 없이는 프로덕션 배포를 의도하지 않습니다.

---

## 다른 언어

- [English](README.md)
- [简体中文](README.zh-CN.md)
- [日本語](README.ja.md)
- [한국어](README.ko.md)
