# 로드맵 전체 색인 (Roadmap Index)

> **규칙**: 전체 로드맵의 진행 상태는 각 로드맵의 `README.md` 대시보드 표를 단일 원천(SSOT)으로 관리합니다.
> - **마스터 설계 청사진**: [MASTER_ROADMAP.md](MASTER_ROADMAP.md)
> - **엔터프라이즈 아키텍처 심층 검토 보고서**: [ENTERPRISE_AUTH_SUPPLEMENT_REPORT.md](ENTERPRISE_AUTH_SUPPLEMENT_REPORT.md)
> - **도메인 보호 및 단일 입출구 배선 감사 보고서**: [../../DOMAIN_PROTECTION_AND_WIRING_AUDIT_REPORT.md](../../DOMAIN_PROTECTION_AND_WIRING_AUDIT_REPORT.md)
> - **작업 흐름 및 로드맵 거버넌스 정책**: [ROADMAP_정책.md](ROADMAP_정책.md)

---

## 단위 로드맵 색인

| 번호 | 로드맵 명 | 상태 | 핵심 목표 |
|:---:|---|:---:|---|
| **00** | [00-개발환경-및-기반골격-구축](00-개발환경-및-기반골격-구축/README.md) | `Done` | Go 1.27 개발환경 구축, Zero Leakage 보안 가드레일, 프로젝트 헌장 및 삼분 배선 골격 수립 |
| **01** | [01-grant-저장소-및-pdp-구현](01-grant-저장소-및-pdp-구현/README.md) | `Done` | 권한 부여/회수(Grant/Revoke) 생명주기 및 중앙 PDP 정책 엔진 구현 |
| **02** | [02-oauth21-토큰-및-축소위임-구현](02-oauth21-토큰-및-축소위임-구현/README.md) | `Done` | OAuth 2.1 Access Token 서명/검증 및 팀장→서브에이전트 축소 위임(Downscoping) |
| **03** | [03-pep-및-workspace-jail-구현](03-pep-및-workspace-jail-구현/README.md) | `Done` | 정책 집행점(PEP) 및 파일시스템 격리(Workspace Jail) 강제 |
| **04** | [04-오케스트레이터-및-서브프로세스-격리](04-오케스트레이터-및-서브프로세스-격리/README.md) | `Done` | OS 서브프로세스 생성(Spawn), 토큰 격리 전달 및 종료 코드 수거 |
| **05** | [05-자동-시나리오-테스트-하네스](05-자동-시나리오-테스트-하네스/README.md) | `Done` | 단일 CLI 명령 전체 시나리오(정상/부정) 자동 판정 러너 및 설명 UX 구축 |
| **06** | [06-포트폴리오-패키징-및-문서화](06-포트폴리오-패키징-및-문서화/README.md) | `Done` | 아키텍처 다이어그램 및 시연 가이드 완성 |
| **07** | [07-도메인보호-및-단일입출구-배선-고도화](07-도메인보호-및-단일입출구-배선-고도화/README.md) | `Draft` | 12대 안티패턴 제거, 순수 도메인 보호 및 의존성 역전(DIP), 단일 입구·단일 출구(SESE) 감사 해시 체인 배선 및 진정한 4중 검증 완성 |
