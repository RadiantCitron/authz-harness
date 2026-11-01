# 010. 리포지토리 최상위 README.md 및 아키텍처 다이어그램 구현지시서

> **상태**: `Draft`
> **선행 조건**: Phase 5 (30대 E2E 시나리오 자동 하네스 및 Explain UX) 완료
> **상위 대시보드**: [README.md](../README.md) | **마스터 설계**: [ROADMAP.md](../ROADMAP.md)

---

## 1. 목적 (Context & Why)

본 지시서는 면접관, 아키텍트, 외부 테크 리더가 `authz-harness` 리포지토리를 방문했을 때, **1분 안에 프로젝트의 존재 이유(Why)와 엔터프라이즈 아키텍처(OAuth 2.1, RFC 8693 Downscoping, NIST SP 800-162 PAP/PIP/PDP/PEP, 3-Zone 상태 격리, 삼분 관측성)를 직관적으로 파악하고, 단 한 줄의 명령으로 30대 시나리오 4중 검증을 눈앞에서 재현할 수 있는 최상위 `README.md`**를 작성하는 작업이다.

보안 및 문서화 불변식에 따라:
1. **1분 재현성 (1-Minute Reproducibility)**:
   - 복잡한 도커 컨테이너나 외부 인프라 설정 없이 Go 1.27+ 환경에서 단일 명령(`go run ./cmd/authz-harness run --scenario all`)으로 30개 전 시나리오가 1초 내에 완주되는 퀵스타트 섹션을 최상단에 배치한다.
2. **시각적 아키텍처 토폴로지 (Visual Architecture Topology)**:
   - Zone A(서명 개인키) / Zone B(원장/공개키) / Zone C(격리 실행 및 감사)의 3-Zone 물리·논리 격리 경계를 Mermaid 다이어그램으로 시각화한다.
   - Layer 0부터 Layer 5까지의 6계층 비순환 의존성(DAG) 구조를 명시한다.
3. **6단계 인가 관문 파이프라인 (6-Gate Pipeline)**:
   - Gate 1(형식/AuthN)부터 Gate 6(Jail/PEP)까지 요청이 통과하는 순차적 검증 관문과 표준 종료 코드(`0`, `11`~`16`)의 매핑을 도표화한다.
4. **부정 테스트의 역설 및 Quad-Assertion 해설**:
   - 단순히 정상 요청 통과가 아니라 "왜 악의적 요청의 차단(Deny)이 보안상 완벽한 성공인가"를 초보자도 납득할 수 있게 설명한다.
   - 종료 코드, 파일 0바이트 무변화, 감사 사유, 해시 체인 무결성을 동시에 증명하는 Quad-Assertion 4중 불변식을 해설한다.
5. **실제 동작과의 100% 일치 (Zero Discrepancy)**:
   - 문서에 기재된 모든 명령어, CLI 플래그, 종료 코드, 감사 이벤트 필드명, 30대 시나리오 명칭은 실제 Go 소스 코드와 1바이트의 오차도 없이 일치해야 한다.

---

## 2. 문서 구조 및 섹션 배치

리포지토리 루트의 최상위 `README.md`는 다음의 표준 8대 섹션으로 구성한다:

```text
README.md (리포지토리 최상위)
 ├── 1. 헤더 & 프로젝트 1줄 정의 (OAuth 2.1 & RFC 8693 권한 검증 하네스)
 ├── 2. ⚡ 1분 퀵스타트 (One-Line Run & Quick Tour)
 ├── 3. 🎯 왜 이 프로젝트를 만들었는가? (배경 & 해결하려는 엔터프라이즈 문제)
 ├── 4. 🏛️ 시스템 아키텍처 & 신뢰 경계 (3-Zone 토폴로지 & 6계층 DAG)
 ├── 5. 🛡️ 6단계 인가 관문 파이프라인 & 표준 종료 코드 매핑
 ├── 6. 🧪 7대 그룹 30개 E2E 시나리오 카탈로그 & Quad-Assertion 4중 불변식
 ├── 7. 🔍 Explain UX & 관측성의 삼분 (Audit ≠ Ops Log ≠ CLI Output)
 └── 8. 📚 문서 색인 및 로드맵 안내
```

---

## 3. 세부 섹션별 작성 명세

### 3.1 헤더 & 1분 퀵스타트 섹션
- **프로젝트 명칭**: `authz-harness` (Enterprise Authorization & Downscoping Test Harness)
- **배지 및 상태**: Go 1.27+, Zero Leakage 사수, 30/30 E2E Pass, Hash-Chained Audit.
- **1분 퀵스타트 명령어**:
  ```bash
  # 1. 리포지토리 클론 및 이동
  git clone https://github.com/RadiantCitron/authz-harness.git
  cd authz-harness

  # 2. 30개 전 구간 E2E 공격 및 인가 시나리오 일괄 실행 (1초 완주)
  go run ./cmd/authz-harness run --scenario all

  # 3. 초보자 친화적 6단계 관문 Explain 뷰 체험 (E2E-22 Read 전용 자식 토큰으로 Write 시도)
  go run ./cmd/authz-harness run --scenario E2E-22 --output-format explain

  # 4. 감사 로그 해시 체인 무결성 사후 검증
  go run ./cmd/authz-harness audit verify
  ```

### 3.2 왜 이 프로젝트를 만들었는가? (Why & Problem Statement)
- **현대 분산 에이전트 / MSA의 문제점**:
  - LLM 에이전트와 마이크로서비스가 하위 워커에게 작업을 위임할 때 권한 과다 부여(Over-Privilege).
  - 권한이 회수(Revoke)되었음에도 만료되지 않은 토큰으로 작업이 계속 강행되는 TOCTOU 위험.
  - 실패 원인이 운영 로그에 파묻혀 사후 감사(Audit Trail)와 법적 증거 확보가 불가능한 문제.
- **`authz-harness`의 해답**:
  - 수학적 부분집합 축소 위임($S_{child} \subseteq S_{parent}$, $exp_{child} \le exp_{parent}$) 강제.
  - 결정(PDP)과 집행(PEP)의 물리적 분리 및 파일 I/O 직전 실시간 회수 원장 검증.
  - 파일 시스템 Workspace Jail 격리 및 사후 감사 로그 해시 체인 자동 기록.

### 3.3 3-Zone 토폴로지 & 6계층 DAG 아키텍처 다이어그램
- **3-Zone 상태 격리 토폴로지**:
  ```mermaid
  flowchart LR
      subgraph ZoneA ["Zone A: Secrets & Authority (0600 Private)"]
          PrivKeys["signing_keys.priv.json (Ed25519 개인키)"]
          ClientCreds["client_credentials.json (클라이언트 시크릿)"]
      end

      subgraph ZoneB ["Zone B: Public Ledger & Registry (Shared Read-Only)"]
          PubKeys["jwks.pub.json (공개 서명 키 링)"]
          Grants["grants_state.json (Grant/Epoch 원장)"]
          Replay["jti_blacklist.json (Replay 방지 원장)"]
      end

      subgraph ZoneC ["Zone C: Isolated Execution & Workspace (Sandboxed)"]
          Jail["./workspace (Workspace Jail 경계)"]
          Audit["audit.jsonl (해시 체인 감사 추적)"]
      end

      ZoneA -.->|서명 발급 시에만 참조| Issuer["Token Issuer (Layer 2)"]
      ZoneB -->|조회| PDP["PDP Engine & Verifier"]
      PDP -->|판정| PEP["PEP Gateway"]
      PEP -->|격리 파일 I/O| Jail
      PEP -->|해시 체인 기록| Audit
  ```
- **6계층 DAG 의존성 구조 표**:
  - Layer 5: `cmd/authz-harness`, `internal/harness`, `internal/ui`
  - Layer 4: `internal/orchestrator`, `internal/subagent`
  - Layer 3: `internal/authz/pep`
  - Layer 2: `internal/authn`, `internal/authz/pdp`, `internal/authz/pap`, `internal/authz/pip`, `internal/jail`
  - Layer 1: `internal/audit`, `internal/authz/state`
  - Layer 0: `internal/domain`, `internal/clock`

### 3.4 6단계 인가 관문 파이프라인 & 표준 종료 코드
- **6단계 관문 순서 및 차단 시 표준 종료 코드 표**:
  1. **Gate 1 (형식 & 클라이언트 인증)**: Bearer 토큰 존재, Base64/JSON 규격, 클라이언트 자격증명 검증 $\rightarrow$ 차단 시 Exit Code `11` (`EXIT_AUTHN_FAILED`)
  2. **Gate 2 (토큰 불변식 & 암호화 헤더)**: `typ == at+jwt`, 허용 알고리즘(Ed25519) 확인, `alg: none` 차단 $\rightarrow$ 차단 시 Exit Code `11` (`EXIT_AUTHN_FAILED`)
  3. **Gate 3 (서명 키 유효성 & 무결성)**: `kid` 기반 서명 검증, 폐기된 키(`retired`) 차단 $\rightarrow$ 차단 시 Exit Code `11` (`EXIT_AUTHN_FAILED`)
  4. **Gate 4 (클레임 바인딩, 시간, Replay & Epoch)**: `exp` 만료, `nbf` 미래, `iss`/`aud` 일치, `jti` Replay 차단, Subject Epoch 무효화 $\rightarrow$ 차단 시 Exit Code `11` (`EXIT_AUTHN_FAILED`)
  5. **Gate 5 (축소 위임 불변식 & PDP 정책 결정)**: RFC 8693 Scope 부분집합, 최대 위임 깊이, 활성 Grant 대조 $\rightarrow$ 차단 시 Exit Code `12` (`EXIT_AUTHZ_DENIED`)
  6. **Gate 6 (Workspace Jail 경로 강제 & 파일 I/O PEP)**: `../` 상대경로 탈출, 루트 접두사 착시, 심볼릭링크 탈출 차단 $\rightarrow$ 차단 시 Exit Code `13` (`EXIT_PATH_VIOLATION`)
  - 특수 코드: `14` (`EXIT_TRACE_MISSING`), `15` (`EXIT_AUDIT_FAILURE`), `16` (`EXIT_INTERNAL_ERROR`).

### 3.5 7대 그룹 30개 E2E 시나리오 카탈로그 & Quad-Assertion 표
- **30개 시나리오 요약 표**:
  - G1: 기본 권한 생명주기 (E2E-01 ~ E2E-03)
  - G2: 워크로드 인증 (E2E-04 ~ E2E-06)
  - G3: 토큰 무결성 & 서명 키 관리 (E2E-07 ~ E2E-13)
  - G4: 시간·클레임·바인딩·Replay (E2E-14 ~ E2E-18)
  - G5: RFC 8693 축소 위임 & PDP 정책 (E2E-19 ~ E2E-24)
  - G6: 파일 Jail & 경로 보안 (E2E-25 ~ E2E-27)
  - G7: 관측성·감사 Fail-Closed·무결성 (E2E-28 ~ E2E-30)
- **Quad-Assertion 4중 불변식 정의**:
  - Exit Code 일치
  - File Mutation 상태 (허용 시 내용 일치, 거부 시 0바이트 무변화 보장)
  - Audit Decision & Reason 코드 일치
  - Hash Chain 무결성 (`audit verify` VALID) 및 원시 토큰 비노출

### 3.6 Explain UX 및 관측성의 삼분 (Tri-Separation)
- **관측성의 삼분**:
  - `stdout`: 초보자 친화적 6단계 관문 상태 다이어그램 및 시각적 Explain 뷰
  - `stderr`: 개발 및 디버깅용 정밀 구조화 로그 (`log/slog`)
  - `audit.jsonl`: SHA-256 해시 체인으로 엮인 법적 효력의 보안 감사 이벤트 원장
- **Explain UX 예시 출력 박스**:
  - E2E-22 차단 시 터미널에 출력되는 ASCII 파이프라인 및 한국어 방어 성공 해설 박스 수록.

---

## 4. 인수 테스트 시나리오 (Acceptance Test Scenarios)

### 시나리오 1: 루트 `README.md` 생성 및 마크다운 렌더링 무결성
- **입력**: 최상위 디렉터리에 `README.md` 작성
- **기대 결과**:
  - 마크다운 문법 오류 없이 깔끔하게 렌더링됨
  - 모든 Mermaid 다이어그램(3-Zone, 6계층 DAG)이 문법 오류 없이 시각화됨
  - 문서 내의 상대경로 링크(`docs/로드맵/...`)가 깨지지 않고 정확한 대상을 가리킴

### 시나리오 2: 1분 퀵스타트 복사 실행 무결성
- **입력**: `README.md`에 기재된 퀵스타트 명령어 실행
  ```bash
  go run ./cmd/authz-harness run --scenario all
  ```
- **기대 결과**:
  - 30개 시나리오 전 항목 `PASS` 출력
  - 종합 결산 `총 시나리오: 30건 | 통과(PASS): 30건 | 실패(FAIL): 0건`
  - 종료 코드 `0`으로 정상 종료

### 시나리오 3: Explain UX 명령어 예시 일치
- **입력**: `README.md`에 기재된 Explain 명령어 실행
  ```bash
  go run ./cmd/authz-harness run --scenario E2E-22 --output-format explain
  ```
- **기대 결과**:
  - 6단계 관문 상태도에서 Gate 5 `[BLOCKED]` 표시
  - 한국어 역설 해설 박스 정상 출력
  - 실제 터미널 출력과 `README.md`의 예시 텍스트가 정확히 부합

### 시나리오 4: 감사 무결성 검증 명령어 예시 일치
- **입력**: `README.md`에 기재된 감사 검증 명령어 실행
  ```bash
  go run ./cmd/authz-harness audit verify
  ```
- **기대 결과**:
  - 해시 체인 검증 결과 정상 출력

---

## 5. 구현 작업 순서 (Implementation Checklist)

1. [ ] **`README.md` 뼈대 및 헤더 작성**: 프로젝트 정의, 배지, 주요 특장점.
2. [ ] **1분 퀵스타트 가이드 작성**: 단 한 줄로 30개 시나리오를 돌려보는 재현 가이드.
3. [ ] **Why & 해결하려는 엔터프라이즈 문제 서술**: 비신뢰 에이전트, 권한 위임 오남용, 감사 단절.
4. [ ] **3-Zone 토폴로지 & 6계층 DAG 아키텍처 다이어그램 작성**: Mermaid 다이어그램 및 디렉터리 권한 매핑.
5. [ ] **6단계 인가 관문 파이프라인 & 표준 종료 코드(0, 11~16) 매핑표 작성**.
6. [ ] **7대 그룹 30개 E2E 시나리오 요약표 및 Quad-Assertion 4중 불변식 정의 작성**.
7. [ ] **Explain UX 예시 및 관측성의 삼분(Stdout/Stderr/Audit) 설명 작성**.
8. [ ] **실제 명령어 실행 결과와 문서 내용 교차 검증 및 상대경로 링크 확인**.
9. [ ] **대시보드(`README.md`) 갱신 및 커밋**.

---

## 6. 검증 명령 (Verification Commands)

```bash
# 1. 퀵스타트 명령어 직접 실행 검증
go run ./cmd/authz-harness run --scenario all

# 2. Explain 출력 검증
go run ./cmd/authz-harness run --scenario E2E-22 --output-format explain

# 3. 전 패키지 테스트 무결성 확인
go test -race ./...
```
