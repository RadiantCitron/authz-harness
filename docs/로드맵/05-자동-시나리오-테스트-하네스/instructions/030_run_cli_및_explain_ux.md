# 030. `run` CLI 명령 통합, 초보자용 Explain UX 및 L4/L5 전 구간 검증 구현지시서

> **상태**: `Draft`  
> **선행 조건**: 010 (Quad-Assertion 검증 엔진 코어), 020 (7대 그룹 30개 시나리오 카탈로그) 완료  
> **상위 대시보드**: [README.md](../README.md) | **마스터 설계**: [ROADMAP.md](../ROADMAP.md)

---

## 1. 목적 (Context & Why)

본 지시서는 앞선 010 및 020 단계에서 구축된 **Quad-Assertion 4중 불변식 검증 엔진(`internal/harness`)**과 **7대 그룹 30개 전 구간 E2E 시나리오 카탈로그(`internal/harness/catalog`)**를 사용자가 단일 CLI 명령으로 손쉽게 구동하고 직관적으로 관찰할 수 있도록 **`authz-harness run` CLI 통합**, **초보자용 Explain UX 및 6단계 관문 상태도 시각화(`internal/ui`)**, 그리고 **L4 블랙박스 CLI 및 L5 E2E 전 구간 검증 스위트**를 완성하는 작업이다.

보안 불변식 및 사용자 경험 원칙:
1. **단일 명령 기반 전 구간 일괄 및 선택 실행**:
   - `authz-harness run --scenario <id|all>` 명령을 통해 30개 전 시나리오를 일괄 실행하거나, 특정 시나리오(`--scenario E2E-22`) 또는 특정 그룹(`--group G5`)만 선별하여 격리 실행할 수 있도록 한다.
2. **부정 테스트의 역설(Paradox of Negative Testing) 해설과 6단계 관문 상태도**:
   - 보안 인가 테스트에서는 의도된 공격 요청이 거부되어 프로세스가 비정상 종료 코드(`11`~`15`)를 반환하는 것이 시스템 관점에서의 "방어 성공(PASS)"이다.
   - 초보자도 이를 한눈에 납득할 수 있도록 `--output-format explain` 옵션 지정 시 6단계 관문(Gate 0~5) 통과/차단 다이어그램과 "왜 이 실패가 보안상 성공인가?"를 설명하는 한국어 역설 해설 박스를 터미널에 렌더링한다.
3. **Quad-Assertion 종합 요약표 및 3대 출력 포맷 지원**:
   - 인간 사용자를 위한 깔끔한 터미널 요약표(`summary`), 교육/설명 목적의 관문 상태도(`explain`), 그리고 CI/CD 및 외부 도구 자동화 연동을 위한 규격화된 기계 판독 포맷(`json`)을 완비한다.
4. **무대기(Zero-Sleep) 1분 이내 초고속 검증 완주**:
   - `time.Sleep`을 배제한 가상 시계 기반 30개 전 시나리오가 60초 이내에 결함 없이 전수 완주됨을 L4/L5 통합 테스트로 증명한다.

---

## 2. 패키지 배치 및 6계층 DAG 구조

```text
Layer 5:  [cmd/authz-harness] (main.go - "run" 서브커맨드 라우팅)
                │
                v
Layer 5:  [internal/cli] (RunRunner)
          ├── run.go            (run CLI 플래그 파싱 및 러너 조립)
          └── run_test.go       (L4 블랙박스 CLI 통합 테스트)
                │
                ├───▶ [internal/ui] (Explain UX & Formatters)
                │      ├── ui.go         (포매터 공통 인터페이스)
                │      ├── pipeline.go   (6단계 관문 상태도 렌더러)
                │      ├── explain.go    (부정 테스트 역설 해설 박스 렌더러)
                │      ├── summary.go    (30대 종합 결과 테이블 렌더러)
                │      ├── json.go       (JSON 직렬화 포매터)
                │      └── ui_test.go    (골든 포맷 및 렌더링 단위 테스트)
                │
                └───▶ [internal/harness] (Core Harness Runner & Quad-Assertion)
                       ▲
                       │
          [internal/harness/catalog] (30 E2E Scenario Catalog)
                       │
                       v
Layer 4:  [internal/orchestrator, internal/subagent]
Layer 3:  [internal/authz/pep]
Layer 2:  [internal/authn, internal/authz/pdp, internal/jail]
Layer 0/1: [internal/audit, internal/domain, internal/clock]
```

- **Layer 5 컴포넌트 간 단방향 원칙**:
  - `cmd/authz-harness`: `internal/cli`의 `RunRunner`를 호출하고 반환된 종료 코드로 `os.Exit` 수행.
  - `internal/cli`: `internal/harness`, `internal/harness/catalog`, `internal/ui`를 조립하여 실행 및 포맷팅 위임.
  - `internal/ui`: `internal/harness`의 결과 구조체(`ScenarioResult`)를 수신하여 포맷팅만 수행하며 비즈니스 로직에 역결합하지 않음.

---

## 3. 세부 설계 및 인터페이스 계약

### 3.1 `RunConfig` 및 CLI 플래그 설계 (`internal/cli/run.go`)

```go
package cli

import (
	"context"
	"io"
	"authz-harness/internal/domain"
)

// RunConfig 는 run 서브커맨드 실행 파라미터다.
type RunConfig struct {
	ScenarioID   string // "all" 또는 "E2E-01" ~ "E2E-30" (기본값: "all")
	GroupID      string // "" 또는 "G1" ~ "G7" (기본값: "")
	OutputFormat string // "summary" (기본), "explain", "json"
	FailFast     bool   // 첫 실패 발생 시 즉시 중단 여부 (기본값: false)
	BaseDir      string // 샌드박스 생성 기준 디렉터리 (공백 시 os.MkdirTemp)
	Verbose      bool   // 상세 운영 로그 출력 여부
}

// RunRunner 는 run 서브커맨드를 조립하고 실행하는 러너다.
type RunRunner struct {
	out     io.Writer
	errOut  io.Writer
	baseDir string
}

func NewRunRunner(out, errOut io.Writer, baseDir string) *RunRunner
func (r *RunRunner) Run(ctx context.Context, args []string) domain.ExitCode
```

- **플래그 명세**:
  - `-scenario <id|all>`: 실행할 시나리오 ID (기본: `all`)
  - `-group <G1~G7>`: 특정 그룹만 필터링하여 실행
  - `-output-format <summary|explain|json>`: 결과 출력 형식 (기본: `summary`)
  - `-fail-fast`: 단 하나의 시나리오라도 FAIL 발생 시 즉시 후속 시나리오 실행 중단
  - `-verbose`: stderr로 디버그 slog 출력 활성화

- **종료 코드 매핑**:
  - 지정된 모든 시나리오가 Quad-Assertion을 만족(`Passed == true`): `domain.ExitSuccess (0)`
  - 하나 이상의 시나리오가 실패(`Passed == false`): `domain.ExitAuthzDenied (12)` (인가/검증 실패 표준)
  - 잘못된 플래그 입력, 미등록 시나리오 ID, 지원하지 않는 포맷: `domain.ExitBadInput (2)`
  - 하네스 샌드박스 초기화 등 시스템 치명적 오류: `domain.ExitInternalError (1)`

---

### 3.2 6단계 관문(Gate 0~5) 파이프라인 매핑 로직 (`internal/ui/pipeline.go`)

모든 E2E 시나리오는 다음 6단계 관문 순서로 평가되며, 시나리오 메타데이터와 결과에 따라 차단 관문이 결정론적으로 매핑된다:

| 관문 번호 | 관문 명칭 | 평가 대상 보안 불변식 | 해당 그룹 및 차단 사유 (`Reason`) |
|---|---|---|---|
| **Gate 0** | **컨텍스트 검증** | `trace_id` 컨텍스트 누락 여부 검증 | G7 (`E2E-28`: `INVALID_ARGUMENTS`) |
| **Gate 1** | **토큰 & 서명** | 클라이언트 인증, Ed25519 서명, JWT 규격(`at+jwt`), 만료/미래 시각, 키 회전/폐기 | G2 (`E2E-04~06`), G3 (`E2E-07~11, 13`), G4 (`E2E-14~17`) |
| **Gate 2** | **위임 & 스코프** | RFC 8693 부분집합 축소 위임, TTL, 깊이(`depth`), 요청 액션의 Scope 포함 여부 | G5 (`E2E-19~22`: `DELEGATION_*`, `TOKEN_INSUFFICIENT_SCOPE`) |
| **Gate 3** | **실시간 Grant** | PAP Grant 존재 여부, Replay 방지(`jti`), Subject Epoch 철회, 실시간 회수 | G1 (`E2E-03`), G4 (`E2E-18`), G5 (`E2E-23~24`) |
| **Gate 4** | **Jail 경로격리** | Workspace 경계, 상대 경로 탈출(`../`), 접두사 착시, 심볼릭 링크 탈출 | G6 (`E2E-25~27`: `PATH_*`, `SYMLINK_ESCAPE`) |
| **Gate 5** | **감사 & I/O** | `audit.jsonl` 동기 기록 (Fail-Closed), 해시 체인 무결성, 0바이트 부작용 방지 | G1 (`E2E-01~02` 정상 I/O 통과), G7 (`E2E-29~30`: `AUDIT_*`) |

```go
package ui

import "authz-harness/internal/harness"

type GateStatus string

const (
	GatePass    GateStatus = "PASS"
	GateBlocked GateStatus = "BLOCKED ❌"
	GateSkipped GateStatus = "SKIPPED"
)

type GateInfo struct {
	GateNumber int
	Name       string
	Status     GateStatus
	Detail     string
}

// ComputePipelineGates 는 시나리오 결과와 메타데이터로부터 6단계 관문 상태를 도출한다.
func ComputePipelineGates(res harness.ScenarioResult) []GateInfo
```

- **관문 상태 전이 규칙**:
  1. 시나리오가 차단(Deny)된 관문 직전까지의 모든 선행 관문은 `PASS`로 표시된다.
  2. 차단이 발생한 관문은 `BLOCKED ❌`와 함께 차단 상세 사유(예: `요청: file:write / 보유: file:read`)가 표시된다.
  3. 차단 관문 이후의 모든 후속 관문은 `SKIPPED (선행 관문 차단)`으로 렌더링되어, 불필요한 연산이나 I/O 부작용이 사전에 완벽히 방지되었음을 명시한다.
  4. 정상 시나리오(`E2E-01`, `E2E-02`)는 Gate 0부터 Gate 5까지 모든 관문이 `PASS`로 표시된다.

---

### 3.3 초보자용 Explain UX 렌더러 (`internal/ui/explain.go`)

`--output-format explain` 실행 시 각 시나리오별로 다음 형식의 터미널 뷰를 렌더링한다:

```text
================================================================================
 시나리오 [E2E-22]: 축소 위임 토큰(file:read)으로 파일 쓰기(file:write) 공격
================================================================================
 [기본 정보]
  - 그룹: G5 (RFC 8693 축소 위임 및 PDP 실시간 인가)
  - 공격 분류: Privilege Escalation (Scope Violation)
  - 판정 결과: PASS (보안 방어 성공) [소요시간: 1.2ms]
  - Quad-Assertion: [종료코드: 일치(12)] [파일상태: 0바이트 유지] [감사사유: TOKEN_INSUFFICIENT_SCOPE] [해시체인: 통과]

 [관문 상태 파이프라인]
  [Gate 0: 컨텍스트 검증] ──▶ PASS (trace_id 존재)
  [Gate 1: 토큰 & 서명]   ──▶ PASS (kid: test-key-1, alg: Ed25519, typ: at+jwt)
  [Gate 2: 위임 & 스코프] ──▶ BLOCKED ❌ (요청: file:write / 축소위임: file:read)
  [Gate 3: 실시간 Grant]  ──▶ SKIPPED (선행 관문 차단)
  [Gate 4: Jail 경로격리] ──▶ SKIPPED
  [Gate 5: 감사 & I/O]    ──▶ SKIPPED (부작용 0바이트 보장)

 [💡 초보자를 위한 보안 원리 해설 (부정 테스트의 역설)]
  - 질문: 왜 프로세스는 실패(Exit Code 12)했는데 하네스는 PASS(통과)라고 하나요?
  - 해설: 팀장은 파일 읽기 권한만 자식에게 떼어주었는데(Downscoping),
          자식 워커가 권한을 속여 쓰기를 시도했습니다.
          Gate 2에서 정확히 이 권한 초과를 감지하고 0바이트 쓰기 차단과 함께
          종료 코드 12를 반환했으므로, 보안 시스템이 완벽히 방어에 '성공'한 것입니다.
================================================================================
```

---

### 3.4 종합 요약표 및 JSON 포매터 (`internal/ui/summary.go`, `json.go`)

- **터미널 요약표 (`summary`)**:
```text
========================================================================================================================
 authz-harness v0.1.0 — 7대 그룹 30개 E2E 시나리오 실행 결과 요약표
========================================================================================================================
 ID     GROUP  시나리오 명칭                               기대코드 실제코드 [Exit/File/Audit/Hash] 결과   소요시간
------------------------------------------------------------------------------------------------------------------------
 E2E-01 G1     정상 단일 파일 읽기                         0        0        [ V  / V  / V  / V  ] PASS     1.4ms
 E2E-02 G1     정상 단일 파일 쓰기                         0        0        [ V  / V  / V  / V  ] PASS     1.8ms
 E2E-03 G1     동적 전환 [거부→허용→회수 후 즉시 거부]    12       12       [ V  / V  / V  / V  ] PASS     2.1ms
 ...
 E2E-22 G5     Read 전용 자식 토큰으로 Write 시도 거부     12       12       [ V  / V  / V  / V  ] PASS     1.1ms
 ...
 E2E-30 G7     사후 감사 로그 변조 적발 (audit verify)    15       15       [ V  / V  / V  / V  ] PASS     3.5ms
------------------------------------------------------------------------------------------------------------------------
 [종합 결산] 총 시나리오: 30건 | 통과(PASS): 30건 | 실패(FAIL): 0건 | 총 소요시간: 48.2ms
 >> 최종 판정: ALL SCENARIOS PASSED (보안 불변식 100% 사수 증명 완료)
========================================================================================================================
```

- **JSON 직렬화 (`json`)**:
  - `{"version": "0.1.0", "total": 30, "passed": 30, "failed": 0, "results": [...]}` 구조의 정형 JSON 스트림 출력.

---

### 3.5 `cmd/authz-harness/main.go` 통합

```go
case "run":
	runRunner := cli.NewRunRunner(os.Stdout, os.Stderr, "")
	exitCode := runRunner.Run(context.Background(), args[1:])
	os.Exit(int(exitCode))
```

---

## 4. 핵심 구현 단계 (Checklist)

- [ ] **1. `internal/ui` 포매팅 엔진 구현**:
  - [ ] `internal/ui/ui.go`: `Formatter` 규약 및 공통 상수 정의
  - [ ] `internal/ui/pipeline.go`: 6단계 관문 도출 로직(`ComputePipelineGates`) 및 상태 다이어그램 포매터 구현
  - [ ] `internal/ui/explain.go`: 시나리오별 역설 해설 박스 렌더러 구현
  - [ ] `internal/ui/summary.go`: 콘솔 ASCII 테이블 종합 요약표 렌더러 구현
  - [ ] `internal/ui/json.go`: JSON 직렬화 포매터 구현
  - [ ] `internal/ui/ui_test.go`: 각 렌더러의 출력 형식 및 파이프라인 매핑 단위 테스트
- [ ] **2. `internal/cli/run.go` CLI 러너 구현**:
  - [ ] `RunRunner` 구조체 및 플래그 파싱(`-scenario`, `-group`, `-output-format`, `-fail-fast`, `-verbose`) 구현
  - [ ] `catalog.RegisterAll` 연동 및 선택 시나리오 필터링 로직 구현
  - [ ] 시나리오 순차 실행 및 결과 수집, UI 포매터 호출, 표준 종료 코드 반환 로직 구현
- [ ] **3. `cmd/authz-harness/main.go` 라우팅 등록**:
  - [ ] `case "run":` 추가 및 `cli.NewRunRunner` 위임
- [ ] **4. L4 블랙박스 CLI 및 L5 E2E 통합 테스트 완비**:
  - [ ] `internal/cli/run_test.go`:
    - 30개 시나리오 전 구간 일괄 실행 및 정상 종료 코드 `0` 검증
    - `--output-format explain`, `summary`, `json` 출력 무결성 검증
    - 단일 시나리오(`--scenario E2E-22`), 특정 그룹(`--group G5`) 필터링 검증
    - 미등록 시나리오 지정 시 에러 반환 검증
    - 60초 이내 완주(Zero-Sleep 성능) 검증
- [ ] **5. 전체 회귀 테스트 통과 확인**:
  - [ ] `go test ./...` 전 패키지 통과 확인

---

## 5. 8대 인수 테스트 시나리오 (Acceptance Criteria)

| 인수 테스트 ID | 입력 조건 (CLI 명령 및 플래그) | 기대 결과 및 검증 기준 |
|---|---|---|
| **AT-CLI-01** | `authz-harness run --scenario all` | 30개 전 시나리오 순차 실행, 종합 요약표 출력, 30개 모두 PASS, 종료 코드 `0` 반환 |
| **AT-CLI-02** | `authz-harness run --scenario E2E-22 --output-format explain` | E2E-22 단일 실행, Gate 2 BLOCKED 표시, 역설 해설 박스 렌더링, 종료 코드 `0` 반환 |
| **AT-CLI-03** | `authz-harness run --group G5` | G5 그룹(E2E-19 ~ E2E-24) 6개 시나리오만 선별 실행, 6건 모두 PASS, 종료 코드 `0` 반환 |
| **AT-CLI-04** | `authz-harness run --output-format json` | 유효한 JSON 출력, 루트 객체에 `total: 30`, `passed: 30` 필드 포함, 종료 코드 `0` 반환 |
| **AT-CLI-05** | `authz-harness run --scenario E2E-99` | 미등록 시나리오 에러 메시지 stderr 출력, 프로세스 종료 코드 `2` (`ExitBadInput`) 반환 |
| **AT-CLI-06** | `authz-harness run --fail-fast` (의도적 결함 시나리오 포함) | 첫 실패 시나리오 발생 즉시 후속 시나리오 실행 중단, 종료 코드 `12` 반환 |
| **AT-CLI-07** | `authz-harness run --scenario all` (성능 측정) | 30개 전 시나리오 전체 실행 소요 시간이 60초(1분) 이내 완주 (실제 목표: 5초 이내) |
| **AT-CLI-08** | Tri-Separation 출력 분리 검증 | 표준 결과는 stdout, 운영 디버그 로그는 stderr, 감사 로그는 audit.jsonl로 상호 비오염 검증 |

---

## 6. 완료 조건 및 커밋 가이드

- **완료 조건**:
  1. `internal/ui` 패키지(파이프라인, 해설 박스, 요약표, JSON)가 생성되고 단위 테스트를 100% 통과한다.
  2. `internal/cli/run.go` 및 `cmd/authz-harness/main.go`에 `run` 서브커맨드가 등록된다.
  3. `internal/cli/run_test.go`를 통해 8대 인수 테스트가 모두 PASS한다.
  4. `go test ./...` 실행 시 전 패키지 테스트가 성공한다.
- **커밋 가이드**:
  - 지시서 커밋: `docs(roadmap): add 030 run CLI and explain UX instruction`
  - 대시보드 갱신 커밋: `docs(roadmap): update 030 instruction commit hash in 05 dashboard`
  - 구현 커밋: `feat(cli): integrate run command and beginner explain ux with quad-assertion`
