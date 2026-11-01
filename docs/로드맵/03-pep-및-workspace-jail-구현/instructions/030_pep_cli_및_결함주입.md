# 030. PEP CLI 명령 및 결함 주입/E2E 검증 구현지시서

> **상태**: `Draft`  
> **선행 조건**: Phase 3 Step 020 (PEP 코어 게이트웨이 구현) 완료  
> **상위 대시보드**: [README.md](../README.md) | **마스터 설계**: [ROADMAP.md](../ROADMAP.md)

---

## 1. 목적 (Context & Why)

본 지시서는 Step 020에서 구축한 정책 집행 게이트웨이(`internal/authz/pep.Gateway`)를 운영자 및 자동화 하네스가 직접 구동하고 관찰할 수 있도록 **`pep` CLI 서브커맨드(`authz-harness pep read`, `authz-harness pep write`) 및 결함 주입 스위치를 구현**하고 E2E 수준의 4층위 검증을 완료하는 작업이다.

보안 불변식 및 설계 원칙:
1. **단일 진입로 및 5단계 관문 집행 (Single Entrypoint Pipeline)**:
   - CLI 사용자는 `pep read <file>` 또는 `pep write <file> --data <content>` 명령을 통해 격리된 파일 작업을 요청한다.
   - 요청은 `Gate 1(AuthN)` -> `Gate 2(PDP)` -> `Gate 2c(Jail)` -> `Stage 4(Pre-Commit Audit)` -> `Stage 5(File I/O)`의 5단계를 거치며, 어떠한 경우에도 관문 우회나 직접 파일 접근을 허용하지 않는다.
2. **시각적 증거 및 삼분 로깅 (Tri-Separation & Visualization)**:
   - **CLI 출력 (`stdout`)**: 인간 운영자를 위한 5단계 관문 박스 뷰(`[PASS]`/`[FAIL]`) 및 결과 요약(JSON 지원).
   - **운영 로그 (`stderr`)**: `log/slog` 디버그/진단 로그.
   - **감사 증거 (`audit.jsonl`)**: 불변 해시 체인 기반 감사 이벤트.
3. **Fail-Closed 감사 결함 주입 (`--inject-audit-failure`)**:
   - 인가 결정이 `ALLOW`이고 경로가 안전하더라도, 감사 로그 기록 실패 시뮬레이션 스위치가 켜지면 파일 쓰기를 즉각 중단하고 디스크 변경 0바이트를 유지하며 `EXIT_AUDIT_FAILURE(15)`를 반환한다.
4. **결정론적 프로세스 종료 규약 (Deterministic Exit Codes)**:
   - 하네스 프로세스는 결과에 따라 마스터 로드맵 §13 규약을 엄격히 반환한다.
     - `0 (ExitSuccess)`: 전 관문 통과 및 I/O 성공
     - `11 (ExitTokenInvalid)`: 토큰 위조, 만료, 불일치, Replay 검증 실패
     - `12 (ExitAuthzDenied)`: 활성 Grant 부재, 권한 불일치, 회수
     - `13 (ExitPathViolation)`: Workspace 경계 상위 탈출(`..`) 또는 외부 심볼릭 링크
     - `14 (ExitBadInput)`: 필수 플래그 누락 또는 잘못된 인자
     - `15 (ExitAuditFailure)`: Fail-Closed 사전 커밋 감사 기록 실패
     - `20 (ExitInternalError)`: 파일 I/O 실패 등 예기치 못한 내부 시스템 오류

---

## 2. 패키지 배치 및 6계층 DAG 구조

```text
Layer 5: [cmd/authz-harness] ───────────────┐ (CLI 서브커맨드 라우팅)
                    │                       │
                    v                       v
         [internal/cli/pep.go]      [internal/cli/formatter.go] (시각화 박스 뷰)
                    │
                    v (Config 의존성 주입)
Layer 3: [internal/authz/pep.Gateway]
                    │
        ┌───────────┼───────────┬───────────┐
        v           v           v           v
Layer 2A:       Layer 2B:   Layer 2C:   Layer 1:
[authn/token]  [authz/pdp] [jail]      [audit.Writer]
        │           │           │           │
        └───────────┴─────┬─────┴───────────┘
                          v
Layer 0:        [internal/domain]
```

- **Layer 5 (`internal/cli/pep.go`)**:
  - `PEPRunner` 구조체를 정의하고, `pep read` 및 `pep write` 플래그 파싱, 하위 서비스(`token.Verifier`, `pdp.Service`, `jail.Jail`, `audit.Writer`) 조립, PEP 게이트웨이 호출 및 파이프라인 시각화를 담당한다.
- **Layer 5 (`cmd/authz-harness/main.go`)**:
  - `pep` 서브커맨드 라우팅 및 `--workspace` 전역 플래그를 추가한다.
- **단방향 계층 원칙**:
  - `internal/authz/pep` 게이트웨이는 CLI(`internal/cli`)의 존재를 전혀 알지 못하며, 인터페이스 기반으로 완벽히 디커플링된다.

---

## 3. 세부 설계 및 인터페이스 계약

### 3.1 PEPRunner 구조체 및 서브커맨드 명세 (`internal/cli/pep.go`)

```go
package cli

import (
	"context"
	"io"

	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

// PEPRunner 는 `pep` 서브커맨드(read, write) 실행을 주관하는 CLI 러너다.
type PEPRunner struct {
	gateway      pep.Gateway
	out          io.Writer
	errOut       io.Writer
	workspaceDir string
	auditPath    string
	statePath    string
	pubJWKSPath  string
	replayPath   string
}

// NewPEPRunner 는 파일 경로들을 받아 의존성을 조립하고 PEPRunner를 생성한다.
func NewPEPRunner(
	out, errOut io.Writer,
	workspaceDir, statePath, pubJWKSPath, replayPath, auditPath string,
) (*PEPRunner, error)
```

### 3.2 CLI 명령어 및 플래그 사양

1. **`authz-harness pep read <resource-path> [flags]`**:
   - 지정된 상대 경로 파일의 읽기 작업을 PEP 게이트웨이에 요청한다.
   - 인가 허용 및 읽기 성공 시 파일 내용(Data)을 표준 출력에 표시하거나 포맷팅한다.
2. **`authz-harness pep write <resource-path> [flags]`**:
   - 지정된 상대 경로 파일에 쓰기 작업을 PEP 게이트웨이에 요청한다.
   - `--data <string>` 또는 `--data-file <path>`로 쓸 내용을 전달한다.

**공통 플래그 사양**:
- `--token <bearer-token>`: RFC 9068 Bearer Access Token 문자열 (필수)
- `--data <string>`: 쓰기 요청 시 기록할 텍스트 내용 (`write` 명령 전용)
- `--expected-aud <string>`: 토큰 수신자 기대값 (기본값: `"authz-harness"`)
- `--expected-sub <string>`: 주체 기대값 검증 (선택)
- `--clock-offset <duration>`: 시간 오프셋 시뮬레이션 (선택, e.g. `"10m"`)
- `--inject-audit-failure`: Fail-Closed 사전 커밋 감사 실패 결함 주입 스위치 (기본값: `false`)
- `--output-format <text|json>`: 출력 형식 지정 (기본값: `"text"`)
- `--trace-id <string>`: 명시적 트랜잭션 추적 ID 지정 (선택, 미지정 시 자동 생성)

### 3.3 시각화 박스 뷰 (Text Output Format)

인가 및 관문 집행 과정을 운영자가 직관적으로 확인할 수 있도록 ASCII 파이프라인 박스 뷰를 제공한다:

```text
=== PEP Pipeline Execution [TraceID: pep-20261101-001] ===
Action: file:write | Resource: reports/summary.txt
[Gate 1] AuthN Token Verification   : [PASS] (Sub: worker-01, JTI: jti-abc)
[Gate 2] Pure PDP Authorization     : [PASS] (Grant: grant-123, Scope: file:write)
[Gate 2c] Workspace Jail Boundary   : [PASS] (SafePath: /repo/workspace/reports/summary.txt)
[Stage 4] Pre-Commit Audit Flush    : [PASS] (Event: pep.execute)
[Stage 5] Confined File I/O         : [PASS] (Wrote 42 bytes)
---------------------------------------------------------
DECISION: ALLOW | EXIT CODE: 0 (ExitSuccess)
=========================================================
```

실패 시 박스 뷰:
```text
=== PEP Pipeline Execution [TraceID: pep-20261101-002] ===
Action: file:write | Resource: ../../etc/passwd
[Gate 1] AuthN Token Verification   : [PASS] (Sub: worker-01, JTI: jti-abc)
[Gate 2] Pure PDP Authorization     : [PASS] (Grant: grant-123)
[Gate 2c] Workspace Jail Boundary   : [FAIL] (PATH_TRAVERSAL_DETECTED)
[Stage 4] Pre-Commit Audit Flush    : [SKIPPED]
[Stage 5] Confined File I/O         : [SKIPPED]
---------------------------------------------------------
DECISION: DENY | EXIT CODE: 13 (ExitPathViolation)
Reason: PATH_TRAVERSAL_DETECTED: path escapes workspace root
=========================================================
```

---

## 4. 사전 점검 및 실패 위험 분석 (Pre-Mortem)

1. **위험: Workspace 디렉토리가 아직 디스크에 없을 때 Jail 초기화 실패**
   - *영향*: 사용자가 최초 실행 시 `./workspace` 폴더를 직접 만들지 않았으면 CLI가 즉시 비정상 종료할 위험.
   - *대응*: `NewPEPRunner` 또는 Jail 팩토리에서 `os.MkdirAll(workspaceDir, 0755)`을 보장하여 자동 준비.
2. **위험: `--data` 미지정 쓰기 요청 시 널 포인터 역참조 또는 공백 쓰기**
   - *영향*: 사용자가 데이터 없이 `pep write foo.txt`를 실행했을 때 크래시 위험.
   - *대응*: `--data`가 주어지지 않으면 0바이트 빈 파일 생성 또는 기본 빈 슬라이스(`[]byte{}`)를 안전하게 처리하며, 플래그 검증에서 명확한 안내를 제공.
3. **위험: CLI stdout 출력 시 읽은 원시 파일 내용과 박스 뷰 혼선**
   - *영향*: 스크립트나 파이프라인에서 `authz-harness pep read` 출력을 파일로 리다이렉트할 때 박스 뷰 텍스트가 파일 내용에 오염될 위험.
   - *대응*: 기본 text 포맷에서는 박스 뷰 아래 명확한 구분자(`--- File Content ---`)와 함께 출력하고, `--output-format json` 시에는 JSON 내에 `base64` 또는 `content` 필드로 구조화하거나, 순수 데이터 출력 옵션을 명확히 제공.

---

## 5. 4층위 검증 설계 및 10대 인수 테스트 시나리오 선기술

### 5.1 4층위 검증 범위

| 층위 | 검증 대상 | 검증 방법 | 성공 기준 |
|---|---|---|---|
| **1층위** (자동화 스크립트) | 시크릿 누출 및 코드 정적 분석 | `scripts/public_safety_scan.py --tree`, `go vet` | 위반 0건 |
| **2층위** (단위 및 CLI 통합) | `internal/cli/pep_test.go` | Go 표준 Table-Driven 단위 테스트 | 10대 시나리오 100% 통과 |
| **3층위** (상태 및 정합성) | 파일 디스크립터 변경 여부 및 감사 로그 | 파일 생성 여부(`os.Stat`), `audit.jsonl` 이벤트 체인 검증 | 거부 시 파일 변경 0바이트 불변식 |
| **4층위** (CLI E2E 검증) | `cmd/authz-harness` 실행 바이너리 | `authz-harness pep read/write` CLI 구동 및 종료 코드 검증 | 규격 Exit Code 일치 |

### 5.2 10대 인수 테스트 시나리오 선기술 (Table-Driven)

| ID | 시나리오명 | 입력 인자 및 조건 | 기대 종료 코드 | 기대 관문 결과 | 파일 부작용 |
|---|---|---|---|---|---|
| **AC-01** | 정상 파일 쓰기 | 유효한 토큰(`write` scope) + 정상 경로 + `--data "hello"` | `0` (ExitSuccess) | Gate 1~Stage 5 모두 PASS | 파일 생성 및 "hello" 기록 |
| **AC-02** | 정상 파일 읽기 | 유효한 토큰(`read` scope) + 기존 파일 존재 | `0` (ExitSuccess) | Gate 1~Stage 5 모두 PASS | 파일 내용 STDOUT 출력 |
| **AC-03** | 유효하지 않은 토큰 | 위조된 토큰 문자열 | `11` (ExitTokenInvalid) | Gate 1 FAIL, 이후 SKIPPED | 파일 생성/수정 0바이트 |
| **AC-04** | 토큰 Replay 재사용 | 동일한 jti 토큰을 2회 연속 제출 | `11` (ExitTokenInvalid) | 1회차 PASS, 2회차 Gate 1 FAIL | 2회차 파일 부작용 0바이트 |
| **AC-05** | Scope 권한 불일치 | `read` scope 토큰으로 `pep write` 시도 | `12` (ExitAuthzDenied) | Gate 1 PASS, Gate 2 FAIL | 파일 생성/수정 0바이트 |
| **AC-06** | Grant 부재/회수 | Grant 발급 없는 주체의 토큰 | `12` (ExitAuthzDenied) | Gate 1 PASS, Gate 2 FAIL | 파일 생성/수정 0바이트 |
| **AC-07** | 상위 경로 탈출 시도 | `../../etc/passwd` 쓰기 시도 | `13` (ExitPathViolation) | Gate 1~2 PASS, Gate 2c FAIL | 파일 생성/수정 0바이트 |
| **AC-08** | 외부 심볼릭 링크 탈출 | Workspace 밖을 가리키는 symlink 경로 접근 | `13` (ExitPathViolation) | Gate 1~2 PASS, Gate 2c FAIL | 외부 파일 손상 0바이트 |
| **AC-09** | 사전 감사 결함 주입 | `--inject-audit-failure` 플래그 지정 쓰기 | `15` (ExitAuditFailure) | Gate 1~2c PASS, Stage 4 FAIL | 파일 쓰기 중단, 0바이트 유지 |
| **AC-10** | 필수 인자 누락 | `--token` 플래그 없이 `pep read foo.txt` | `14` (ExitBadInput) | CLI 파싱 단계에서 즉시 거부 | I/O 없음 |

---

## 6. 구현 체크리스트 및 완료 조건

- [ ] `internal/cli/pep.go` 구현:
  - [ ] `PEPRunner` 구조체 및 생성자 `NewPEPRunner`
  - [ ] `runRead(ctx, args)` 및 `runWrite(ctx, args)` 구현
  - [ ] 5단계 파이프라인 ASCII 박스 뷰 포매터 구현
  - [ ] JSON 포맷 지원 (`--output-format json`)
  - [ ] Fail-Closed `--inject-audit-failure` 스위치 연동
- [ ] `cmd/authz-harness/main.go` 연동:
  - [ ] `workspace` 전역 플래그 추가 (기본값: `./workspace`)
  - [ ] `case "pep":` 라우팅 추가
- [ ] `internal/cli/pep_test.go` 작성:
  - [ ] 10대 인수 테스트 시나리오(AC-01 ~ AC-10) 전체 작성 및 100% 통과
- [ ] 불변식 검증:
  - [ ] 거부(`11`, `12`, `13`, `14`, `15`) 시 파일 부작용 0바이트 검증
  - [ ] Fail-Closed 감사 실패 시 쓰기 중단 검증
  - [ ] `audit.jsonl`에 원시 Bearer 토큰 문자열 유출 0건 확인
- [ ] `scripts/public_safety_scan.py --tree` Zero Leakage 검증 통과
