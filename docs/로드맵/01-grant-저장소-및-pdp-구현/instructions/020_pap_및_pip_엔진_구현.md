# 020. PAP 정책 관리 및 PIP 실시간 상태 공급 구현지시서

> **상태**: `Done`
> **선행 조건**: 010 (원자적 Grant/Epoch 상태 저장소 구축) 완료 (`e40e257`)
> **상위 대시보드**: [README.md](../README.md) | **마스터 설계**: [ROADMAP.md](../ROADMAP.md)

---

## 1. 목적 (Context & Why)

본 지시서는 NIST SP 800-162 표준 인가 아키텍처의 4대 핵심 축 중 **정책 관리점(Policy Administration Point, PAP)**과 **정책 정보점(Policy Information Point, PIP)**을 구축하고, 관리자 CLI(`authz-harness grant`)를 통해 권한의 생성·회수 및 주체별 보안 Epoch를 실시간으로 제어할 수 있도록 완성하는 작업이다.

1. **PAP (`internal/authz/pap`)**:
   - 권한의 라이프사이클(발급, 회수, Epoch 증가)을 관장하는 유일한 관리자 진입점.
   - Zone B 상태 저장소(`internal/authz/state.Store`)를 원자적으로 갱신하고, 모든 정책 변경을 `internal/audit.Writer`를 통해 감사 증거(`audit.jsonl`)로 확정한다.
2. **PIP (`internal/authz/pip`)**:
   - 정책 결정점(PDP)이 인가 판단 시 필요로 하는 최신 활성 Grant 목록과 주체별 Security Epoch를 공급하는 정보 제공점.
   - 파일 I/O를 직접 수행할 수 없는 순수 PDP 엔진에 격리된 스냅샷 객체(`SubjectSnapshot`)를 안전하게 제공하여, NIST SP 800-162 순수 결정 불변식을 성립시킨다.
3. **CLI 연동 (`cmd/authz-harness`, `internal/cli`)**:
   - 관리자가 직관적으로 권한을 생성(`grant create`), 회수(`grant revoke`), 세대 교체(`grant bump-epoch`), 목록 조회(`grant list`)할 수 있는 CLI 인터페이스를 완성한다.

---

## 2. 패키지 배치 및 6계층 DAG 구조

```text
Layer 5:  [cmd/authz-harness] / [internal/cli]  (CLI grant 서브커맨드)
             │                       │
             v (호출)                v (호출)
Layer 2B: [internal/authz/pap]   [internal/authz/pip]
             │         │             │
             │         │ (상태 조회) │
             │         +──────────┐  │
             │                    v  v
             │              [internal/authz/state] (FileStore: flock + Rename)
             │                     │
             v (감사 기록)          v
Layer 1:  [internal/audit] (JSONLWriter)
             │                     │
             v                     v
Layer 0:  [internal/domain] (Grant, SecurityEpoch, Action, Reason, ExitCode)
```

- **계층 분리 규칙**:
  - `internal/authz/pap`는 `internal/authz/state.Store`와 `internal/audit.Writer`에만 의존하며, PDP나 PEP에 역의존하지 않는다.
  - `internal/authz/pip`는 순수 읽기(`Store.Load()`) 전용 계층이며, 상태 쓰기(`Store.Save()`, `Store.Update()`) 함수를 절대 호출하지 않는다.
  - 차후 구축될 `internal/authz/pdp`(030 단계)는 디스크 I/O를 배제하고 오직 PIP가 반환한 스냅샷을 입력받는다.

---

## 3. 세부 설계 및 인터페이스 정의

### 3.1 PAP 인터페이스 및 서비스 (`internal/authz/pap`)

```go
package pap

import (
    "context"
    "authz-harness/internal/domain"
)

// CreateGrantRequest 는 권한 신규 발급 요청 명세다.
type CreateGrantRequest struct {
    Subject  string        `json:"subject"`
    Action   domain.Action `json:"action"`
    Resource string        `json:"resource"`
}

// GrantFilter 는 권한 목록 조회 시 필터 조건이다.
type GrantFilter struct {
    Subject string              `json:"subject,omitempty"`
    Status  *domain.GrantStatus `json:"status,omitempty"`
}

// Service 는 정책 관리점(PAP)의 핵심 관리 규약이다.
type Service interface {
    // CreateGrant 는 주체에게 특정 리소스/액션의 활성 권한을 발급하고 감사 로그를 남긴다.
    CreateGrant(ctx context.Context, req CreateGrantRequest) (*domain.Grant, error)

    // RevokeGrant 는 특정 ID의 권한을 즉시 회수 상태로 변경하고 감사 로그를 남긴다.
    RevokeGrant(ctx context.Context, grantID string) (*domain.Grant, error)

    // BumpEpoch 는 주체의 Security Epoch를 1 증가시켜 이전 권한/토큰을 일괄 무효화하고 감사 로그를 남긴다.
    BumpEpoch(ctx context.Context, subject string) (domain.Epoch, error)

    // ListGrants 는 조건에 부합하는 Grant 목록을 반환한다.
    ListGrants(ctx context.Context, filter GrantFilter) ([]domain.Grant, error)
}
```

- **감사 이벤트 매핑 (`internal/audit.Event`)**:
  - `grant.create`: `actor: "admin"`, `action: "grant.create"`, `resource: req.Resource`, `metadata: {"grant_id": g.ID, "subject": g.Subject}`
  - `grant.revoke`: `actor: "admin"`, `action: "grant.revoke"`, `metadata: {"grant_id": id, "subject": g.Subject}`
  - `epoch.bump`: `actor: "admin"`, `action: "epoch.bump"`, `metadata: {"subject": subject, "new_epoch": nextEpoch}`

### 3.2 PIP 인터페이스 및 서비스 (`internal/authz/pip`)

```go
package pip

import (
    "context"
    "time"
    "authz-harness/internal/domain"
)

// SubjectSnapshot 은 PDP 인가 결정을 위해 PIP가 제공하는 주체별 권한 상태 스냅샷이다.
type SubjectSnapshot struct {
    Subject      string         `json:"subject"`
    CurrentEpoch domain.Epoch   `json:"current_epoch"`
    ActiveGrants []domain.Grant `json:"active_grants"`
    Timestamp    time.Time      `json:"timestamp"`
}

// Service 는 정책 정보점(PIP)의 읽기 전용 조회 규약이다.
type Service interface {
    // GetSubjectSnapshot 은 PDP가 단일 트랜잭션에서 결정할 수 있도록 주체의 최신 Epoch와 활성 Grant 목록을 원자적으로 읽어 반환한다.
    GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)

    // GetActiveGrants 는 특정 주체의 활성화(active)된 Grant 목록만 반환한다.
    GetActiveGrants(ctx context.Context, subject string) ([]domain.Grant, error)

    // GetCurrentEpoch 는 특정 주체의 현재 Security Epoch를 반환한다 (미등록 주체는 기본값 1).
    GetCurrentEpoch(ctx context.Context, subject string) (domain.Epoch, error)
}
```

### 3.3 CLI 서브커맨드 UX 설계

```bash
# 1. Grant 발급
authz-harness grant create --sub <subject> --action <file:read|file:write> --resource <path>
# 출력 (stdout):
# [GRANT CREATED] ID: grant-xxx | Subject: worker-01 | Action: file:read | Resource: docs/plan.txt

# 2. Grant 회수
authz-harness grant revoke --id <grant_id>
# 출력 (stdout):
# [GRANT REVOKED] ID: grant-xxx | RevokedAt: 2026-11-01T18:30:00Z

# 3. Security Epoch 갱신 (일괄 무효화)
authz-harness grant bump-epoch --sub <subject>
# 출력 (stdout):
# [EPOCH BUMPED] Subject: worker-01 | Previous: 1 -> Current: 2

# 4. Grant 목록 조회
authz-harness grant list [--sub <subject>] [--status <active|revoked>]
```

---

## 4. 파급 범위와 무영향 근거 증명 (Impact Scope & Zero-Impact Proof)

1. **변경 및 추가 컴포넌트**:
   - `internal/authz/pap`: PAP 비즈니스 로직 및 감사 연동 신규 구현
   - `internal/authz/pip`: PIP 스냅샷 조회 및 필터링 로직 신규 구현
   - `cmd/authz-harness/main.go` & `internal/cli`: `grant` 서브커맨드 라우팅 및 플래그 파싱 배선
2. **무영향 컴포넌트 (Zero-Impact Proof)**:
   - `internal/domain`: 010 단계에서 정의된 `Grant`, `SecurityEpochs`, `Reason`, `ExitCode`를 그대로 활용하므로 도메인 규칙 파괴가 전혀 없음.
   - `internal/authz/state`: 010에서 검증된 `FileStore` 인터페이스를 그대로 주입받으므로 상태 동시성 엔진의 재작성이나 변경이 불필요함.
   - `internal/audit`: 기존 `JSONLWriter` 인터페이스를 사용하여 이벤트를 기록하므로 감사 저장 엔진에 영향을 주지 않음.
   - `internal/authz/pdp`: 030 단계 대상이므로 020 단계에서는 생성되지 않으며 무영향.

---

## 5. 사전 점검 및 실패 위험 분석 (Pre-Mortem)

1. **위험: 상태 저장소 쓰기 성공 후 감사 로그 쓰기 실패 시 데이터 불일치**
   - *원인*: 디스크 용량 부족이나 파일 권한 문제로 `audit.jsonl` 기록이 실패함.
   - *방어책*: Fail-Closed 보안 원칙에 따라, 감사 로깅이 실패하면 에러를 즉시 상위 호출자에게 전파하고 CLI는 `EXIT_AUDIT_FAILURE(15)`로 종료한다.
2. **위험: PIP 조회 시 오래된 상태(Stale State) 반환**
   - *원인*: PIP 내부에 부적절한 메모리 캐시를 두어 PAP의 최신 갱신을 즉시 반영하지 못함.
   - *방어책*: PIP 내부에는 별도의 장기 캐시를 두지 않고, 매 요청마다 `Store.Load()`(공유 락 기반)를 수행하여 디스크 상의 최신 진본 상태를 직접 읽도록 강제한다.
3. **위험: CLI 입력 인자 검증 누락으로 인한 샌드박스 오염**
   - *원인*: 리소스 경로에 `../`나 공백이 포함된 상태로 Grant가 발급됨.
   - *방어책*: `Grant.Validate()`를 호출하여 리소스 경로 탈출 시도를 사전에 차단하고, 필수 인자 누락 시 `EXIT_BAD_INPUT(14)`을 반환한다.

---

## 6. 4층위 검증 범위 설계

1. **1층위 (자동화 스크립트)**: `scripts/run_lint.sh` 및 Go 포맷팅 검증.
2. **2층위 (단위 및 구조 검증)**:
   - `internal/authz/pap/pap_test.go`: Grant 발급, 회수(성공 및 없는 ID 에러), Epoch 증가, 동시 호출 시 락 무결성 단위 테스트.
   - `internal/authz/pip/pip_test.go`: 주체별 스냅샷 생성, 활성 Grant 필터링, Epoch 조회 일관성 단위 테스트.
3. **3층위 (상태 및 정합성 검증)**:
   - PAP 작업 수행 후 `audit.jsonl`에 규격화된 이벤트가 누락 없이 기록되는지 대조.
   - `grants_state.json` 파일의 `version`, `updated_at`, `grants`, `epochs` 데이터 직렬화 정합성 검증.
4. **4층위 (CLI 인수 검증)**:
   - `authz-harness grant create`, `revoke`, `bump-epoch`, `list` 명령을 실제 실행하여 올바른 stdout 출력과 종료 코드(`0`, `14`) 확인.

---

## 7. 사전 인수 테스트 시나리오 (Acceptance Scenarios)

### 시나리오 1: Grant 정상 발급 및 감사 기록
- **입력 (Given/When)**:
  - `authz-harness grant create --sub worker-01 --action file:read --resource docs/plan.txt`
- **기대 결과 (Then)**:
  - stdout: `[GRANT CREATED] ID: grant-... | Subject: worker-01 | Action: file:read | Resource: docs/plan.txt`
  - 종료 코드: `EXIT_SUCCESS(0)`
  - `audit.jsonl`에 `action: "grant.create"`, `actor: "admin"` 이벤트 1건 기록 확인.

### 시나리오 2: 필수 플래그 누락 시 입력 오류 처리
- **입력 (Given/When)**:
  - `authz-harness grant create --sub worker-01` (action 및 resource 누락)
- **기대 결과 (Then)**:
  - stderr: 에러 안내 문구 출력
  - 종료 코드: `EXIT_BAD_INPUT(14)`
  - 상태 파일 및 감사 로그에 잘못된 레코드 미기록.

### 시나리오 3: 발급된 Grant의 명시적 회수 (Revoke)
- **입력 (Given/When)**:
  - 발급된 `grant_id`로 `authz-harness grant revoke --id <grant_id>` 호출
- **기대 결과 (Then)**:
  - stdout: `[GRANT REVOKED] ID: <grant_id>`
  - 종료 코드: `EXIT_SUCCESS(0)`
  - PIP를 통해 해당 주체의 활성 Grant 목록 조회 시 해당 ID가 제외됨.
  - `audit.jsonl`에 `action: "grant.revoke"` 이벤트 기록 확인.

### 시나리오 4: Security Epoch 증가에 따른 주체 세대 갱신
- **입력 (Given/When)**:
  - 주체 `worker-01`에 대해 `authz-harness grant bump-epoch --sub worker-01` 호출
- **기대 결과 (Then)**:
  - stdout: `[EPOCH BUMPED] Subject: worker-01 | Previous: 1 -> Current: 2`
  - 종료 코드: `EXIT_SUCCESS(0)`
  - PIP 조회 시 `worker-01`의 Epoch가 즉각 `2`로 반환됨.
  - `audit.jsonl`에 `action: "epoch.bump"` 이벤트 기록 확인.

### 시나리오 5: PIP 스냅샷 원자적 제공
- **입력 (Given/When)**:
  - 주체 `worker-01`에 활성 Grant 2건 발급, 1건 회수, Epoch = 2 상태에서 PIP의 `GetSubjectSnapshot("worker-01")` 호출
- **기대 결과 (Then)**:
  - 반환된 `SubjectSnapshot.CurrentEpoch` == 2
  - `SubjectSnapshot.ActiveGrants`의 길이는 정확히 2 (회수된 1건은 미포함)
  - 불변식 검증 성공.

---

## 8. 완료 조건 (Definition of Done)

- [x] `internal/authz/pap/service.go` 및 구현체 작성 완료
- [x] `internal/authz/pap/pap_test.go` 단위 테스트 작성 및 통과
- [x] `internal/authz/pip/service.go` 및 구현체 작성 완료
- [x] `internal/authz/pip/pip_test.go` 단위 테스트 작성 및 통과
- [x] `cmd/authz-harness/main.go`에 `grant` 서브커맨드(`create`, `revoke`, `bump-epoch`, `list`) 라우팅 완성
- [x] `go test -race -v ./internal/authz/pap/... ./internal/authz/pip/...` 100% 통과
- [x] Pre-commit 보안 스캔(`public_safety_scan.py`, `gitleaks`) 통과
- [x] 대시보드([README.md](../README.md)) 020 구현지시서 링크 등록 및 실행 기록 갱신
