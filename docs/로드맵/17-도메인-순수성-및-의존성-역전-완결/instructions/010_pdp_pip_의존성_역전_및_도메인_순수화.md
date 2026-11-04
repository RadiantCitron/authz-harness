# [구현지시서 010] PDP-PIP·Audit 의존성 역전(DIP) 완결 및 도메인 스냅샷·감사 포트 순수화

> **문서 상태**: `Draft` ([026번 보고서](../../../보고서/026-17번로드맵_구조결함_및_진행가능성_검증보고서.md) 검증 완료 — 착수 가능)
> **상위 대시보드**: [17번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [로드맵 16](../../16-도구-종류-확장-및-egress-통제/README.md) `Done` (79대 PASS)
> **후속 단계**: [030_cli_합성루트_일원화_및_중복_제거.md](030_cli_합성루트_일원화_및_중복_제거.md) (`020`은 과잉 추상화 배제를 위해 `Dropped`)

---

## 1. 목적 및 배경

현재 [`internal/authz/pdp/service.go`](../../../../internal/authz/pdp/service.go)는 `"os"`를 직접 import하지 않지만(`TC-060-01`), 다음 **두 갈래의 전이적(Transitive) 의존성**을 통해 하위 인프라(`storage`, `os`, `syscall`)를 끌고 들어오고 있다:
1. `"authz-harness/internal/authz/pip"` import → `pip`가 `internal/authz/state`를 import → `state`가 `internal/storage`(`os`, `syscall`)를 import함.
2. `"authz-harness/internal/audit"` import → `audit` 패키지 안에 인터페이스(`audit.Writer`)와 파일 구현체(`JSONLWriter`: `os`, `syscall`, `storage` 사용)가 함께 들어 있어 `pdp`가 전이적으로 `internal/audit` 및 그 내부의 `os`와 `syscall`에 의존함.

본 단계에서는 순수 값 객체와 포트 인터페이스(`SubjectSnapshot`, `SnapshotProvider`, `AuditEvent`, `AuditWriter`)를 `internal/domain`으로 이동하고 `pip`와 `audit`에는 **Go 타입 별칭(`type ... = domain....`)**을 두어, 기존 호출부 코드를 단 1줄도 깨뜨리지 않으면서 **`internal/authz/pdp`의 프로젝트 내부 전이적 의존성을 오직 `internal/domain` 단 하나로 수렴시키는 완벽한 의존성 역전(DIP)**을 달성한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/domain/snapshot.go` [신규]: 현행 [`internal/authz/pip/service.go`](../../../../internal/authz/pip/service.go)(14~24행) 및 [`internal/audit/audit.go`](../../../../internal/audit/audit.go)(18~37, 152~155행)의 실제 정의와 100% 일치하는 순수 타입·포트 정의:
    - `SubjectSnapshot`: `Subject string`, `CurrentEpoch Epoch`, `ActiveGrants []Grant`, `RevokedGrants []Grant`, `Timestamp time.Time`, `SubjectEpochs SecurityEpochs`, `Approvals []Approval` (※ 12·15번 로드맵에서 폐기된 `BudgetEntries`나 `StateVersion`은 절대 추가하지 말 것 — [026번 보고서](../../../보고서/026-17번로드맵_구조결함_및_진행가능성_검증보고서.md) `D17-04`)
    - `SnapshotProvider`: `GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)`
    - `AuditEvent` 및 `AuditWriter`: `Log(event AuditEvent) error`, `Close() error`
  - `internal/authz/pip/service.go`: `type SubjectSnapshot = domain.SubjectSnapshot` 타입 별칭 선언 (`pip.Service`는 `GetSubjectSnapshot` 시그니처를 그대로 유지하여 자동으로 `domain.SnapshotProvider`를 만족함)
  - `internal/audit/audit.go`: `type Event = domain.AuditEvent`, `type Writer = domain.AuditWriter` 타입 별칭 선언으로 기존 `audit.Event`·`audit.Writer` 참조 코드 100% 무수정 호환 보장
  - `internal/authz/pdp/service.go`:
    - `"authz-harness/internal/authz/pip"` 및 `"authz-harness/internal/audit"` import를 완전히 제거하고 오직 `"authz-harness/internal/domain"`(및 표준 라이브러리 `context`, `fmt`, `strings`, `time`)만 import하도록 전환
    - `Evaluate(req Request, snapshot *domain.SubjectSnapshot) Decision`
    - `pdpService.pipSvc`의 타입을 `domain.SnapshotProvider`로, `pdpService.audit`의 타입을 `domain.AuditWriter`로, `NewService(pipSvc domain.SnapshotProvider, audit domain.AuditWriter, opts ...ServiceOption) Service`로 전환하고 내부 감사 이벤트 생성을 `domain.AuditEvent{...}`로 변경
- **무영향**:
  - Go의 타입 별칭(`=`)은 동일 타입으로 취급되므로, 기존 테스트(`pdp_test.go`, `ask_test.go`, `pdp_actor_test.go`, `pip_test.go`, `gateway_test.go`)와 시나리오 코드는 수정 없이 100% 그대로 컴파일·통과된다.

---

## 3. 세부 명세 (`internal/domain/snapshot.go`)

```go
package domain

import (
	"context"
	"time"
)

// SubjectSnapshot 은 PDP 인가 결정을 위해 공급되는 주체별 권한 상태 스냅샷이다.
type SubjectSnapshot struct {
	Subject       string         `json:"subject"`
	CurrentEpoch  Epoch          `json:"current_epoch"`
	ActiveGrants  []Grant        `json:"active_grants"`
	RevokedGrants []Grant        `json:"revoked_grants,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
	SubjectEpochs SecurityEpochs `json:"subject_epochs,omitempty"`
	Approvals     []Approval     `json:"approvals,omitempty"`
}

// SnapshotProvider 는 PDP가 주체 상태 스냅샷을 조회하는 도메인 포트(DIP)다.
type SnapshotProvider interface {
	GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)
}

// AuditEvent 는 감사 로그에 기록되는 불변의 보안 증거 레코드 스키마다.
type AuditEvent struct {
	SchemaVersion int                    `json:"schema_version,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	TraceID       string                 `json:"trace_id"`
	Step          string                 `json:"step,omitempty"`
	Actor         string                 `json:"actor"`
	AgentID       string                 `json:"agent_id,omitempty"`
	Action        string                 `json:"action,omitempty"`
	Resource      string                 `json:"resource,omitempty"`
	Decision      string                 `json:"decision,omitempty"`
	Reason        string                 `json:"reason,omitempty"`
	TokenJTI      string                 `json:"token_jti,omitempty"`
	ArgHash       string                 `json:"arg_hash,omitempty"`
	ResultHash    string                 `json:"result_hash,omitempty"`
	Success       bool                   `json:"success"`
	ErrorClass    string                 `json:"error_class,omitempty"`
	PrevHash      string                 `json:"prev_hash,omitempty"`
	CurrHash      string                 `json:"curr_hash,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// AuditWriter 는 감사 로그를 Append-only 방식으로 기록하는 도메인 포트(DIP)다.
type AuditWriter interface {
	Log(event AuditEvent) error
	Close() error
}
```

### 전이적 인프라 의존성 절단 확인 주의사항 ([026번 보고서](../../../보고서/026-17번로드맵_구조결함_및_진행가능성_검증보고서.md) `D17-02`)
- Go 표준 라이브러리의 `time`과 `crypto/ed25519`는 내부적으로 표준 라이브러리 `os`와 `syscall`을 import하므로, `go list -deps` 전체 출력에는 항상 표준 라이브러리 `os`와 `syscall`이 나타난다.
- 따라서 `go list -deps ./internal/authz/pdp`로 확인할 때는 **`authz-harness/` 접두사를 가진 프로젝트 내부 패키지 목록**을 확인해야 하며, 그 결과가 오직 `authz-harness/internal/domain`과 `authz-harness/internal/authz/pdp` 2개뿐이고 `pip`, `state`, `audit`, `storage`가 0건이어야 한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | `go list -deps ./internal/authz/pdp \| grep '^authz-harness/'` 실행 | 출력이 `authz-harness/internal/domain`과 `authz-harness/internal/authz/pdp` 2줄뿐이며, `pip`, `state`, `audit`, `storage` 0건 |
| **TC-010-02** | 기존 `pdp`, `pip`, `audit`, `pep` 단위 테스트 전수 실행 | 기존 테스트 파일 무수정 상태에서 100% `PASS` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/domain ./internal/authz/pdp ./internal/authz/pip ./internal/audit ./internal/authz/pep` PASS
2. `go list -deps ./internal/authz/pdp | grep '^authz-harness/'` 결과에 `pip`, `state`, `audit`, `storage` 0건
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `internal/domain/snapshot.go` 생성(`SubjectSnapshot`, `SnapshotProvider`, `AuditEvent`, `AuditWriter`) 및 `pip`·`audit` 타입 별칭(`=`) 선언 완료
- [ ] `internal/authz/pdp/service.go`에서 `pip`·`audit` import 제거 및 프로젝트 내부 전이 의존성(`domain` 단독) 확인 후 단독 커밋
