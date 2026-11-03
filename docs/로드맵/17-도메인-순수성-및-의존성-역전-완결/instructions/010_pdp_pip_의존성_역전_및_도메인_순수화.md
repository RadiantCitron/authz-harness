# [구현지시서 010] PDP-PIP·Audit 의존성 역전(DIP) 완결 및 도메인 스냅샷·감사 포트 순수화

> **문서 상태**: `Draft`
> **상위 대시보드**: [17번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [로드맵 16](../../16-도구-종류-확장-및-egress-통제/README.md) `Done`
> **후속 단계**: [030_cli_합성루트_일원화_및_중복_제거.md](030_cli_합성루트_일원화_및_중복_제거.md) (`020`은 과잉 추상화 배제를 위해 `Dropped`)

---

## 1. 목적 및 배경

현재 [`internal/authz/pdp/service.go`](../../../../internal/authz/pdp/service.go)는 `"os"`를 직접 import하지 않지만(`TC-060-01`), 다음 **두 갈래의 전이적(Transitive) 의존성**을 통해 하위 인프라(`storage`, `os`, `syscall`)를 끌고 들어오고 있다:
1. `"authz-harness/internal/authz/pip"` import → `pip`가 `internal/authz/state`를 import → `state`가 `internal/storage`(`os`, `syscall`)를 import함.
2. `"authz-harness/internal/audit"` import → `audit` 패키지 안에 인터페이스(`audit.Writer`)와 파일 구현체(`JSONLWriter`: `os`, `syscall`, `storage` 사용)가 함께 들어 있어 `pdp`가 전이적으로 `os`와 `syscall`에 의존함.

본 단계에서는 순수 값 객체와 포트 인터페이스(`SubjectSnapshot`, `SnapshotProvider`, `AuditEvent`, `AuditWriter`)를 `internal/domain`으로 이동하고 `pip`와 `audit`에는 **Go 타입 별칭(`type ... = domain....`)**을 두어, 기존 호출부 코드를 단 1줄도 깨뜨리지 않으면서 **`internal/authz/pdp`의 전이적 프로젝트 의존성을 오직 `internal/domain` 단 하나로 수렴시키는 완벽한 의존성 역전(DIP)**을 달성한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/domain/snapshot.go` [신규]: Phase 01~15 및 [011번 보고서](../../../보고서/011-권한관리_본질_코어파이프라인_안티패턴_및_분산적응형_기본구조_전문가진단_보고서.md)의 모든 누적 필드를 포함한 순수 `SubjectSnapshot` 구조체(`Subject`, `CurrentEpoch`, `SubjectEpochs SecurityEpochs`[계보 연쇄 Epoch 검증용], `StateVersion int`[단조 증가 원장 버전], `ActiveGrants`, `RevokedGrants`, Phase 12의 `BudgetEntries map[string]BudgetEntry`, Phase 15의 `Approvals []Approval`, `Timestamp`) 및 `SnapshotProvider` 인터페이스 정의
  - `internal/authz/pip/service.go`: `type SubjectSnapshot = domain.SubjectSnapshot` 타입 별칭 선언 및 `domain.SnapshotProvider` 구현
  - `internal/audit/audit.go`: `type Event = domain.AuditEvent`, `type Writer = domain.AuditWriter` 타입 별칭 선언으로 기존 `audit.Event`·`audit.Writer` 참조 코드 100% 무수정 호환 보장
  - `internal/authz/pdp/service.go`: `"authz-harness/internal/authz/pip"` 및 `"authz-harness/internal/audit"` import를 제거하고 오직 `"authz-harness/internal/domain"`(및 순수 표준 라이브러리 `context`, `fmt`, `strings`, `time`)만 import하도록 전환
- **무영향**:
  - Go의 타입 별칭(`=`)은 동일 타입으로 취급되므로, 기존 테스트(`pdp_test.go`, `pip_test.go`, `gateway_test.go`)와 시나리오 코드는 수정 없이 100% 그대로 컴파일·통과된다.

---

## 3. 세부 명세

1. **전이적 인프라 의존성 완전 절단 검증**:
   - 변경 후 `go list -deps ./internal/authz/pdp` 실행 시 프로젝트 내부 패키지는 `authz-harness/internal/domain`만 출력되어야 하며, `pip`, `state`, `audit`, `storage`, `os`, `syscall`이 단 하나도 포함되지 않아야 한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | `go list -deps ./internal/authz/pdp` 실행 | 출력 목록에 `pip`, `state`, `audit`, `storage`, `os`, `syscall` 0건 |
| **TC-010-02** | 기존 `pdp`, `pip`, `audit`, `pep` 단위 테스트 전수 실행 | 100% `PASS` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/domain ./internal/authz/pdp ./internal/authz/pip ./internal/audit` PASS
2. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `domain.SubjectSnapshot`/`SnapshotProvider` 및 `domain.AuditEvent`/`AuditWriter` 이동 + `pip`·`audit` 타입 별칭 선언 완료
- [ ] `pdp`에서 `pip`·`audit` import 제거 및 전이적 순수성 확인 후 단독 커밋
