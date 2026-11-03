# [구현지시서 010] PDP-PIP 의존성 역전(DIP) 완결 및 도메인 스냅샷 순수화

> **문서 상태**: `Draft`
> **상위 대시보드**: [17번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [로드맵 16](../../16-도구-종류-확장-및-egress-통제/README.md) `Done`
> **후속 단계**: [020_pep_도구_핸들러_전략_포트_추상화.md](020_pep_도구_핸들러_전략_포트_추상화.md)

---

## 1. 목적 및 배경

현재 [`internal/authz/pdp/service.go`](../../../../internal/authz/pdp/service.go)는 `internal/authz/pip` 패키지를 직접 import하고 있어, `pdp → pip → state → storage(os, syscall)`로 이어지는 전이적(Transitive) 인프라 의존성을 갖고 있다.
본 단계에서는 스냅샷 값 객체(`SubjectSnapshot`)와 조회 포트 인터페이스(`SnapshotProvider`)를 순수 도메인(`internal/domain`)으로 이동하고 `pip.Service`가 이를 구현하게 함으로써, **고수준 정책 결정 코어(`pdp`)가 저수준 데이터 공급 구현체(`pip`)에 의존하지 않고 둘 다 추상화(`domain`)에 의존하는 교과서적 의존성 역전(DIP)**을 완성한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/domain/snapshot.go` [신규]: `SubjectSnapshot` 구조체 및 `SnapshotProvider` 인터페이스(`GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)`) 정의
  - `internal/authz/pip/service.go`: `type SubjectSnapshot = domain.SubjectSnapshot` 타입 별칭(하위 호환 유지) 및 `domain.SnapshotProvider` 구현
  - `internal/authz/pdp/service.go`: `"authz-harness/internal/authz/pip"` import를 제거하고 `domain.SnapshotProvider`와 `*domain.SubjectSnapshot`만 참조하도록 전환
- **무영향**:
  - `pip.SubjectSnapshot` 타입 별칭을 유지하므로 기존 모든 테스트 코드(`pdp_test.go`, `pip_test.go`)는 수정 없이 100% 그대로 컴파일·통과된다.

---

## 3. 세부 명세

1. **전이적 인프라 의존성 완전 절단**:
   - 변경 후 `go list -deps ./internal/authz/pdp` 실행 시 `internal/authz/pip`, `internal/authz/state`, `internal/storage`, `os`, `syscall`이 단 하나도 포함되지 않아야 한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | `go list -deps ./internal/authz/pdp` 실행 | 출력 목록에 `pip`, `state`, `storage`, `os`, `syscall` 0건 |
| **TC-010-02** | 기존 `pdp` 및 `pip` 단위 테스트 전수 실행 | 100% `PASS` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pdp ./internal/authz/pip` PASS
2. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `domain.SubjectSnapshot` 및 `domain.SnapshotProvider` 이동 완료
- [ ] `pdp`의 `pip` 직접 import 제거 및 전이적 순수성 확인 후 단독 커밋
