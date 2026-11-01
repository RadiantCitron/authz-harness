# 010. 원자적 Grant/Epoch 상태 저장소 구축 구현지시서

> **상태**: `Draft`
> **선행 조건**: Phase 0 (기반 골격 및 삼분 배선) 완료
> **상위 대시보드**: [README.md](../README.md) | **마스터 설계**: [ROADMAP.md](../ROADMAP.md)

---

## 1. 목적 (Context & Why)

본 지시서는 NIST SP 800-162 표준의 권한 관리점(PAP)과 정책 정보점(PIP)이 공유할 **Zone B 상태 저장소(`./.authz-state/public/grants_state.json`)**의 기반 모델과 저장소 계층을 구축하는 작업이다.

다중 프로세스(CLI, 오케스트레이터, 서브에이전트)가 동시에 상태를 조회하거나 갱신하더라도 데이터가 손상(Torn Read/Write)되지 않도록, OS 수준의 배타적 파일 락(`flock`)과 원자적 파일 교체(Atomic Write-and-Rename)를 강제하는 동시성 안전 저장소(`FileStore`)를 완성한다.

---

## 2. 패키지 배치 및 6계층 DAG 구조

```text
Layer 2B: [internal/authz/state] (FileStore: flock + Atomic Rename)
   │
   v (단방향 참조)
Layer 0:  [internal/domain] (Grant, SecurityEpoch, Action, Reason, ExitCode)
```

- **Layer 0 (`internal/domain`)**: 외부 의존성 없는 순수 원시 타입 및 표준 상수 정의.
- **Layer 2B (`internal/authz/state`)**: Zone B 물리 디스크 파일과 메모리 스냅샷 간의 원자적 동기화 전당. **순수 PDP 패키지가 파일 I/O를 직접 하지 않도록 저장소 로직을 완전히 캡슐화.**

---

## 3. 세부 설계 및 JSON 스키마

### 3.1 Zone B 상태 스키마 (`grants_state.json`)

```json
{
  "version": 1,
  "updated_at": "2026-11-01T18:00:00Z",
  "grants": [
    {
      "id": "grant-550e8400-e29b-41d4-a716-446655440000",
      "subject": "worker-01",
      "action": "file:read",
      "resource": "docs/plan.txt",
      "status": "active",
      "created_at": "2026-11-01T18:00:00Z",
      "revoked_at": null
    }
  ],
  "epochs": {
    "worker-01": 1
  }
}
```

### 3.2 핵심 인터페이스 계약 (`internal/authz/state`)

```go
type Store interface {
    // Load 는 Zone B 상태 파일을 공유 락(Shared Lock)으로 읽어 스냅샷을 반환한다.
    Load() (*domain.GrantsState, error)
    
    // Save 는 상태를 임시 파일에 기록한 뒤 배타적 락(Exclusive Lock) 하에서 원자적으로 교체한다.
    Save(state *domain.GrantsState) error
    
    // Update 는 배타적 락을 획득한 상태에서 상태를 읽고, 변경 함수를 실행한 후 저장하는 트랜잭션 함수다.
    Update(fn func(state *domain.GrantsState) error) error
}
```

---

## 4. 작업 내역 및 산출물 (구현 대상)

1. `internal/domain/grant.go`:
   - `Grant`: ID, Subject, Action, Resource, Status, CreatedAt, RevokedAt
   - `GrantStatus`: `GrantStatusActive = "active"`, `GrantStatusRevoked = "revoked"`
   - `Action`: `ActionFileRead = "file:read"`, `ActionFileWrite = "file:write"`
   - `Validate()`: 필수 필드 및 경로 규칙 정규화 검증
2. `internal/domain/epoch.go`:
   - `SecurityEpoch`: Subject별 정수 버전 매핑 및 증가 함수
3. `internal/domain/constants.go`:
   - 마스터 로드맵 §13 표준 `ExitCode` (`EXIT_SUCCESS(0)`, `EXIT_TOKEN_INVALID(11)`, `EXIT_AUTHZ_DENIED(12)`, `EXIT_PATH_VIOLATION(13)`, `EXIT_BAD_INPUT(14)`, `EXIT_AUDIT_FAILURE(15)`, `EXIT_INTERNAL_ERROR(16)`)
   - 표준 `Reason` (`AUTHORIZED`, `NO_ACTIVE_GRANT`, `GRANT_REVOKED`, `SUBJECT_EPOCH_REVOKED`, `TOKEN_INSUFFICIENT_SCOPE` 등)
4. `internal/domain/domain_test.go`:
   - 도메인 모델 직렬화/역직렬화 및 유효성 검증 단위 테스트
5. `internal/authz/state/store.go`:
   - `GrantsState` 구조체 및 `FileStore` 구현체
   - `syscall.Flock` 기반 파일 잠금 및 `.tmp` 원자적 `os.Rename` 로직
6. `internal/authz/state/store_test.go`:
   - 원자적 저장소 기본 연산 및 `-race` 동시성 테스트

---

## 5. 사전 인수 테스트 시나리오 (Acceptance Scenarios)

- **시나리오 1 (빈 상태 자동 초기화)**: 상태 파일이 아직 존재하지 않는 경로로 `NewFileStore` 호출 후 `Load` 시, 에러 없이 버전 1의 빈 상태(비어있는 슬라이스 및 맵)가 반환된다.
- **시나리오 2 (Grant 생성 및 영속화)**: `Update` 함수를 통해 새 `Grant`를 추가하고 저장한 뒤, 새 `Store` 인스턴스로 다시 `Load`했을 때 동일한 데이터가 완벽히 복원된다.
- **시나리오 3 (Epoch 일괄 무효화 반영)**: 특정 Subject의 Epoch를 `1`에서 `2`로 증가시킨 후 저장 시, 디스크 JSON에 즉각 반영되어 PIP 조회가 지연 없이 최신 Epoch를 인식한다.
- **시나리오 4 (Atomic Rename 실패 방어)**: 쓰기 도중 에러가 발생하더라도 원본 상태 파일이 0바이트로 깨지거나 손상되지 않고 직전 상태를 온전히 보존한다.
- **시나리오 5 (동시성 무결성 & Race 검증)**: 20개의 고루틴이 동시에 `Update`를 호출하여 각각 다른 Grant를 추가할 때, Data Race가 발생하지 않고 최종 결과에 20개의 Grant가 누락 없이 기록된다 (`go test -race`).

---

## 6. 완료 조건 (Definition of Done)

- [ ] 산출물 파일 6종 작성 완료
- [ ] `go test -race -v ./internal/domain/... ./internal/authz/state/...` 100% 통과
- [ ] Pre-commit 보안 스캔(`public_safety_scan.py`, `gitleaks`) 통과
- [ ] 대시보드([README.md](../README.md)) 010 상태를 `Done`으로 갱신 후 커밋
