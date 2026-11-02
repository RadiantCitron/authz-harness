# [구현지시서 040] 스포너 격리 배선, Fail-Closed 모드 및 `agent.confined` 감사 기록

> **문서 상태**: `Draft`
> **상위 대시보드**: [11번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_linux_어댑터_및_검증_환경.md](030_linux_어댑터_및_검증_환경.md) 완료
> **후속 단계**: [050_g10_악의_워커_시나리오.md](050_g10_악의_워커_시나리오.md)

---

## 1. 목적 및 배경

`010`~`030`에서 만든 `confinement.Confiner`와 `confinement.Policy`를 단일 합성 루트(`internal/app`)와 오케스트레이터 스포너(`internal/orchestrator/spawner.go`)에 배선한다.
격리 필수 모드(`RequireConfinement: true`)에서 어댑터가 없거나 프로파일 적용이 실패하면 자식 프로세스를 아예 기동하지 않고 `ExitInternalError(16)`로 거부(Fail-Closed)하며, 격리 적용 여부를 `agent.confined` 감사 이벤트로 기록한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/domain/event.go`: `EventAgentConfined EventType = "agent.confined"` 상수 추가
  - `internal/orchestrator/spawner.go`: `SpawnConfig`에 `Confiner confinement.Confiner` 및 `ConfinementPolicy confinement.Policy` 추가. 스폰 직전 `Confiner.WrapCommand` 호출 및 `agent.confined` 감사 기록
  - `internal/app/builder.go`: 플랫폼 기본 `Confiner` 선택 헬퍼 제공
  - `internal/subagent/testworker_enabled.go` (`//go:build testworker`): PEP를 우회해 직접 OS 파일/네트워크에 접근하는 악의 워커 모드 3종(`bypass_read_zone_a`, `bypass_write_outside`, `bypass_open_socket`) 추가
  - `internal/orchestrator/spawner_confinement_test.go` [신규]: 스포너 배선·Fail-Closed·정직한 워커 비회귀 테스트
- **무영향**:
  - `Confiner == nil`이고 `RequireConfinement == false`인 기본 설정에서는 기존 스포너 동작과 100% 동일하여 기존 `E2E-01`~`E2E-44` 시나리오에 영향을 주지 않는다.

---

## 3. 세부 명세

1. **스포너 격리 적용 및 감사 (`internal/orchestrator/spawner.go`)**:
   - `s.cfg.ConfinementPolicy.RequireConfinement == true`인데 `s.cfg.Confiner == nil`이거나 `!s.cfg.Confiner.Available()`이면, 프로세스를 실행하지 않고 `agent.confined` 실패 감사를 기록한 뒤 `*domain.Error`(`ReasonConfinementUnavailable`, `ExitInternalError = 16`)를 반환한다.
   - `Confiner != nil`이면 `Confiner.WrapCommand(cmd, policy)`를 적용하고, `ORCHESTRATE_SPAWN` 또는 `agent.confined` 감사 이벤트 메타데이터에 `confiner: confiner.Name()`, `confined: true`를 기록한다.
2. **테스트 전용 악의 워커 모드 추가 (`internal/subagent/testworker_enabled.go`)**:
   - `bypass_read_zone_a`: PEP를 거치지 않고 `os.ReadFile(targetPath)`로 Zone A 개인키 파일을 직접 읽으려 시도한다.
   - `bypass_write_outside`: PEP를 거치지 않고 `os.WriteFile(targetPath, ...)`로 Workspace 외부 경로에 직접 파일을 쓰려 시도한다.
   - `bypass_open_socket`: PEP를 거치지 않고 `net.Listen("tcp", "127.0.0.1:0")`로 로컬 소켓 오픈을 시도한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `RequireConfinement: true` + `NoopConfiner`(또는 `nil`)로 `Spawner.Spawn` 호출 | 자식 프로세스 미기동, `ReasonConfinementUnavailable`(`16`) 에러 반환 |
| **TC-040-02** | `SeatbeltConfiner` 활성 상태에서 정직한 워커의 `file:read` / `file:write` 실행 | `ExitCode == 0`, 정상 수행 및 `audit.jsonl`에 `agent.confined` 기록 |
| **TC-040-03** | 감사 기록 실패 주입 상태에서 격리 스폰 호출 | 자식 프로세스 미기동, `ExitAuditFailure(15)` 반환 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/orchestrator -run TestSpawnerConfinement` PASS
2. `go test -v -tags testworker ./internal/orchestrator` PASS
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `Spawner` 격리 어댑터 배선 및 `RequireConfinement` Fail-Closed 구현
- [ ] `agent.confined` 감사 기록 및 정직한 워커 비회귀 검증 완료
- [ ] `testworker` 악의 모드 3종 추가 및 일반 빌드 심볼 부재 유지 확인
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
