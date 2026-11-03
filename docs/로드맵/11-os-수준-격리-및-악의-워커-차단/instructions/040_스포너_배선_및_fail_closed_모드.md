# [구현지시서 040] 스포너 격리 배선, Fail-Closed 모드 및 `agent.confined` 감사 기록

> **문서 상태**: `Draft`
> **상위 대시보드**: [11번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_linux_어댑터_및_검증_환경.md](030_linux_어댑터_및_검증_환경.md) 완료
> **후속 단계**: [050_g10_악의_워커_시나리오.md](050_g10_악의_워커_시나리오.md)

---

## 1. 목적 및 배경

`010`~`030`에서 만든 `confinement.Confiner`와 `confinement.ConfinementPolicy`를 오케스트레이터 스포너(`internal/orchestrator/spawner.go`)와 단일 합성 루트(`internal/app`)에 배선한다.
격리 필수 모드(`RequireConfinement: true`)에서 어댑터가 없거나(`nil` 또는 `NoopConfiner`) 프로파일/커널 격리 적용(`Prepare`)이 실패하면 자식 프로세스를 아예 기동하지 않고 `ExitInternalError(16)`로 거부(Fail-Closed)하며, 악의 워커가 커널 격리에 의해 차단되었을 때 `Action: "agent.confined"`, `Decision: "deny"`, `Reason: "CONFINEMENT_VIOLATION"` 감사 이벤트를 기록하여 하네스 Quad-Assertion(`assertion.go`)과 정확히 맞물리게 한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/orchestrator/spawner.go`:
    - `SpawnConfig`에 `Confiner confinement.Confiner` 및 `ConfinementPolicy confinement.ConfinementPolicy` 필드 추가
    - 스폰 직전 `Confiner.Prepare(cmd, policy)` 호출 및 `defer cleanup()` 보장
    - 격리 적용 실패 시 자식 미기동 Fail-Closed(`ExitInternalError = 16`, `ReasonConfinementUnavailable`) 및 감사 기록
    - 격리 활성 상태에서 자식이 `ExitPathViolation(13)`(`ReasonConfinementViolation`) 등으로 차단 종료되면 사후 감사 이벤트(`Action: "agent.confined"`, `Decision: "deny"`, `Reason: "CONFINEMENT_VIOLATION"`) 기록
  - `internal/subagent/testworker_enabled.go` (`//go:build testworker`) 및 `internal/cli/subagent.go`:
    - `-test-fault` 및 `-test-target <path>` 플래그를 통해 PEP를 완전히 건너뛰고 직접 OS 시스템콜을 호출하는 악의 워커 모드 4종(`bypass_read_zone_a`, `bypass_write_outside`, `bypass_open_socket`, `bypass_child_read_zone_a`) 추가
  - `internal/orchestrator/spawner_confinement_test.go` [신규]: 스포너 격리 배선·Fail-Closed·정직한 워커 비회귀 단위 테스트
- **무영향**:
  - `Confiner == nil`이고 `RequireConfinement == false`인 기본 설정에서는 기존 스포너 동작 및 `ORCHESTRATE_SPAWN` / `ORCHESTRATE_COLLECT` 2이벤트 구조와 100% 동일하여 기존 `E2E-01`~`E2E-44` 시나리오에 영향을 주지 않는다.

---

## 3. 세부 명세

### 3.1 스포너 격리 적용 및 `agent.confined` 감사 기록 (`internal/orchestrator/spawner.go`)
1. **사전 검증 및 `Prepare` 호출**:
   - `s.cfg.ConfinementPolicy.RequireConfinement == true`인데 `s.cfg.Confiner == nil`이거나 `!s.cfg.Confiner.Available()`이면:
     - `s.cfg.Audit != nil`일 때 `Action: domain.AuditActionAgentConfined`(`"agent.confined"`), `Step: "ORCHESTRATE_CONFINEMENT_FAILED"`, `Decision: "deny"`, `Reason: string(domain.ReasonConfinementUnavailable)`, `Success: false` 감사 이벤트를 기록한다 (감사 기록 자체가 실패하면 `ExitAuditFailure = 15` 반환).
     - 자식 프로세스를 기동하지 않고 `&SpawnResult{TraceID: req.TraceID, ExitCode: int(domain.ExitInternalError), Reason: domain.ReasonConfinementUnavailable}, nil`(또는 대응 에러)을 반환한다.
   - `s.cfg.Confiner != nil`이면 `cleanup, err := s.cfg.Confiner.Prepare(cmd, s.cfg.ConfinementPolicy)`를 호출하고 `defer cleanup()`을 등록한다.
2. **사후 감사 기록**:
   - 격리가 적용된 스폰(`s.cfg.Confiner != nil && s.cfg.Confiner.Available()`)에서 자식이 `ReasonConfinementViolation`(`ExitCode == 13`)으로 차단 종료된 경우, 사후 감사 이벤트를 `Action: domain.AuditActionAgentConfined`(`"agent.confined"`), `Step: "ORCHESTRATE_CONFINED_BLOCK"`, `Decision: "deny"`, `Reason: string(domain.ReasonConfinementViolation)`, `Success: false`, `Metadata: {"confiner": s.cfg.Confiner.Name(), "exit_code": result.ExitCode}`로 기록하여 `assertion.go`의 `ExpectedAction: "agent.confined"` 검증과 100% 일치시킨다.

### 3.2 테스트 전용 악의 워커 모드 4종 (`internal/subagent/testworker_enabled.go`)
1. `bypass_read_zone_a`: PEP를 전혀 거치지 않고 `os.ReadFile(targetPath)`로 Zone A 개인키 파일을 직접 읽는다.
   - 커널이 차단(`err != nil`)하면 `SubagentResponse{ExitCode: 13, Reason: "CONFINEMENT_VIOLATION", Error: err.Error()}`를 출력하고 종료 코드 `13`(`ExitPathViolation`)을 반환한다.
   - 읽기에 성공하면(격리 끔 대조군) 종료 코드 `0`을 반환한다.
2. `bypass_write_outside`: PEP를 거치지 않고 `os.WriteFile(targetPath, []byte("pwned"), 0600)`으로 외부 경로에 직접 파일 쓰기를 시도한다. 차단 시 `13`(`CONFINEMENT_VIOLATION`), 성공 시 `0`을 반환한다.
3. `bypass_open_socket`: PEP를 거치지 않고 루프백 TCP 소켓 생성을 시도한다. 커널/격리에 의해 차단되면 `13`(`CONFINEMENT_VIOLATION`), 성공 시 소켓을 닫고 `0`을 반환한다.
4. `bypass_child_read_zone_a`: 자식(손자) 프로세스를 한 단계 더 띄워 그 손자 프로세스가 `bypass_read_zone_a`를 수행하게 하고 손자의 종료 코드를 그대로 반환한다(커널 격리 프로파일/DAC가 손자 프로세스에도 상속되어 우회할 수 없음을 증명).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `RequireConfinement: true` + `NoopConfiner`로 스폰 실행 | 자식 미기동, `ExitCode == 16`, 감사에 `Action: "agent.confined"`, `Reason: "CONFINEMENT_UNAVAILABLE"` 기록 |
| **TC-040-02** | `DefaultConfiner()` 활성 상태에서 정직한 워커로 `file:read` / `file:write` 실행 | `ExitCode == 0`, 정상 파일 읽기·쓰기 성공 |
| **TC-040-03** | `DefaultConfiner()` 활성 상태에서 `bypass_read_zone_a` 악의 워커 스폰 | 커널 차단으로 `ExitCode == 13`, 감사에 `Action: "agent.confined"`, `Reason: "CONFINEMENT_VIOLATION"` 기록 |

---

## 5. 4층위 검증 기준

1. `go test -v -tags testworker ./internal/orchestrator -run TestSpawnerConfinement` PASS
2. `go test -v ./internal/subagent -run TestWorkerSymbolAbsence` PASS (일반 빌드 심볼 0건 유지)
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `Spawner` 내 `Confiner.Prepare` 및 `defer cleanup()` 배선 완료
- [ ] `agent.confined` 감사 기록 및 `testworker` 악의 모드 4종 구현 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
