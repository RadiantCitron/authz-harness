# [구현지시서 040] 감사 이벤트(`agent.limit_exceeded`)·UI·MCP 오류 매핑

> **문서 상태**: `Draft`
> **상위 대시보드**: [10번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_출력_상한_리더_및_rlimit_적용.md](030_출력_상한_리더_및_rlimit_적용.md) 완료
> **후속 단계**: [050_g9_e2e_시나리오.md](050_g9_e2e_시나리오.md)

---

## 1. 목적 및 배경

`020`과 `030`에서 구현한 프로세스 그룹 종료 및 출력 상한 차단이 발생했을 때, ① 감사 원장(`audit.jsonl`)에 전용 이벤트(`agent.limit_exceeded`)와 구체적 `Reason`·`RLimitResult`가 기록되고, ② MCP 어댑터(`internal/mcp`)가 종료 코드 `17`과 `Reason` 3종을 누락 없이 JSON-RPC 에러 응답으로 매핑하며, ③ 하네스 UI(`internal/ui`)가 자원 한계 차단 관문과 해설을 명확히 표시하도록 전 구간 배선을 완성한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/domain/event.go`: `EventAgentLimitExceeded EventType = "agent.limit_exceeded"` 상수 추가
  - `internal/orchestrator/spawner.go`: 자원 한계(`ExitCode == 17`) 발생 시 `agent.limit_exceeded` 감사 이벤트(Reason, `timed_out`, `output_exceeded`, `rlimit` 상태 포함) 기록. 감사 기록 실패 시 기존 원칙대로 `ExitAuditFailure(15)`로 Fail-Closed 수렴
  - `internal/mcp/errors.go`: `MapSubprocessError`에 `domain.ExitResourceLimit(17)` 기본 Reason 폴백(`ReasonResourceTimeout`) 및 Reason 3종(`RESOURCE_TIMEOUT`, `RESOURCE_OUTPUT_LIMIT`, `RESOURCE_SIGNAL_KILLED`) 매핑 추가
  - `internal/mcp/errors_test.go`: `Reason → ExitCode(17) → ToolExecutionResult` 전수 매핑 Table-Driven 테스트 및 원시 JWT 비노출 검증 추가
  - `internal/ui/pipeline.go` 및 `internal/ui/explain.go`: `ExitResourceLimit(17)` 및 `G9` 그룹 시나리오에 대한 관문 차단 표시·초보자 해설 문구 추가
- **무영향**:
  - 기존 종료 코드 `11`~`16`의 MCP 매핑 및 `G1`~`G8` UI 출력 포맷은 변경하지 않는다.

---

## 3. 세부 명세

### 3.1 감사 이벤트 `agent.limit_exceeded` 기록 (`internal/domain/event.go`, `internal/orchestrator/spawner.go`)
1. `domain.EventAgentLimitExceeded EventType = "agent.limit_exceeded"` 상수를 정의한다.
2. `SubprocessSpawner.Spawn`에서 자원 한계 초과(`result.ExitCode == int(domain.ExitResourceLimit)`)가 발생하면, 사후 감사 로그 기록 시 아래 필드를 채워 기록한다:
   - `EventType`: `string(domain.EventAgentLimitExceeded)`
   - `Step`: `"ORCHESTRATE_LIMIT_EXCEEDED"`
   - `Decision`: `string(domain.DecisionDeny)`
   - `Reason`: `string(result.Reason)` (`RESOURCE_TIMEOUT`, `RESOURCE_OUTPUT_LIMIT`, `RESOURCE_SIGNAL_KILLED` 중 하나)
   - `Success`: `false`
   - `Metadata`: `exit_code`(`17`), `duration_ms`, `timed_out`, `output_exceeded`, `max_output_bytes`, `rlimit` (`RLimitResult`)
3. 만약 `s.cfg.Audit.Log(...)` 호출이 실패하면 에러를 무시하지 않고 즉시 `domain.NewError(domain.ReasonAuditLogFailed, "orchestrator_limit_audit", ...)`(`ExitAuditFailure = 15`)를 반환한다.

### 3.2 MCP 어댑터 오류 매핑 (`internal/mcp/errors.go`)
1. `MapSubprocessError(exitCode int, rawReason string, rawErrMsg string)`에서:
   - `rawReason`이 비어 있고 `domain.ExitCode(exitCode) == domain.ExitResourceLimit`인 경우 기본 Reason을 `domain.ReasonResourceTimeout`으로 지정한다.
   - `rawReason`이 `RESOURCE_TIMEOUT`, `RESOURCE_OUTPUT_LIMIT`, `RESOURCE_SIGNAL_KILLED` 중 하나이면 그대로 보존하여 `[<REASON>] ... (exit code 17)` 형식의 `IsError: true` 응답을 생성한다.
   - `sanitizeMessage`를 통해 어떤 경우에도 원시 JWT 토큰이 에러 응답이나 `stderr`에 노출되지 않게 한다.

### 3.3 UI 파이프라인 및 해설 확장 (`internal/ui/pipeline.go`, `internal/ui/explain.go`)
1. `ComputePipelineGates`: `ExitResourceLimit(17)` 발생 시 실행/격리 관문에서 차단(`GateBlocked`)된 것으로 표시한다.
2. `generateExplanation`: `meta.Group == "G9"` 또는 `actualExit == domain.ExitResourceLimit`일 때 서브프로세스 자원·수명 한계(무한 대기 그룹 종료, 출력 폭주 차단) 방어 원리를 해설한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `MapSubprocessError(17, "RESOURCE_TIMEOUT", "...")` 호출 | `IsError == true`, 응답 텍스트에 `[RESOURCE_TIMEOUT]` 및 `exit code 17` 포함 |
| **TC-040-02** | `MapSubprocessError(17, "RESOURCE_OUTPUT_LIMIT", "...")` 및 `RESOURCE_SIGNAL_KILLED` 호출 | 각각의 Reason 코드와 `exit code 17` 정확히 매핑 |
| **TC-040-03** | 자원 한계 에러 메시지에 원시 JWT 문자열을 섞어 `MapSubprocessError` 호출 | `[REDACTED_TOKEN]`으로 마스킹, `ContainsRawToken == false` |
| **TC-040-04** | 스포너에서 타임아웃/출력 초과 발생 시 `audit.jsonl` 검증 | `event_type == "agent.limit_exceeded"`, `reason` 일치, 해시 체인 `VALID` |
| **TC-040-05** | 자원 한계 초과 시점에 감사 파일 쓰기 실패 주입 | `ExitAuditFailure(15)` 에러 반환 (감사 누락 방치 0건) |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/mcp -run TestMapSubprocessError` PASS
2. `go test -v ./internal/ui` PASS
3. `go test -v -tags testworker ./internal/orchestrator` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `agent.limit_exceeded` 감사 이벤트 기록 및 감사 실패 시 `15` 수렴 검증 완료
- [ ] MCP `Reason → ExitCode(17) → JSON-RPC` 매핑 Table-Driven 테스트 통과
- [ ] UI `G9` / 종료 코드 `17` 표시 및 해설 반영 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
