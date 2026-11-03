# [구현지시서 040] 감사 이벤트(`agent.limit_exceeded`)·UI·MCP 오류 매핑

> **문서 상태**: `Draft`
> **상위 대시보드**: [10번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_출력_상한_리더_및_rlimit_적용.md](030_출력_상한_리더_및_rlimit_적용.md) 완료
> **후속 단계**: [050_g9_e2e_시나리오.md](050_g9_e2e_시나리오.md)

---

## 1. 목적 및 배경

`020`과 `030`에서 구현한 프로세스 그룹 종료 및 출력 상한 차단이 발생했을 때, ① 감사 원장(`audit.jsonl`)에 `Action: "agent.limit_exceeded"` 이벤트와 구체적 `Reason`(`RESOURCE_TIMEOUT`, `RESOURCE_OUTPUT_LIMIT`, `RESOURCE_SIGNAL_KILLED`)이 기록되어 하네스 Quad-Assertion(`DefaultEvaluator`)이 정확히 매칭할 수 있게 하고, ② MCP 어댑터(`internal/mcp`)가 종료 코드 `17`과 `SpawnResult.Reason`을 누락 없이 JSON-RPC 에러 응답으로 전달하며, ③ 하네스 UI(`internal/ui`)가 자원 한계 차단 관문과 해설을 표시하도록 전 구간 배선을 완성한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/orchestrator/spawner.go`:
    - 정상/기존 종료(`ExitCode != 17`) 시에는 기존 `ORCHESTRATE_COLLECT` 감사 이벤트를 그대로 유지(`TestTC08_AuditChain` 2개 이벤트 불변식 보존)
    - 자원 한계 종료(`result.ExitCode == int(domain.ExitResourceLimit)`, `17`) 시에는 사후 감사 이벤트의 `Action`을 `domain.AuditActionAgentLimitExceeded`(`"agent.limit_exceeded"`), `Step`을 `"ORCHESTRATE_LIMIT_EXCEEDED"`, `Decision`을 `"deny"`, `Reason`을 `string(result.Reason)`, `Success`를 `false`로 기록하고 메타데이터에 `output_exceeded`, `timed_out`을 포함하며, 단일 `postEvent` 구조체를 조립해 `s.cfg.Audit.Log(postEvent)` 호출은 함수 말미 단 1곳에서만 수행한다 ([016번 보고서](../../../보고서/016-다중로드맵_일괄설계_안티패턴_진단_및_10번로드맵_단독집중_구조정제_보고서.md) `R10-03`). 감사 기록 실패 시 `ExitAuditFailure(15)`로 Fail-Closed 수렴한다.
  - `internal/mcp/executor.go`:
    - 70행의 `MapSubprocessError(spawnRes.ExitCode, "", spawnRes.StderrRaw)` 호출을 `MapSubprocessError(spawnRes.ExitCode, string(spawnRes.Reason), spawnRes.StderrRaw)`로 수정하여, 자식 JSON 프레임이 없는 타임아웃·출력 초과 시에도 `spawnRes.Reason`(`RESOURCE_TIMEOUT` 등)이 손실되지 않고 전달되게 한다.
  - `internal/mcp/errors.go`:
    - `MapSubprocessError`의 기본 Reason 폴백 스위치에 `case domain.ExitResourceLimit: reason = domain.ReasonResourceTimeout`을 추가한다.
  - `internal/mcp/errors_test.go`: 종료 코드 `17` 및 Reason 3종(`RESOURCE_TIMEOUT`, `RESOURCE_OUTPUT_LIMIT`, `RESOURCE_SIGNAL_KILLED`) 매핑 Table-Driven 테스트 및 원시 JWT 비노출 검증 추가
  - `internal/ui/pipeline.go` 및 `internal/ui/explain.go`:
    - `ComputePipelineGates`: `meta.Group == "G9"` 또는 `reason == domain.ReasonResourceTimeout || reason == domain.ReasonResourceOutputLimit || reason == domain.ReasonResourceSignalKilled`일 때 Gate 5(실행/자원 통제 관문)에서 차단(`GateBlocked`)으로 표시
    - `generateExplanation`: `case "G9":` 해설 문구 추가
- **무영향**:
  - 기존 종료 코드 `11`~`16`의 감사·MCP·UI 동작과 기존 `spawner_test.go`(`TestTC08_AuditChain`)는 100% 그대로 통과한다.

---

## 3. 세부 명세

### 3.1 `audit.Event` 스키마 및 `assertion.go` 정합성 (`internal/orchestrator/spawner.go`)
- [`internal/harness/assertion.go`](../../../../internal/harness/assertion.go)의 `DefaultEvaluator.Evaluate`는 `exp.Audit.ExpectedAction`을 `ev.Action`과 비교하고, `exp.Audit.ExpectedDecision`을 `ev.Decision`, `exp.Audit.ExpectedReason`을 `ev.Reason`과 비교한다.
- 따라서 `result.ExitCode == int(domain.ExitResourceLimit)`일 때 기록되는 `audit.Event`는 다음과 같이 설정한다:
  ```go
  Action:   domain.AuditActionAgentLimitExceeded, // "agent.limit_exceeded"
  Step:     "ORCHESTRATE_LIMIT_EXCEEDED",
  Actor:    "orchestrator",
  Resource: req.FilePath,
  Decision: "deny",
  Reason:   string(result.Reason), // RESOURCE_TIMEOUT | RESOURCE_OUTPUT_LIMIT | RESOURCE_SIGNAL_KILLED
  Success:  false,
  ```

### 3.2 MCP 어댑터 Reason 전파 (`internal/mcp/executor.go`, `internal/mcp/errors.go`)
- 워커가 타임아웃이나 출력 초과로 강제 종료되면 JSON 응답 프레임(`spawnRes.Response`)이 없으므로 `executor.go`의 마지막 분기로 진입한다.
- 이때 `spawnRes.Reason`을 `MapSubprocessError`에 그대로 전달하여 `[RESOURCE_TIMEOUT] ... (exit code 17)` 또는 `[RESOURCE_OUTPUT_LIMIT] ... (exit code 17)`이 정확히 생성되도록 보장한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `MapSubprocessError(17, "RESOURCE_TIMEOUT", "...")` 호출 | `IsError == true`, 응답 텍스트에 `[RESOURCE_TIMEOUT]` 및 `exit code 17` 포함 |
| **TC-040-02** | `MapSubprocessError(17, "RESOURCE_OUTPUT_LIMIT", "...")` 및 `RESOURCE_SIGNAL_KILLED` 호출 | 각각의 Reason 코드와 `exit code 17` 정확히 매핑 |
| **TC-040-03** | 자원 한계 에러 메시지에 원시 JWT 문자열을 섞어 `MapSubprocessError` 호출 | `[REDACTED_TOKEN]`으로 마스킹, `ContainsRawToken == false` |
| **TC-040-04** | 스포너에서 타임아웃/출력 초과 발생 시 `audit.jsonl` 검증 | `action == "agent.limit_exceeded"`, `decision == "deny"`, `reason` 일치, 해시 체인 `VALID` |
| **TC-040-05** | 자원 한계 초과 시점에 감사 파일 쓰기 실패 주입 | `ExitAuditFailure(15)` 에러 반환 (감사 누락 방치 0건) |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/mcp -run TestMapSubprocessError` PASS
2. `go test -v ./internal/ui` PASS
3. `go test -v -tags testworker ./internal/orchestrator` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `Action: "agent.limit_exceeded"` 감사 기록 및 감사 실패 시 `15` 수렴 검증 완료
- [ ] `executor.go` `spawnRes.Reason` 전달 및 `errors.go` 매핑 테스트 통과
- [ ] UI `G9` / 자원 한계 사유 관문 표시 및 해설 반영 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
