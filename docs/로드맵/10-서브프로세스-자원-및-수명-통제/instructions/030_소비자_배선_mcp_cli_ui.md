# [구현지시서 030] 소비자 배선 (MCP·CLI·UI)

> **문서 상태**: `Draft`
> **상위 대시보드**: [10번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [020_스포너_감독_계층_일괄_구현.md](020_스포너_감독_계층_일괄_구현.md) 완료
> **후속 단계**: [040_결함_워커_전용_실행파일_및_실행모드_선언.md](040_결함_워커_전용_실행파일_및_실행모드_선언.md)
> **근거**: [보고서 019](../../../보고서/019-10번로드맵_구조결함_및_기존구조_견고성_검토보고서.md) S-8

---

## 1. 목적 및 배경

020에서 스포너가 `Termination`, `Reason`, 표준 종료 코드 `17`/`16`을 내게 되었다. 이 단계에서는 그 결과를 **소비하는 쪽**만 배선한다. 스포너 내부는 건드리지 않는다.

- **MCP**: 자식 JSON 응답이 없는 강제 종료에서도 스포너가 정한 `Reason`이 도구 오류에 실려야 한다.
- **CLI**: `orchestrate` 출력에 종료 형태와 사유가 보여야 한다.
- **UI**: 자원 한계는 인가 관문(Gate 0~5)의 결과가 아니다. 관문 표와 별도의 "실행 감독" 줄로 표시하고, 관문 표에 거짓 `PASS`를 칠하지 않는다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/mcp/executor.go` 70행: `MapSubprocessError(spawnRes.ExitCode, "", spawnRes.StderrRaw)` → `MapSubprocessError(spawnRes.ExitCode, string(spawnRes.Reason), spawnRes.StderrRaw)`
  - `internal/mcp/executor_test.go`: 가짜 `Spawner`로 강제 종료 결과 주입 테스트
  - `internal/cli/orchestrate.go`: 결과 출력에 `Termination`, `Reason` 줄 추가. 반환 종료 코드는 지금처럼 `result.ExitCode`(이제 `17`이 나올 수 있음)
  - `internal/cli/pep.go`의 `exitCodeName`: `ExitResourceLimit` → `"ExitResourceLimit"` 추가
  - `internal/ui/pipeline.go`: `ComputeSupervision(res) SupervisionInfo` 신규. 자원 한계 사유일 때 `ComputePipelineGates`는 모든 관문을 `GateSkipped`로 반환
  - `internal/ui/explain.go`, `summary.go` 및 출력부: "실행 감독" 줄 표시, `case "G9"` 해설 추가
  - `internal/ui/ui_test.go`: 표시 테스트
- **무영향**:
  - `MapSubprocessError`의 기존 Reason 폴백 표는 바꾸지 않는다. 020 이후 스포너는 `17`이면 항상 `Reason`을 채우므로, `17` 폴백 행은 필요 없다.
  - 기존 G1~G8 시나리오의 관문 표시는 바뀌지 않는다(자원 한계 사유가 아닌 한 기존 `switch`를 그대로 탄다).

---

## 3. 세부 명세

### 3.1 MCP Reason 전파 (`internal/mcp/executor.go`)
1. `spawnRes.Response == nil`인 경로에서 `spawnRes.Reason`을 전달한다. 결과로 `[RESOURCE_TIMEOUT] ... (exit code 17)` 텍스트와 `structuredContent{exit_code: 17, reason: RESOURCE_TIMEOUT}`(010에서 도입)가 생성된다.
2. `Response != nil` 경로는 바꾸지 않는다. `Response`는 020에서 `TermExited`일 때만 채워지므로 강제 종료와 섞이지 않는다.

### 3.2 CLI (`internal/cli/orchestrate.go`, `pep.go`)
1. `Child Exit Code` 줄 다음에 `Termination: <값>`을 출력한다. `Reason`이 비어 있지 않으면 `Reason: <값>`도 출력한다.
2. `exitCodeName`에 `17` 이름을 추가한다.

### 3.3 UI 실행 감독 줄 (`internal/ui`)
1. ```go
   type SupervisionInfo struct {
       Blocked bool
       Reason  domain.Reason // RESOURCE_TIMEOUT | RESOURCE_OUTPUT_LIMIT
       Detail  string        // "시간 상한 초과로 프로세스 그룹 종료" 등
   }
   func ComputeSupervision(res harness.ScenarioResult) SupervisionInfo
   ```
   사유 판정은 `ComputePipelineGates`와 같은 방식(`AuditActualReason`, 없으면 `Expected.Audit.ExpectedReason`)으로 한다. `RESOURCE_TIMEOUT` 또는 `RESOURCE_OUTPUT_LIMIT`이면 `Blocked = true`다.
2. `ComputePipelineGates`는 `ComputeSupervision(res).Blocked`이면 6개 관문을 모두 `GateSkipped`, 상세 `"실행 감독에서 종료됨 — 관문 판정과 무관"`으로 반환한다. Gate 5(「감사 & I/O」)의 의미는 바꾸지 않는다.
3. 시나리오 상세 출력과 요약에서 관문 표 아래에 `실행 감독: 차단 (<Reason>) — <Detail>` 또는 `실행 감독: 정상` 한 줄을 표시한다.
4. `generateExplanation`에 `case "G9":` 해설을 추가한다. 내용: "판정(허용/거부)과 별개로, 부모가 시간·출력 한계를 넘은 워커와 그 자식 전체를 끝냈다."

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | 가짜 Spawner가 `{ExitCode: 17, Reason: RESOURCE_TIMEOUT, Response: nil, StderrRaw: "<원시 JWT 포함>"}` 반환 → `ExecuteTool` | `IsError == true`, 텍스트에 `[RESOURCE_TIMEOUT]`과 `exit code 17`, `StructuredContent.ExitCode == 17`, 원시 토큰 0건 |
| **TC-030-02** | 같은 조건에서 `Reason: RESOURCE_OUTPUT_LIMIT` | 텍스트와 구조화 필드 모두 `RESOURCE_OUTPUT_LIMIT` |
| **TC-030-03** | `AuditActualReason == RESOURCE_TIMEOUT`인 `ScenarioResult` → `ComputePipelineGates` | 6개 관문 모두 `GateSkipped`(PASS 0개) |
| **TC-030-04** | 같은 결과 → `ComputeSupervision` | `Blocked == true`, `Reason == RESOURCE_TIMEOUT` |
| **TC-030-05** | 기존 G1~G8 결과 표본(예: `PATH_TRAVERSAL`) → `ComputePipelineGates` | 기존과 동일한 차단 관문, `ComputeSupervision.Blocked == false` |
| **TC-030-06** | `exitCodeName(17)` | `"ExitResourceLimit"` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/mcp` PASS
2. `go test -v ./internal/ui ./internal/cli` PASS
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
4. `go test ./...` 회귀 0건, `run --scenario all` 39/39 PASS

---

## 6. 완료 판정 체크리스트

- [ ] MCP 강제 종료 경로 `Reason` 전파
- [ ] CLI `Termination`·`Reason` 출력, `exitCodeName(17)`
- [ ] UI 실행 감독 줄과 관문 `GateSkipped` 처리, `G9` 해설
- [ ] 대시보드 갱신 후 변경 파일만 커밋
