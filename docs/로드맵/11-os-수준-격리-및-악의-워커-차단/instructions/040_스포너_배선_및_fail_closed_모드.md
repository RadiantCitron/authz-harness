# [구현지시서 040] 스포너 격리 배선, Fail-Closed 및 `agent.confined` 감사 기록

> **문서 상태**: `Draft` (2026-11-04 [020번 보고서](../../../보고서/020-11번로드맵_구조결함_및_진행가능성_검증보고서.md) 기준 교정)
> **상위 대시보드**: [11번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_linux_어댑터_및_검증_환경.md](030_linux_어댑터_및_검증_환경.md) 완료
> **후속 단계**: [050_g10_악의_워커_시나리오.md](050_g10_악의_워커_시나리오.md)

---

## 1. 목적 및 배경

010~030의 `Confiner`·`Policy`를 오케스트레이터 스포너([`spawner.go`](../../../../internal/orchestrator/spawner.go)) **한 파일**에 배선한다. 이 단계는 `orchestrator` 모듈만 고친다(모듈 경계 단계, 020번 보고서 L-8). 악의 워커 모드와 시나리오는 050에서 만든다.

**배선 지점은 `SpawnConfig`다.** 스포너를 만드는 곳은 7곳이다([`cli/orchestrate.go`](../../../../internal/cli/orchestrate.go) 165행, [`cli/mcp.go`](../../../../internal/cli/mcp.go) 146행, [`catalog/helpers.go`](../../../../internal/harness/catalog/helpers.go) 143행, [`g8_mcp_adapter.go`](../../../../internal/harness/catalog/g8_mcp_adapter.go) 35행, [`g9_resource_limits.go`](../../../../internal/harness/catalog/g9_resource_limits.go) 3곳, [`multi_hop.go`](../../../../internal/orchestrator/multi_hop.go) 118행). `internal/app`은 스포너를 만들지 않는다. 새 필드의 영값을 "격리 꺼짐"으로 정해 7곳을 고치지 않는다(L-6).

**스포너는 부모가 아는 사실만 감사한다.** 부모가 아는 것은 "격리를 적용했는가/할 수 없었는가"다. 커널이 자식의 어떤 시스템콜을 막았는지는 부모가 알 수 없다. 그래서 교정 전 설계의 "격리 중 자식이 `13`으로 끝나면 `CONFINEMENT_VIOLATION`으로 기록"은 폐기한다. `13`은 PEP 경로 위반([`error.go`](../../../../internal/domain/error.go) 110행)과 같은 코드라서, 정직한 워커의 PEP 거부를 커널 차단으로 오기록하기 때문이다(L-3). [`termination.go`](../../../../internal/orchestrator/termination.go)의 `classifyExit`는 **수정하지 않는다**.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/orchestrator/spawner.go`:
    - `SpawnConfig`에 `Confiner confinement.Confiner`, `Confinement confinement.Policy` 추가
    - `cmd` 조립(Env·프로세스 그룹·stdin·출력 버퍼) 후, `cmd.Run()` 직전에 격리 적용 블록 1곳
  - `internal/orchestrator/termination.go`: 상수 `AuditActionAgentConfined = "agent.confined"` 추가(`AuditActionLimitExceeded` 옆, L-9)
  - `internal/orchestrator/spawner_confinement_test.go` [신규]
- **무영향**:
  - `Confiner == nil && !Confinement.Require`(영값)이면 격리 블록을 건너뛴다. 감사는 기존과 같은 `ORCHESTRATE_SPAWN` / `ORCHESTRATE_COLLECT`(또는 `ORCHESTRATE_LIMIT_EXCEEDED`) 2이벤트이며 `E2E-01`~`E2E-44`에 영향이 없다.
  - `classifyExit`, 출력 상한, 그룹 종료는 그대로다. 래퍼는 `exec`로 대상이 되므로(010 §3.2) PID·그룹이 같다.

---

## 3. 세부 명세

### 3.1 격리 적용 블록 (`Spawn` 내부, 단일 지점)

`ORCHESTRATE_SPAWN` 감사 뒤, `cmd` 조립 뒤, `cmd.Run()` 앞에 둔다.

```text
active := cfg.Confiner != nil || cfg.Confinement.Require
if active:
    c := cfg.Confiner ; if c == nil { c = confinement.NoopConfiner{} }
    err := c.Prepare(cmd, cfg.Confinement)
    감사 1건: Step "ORCHESTRATE_CONFINE", Action AuditActionAgentConfined,
             Metadata {confiner: c.Name(), protected_root, write_paths 개수, allow_network}
       - err == nil  → Decision "allow", Success true
       - err != nil  → Decision "deny",  Success false, Reason = ReasonFromError(err, ReasonConfinementUnavailable)
    감사 기록 실패 → ReasonAuditLogFailed(15) 에러 반환 (자식 미기동)
    err != nil → 자식 미기동. SpawnResult{TraceID, ExitCode: ExitCodeFromError(err, 16), Reason, Termination: TermExited, RawExitCode: -1} 반환
                 (이 경우 ORCHESTRATE_COLLECT 는 기록하지 않는다: 수거할 자식이 없다)
```

1. `Require == false`이고 `Confiner == NoopConfiner`(대조군)이면 `Prepare`가 `nil`을 반환하므로 감사는 `allow` + `confiner: "none"`이다. 대조군 실행 기록이 감사에 남는다.
2. `Validate` 실패(`14`)도 같은 경로로 거부되며 `Reason`은 `INVALID_ARGUMENTS`가 된다.
3. 정책에는 경로만 있고 토큰·비밀값은 없다. 감사 메타데이터에 경로 목록 전체 대신 개수와 루트만 남긴다.

### 3.2 `SpawnResult`

- 필드를 추가하지 않는다. 부모가 적용한 어댑터 이름은 감사에 있다. 시나리오는 자체 스포너를 만들므로 자신이 무엇을 주입했는지 안다.

---

## 4. 인수 테스트 시나리오 (요구사항에서 도출)

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `Confinement.Require: true`, `Confiner: nil` | 자식 미기동(헬퍼가 남기는 표식 파일 없음), `ExitCode == 16`, `Reason == CONFINEMENT_UNAVAILABLE`, 감사에 `agent.confined`/`deny` 1건, `ORCHESTRATE_COLLECT` 0건 |
| **TC-040-02** | `Require: true`, `NoopConfiner` | TC-040-01과 동일 |
| **TC-040-03** | `Require: false`, `NoopConfiner` (대조군) | 자식 정상 실행, 감사에 `agent.confined`/`allow`/`confiner: "none"` |
| **TC-040-04** | 영값 `SpawnConfig` | 감사 이벤트 Step 목록이 정확히 `[ORCHESTRATE_SPAWN, ORCHESTRATE_COLLECT]` |
| **TC-040-05** | `Prepare`가 `cmd.Path`를 `/usr/bin/env`로 감싸는 가짜 `Confiner`(테스트 전용) | 자식 정상 실행, `classifyExit` 결과와 출력 수거가 래핑 없을 때와 동일 (래핑 투명성) |
| **TC-040-06** | 격리 적용 상태에서 헬퍼가 `exit 13` | `ExitCode == 13`, 사후 감사는 `ORCHESTRATE_COLLECT`. `agent.confined`는 Prepare 시점 `allow` 1건뿐 (13 재해석 없음) |
| **TC-040-07** | (darwin, 프로브 가능 시) `Platform()` + `WorkerPolicy`로 정직한 헬퍼가 workspace 쓰기 | `ExitCode == 0`, 부모가 파일 내용 확인. 프로브 불가 시 Skip |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/orchestrator -run 'TestSpawnerConfinement'` PASS
2. `go test -race ./internal/orchestrator` PASS
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
4. `go test ./...` 회귀 0건 (기존 44대 시나리오 포함)

---

## 6. 완료 판정 체크리스트

- [ ] `SpawnConfig` 필드와 격리 적용 블록 1곳 구현, `classifyExit` 무수정
- [ ] `AuditActionAgentConfined`를 `orchestrator`에 정의
- [ ] TC-040-01~07 통과
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
