# [구현지시서 040] 위임 계보(`act` 사슬) 연쇄 `Epoch` 회수와 TOCTOU 창 구간별 실측

> **문서 상태**: `Done`
> **상위 대시보드**: [13번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **교정 기준**: [022번 보고서](../../../보고서/022-13번로드맵_구조결함_및_진행가능성_검증보고서.md) T-6, T-7, T-8
> **선행 조건**: [030_재교환_흐름_검증.md](030_재교환_흐름_검증.md) 완료
> **후속 단계**: [050_g12_e2e_시나리오.md](050_g12_e2e_시나리오.md)

---

## 1. 목적 및 배경

1. **`act` 사슬 연쇄 Epoch 검증 ([011번 보고서](../../../보고서/011-권한관리_본질_코어파이프라인_안티패턴_및_분산적응형_기본구조_전문가진단_보고서.md) 제안 1)**:
   - 현재 [`pdp/service.go`](../../../../internal/authz/pdp/service.go) 65행은 주체(`req.Subject`)의 Epoch만 검사하고 `req.Actor` 사슬은 보지 않는다.
   - PIP 스냅샷에 모든 주체의 Epoch 사본 `SubjectEpochs`를 담고, 순수 함수 `pdp.Evaluate`가 주체 검사 직후 `req.Actor` 사슬의 **모든 고리**를 검사한다. 규칙은 기존 주체 검사와 같은 **동등 비교**다(022 T-6). 15번 030의 `<`, MASTER 175행의 「이상」은 현재 값보다 큰 Epoch를 통과시키므로 쓰지 않는다.
2. **TOCTOU 창 실측**: 회수가 일어나는 시점(Window A/B/C)별로 진행 중 호출과 다음 호출의 판정을 결정론적으로 관찰한다. 관찰 수단은 **생성 시점 주입 관찰자** `pep.Config.StageObserver`이며, 요청 구조체에 함수 필드를 넣지 않는다(022 T-8).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - [`internal/authz/pip/service.go`](../../../../internal/authz/pip/service.go) `SubjectSnapshot`: `SubjectEpochs domain.SecurityEpochs` (`json:"subject_epochs,omitempty"`). 내용은 같은 `Load`(53행)의 `st.Epochs` **사본**(추가 I/O 없음, 호출자가 원본을 바꾸지 못하게 복사). 이름은 [17번 010](../../17-도메인-순수성-및-의존성-역전-완결/instructions/010_pdp_pip_의존성_역전_및_도메인_순수화.md)과 맞춘다. `StateVersion`은 넣지 않는다(022 T-7).
  - [`internal/authz/pdp/service.go`](../../../../internal/authz/pdp/service.go) `Evaluate`: 2단계(주체 Epoch) 직후
    ```go
    if req.Actor != nil && snapshot.SubjectEpochs == nil { deny(ReasonSubjectEpochRevoked) } // 공급 누락 = Fail-Closed
    for a := req.Actor; a != nil; a = a.Actor {
        if a.Epoch < 1 || snapshot.SubjectEpochs.Get(a.Subject) != a.Epoch { deny(ReasonSubjectEpochRevoked) }
    }
    ```
    `Details`에 어느 조상(`a.Subject`)이 몇 대 몇으로 불일치했는지 적는다.
  - [`internal/authz/pep/gateway.go`](../../../../internal/authz/pep/gateway.go): `Config.StageObserver func(Stage)`(반환값 없음, nil 허용). `runStage`(172행)에서 `fn()` 성공 직후 호출한다. `BuildStack`은 배선하지 않는다(단위 시험 전용). `Execute`는 바꾸지 않으므로 `TC-060-04`(단일 `return`)와 무관하다.
  - `internal/authz/pdp/pdp_test.go`: 조상 Epoch Table-Driven 시험 추가.
  - `internal/authz/pep/toctou_window_test.go` [신규]: Window A/B/C 시험.
- **무영향**: `act`가 없는 토큰과, 교환으로 `act.epoch`가 채워진 기존 위임 토큰(조상 Epoch 미변경)은 그대로 통과한다. 수동 `act`를 가진 루트 토큰은 `E2E-21` 하나이며 교환 단계(`DELEGATION_DEPTH_EXCEEDED`)에서 끝나 PEP에 오지 않는다([`g5_delegation_pdp.go`](../../../../internal/harness/catalog/g5_delegation_pdp.go) 250행).

---

## 3. 세부 명세: TOCTOU 창 기준표

현재 파이프라인: Gate 0 → Gate 1 → Gate 2 → Gate 2c → `StageBudget`(예산 쓰기만) → Stage 4 → Stage 5 ([`gateway.go`](../../../../internal/authz/pep/gateway.go) 23~41행).

| 구간 | 상태 변화(Grant 회수 / 주체·조상 Epoch 증가) 주입 시점 | 진행 중 호출 | 같은 토큰의 다음 호출 | 근거 |
|:---:|---|:---:|:---:|---|
| **Window A** | `Execute` 진입 전 (`WithBeforeIOHook`, [`decorator.go`](../../../../internal/authz/pep/decorator.go). 이름과 달리 I/O 직전이 아니라 관문 전체 앞에서 돈다) | `12` | `12` | Gate 2 PIP 조회 전에 원장이 바뀜 |
| **Window B** | `StageObserver(StageGate1AuthN)` | `12` | `12` | Gate 2 진입 시 PIP가 최신 `grants_state.json`을 읽음 |
| **Window C** | `StageObserver(StageGate2AuthZ)` (Gate 2c·`StageBudget`·Stage 4 앞) | `0` (완료) | `12` | Gate 2 결정 후에는 재검사가 없으므로 이 구간이 실제 TOCTOU 창이다 |

- Window C의 「다음 호출」은 **예산 토큰**으로 한다. 1회성 토큰이면 Gate 1 Replay(`TOKEN_REPLAY_DETECTED`, `11`)가 먼저 막아 창을 관찰할 수 없다([`verifier.go`](../../../../internal/authn/token/verifier.go) 234행). 시험 스택에는 예산 원장을 주입하고 루트 예산 토큰(`MaxCalls: 5`)을 쓴다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `lead-01 → mid-01 → worker-01` 2단 위임 토큰 발급 후 최상위 `lead-01`만 `BumpEpoch` → `worker-01` 토큰 실행 | `SUBJECT_EPOCH_REVOKED`(`12`), `Details`에 `lead-01` |
| **TC-040-02** | 같은 사슬에서 중간 `mid-01`만 `BumpEpoch` | `12` |
| **TC-040-03** | `act` 고리 `Epoch: 0`인 요청을 `Evaluate`에 직접 입력 | `DENY` / `SUBJECT_EPOCH_REVOKED` (건너뛰지 않음) |
| **TC-040-04** | `act`가 있는데 `SubjectEpochs == nil`인 스냅샷 | `DENY` / `SUBJECT_EPOCH_REVOKED` |
| **TC-040-05** | `act` 사슬 Epoch가 모두 현재 값과 같음 | `ALLOW` (회귀 없음) |
| **TC-040-06** | Window A·B에서 Grant 회수 / 조상 Epoch 증가 주입 | 진행 중 호출 `12`, 대상 파일 무변화 |
| **TC-040-07** | Window C에서 Grant 회수 주입 후 같은 예산 토큰으로 2차 호출 | 1차 `0`(쓰기 완료), 2차 `12`(`GRANT_REVOKED`) |
| **TC-040-08** | `StageObserver` 호출 기록 | 통과한 단계만 순서대로 기록, 실패 단계는 기록 없음 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pdp ./internal/authz/pep -run 'TestEvaluate|TestTOCTOUWindow'` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS (`TC-060-01` PDP 순수성, `TC-060-04` 단일 출구 무회귀)
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [x] PIP `SubjectEpochs`, PDP `act` 사슬 동등 비교(Fail-Closed) 구현
- [x] `Config.StageObserver` 추가 및 Window A/B/C 시험 통과
- [x] 대시보드 상태 갱신 및 변경 파일 단독 커밋
