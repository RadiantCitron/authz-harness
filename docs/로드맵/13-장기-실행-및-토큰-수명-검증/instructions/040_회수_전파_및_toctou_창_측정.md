# [구현지시서 040] 위임 계보(`act` 체인) 연쇄 `Epoch` 회수(Subtree Kill-Switch) 및 TOCTOU 창 구간별 실측

> **문서 상태**: `Draft`
> **상위 대시보드**: [13번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_재교환_흐름_검증.md](030_재교환_흐름_검증.md) 완료
> **후속 단계**: [050_g12_e2e_시나리오.md](050_g12_e2e_시나리오.md)

---

## 1. 목적 및 배경

1. **위임 계보(`act` 체인) 연쇄 `Epoch` 검증 (Subtree Kill-Switch, [011번 보고서](../../../보고서/011-권한관리_본질_코어파이프라인_안티패턴_및_분산적응형_기본구조_전문가진단_보고서.md) 제안 1)**:
   - 현재 [`internal/authz/pdp/service.go:64`](../../../../internal/authz/pdp/service.go)는 마지막 실행 주체(`req.Subject`)의 `CurrentEpoch`만 검사하고 `req.Actor`(`act` 위임 사슬)의 상위 주체들(`lead-01`, `mid-01`)의 `Epoch`는 검사하지 않는다.
   - 본 단계에서는 `pip.SubjectSnapshot`에 `SubjectEpochs map[string]domain.Epoch`를 공급하고, 순수 함수 `pdp.Evaluate`가 `req.Subject`뿐 아니라 **`req.Actor` 연결 리스트의 모든 조상 주체에 대해 `act.Epoch > 0 && snapshot.SubjectEpochs.Get(act.Subject) != act.Epoch`이면 즉시 `DecisionDeny` + `ReasonSubjectEpochRevoked(12)`를 반환**하도록 보강한다. 이로써 상위 에이전트 1명의 `bump-epoch`만으로 하위 파생 토큰 전체가 일괄 무효화된다.
2. **구간별 TOCTOU 창 실측·문서화**:
   - [`internal/authz/pep/gateway.go`](../../../../internal/authz/pep/gateway.go) 파이프라인에서 회수가 일어나는 시점(Window A/B/C)별로 현재 진행 중인 호출과 다음 호출이 어떻게 판정되는지 결정론적 훅(`OnStagePassed`)으로 실측한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/pip/service.go`: `SubjectSnapshot`에 `SubjectEpochs domain.SecurityEpochs` (`json:"subject_epochs,omitempty"`) 및 `StateVersion int` (`json:"state_version,omitempty"`) 공급 추가
  - `internal/authz/pdp/service.go`: `Evaluate`에서 `req.Subject`의 Epoch 대조 직후 `for curr := req.Actor; curr != nil; curr = curr.Actor` 루프로 모든 상위 위임자의 `curr.Epoch`와 `snapshot.SubjectEpochs.Get(curr.Subject)`를 대조하여 불일치 시 `ReasonSubjectEpochRevoked(12)` 반환
  - `internal/authz/pep/gateway.go`: `Request`에 선택적 `OnStagePassed func(stage Stage) error` 테스트 훅 추가
  - `internal/authz/pep/toctou_window_test.go` [신규]: 2-Hop 계보 연쇄 Epoch 회수(`lead-01` Bump → `worker-01` 즉시 차단) 및 Window A/B/C 구간별 TOCTOU 실측 테스트
- **무영향**:
  - `act`가 없거나 상위자의 Epoch가 변경되지 않은 기존 시나리오는 100% 동일하게 통과한다.

---

## 3. 세부 명세

### 구간별 회수 전파 및 TOCTOU 창 실측 기준표 (`gateway.go` 실제 동작 기반)

| 구간 ID | 상태 변화(Grant Revoke / 본인·조상 Epoch Bump) 발생 시점 | 현재 진행 중인 호출 (In-Flight Call) | 동일 세션의 직후 다음 호출 (Next Call) | 코드상 인과 근거 (`gateway.go`) |
|:---:|---|:---:|:---:|---|
| **Window A** | PEP `Execute` 진입 직전 (`WithBeforeIOHook` 포함) | **즉시 거부 (`Exit 12`)** | **즉시 거부 (`Exit 12`)** | Gate 2 PIP 조회 전에 원장이 갱신되므로 본인 또는 조상 `act`의 회수 상태가 즉시 반영됨 |
| **Window B** | **Gate 1 통과 직후 ~ Gate 2(PDP 결정) 진입 직전** (`OnStagePassed(StageGate1AuthN)`) | **즉시 거부 (`Exit 12`)** | **즉시 거부 (`Exit 12`)** | Gate 2 진입 시 `PIP.GetSubjectSnapshot`이 최신 `grants_state.json`을 실시간으로 읽어 포착함 |
| **Window C (물리적 TOCTOU 창)** | **Gate 2(PDP `ALLOW` 결정) 통과 직후 ~ Stage 4/5 사이** (`OnStagePassed(StageGate2AuthZ)`) | **현재 호출은 완료 허용 (`Exit 0`)** | **다음 호출부터 즉시 거부 (`Exit 12`)** | Gate 2 인가 결정 확정 후 파일 I/O 직전까지의 짧은 창이 실제 물리적 TOCTOU 창이며, 직후 다음 호출은 100% 차단됨 |

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `lead-01 → mid-01 → worker-01` 2-Hop 위임 토큰 발급 후 최상위 `lead-01`만 `BumpEpoch` 수행 → `worker-01` 토큰으로 실행 | `pdp.Evaluate`가 조상 `lead-01`의 Epoch 불일치를 적발하여 즉시 `ReasonSubjectEpochRevoked(12)` 차단 |
| **TC-040-02** | `Window A` 및 `Window B`(`OnStagePassed(StageGate1AuthN)`)에서 Grant Revoke / 조상 Epoch Bump 주입 | 현재 호출이 즉시 `ExitAuthzDenied(12)`로 차단, 파일 무변화 |
| **TC-040-03** | `Window C`(`OnStagePassed(StageGate2AuthZ)`)에서 Grant Revoke 주입 후 동일 세션 토큰으로 2차 호출 실행 | 1차(In-Flight) 호출은 `ExitSuccess(0)` 완료, 직후 2차(Next) 호출이 즉시 `ExitAuthzDenied(12)`로 차단됨 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pdp ./internal/authz/pep -run TestTOCTOUWindow` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `pdp.Evaluate` 내 `act` 계보 조상 Epoch 전수 대조(Subtree Kill-Switch) 구현 완료
- [ ] `OnStagePassed` 훅 추가 및 Window A/B/C 구간별 TOCTOU 실측 테스트 통과 후 단독 커밋
