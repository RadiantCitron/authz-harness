# [구현지시서 040] 권한 회수 전파 및 TOCTOU 창 구간별 실측·문서화

> **문서 상태**: `Draft`
> **상위 대시보드**: [13번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_재교환_흐름_검증.md](030_재교환_흐름_검증.md) 완료
> **후속 단계**: [050_g12_e2e_시나리오.md](050_g12_e2e_시나리오.md)

---

## 1. 목적 및 배경

권한 회수(Grant Revoke, Epoch Bump, Key Retire)가 "무조건 즉시 반영된다"고 과장하는 대신([ROADMAP.md](../ROADMAP.md) §4 방어책), 실제 [`internal/authz/pep/gateway.go`](../../../../internal/authz/pep/gateway.go)의 파이프라인(`StageGate0Input → StageGate1AuthN → StageGate2AuthZ → StageGate2cJail → Stage4Audit → Stage5FileIO`)에서 회수가 일어나는 시점별로 **진행 중인 호출(In-Flight Call)과 직후 다음 호출(Next Call)이 각각 어떻게 판정되는지(물리적 TOCTOU 창의 정확한 경계)**를 결정론적 단계 훅으로 실측하고 문서로 고정한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/pep/gateway.go`: 테스트에서 관문 단계 완료 직후 상태 변이를 결정론적으로 주입할 수 있도록 `Request`에 선택적 `OnStagePassed func(stage Stage) error` 테스트 훅 필드 추가 (`nil`일 때 비용 0, `Execute` 단일 `return` `TC-060-04` 유지)
  - `internal/authz/pep/toctou_window_test.go` [신규]: Window A(실행 전 / `WithBeforeIOHook`), Window B(`StageGate1AuthN` 통과 직후 ~ `StageGate2AuthZ` 진입 전), Window C(`StageGate2AuthZ` 통과 직후 ~ `Stage5FileIO` 진입 전: 물리적 TOCTOU 창) 3개 구간에 대한 실측 Table-Driven 테스트
  - [ROADMAP.md](../ROADMAP.md) 및 [13번 README.md](../README.md): 실측된 구간별 TOCTOU 경계표 동기화
- **무영향**:
  - `OnStagePassed == nil`인 모든 일반 요청은 기존 파이프라인과 100% 동일하게 동작한다.

---

## 3. 세부 명세

### 구간별 회수 전파 및 TOCTOU 창 실측 기준표 (`gateway.go` 실제 동작 기반)

| 구간 ID | 상태 변화(Grant Revoke / Epoch Bump) 발생 시점 | 현재 진행 중인 호출 (In-Flight Call) | 동일 세션의 직후 다음 호출 (Next Call) | 코드상 인과 근거 (`gateway.go`) |
|:---:|---|:---:|:---:|---|
| **Window A** | PEP `Execute` 진입 직전 (`WithBeforeIOHook` 포함) | **즉시 거부 (`Exit 12`)** | **즉시 거부 (`Exit 12`)** | `decorator.go`의 `WithBeforeIOHook`이 `d.next.Execute` 호출 전에 상태를 갱신하므로 Gate 2 PIP 조회 시 회수 상태가 반영됨 |
| **Window B** | **Gate 1(토큰 서명·만료 검증) 통과 직후 ~ Gate 2(PDP 결정) 진입 직전** (`OnStagePassed(StageGate1AuthN)`) | **즉시 거부 (`Exit 12`)** | **즉시 거부 (`Exit 12`)** | 토큰이 이미 Gate 1을 통과했더라도, Gate 2(`StageGate2AuthZ`) 진입 시 `PIP.GetSubjectSnapshot`이 `grants_state.json`을 실시간으로 읽어 회수를 포착함 |
| **Window C (물리적 TOCTOU 창)** | **Gate 2(PDP `ALLOW` 결정) 통과 직후 ~ Stage 4/5(사전 감사 및 파일 I/O) 사이** (`OnStagePassed(StageGate2AuthZ)`) | **현재 호출은 완료 허용 (`Exit 0`)** | **다음 호출부터 즉시 거부 (`Exit 12`)** | Gate 2 인가 결정이 이미 확정된 뒤 커널 파일 I/O가 수행되기까지의 짧은 창이 실제 물리적 TOCTOU 창임. 단, 세션 캐시가 없으므로 직후 다음 호출은 100% 차단됨 |

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `Window A`(`WithBeforeIOHook`)에서 Grant Revoke 주입 | 현재 호출이 즉시 `ExitAuthzDenied(12)`(`GRANT_REVOKED`)로 차단, 파일 무변화 |
| **TC-040-02** | `Window B`(`OnStagePassed(StageGate1AuthN)`)에서 Grant Revoke 및 Epoch Bump 주입 | Gate 1은 통과했으나 Gate 2에서 즉시 `ExitAuthzDenied(12)`로 차단, 파일 무변화 |
| **TC-040-03** | `Window C`(`OnStagePassed(StageGate2AuthZ)`)에서 Grant Revoke 주입 후 동일 세션 토큰으로 2차 호출 실행 | 1차(In-Flight) 호출은 `ExitSuccess(0)`으로 완료되고, 직후 2차(Next) 호출이 즉시 `ExitAuthzDenied(12)`(`GRANT_REVOKED`)로 차단됨 |
| **TC-040-04** | `TC-060-04` PEP 단일 `return` 가드레일 실행 | `PASS` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pep -run TestTOCTOUWindow` PASS
2. `go test -race ./internal/authz/pep` PASS
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `OnStagePassed` 훅 추가 및 Window A/B/C 구간별 TOCTOU 실측 테스트 통과
- [ ] 구간별 판정 경계표 문서화 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
