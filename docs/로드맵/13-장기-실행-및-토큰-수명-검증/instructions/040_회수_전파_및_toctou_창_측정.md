# [구현지시서 040] 권한 회수 전파 및 TOCTOU 창 구간별 실측·문서화

> **문서 상태**: `Draft`
> **상위 대시보드**: [13번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_재교환_흐름_검증.md](030_재교환_흐름_검증.md) 완료
> **후속 단계**: [050_g12_e2e_시나리오.md](050_g12_e2e_시나리오.md)

---

## 1. 목적 및 배경

권한 회수(Grant Revoke, Epoch Bump, Key Retire)가 "즉시 반영된다"고 추상적으로 주장하는 대신, 단일 요청 파이프라인(`Gate 1 → Gate 2 → Gate 2c → Stage 4 Pre-Commit Audit → Stage 5 File I/O`) 내의 어느 시점에 회수가 발생했을 때 **해당 호출이 차단되는지 혹은 완료 허용 후 다음 호출부터 차단되는지(TOCTOU 창 경계)**를 결정론적 훅으로 실측하고 문서로 고정한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/pep/toctou_window_test.go` [신규]: 파이프라인 구간별(① Gate 1 직전, ② Gate 1 통과 직후 Gate 2 직전, ③ Gate 2 통과 후 Stage 4 직전(`WithBeforeIOHook`), ④ Stage 5 I/O 완료 직후) 상태 변이 주입에 따른 현재 호출 및 후속 호출 판정표 검증 테스트
  - [ROADMAP.md](../ROADMAP.md) 또는 [13번 README.md](../README.md): 실측된 구간별 TOCTOU 판정 경계표 반영
- **무영향**:
  - PEP 프로덕션 판정 로직 변경 없음.

---

## 3. 세부 명세

### 구간별 회수 전파 불변식 표 (테스트로 증명할 기준선)

| 회수 발생 시점 | 현재 진행 중인 호출 (In-Flight Call) | 직후 다음 호출 (Next Call) | 근거 |
|---|:---:|:---:|---|
| **Window A**: Gate 1(토큰 검증) 진입 전 Key Retire / Grant Revoke | **거부 (`11` 또는 `12`)** | **거부 (`11` 또는 `12`)** | Gate 1 / Gate 2 진입 시 최신 Zone B 상태를 읽음 |
| **Window B**: Gate 1 통과 후 ~ Gate 2(PDP) 진입 전 Grant Revoke / Epoch Bump | **거부 (`12`)** | **거부 (`12`)** | PIP가 Gate 2 직전에 `grants_state.json`을 실시간 조회함 |
| **Window C**: Gate 2 통과 후 ~ Stage 5 I/O 진입 직전 (`BeforeIOHook`) Grant Revoke | **거부 (`12`)** | **거부 (`12`)** | PEP가 I/O 직전 훅 이후 재검증하여 파일 접근을 차단함 (`TestOrchestrateRunner_TC09`) |
| **Window D**: Stage 5 커널 `read`/`write` 시스템콜 진입 이후 Revoke | **현재 호출만 완료 (`0`)** | **즉시 거부 (`12`)** | 이미 커널 I/O가 커밋된 창(불가피한 물리적 TOCTOU 창). 단, 다음 호출은 100% 차단됨 |

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | Window A/B/C 각 시점에 훅으로 Grant Revoke 주입 | 현재 호출이 즉시 `ExitAuthzDenied(12)`로 거부되고 파일 부작용 0바이트 |
| **TC-040-02** | Window D(I/O 완료 직후)에 Grant Revoke 주입 후 동일 토큰으로 2차 호출 실행 | 1차 호출은 `ExitSuccess(0)`, 직후 2차 호출은 대기 없이 즉시 `ExitAuthzDenied(12)` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pep -run TestTOCTOUWindow` PASS
2. `go test -race ./internal/authz/pep` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] Window A~D 구간별 TOCTOU 검증 테스트 작성 및 통과
- [ ] 구간별 판정 경계표 문서화 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
