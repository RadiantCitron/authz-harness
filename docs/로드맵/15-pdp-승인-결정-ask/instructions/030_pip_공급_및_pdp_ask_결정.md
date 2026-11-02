# [구현지시서 030] PIP 승인 상태 공급 및 순수 PDP 3값(`allow`/`deny`/`ask`) 판정

> **문서 상태**: `Draft`
> **상위 대시보드**: [15번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [020_승인_원장_및_pap_명령.md](020_승인_원장_및_pap_명령.md) 완료
> **후속 단계**: [040_pep_배선_및_승인_소비.md](040_pep_배선_및_승인_소비.md)

---

## 1. 목적 및 배경

PIP가 활성 Grant 정보와 함께 현재 요청에 대응하는 승인 레코드 스냅샷을 조회해 공급하고, PDP가 파일 I/O 없이 순수하게 `allow`/`deny`/`ask` 3값 결정을 내리도록 확장한다.
이때 **승인은 Grant나 Epoch 검사를 대체하는 것이 아니라 추가 조건**이므로, Grant가 회수되었거나 Epoch가 올랐다면 유효한 승인이 있더라도 반드시 `deny`(`12`)가 반환되어야 한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/pip/service.go`: `DecisionEnvironment`에 `Approvals []domain.Approval` 공급 필드 추가
  - `internal/authz/pdp/service.go`: 매칭된 활성 Grant의 `RequiresApproval == true`일 때 `env.Approvals`에서 4요소 바인딩·미만료·미소비 승인을 검사하여:
    - 일치하는 유효 승인이 있으면 `DecisionAllow` + `ReasonAuthorized`
    - 만료된 승인만 있으면 `DecisionAsk` + `ReasonApprovalExpired`
    - 바인딩 불일치 승인만 있으면 `DecisionAsk` + `ReasonApprovalMismatch`
    - 승인이 전혀 없으면 `DecisionAsk` + `ReasonApprovalRequired` 반환
  - `internal/authz/pdp/ask_test.go` [신규]: 3값 결정표 Table-Driven 단위 테스트
- **무영향**:
  - PDP는 여전히 `os`나 `storage`를 import하지 않는 100% 순수 패키지다(`TC-060-01` 유지).

---

## 3. 세부 명세

1. **판정 우선순위 불변식**:
   - Gate 2a(Epoch 일치) → Gate 2b(Scope 포함) → Gate 2c(활성 Grant 존재)를 **모두 통과한 뒤에만** `grant.RequiresApproval` 여부를 평가한다.
   - 따라서 승인(`Approval`)을 받은 뒤에 Grant가 Revoke되거나 Epoch가 증가하면 `ask`나 `allow`가 아니라 즉시 `DecisionDeny`(`GRANT_REVOKED` / `SUBJECT_EPOCH_REVOKED`, 종료 코드 `12`)가 반환된다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | `RequiresApproval: true` Grant + 승인 없음 | `DecisionAsk`, `ReasonApprovalRequired`, `Allowed == false` |
| **TC-030-02** | `RequiresApproval: true` Grant + 4요소 일치 유효 승인 존재 | `DecisionAllow`, `ReasonAuthorized`, `Allowed == true` |
| **TC-030-03** | `RequiresApproval: true` Grant + 다른 `TokenJTI`에 발급된 승인만 존재 | `DecisionAsk`, `ReasonApprovalMismatch`, `Allowed == false` |
| **TC-030-04** | 유효한 승인이 존재하지만 Grant가 `Revoked` 상태 | `DecisionDeny`, `ReasonGrantRevoked` (`ExitCode == 12`, 승인 우회 불가) |
| **TC-030-05** | `TC-060-01` AST 가드레일 실행 | PDP의 파일/OS/저장소 의존성 0% 통과 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pdp -run TestAskDecision` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] PIP 승인 공급 및 순수 PDP 3값 결정표 구현 완료
- [ ] Grant 회수 우선순위 및 바인딩 불일치 단위 테스트 통과 후 단독 커밋
