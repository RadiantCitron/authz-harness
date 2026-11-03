# [구현지시서 030] PIP 승인·버전 상태 공급 및 순수 PDP 3값(`allow`/`deny`/`ask`) 판정

> **문서 상태**: `Draft`
> **상위 대시보드**: [15번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [020_승인_원장_및_pap_명령.md](020_승인_원장_및_pap_명령.md) 완료
> **후속 단계**: [040_pep_배선_및_승인_소비.md](040_pep_배선_및_승인_소비.md)

---

## 1. 목적 및 배경

PIP가 활성 Grant 정보와 함께 현재 주체에 발급된 승인 레코드 스냅샷(`Approvals []domain.Approval`), 상태 원장 버전(`StateVersion`), 그리고 주입된 시계 시각을 조회해 공급하고, PDP가 파일 I/O나 OS 시계 호출 없이 순수하게 `allow`/`deny`/`ask` 3값 결정을 내리도록 확장한다.
이때 **승인은 Grant나 Epoch 검사를 대체하는 것이 아니라 추가 조건**이므로, Grant가 회수되었거나 본인/상위 위임자(`act`)의 Epoch가 올랐다면 유효한 승인이 있더라도 반드시 `deny`(`12`)가 반환되어야 한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/pip/service.go`:
    - `SubjectSnapshot`에 `Approvals []domain.Approval` (`json:"approvals,omitempty"`) 및 `StateVersion int` (`json:"state_version,omitempty"`) 필드 추가
    - `pip.NewService(store, opts ...Option)`에 `WithClock(clock domain.Clock)` 옵션 지원
  - `internal/authz/pdp/service.go`:
    - `DecisionAsk DecisionType = "ASK"` 상수 추가
    - `pdp.Request`에 `TokenJTI string` (`json:"token_jti,omitempty"`), `ArgHash string` (`json:"arg_hash,omitempty"`), `Now time.Time` (`json:"now,omitempty"`) 필드 추가 (`Decide`에서 감사 이벤트 `Metadata["state_version"] = snapshot.StateVersion` 기록)
    - 순수 함수 `Evaluate(req Request, snapshot *pip.SubjectSnapshot) Decision`에서 매칭된 활성 Grant의 `RequiresApproval == true`일 때 `snapshot.Approvals`를 검사하여 `DecisionAllow` 또는 `DecisionAsk`(`ReasonApprovalRequired`, `ReasonApprovalExpired`, `ReasonApprovalMismatch`) 반환
  - `internal/authz/pdp/ask_test.go` [신규]: 3값 결정표(`ArgHash` 불일치 포함) Table-Driven 단위 테스트
- **무영향**:
  - PDP는 여전히 `os`나 `storage`를 import하지 않는 100% 순수 패키지다(`TC-060-01` 유지).

---

## 3. 세부 명세

1. **8단 누적 판정 우선순위 불변식 (`pdp.Evaluate` — [012번 보고서](../../../보고서/012-타에이전트_구현이관대비_전체설계정합성_및_코어구조_위험요소_검증보고서.md) §3.3-A)**:
   - `pdp.Evaluate(req, snapshot)`은 반드시 다음 8단 순서를 엄수한다:
     - ① 입력 무결성 검사 (`ReasonNoActiveGrant = 12`)
     - ② 본인 `Epoch` 일치 검사 (`req.Epoch != snapshot.CurrentEpoch` → `ReasonSubjectEpochRevoked = 12`)
     - ③ 다단계 위임 `act` 조상 계보 전원의 `Epoch` 연쇄 검사 (로드맵 13: `anc.Epoch < snapshot.SubjectEpochs.Get(anc.Subject)` → `ReasonSubjectEpochRevoked = 12`)
     - ④ 토큰 `Scope` 포함 검사 (`ReasonTokenInsufficientScope = 12`)
     - ⑤ 활성/회수 Grant 매칭 검사 (`ReasonGrantRevoked = 12` / `ReasonNoActiveGrant = 12`)
     - ⑥ 예산 충분 여부 검사 (로드맵 12: `snapshot.BudgetEntries[req.TokenJTI]` 잔량 부족 시 `ReasonBudgetExhausted = 12` 하드 거부 — 예산이 고갈된 요청은 절대 `ask(18)`로 넘어가지 않음)
     - ⑦ 매칭된 활성 Grant의 `g.RequiresApproval == true`일 때만 5요소 승인 바인딩(`sub`, `action`, `resource`, `TokenJTI`, 선택적 `ArgHash`) 및 만료(`now < ExpiresAt`) 검사 → 미충족 시 `DecisionAsk`(`ExitApprovalRequired = 18`)
     - ⑧ 최종 `DecisionAllow`(`ReasonAuthorized = 0`)
   - 따라서 승인(`Approval`)을 받은 뒤에 Grant가 Revoke되거나 Epoch가 증가하면 `ask`나 `allow`가 아니라 즉시 `DecisionDeny`(`GRANT_REVOKED` / `SUBJECT_EPOCH_REVOKED`, 종료 코드 `12`)가 반환된다.
2. **`RequiresApproval == true`일 때의 승인 매칭 우선순위**:
   - 평가 시각 `evalTime := req.Now` (`evalTime.IsZero()`이면 `snapshot.Timestamp`)를 사용한다.
   - `snapshot.Approvals`를 순회하며 `a.Matches(cleanSub, req.Action, cleanRes, req.TokenJTI, req.ArgHash, evalTime)`을 평가하여:
     - 4+1요소(`Subject`, `Action`, `Resource`, `TokenJTI` 및 지정된 경우 `ArgHash`)가 모두 일치하고 `Consumed == false && evalTime.UTC().Unix() < ExpiresAt`인 승인이 하나라도 있으면 즉시 `DecisionAllow` + `ReasonAuthorized`를 반환한다.
     - 그렇지 않고 바인딩이 일치하나 `Consumed == false && evalTime.UTC().Unix() >= ExpiresAt`인 만료 승인이 존재하면 `DecisionAsk` + `ReasonApprovalExpired`를 반환한다.
     - 그렇지 않고 미소비(`Consumed == false`) 상태이나 `(Action, Resource, TokenJTI, ArgHash)` 중 일부가 다른 승인만 존재하면 `DecisionAsk` + `ReasonApprovalMismatch`를 반환한다.
     - 그 외(승인이 없거나 이미 `Consumed == true`인 승인만 존재)에는 `DecisionAsk` + `ReasonApprovalRequired`를 반환한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | `RequiresApproval: true` Grant + 승인 없음 (또는 이미 `Consumed: true`인 승인만 존재) | `DecisionAsk`, `ReasonApprovalRequired` |
| **TC-030-02** | `RequiresApproval: true` Grant + 4+1요소 일치 유효 승인 존재 | `DecisionAllow`, `ReasonAuthorized` |
| **TC-030-03** | `RequiresApproval: true` Grant + 다른 `TokenJTI`, 다른 `Resource`, 또는 다른 `ArgHash`(페이로드 변조)에 발급된 미소비 승인만 존재 | `DecisionAsk`, `ReasonApprovalMismatch` |
| **TC-030-04** | `RequiresApproval: true` Grant + 바인딩 일치하나 `req.Now.Unix() >= ExpiresAt`인 승인만 존재 | `DecisionAsk`, `ReasonApprovalExpired` |
| **TC-030-05** | 유효한 승인이 존재하지만 Grant가 `Revoked` 상태이거나 Epoch가 불일치 | `DecisionDeny`, `ReasonGrantRevoked` / `ReasonSubjectEpochRevoked` (`ExitCode == 12`, 승인 우회 불가) |
| **TC-030-06** | `TC-060-01` AST 가드레일 실행 | PDP의 파일/OS/저장소 의존성 0% 통과 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pdp -run TestAskDecision` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] PIP 승인·`StateVersion`·시계 공급 및 순수 PDP 3값 결정표(`ArgHash` 포함) 구현 완료
- [ ] Grant 회수 우선순위, 바인딩 불일치, 가상 시계 만료 단위 테스트 통과 후 단독 커밋
