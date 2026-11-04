# [구현지시서 030] PIP 승인 공급 및 순수 PDP 3값(`ALLOW`/`DENY`/`ASK`) 판정

> **문서 상태**: `Draft`
> **상위 대시보드**: [15번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | 교정 근거: [024번 보고서](../../../보고서/024-15번로드맵_구조결함_및_진행가능성_검증보고서.md) A-3·A-4·A-9·A-10·A-11
> **선행 조건**: [020_승인_원장_및_pap_명령.md](020_승인_원장_및_pap_명령.md) 완료
> **후속 단계**: [040_pep_배선_및_승인_소비.md](040_pep_배선_및_승인_소비.md)

---

## 1. 목적 및 배경

PIP가 Grant와 **같은 `Load`**에서 주체의 승인 목록을 공급한다. PDP는 파일 I/O나 OS 시계 없이 `ALLOW`/`DENY`/`ASK`를 판정한다. 승인으로 allow를 낼 때는 어떤 승인인지(`ApprovalID`)를 돌려준다. 그래야 PEP가 그 승인만 소비할 수 있다(024 A-4).
승인은 Grant·Epoch 검사를 대체하지 않는 **추가 조건**이다. PDP는 예산을 보지 않는다(12번 결정, [ADR 0004](../../../adr/0004-예산-축소-위임-예약-및-정산-모델.md) §2.4).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/pip/service.go`: `SubjectSnapshot.Approvals []domain.Approval` (`json:"approvals,omitempty"`). `GetSubjectSnapshot`이 `st.Approvals` 중 `Subject == cleanSub`인 것을 **복사**해서 담는다. `WithClock`은 이미 있다(13번).
  - `internal/authz/pdp/service.go`:
    - `DecisionAsk DecisionType = "ASK"`.
    - `Request`에 `TokenJTI string`, `ArgHash string`, `Now time.Time`을 추가한다(JSON `omitempty`).
    - `Decision.ApprovalID string` (`json:"approval_id,omitempty"`).
    - `Evaluate`: §3.
    - `Decide`: `pdp.decide` 감사 `Metadata`에 `approval_id`(있을 때)를 더한다. `Decision` 필드는 이미 `strings.ToLower`이므로 `"ask"`가 그대로 기록된다. `Success`는 `ALLOW`일 때만 `true`다.
  - `internal/cli/pdp.go`: 변경 없음(ASK는 `ExitCodeForReason` → 18로 자연히 나간다). `Now`가 비면 `snapshot.Timestamp`를 쓴다.
  - `internal/authz/pdp/ask_test.go` [신규]: §4.
- **바꾸지 않는 것**:
  - PDP의 import 집합(`TC-060-01`).
  - `RequiresApproval == false`인 Grant만 있는 요청의 판정과 감사.
  - 13번 act 사슬 동등 비교(`!=`, `pdp/service.go` 82행).

---

## 3. 세부 명세 — `Evaluate` 판정 순서

1. 입력 무결성, 스냅샷 nil → `DENY`/`NO_ACTIVE_GRANT` (기존)
2. 본인 Epoch 불일치 → `DENY`/`SUBJECT_EPOCH_REVOKED` (기존)
3. act 사슬 조상 Epoch 동등 비교 → `DENY`/`SUBJECT_EPOCH_REVOKED` (기존, 13번)
4. 토큰 Scope → `DENY`/`TOKEN_INSUFFICIENT_SCOPE` (기존)
5. **활성 Grant 매칭 (변경)**: `(sub, action, resource)`가 맞는 활성 Grant를 **모두** 모은다.
   - 하나도 없으면 6으로 간다.
   - 하나라도 `RequiresApproval`이면(가장 엄격한 쪽, 024 A-11) 아래와 같이 판정한다.
     - `now := req.Now`, 비었으면 `snapshot.Timestamp`.
     - `id, reason := domain.SelectApproval(snapshot.Approvals, ApprovalBinding{cleanSub, req.Action, cleanRes, req.TokenJTI, req.ArgHash}, now)`.
     - `reason == AUTHORIZED`이면 `ALLOW` + `ApprovalID = id` + `GrantID`. 아니면 `ASK` + 그 `reason`(`APPROVAL_REQUIRED`/`EXPIRED`/`MISMATCH`).
   - 모두 일반 Grant이면 지금처럼 `ALLOW`.
6. 회수 Grant 이력 → `DENY`/`GRANT_REVOKED` (기존)
7. 기본 거부 → `DENY`/`NO_ACTIVE_GRANT` (기존)

이 순서 때문에, 승인을 받은 뒤 Grant가 회수되거나 Epoch가 오르면 `ASK`나 `ALLOW`가 아니라 `DENY`(12)가 나온다. `TokenJTI`가 빈 요청(예: pdp CLI)은 jti 바인딩이 맞을 수 없으므로 승인 필요 Grant에 대해 `ASK`다(Fail-Closed).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | 승인 필요 Grant + 승인 없음 | `ASK`, `APPROVAL_REQUIRED`, `ApprovalID == ""` |
| **TC-030-02** | 승인 필요 Grant + 바인딩·인자 일치 유효 승인 | `ALLOW`, `AUTHORIZED`, `ApprovalID == 그 승인 ID` |
| **TC-030-03** | 승인 필요 Grant + 다른 `Resource` / 다른 `TokenJTI` / 다른 `ArgHash`의 승인만 | 셋 다 `ASK`, `APPROVAL_MISMATCH` |
| **TC-030-04** | 승인 필요 Grant + `req.Now == ExpiresAt`인 승인만 / `req.Now` 비고 `snapshot.Timestamp >= ExpiresAt` | 둘 다 `ASK`, `APPROVAL_EXPIRED` |
| **TC-030-05** | 유효 승인이 있으나 Grant가 회수됨 / 본인 Epoch 불일치 / act 조상 Epoch 불일치 | `DENY`, `GRANT_REVOKED` / `SUBJECT_EPOCH_REVOKED` / `SUBJECT_EPOCH_REVOKED` (12) |
| **TC-030-06** | 일반 Grant만 + 승인 없음 | `ALLOW`(기존과 동일), `ApprovalID == ""` |
| **TC-030-07** | 같은 `(sub, action, resource)`에 일반 Grant 1 + 승인 필요 Grant 1, 승인 없음 (저장 순서 두 가지 모두) | 둘 다 `ASK`, `APPROVAL_REQUIRED` |
| **TC-030-08** | PIP: 두 주체의 승인이 있는 원장에서 `GetSubjectSnapshot("worker-01")` 후 반환 슬라이스 변경 | worker-01 승인만 포함, 원장·재조회 결과 불변 |
| **TC-030-09** | `Decide`로 ASK 판정 | 감사 `pdp.decide`의 `decision == "ask"`, 해시 체인 `VALID` |
| **TC-030-10** | `TC-060-01` | PDP의 파일·OS·저장소 의존 0 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pdp ./internal/authz/pip` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] PIP 승인 공급, PDP `DecisionAsk`·`ApprovalID`·`Request.TokenJTI/ArgHash/Now` 구현
- [ ] 회수 우선, 중복 Grant, 바인딩 불일치, 만료 경계 단위 시험 통과
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
