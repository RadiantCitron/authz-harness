# ROADMAP — 19 파이프라인 구조 도메인화 및 표준 재설계 (마스터 설계)

> 대시보드: [README.md](README.md) | 결정: [ADR 0007](../../adr/0007-파이프라인-단계-분류-기준.md), [ADR 0008](../../adr/0008-범용-파이프라인-엔진과-도구-전략.md), [ADR 0009](../../adr/0009-감사-스키마-v4-단계-보호.md)

## 1. As-Is / To-Be

| 항목 | As-Is | To-Be |
|---|---|---|
| 단계 정의 | `pep`의 상수, 성격 없음 | `domain.Stage`·`StageKind` 한 곳 |
| 단계 이름 | `Gate`·`Stage` 혼용, `2b`·`3a` | 번호 없는 이름 10개 |
| 순서 보장 | `runPipeline` 수작업, 일치 시험 | 조립 목록, 등급 규칙을 생성 시 검사 |
| 소비 시점 | 검사 사이에 소비 | 검사 전부 뒤 소비 |
| 도구 지식 | 세 단계의 `switch` | `pep.Tool` 구현 4개 |
| 예산 정책 | 실행 코드 안, 읽기는 실행 뒤 차감 | 호출은 `budget`, 바이트는 `settle`, 도구별 차이는 `Tool.BudgetPlan` |
| 교환 흐름 | 거부 감사 분기 반복 | 같은 엔진, 마감 한 곳. 예약은 발급 뒤 정산 |
| 단계 증거 | `Metadata`, 해시 밖 | 최상위 `Stage`, 해시 안 (v4) |
| 시나리오 판정 | 단계를 보지 않음 | `ExpectedStage` |
| `explain` | 사유 코드로 추측, 모르면 `PASS` | 감사 기록을 그림, 모르면 `판단 불가` |

## 2. 목표 구조

```text
cmd / cli / harness
   │
   ├─ ui ────────────── 감사 기록을 읽어 그림
   ├─ authz/pep ─┐
   │             ├──▶ pipeline  (표준 라이브러리만)
   └─ authn/exchange ┘
         │
         ▼
       domain (Stage, StageKind, 정의 표)
```

- `pipeline`은 `domain`도 모릅니다. `Kind`와 등급은 엔진의 것이고, `domain.StageKind`는 그 값으로 변환됩니다. 변환 표는 소비자의 조립 코드에 두고, 조립 목록과 `domain` 정의의 일치 시험이 ID·순서·성격·조건부를 대조합니다(040·080).
- 조립 목록은 PEP의 경우 `pep` 패키지의 함수 하나에 있습니다.

```go
// 조립 목록의 모습 (040)
pipeline.New([]pipeline.Step[call]{
    {ID: "input", Kind: pipeline.Check, Run: g.input},
    {ID: "authn", Kind: pipeline.Check, Run: g.authn},
    {ID: "authz", Kind: pipeline.Decide, Run: g.authz},
    {ID: "boundary", Kind: pipeline.Check, Run: g.boundary},
    {ID: "replay", Kind: pipeline.Consume, Run: g.replay},
    {ID: "approval", Kind: pipeline.Consume, Applies: approved, Run: g.approval},
    {ID: "budget", Kind: pipeline.Consume, Applies: budgeted, Run: g.budget, Compensate: g.refund},
    {ID: "precommit_audit", Kind: pipeline.Record, Run: g.precommitAudit},
    {ID: "execute", Kind: pipeline.Execute, Run: g.execute},
    {ID: "settle", Kind: pipeline.Settle, Applies: postCharged, Run: g.settle},
})
```

## 3. 파급 범위와 무영향 근거

| 영향 | 대상 |
|---|---|
| 큰 변경 | `internal/authz/pep/gateway.go`, `internal/authn/exchange/service.go`, `internal/ui/pipeline.go` |
| 변경 | `internal/domain`, `internal/audit`, `internal/cli/pep.go`, `internal/cli/pdp.go`, `internal/harness/assertion.go`, `internal/harness/architecture_test.go`, `internal/orchestrator/spawner.go`, 카탈로그 기대 단계 |
| 신규 | `internal/pipeline` |
| 기계적 변경 | `domain.NewError` 호출부 (090) |
| 무영향 | PDP 판정 로직, `jail`, `netguard`, `execguard`, 격리, 토큰 서명·검증, 예산 원장, 저장소 |

허가와 거부의 결론, 사유 코드, 종료 코드는 바꾸지 않습니다. 바뀌는 동작은 다음 네 가지뿐입니다.

1. 경계 거부 시 jti가 남습니다.
2. 호출 예산이 없는 읽기·`net:fetch`는 실행 전에 `budget`에서 거부됩니다. 사유와 종료 코드, 원장의 최종 잔량은 같습니다.
3. 단계 문자열과 감사 어휘가 바뀝니다.
4. 화면이 실제를 그립니다.

## 4. 사전 점검 (Pre-Mortem)

| 실패 원인 | 방어 |
|---|---|
| 040이 커서 무엇이 깨졌는지 모른다 | 030에서 도구 변화를 먼저 끝낸다. 동작 불변과 변화 단계를 분리한다 |
| 시험이 이름과 함께 바뀌어 동어반복이 된다 | 060의 기대 단계는 요구사항에서 먼저 적는다. 040의 순서 시험도 지시서 표가 정답이다 |
| 엔진이 구조를 위한 구조가 된다 | 소비자가 쓰지 않는 기능을 넣지 않는다. 100에서 미사용 필드를 찾아 삭제한다 |
| 교환으로 옮기며 감사 내용이 달라진다 | 080 전에 감사 이벤트 스냅샷을 인수 기준으로 고정한다 |
| v4가 `audit tree`·`timeline`·체크포인트를 깬다 | 050 인수 시험에 v3 파일 검증과 세 명령을 넣는다 |
| 보상이 이중 실행되거나 실행 뒤 환급된다 | 020에서 역순·1회 보상을 시험하고, 040에서 `exec:run` 무환급을 시험한다 |
| 자식 프로세스 모드에서 단계를 못 읽는다 | 감사 파일을 읽으므로 모드와 무관하다. 060에서 기본 모드로 판정한다 |
| 재사용되는 엔진이 요청별 관측 값을 잃는다 | `Hook[S]`가 상태를 받는다. 020·040에서 시험한다 |
| 감사에 없는 사실을 화면이 추측한다 | 070의 표시 규칙과 앞 칸 규칙만 쓴다. 증거가 없으면 `판단 불가`다 |
| 호출 사전 차감이 실패한 읽기의 예산을 태운다 | `settle`·`execute` 실패는 `budget` 보상으로 돌려준다. `TestBudget_ReadBytesExceeded`를 유지한다 |
| 문서 동기화가 끝없이 커진다 | 살아 있는 문서만 고친다. 과거 기록은 고치지 않는다 |

## 5. 4층위 검증 설계

| 층위 | 내용 |
|---|---|
| 1 자동화 | `go test -race ./...`, `go vet ./...`, pre-push 검사 |
| 2 단위·구조 | 엔진 등급 규칙·보상 시험, 조립 목록과 `domain` 정의 일치, 아키텍처 허용 목록 |
| 3 상태·정합성 | 스키마 v4 해시, v3 검증 유지, 단계 값 변조 탐지, 거부 시 jti·승인·예산 상태 |
| 4 통합 | `run --scenario all` 79건 `ExpectedStage` 포함 PASS, 전 시나리오 화면 대조 |

**완료 판정**: 보고서 036 9장의 변이를 다시 돌립니다. M1(단계 값 변경)과 M2(화면 왜곡)가 **이제 실패해야** 하고, M4(PDP 무력화)는 계속 실패해야 합니다. 거부를 `PASS`로 그리는 시나리오는 0건이어야 합니다.

**실행 환경**: 각 지시서의 `go test -race ./...`는 루프백 소켓을 열 수 있는 호스트에서 돌립니다. `internal/netguard`, `internal/authz/pep`의 `TestToolNetFetch_*`, `internal/harness/catalog`의 G10·G15, `internal/cli`의 전 시나리오 시험은 `127.0.0.1:0` 바인딩이 필요합니다. 이것이 막힌 샌드박스의 `bind: operation not permitted`는 합격이 아니라 **미실행**입니다. 권한을 받아 다시 돌리고, 못 돌렸으면 단계를 `Done`으로 올리지 않고 보고합니다.

## 6. 단계 의존 관계

```text
010 ─▶ 020 ─▶ 030 ─▶ 040 ─▶ 050 ─▶ 060 ─▶ 070 ─▶ 080 ─▶ 090 ─▶ 100
```

한 줄로 차례대로 진행합니다. 각 지시서의 선행 조건과 같습니다.

## 7. 단계 분해표

[README.md](README.md) 2장을 따릅니다. 상태의 단일 원천은 대시보드입니다.
