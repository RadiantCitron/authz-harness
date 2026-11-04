# [구현지시서 010] 관측성 포트(`internal/observe`) 및 `slog` 어댑터 구현

> **문서 상태**: `Done`
> **상위 대시보드**: [14번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md) | 교정 근거: [023번 보고서](../../../보고서/023-14번로드맵_구조결함_및_진행가능성_검증보고서.md) O-4~O-7
> **선행 조건**: 로드맵 13 `Done` (충족). 착수와 함께 ADR 0002를 `Accepted`로 전환한다(본 단계 산출물).
> **후속 단계**: [020_의존_금지_ast_가드.md](020_의존_금지_ast_가드.md)

---

## 1. 목적 및 배경

[`pep/gateway.go`](../../../../internal/authz/pep/gateway.go) 99행의 `Config.Logger *slog.Logger` 때문에, 코어 인가 계층이 로거의 구체 타입을 직접 안다. 로거를 바꾸면 PEP 시그니처도 바뀐다.
본 단계에서는 다음을 만든다.
- `slog`·OTel 타입을 노출하지 않는 관측성 포트 `observe.Observer`
- 기본 어댑터 `slogadapter`
- 어댑터의 panic이 판정을 멈추지 못하게 하는 `SafeObserver`
- 원시 토큰을 가리는 속성 필터 `SanitizeAttrs`

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `docs/adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md`: 상태를 `Proposed` → `Accepted`로 바꾼다. §6을 023 결정으로 고친다. ① 인터페이스는 §3.1의 4메서드와 `Attr` ② W3C 정규화·OTel SDK 도입 항목은 060 `Dropped`로 철회 ③ 하위 패키지는 `slogadapter` 하나(`otel`·`noop` 하위 패키지 없음) ④ B-8 대상 목록은 [020](020_의존_금지_ast_가드.md)의 목록.
  - `internal/domain/rawtoken.go` [신규]: 원시 토큰 탐지 규칙을 한 곳에 둔다. [`audit.go`](../../../../internal/audit/audit.go) 20행의 `eyJ[A-Za-z0-9_\.\-]{10,}`을 옮겨 `ContainsRawToken(s string) bool`, `RedactRawTokens(s string) string`(`[REDACTED_TOKEN]` 치환)을 제공한다.
  - `internal/audit/audit.go`: `jwtTokenPattern`을 지우고 `VerifyHashChain`이 `domain.ContainsRawToken`을 쓰게 한다(동작 동일).
  - `internal/observe/port.go` [신규]: `Observer`, `Attr`, `NoopObserver`, `WrapSafe`(`SafeObserver`), `SanitizeAttrs`. **`log/slog`를 import하지 않는다.**
  - `internal/observe/slogadapter/adapter.go` [신규]: `New(l *slog.Logger) observe.Observer`. `l == nil`이면 `slog.Default()`를 쓴다.
  - `internal/authz/pep/gateway.go`: `Config.Logger`를 지우고 `Config.Observer observe.Observer`를 둔다. `gateway.logger`는 `gateway.obs`(항상 `WrapSafe` 적용, nil이면 `NoopObserver`)로 바꾼다. slog 호출 8곳(`runStage` 3, `refundBudget` 1, `finalize` 4)을 §3.1의 메서드로 옮긴다. `"log/slog"` import는 0건이 된다.
  - `internal/authz/pep/gateway_test.go`: `TC-060-05-6`(1274행)의 `Logger: testLogger`를 `Observer: slogadapter.New(testLogger)`로 바꾼다. 검증 문구는 그대로다.
  - `internal/app/builder.go`: `AppConfig.Logger`를 `AppConfig.Observer observe.Observer`로 바꾼다. nil이면 `slogadapter.New(slog.Default())`를 PEP에 넘긴다. `AppConfig.Logger`를 설정하는 호출자는 0건이므로(023 O-7) 하위 호환 래핑은 두지 않는다.
  - `internal/observe/port_test.go`, `internal/observe/slogadapter/adapter_test.go` [신규]: §4 인수 시험.
- **바꾸지 않는 것**:
  - `pep.Config.StageObserver func(Stage)`(13번 040, 100행). 이것은 [`toctou_window_test.go`](../../../../internal/authz/pep/toctou_window_test.go)가 단계 사이에 상태를 바꾸는 **동기 시험 훅**이다. `SafeObserver`로 감싸지 않고, `Observer`와 합치지도 않는다(023 O-5).
  - `internal/mcp/server.go`, `internal/cli/mcp.go`, `cmd/authz-harness/main.go`, `internal/confinement`의 slog 사용(코어가 아님).
- **무영향**: stderr 운영 로그의 문구(`"pep stage entering"`, `"pep stage passed"`, `"pep stage blocked"`, `"pep execution succeeded"`, `"pep execution denied or failed"`, `"failed to refund budget"`, `"failed to record block audit event"`, `"failed to record completion audit event"`), 수준(Debug/Info/Warn/Error), 필드 이름은 그대로다. 인가 판정과 감사 기록도 바뀌지 않는다.

---

## 3. 세부 명세

1. **`observe.Observer` (4메서드)**:
   - `OnStageStart(ctx, traceID, stage string, attrs ...Attr)` → slogadapter: `DebugContext("pep stage entering")`
   - `OnStageEnd(ctx, traceID, stage string, allowed bool, attrs ...Attr)` → `allowed`이면 `InfoContext("pep stage passed")`, 아니면 `WarnContext("pep stage blocked")`
   - `OnExecutionEnd(ctx, traceID string, allowed bool, attrs ...Attr)` → `allowed`이면 `InfoContext("pep execution succeeded")`, 아니면 `WarnContext("pep execution denied or failed")`
   - `OnError(ctx, traceID, msg string, attrs ...Attr)` → `ErrorContext(msg)`. 환급 실패, 차단 감사 실패, 완료 감사 실패의 세 경로가 이 메서드를 쓴다(023 O-4: 환급 실패는 감사 오류가 아니므로 `OnAuditError`라는 이름은 쓰지 않는다).
   - `Attr`는 `{Key string; Value any}`다. slogadapter는 `trace_id`를 첫 필드로 붙이고, 나머지는 호출 순서대로 `slog.Any`로 넘긴다. 지금 필드 순서와 이름(`stage`, `resource`, `subject`, `reason`, `duration_ms`, `exit_code`, `agent_id`, `caller_id`, `bytes_read`, `bytes_wrote`, `token_jti`, `error`)을 그대로 유지한다.
2. **`SafeObserver` (`WrapSafe`)**: 각 메서드 호출을 `defer recover()`로 감싼다. 패닉은 버리고 반환값도 없다(포트는 best-effort다). `WrapSafe(nil)`은 `NoopObserver`이고, 이미 감싼 것은 다시 감싸지 않는다.
3. **`SanitizeAttrs`**: 모든 `Attr`의 문자열 값(그리고 `error`의 `Error()` 문자열)에 `domain.RedactRawTokens`를 적용한다. slogadapter는 출력 직전에 항상 이 함수를 거친다. 탐지 규칙은 감사 검증과 같은 `domain` 패턴 하나다(023 O-6).
4. **PEP 배선**: `NewGateway`에서 `obs := observe.WrapSafe(cfg.Observer)`를 만든다. `Execute`의 단일 `return`(`TC-060-04`)은 그대로 둔다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | `NoopObserver`(또는 `Observer` 미주입)로 `pep.Gateway.Execute` 허용·거부 각 1회 | 판정·종료 코드·감사 레코드가 기존과 동일 |
| **TC-010-02** | `slogadapter.New(testLogger)` 주입(`TC-060-05-6` 포함) | `"pep stage entering"`, `"pep stage passed"`, `"pep execution succeeded"`와 `stage`, `duration_ms`, `caller_id`가 출력됨 |
| **TC-010-03** | `Attr` 값에 원시 JWT(완전한 것과 서명이 잘린 것 둘 다)를 넣어 slogadapter 호출 | 출력에 `domain.ContainsRawToken`이 참인 문자열 0건, `[REDACTED_TOKEN]` 존재 |
| **TC-010-04** | 모든 메서드에서 panic하는 Observer를 주입하고 허용 요청 실행 | 판정 허용, 감사 레코드 정상, 테스트 프로세스 생존 |
| **TC-010-05** | 환급이 실패하는 예산 원장 스텁 + 기록하는 Observer | `OnError`가 `"failed to refund budget"`으로 1회 호출됨 |
| **TC-010-06** | panic하는 `StageObserver`를 `pep.Config`에 주입 | panic이 삼켜지지 않고 테스트에서 관찰됨(`StageObserver`는 `SafeObserver` 대상이 아님) |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/observe/... ./internal/domain` PASS
2. `go test -v ./internal/authz/pep ./internal/audit ./internal/app` PASS (`TC-060-05-6`, 13번 `toctou_window_test.go` 포함)
3. `go test -race ./internal/observe/... ./internal/authz/pep` PASS
4. `go test ./...` 전체 회귀 0건, `grep -n '"log/slog"' internal/authz/pep/gateway.go internal/observe/port.go` 0건

---

## 6. 완료 판정 체크리스트

- [x] ADR 0002 `Accepted` 전환 및 §6 개정
- [x] `domain` 원시 토큰 규칙 일원화, `internal/observe` 포트·`slogadapter`·`SafeObserver`·`SanitizeAttrs` 구현
- [x] `pep.Config.Logger` → `Observer`, `AppConfig.Logger` → `Observer` 전환 (`StageObserver` 유지)
- [x] 대시보드 상태 갱신 및 변경 파일 단독 커밋
