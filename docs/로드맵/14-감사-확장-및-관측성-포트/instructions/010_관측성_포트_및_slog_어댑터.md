# [구현지시서 010] 관측성 포트(`internal/observe`) 및 `slog`·`noop` 어댑터 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [14번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md)
> **선행 조건**: [ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md) `Accepted` 전환
> **후속 단계**: [020_의존_금지_ast_가드.md](020_의존_금지_ast_가드.md)

---

## 1. 목적 및 배경

현재 [`internal/authz/pep/gateway.go`](../../../../internal/authz/pep/gateway.go)의 `Config.Logger *slog.Logger`는 코어 인가 계층이 표준 라이브러리의 구체 타입(`*slog.Logger`)을 직접 참조하고 있어, 향후 OpenTelemetry 등으로 교체할 때 코어 시그니처 변경이 전파된다.
본 단계에서는 `slog`·OTel 구체 타입을 일절 노출하지 않는 순수 관측성 포트(`internal/observe.Observer`)와 기본 어댑터(`slogadapter`, `noop`), 원시 JWT 유출을 차단하는 속성 필터(`SanitizeAttrs`), 그리고 어댑터 panic/오류를 격리하는 `SafeObserver`를 구현한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/observe/port.go` [신규]: `Observer` 인터페이스, `Attr` 구조체, `NoopObserver`, `SafeObserver`(panic 복구 래퍼), 원시 JWT 마스킹 필터 `SanitizeAttrs` 구현
  - `internal/observe/slogadapter/adapter.go` [신규]: `*slog.Logger`를 감싸 `observe.Observer`를 구현하는 어댑터
  - `internal/authz/pep/gateway.go`: `Config.Logger *slog.Logger` 필드를 **완전히 제거**하고 `Config.Observer observe.Observer`로 교체하여 `internal/authz/pep`에서 `"log/slog"` import를 0건으로 만든다 (`020` 단계의 `TC-140-01` AST 가드레일 충족 필수 조건)
  - `internal/authz/pep/gateway_test.go`: `TC-060-05-6`(`gateway_test.go:1274`)에서 `Logger: testLogger` 대신 `Observer: slogadapter.New(testLogger)`를 주입하도록 갱신
  - `internal/app/builder.go`: 합성 루트 `AppConfig`에 `Observer observe.Observer`를 추가하고, 하위 호환을 위해 `cfg.Observer == nil`이면 `slogadapter.New(cfg.Logger)`로 자동 래핑하여 `pep.Config.Observer`에 주입
  - `internal/observe/port_test.go` [신규]: `slogadapter`, `NoopObserver`, `SafeObserver` panic 복구 및 `SanitizeAttrs` 원시 토큰 마스킹 단위 테스트
- **무영향**:
  - `stderr`로 출력되는 기존 `slog` 운영 로그 문구(`"pep stage entering"`, `"pep stage passed"`, `"pep stage blocked"`, `"pep execution succeeded"`, `"pep execution denied or failed"`)와 필드(`trace_id`, `stage`, `caller_id`, `duration_ms`), 인가 판정 결과는 기존과 100% 동일하다.

---

## 3. 세부 명세

1. **`observe.Observer` 인터페이스 및 기존 로그 문구 호환**:
   - [`gateway_test.go`](../../../../internal/authz/pep/gateway_test.go)의 `TC-060-05-6` 호환 및 SESE Around 계측을 위해 다음 메서드를 제공한다:
     - `OnStageStart(ctx context.Context, traceID, stage string, attrs ...Attr)` (`slogadapter`: `DebugContext(ctx, "pep stage entering", ...)`)
     - `OnStageEnd(ctx context.Context, traceID, stage string, allowed bool, attrs ...Attr)` (`slogadapter`: `allowed == true`이면 `InfoContext(ctx, "pep stage passed", ...)`, `false`이면 `WarnContext(ctx, "pep stage blocked", ...)`)
     - `OnExecutionEnd(ctx context.Context, traceID string, allowed bool, attrs ...Attr)` (`slogadapter`: `allowed == true`이면 `InfoContext(ctx, "pep execution succeeded", ...)`, `false`이면 `WarnContext(ctx, "pep execution denied or failed", ...)`)
     - `OnAuditError(ctx context.Context, traceID, msg string, attrs ...Attr)` (`slogadapter`: `ErrorContext(ctx, msg, ...)`)
   - `pep.NewGateway`는 주입된 `cfg.Observer`가 `nil`이면 `observe.NoopObserver{}`(또는 기본 `SafeObserver`)를 사용하고, 항상 `observe.WrapSafe(cfg.Observer)`로 감싸 어댑터 내부 panic이 PEP 인가 판정이나 Fail-Closed 감사 기록을 절대 중단시키지 못하게 한다.
2. **Zero Leakage 속성 필터 (`SanitizeAttrs`)**:
   - 모든 `Attr` 문자열 값에 대해 JWT 형태(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`) 정규식 검사를 수행하여 원시 토큰이 포함되면 `[REDACTED_TOKEN]`으로 치환한다 ([ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md) B-7).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | `NoopObserver`를 주입한 `pep.Gateway.Execute` 호출 | 기존과 동일한 인가 판정 및 감사 기록 |
| **TC-010-02** | `slogadapter.New(testLogger)`를 주입한 `pep.Gateway.Execute` 호출 (`TC-060-05-6` 포함) | `"pep stage entering"`, `"pep stage passed"`, `"pep execution succeeded"` 및 `stage`, `duration_ms`, `caller_id` 출력 유지 |
| **TC-010-03** | `Attr` 값에 원시 JWT 문자열을 넣어 `Observer` 호출 | 출력 로그에 원시 JWT 0건, `[REDACTED_TOKEN]`으로 마스킹 |
| **TC-010-04** | 고의로 panic을 일으키는 악성 `Observer`를 `pep.Gateway`에 주입 | `SafeObserver`가 복구하여 PEP 인가 판정 및 감사 기록 정상 완료 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/observe/...` PASS
2. `go test -v ./internal/authz/pep` (`TC-060-05-6` 포함 전수) PASS
3. `go test -race ./internal/observe/... ./internal/authz/pep` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `internal/observe` 포트, `slogadapter`, `NoopObserver`, `SafeObserver`, `SanitizeAttrs` 구현 완료
- [ ] `pep.Config.Logger` 제거 및 `pep.Config.Observer` 전환, `app.BuildStack` 자동 래핑 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
