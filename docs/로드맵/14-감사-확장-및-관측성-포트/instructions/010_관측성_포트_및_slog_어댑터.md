# [구현지시서 010] 관측성 포트(`internal/observe`) 및 `slog`·`noop` 어댑터 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [14번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md)
> **선행 조건**: [ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md) `Accepted`
> **후속 단계**: [020_의존_금지_ast_가드.md](020_의존_금지_ast_가드.md)

---

## 1. 목적 및 배경

현재 [`internal/authz/pep/gateway.go`](../../../../internal/authz/pep/gateway.go)의 `Config.Logger *slog.Logger` 등 코어 계층이 표준 라이브러리의 구체 타입(`*slog.Logger`)을 직접 참조하고 있어 향후 OpenTelemetry 등으로 교체할 때 시그니처 변경이 전파된다.
본 단계에서는 `slog`·OTel 타입을 일절 노출하지 않는 순수 관측성 포트(`internal/observe.Observer`)와 기본 어댑터(`slogadapter`, `noop`), 그리고 원시 JWT 유출을 차단하는 속성 필터(`SanitizeAttrs`)를 구현하고, PEP·단일 합성 루트(`internal/app`)가 포트를 주입받도록 전환한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/observe/port.go` [신규]: `Observer` 인터페이스(`OnStageStart`, `OnStageEnd`, `RecordEvent`), `Attr` 구조체, `NoopObserver`, 원시 JWT 마스킹 필터 `SanitizeAttrs` 구현
  - `internal/observe/slogadapter/adapter.go` [신규]: `*slog.Logger`를 감싸 `observe.Observer`를 구현하는 어댑터
  - `internal/authz/pep/gateway.go` 및 `internal/app/builder.go`: `Config.Logger *slog.Logger`를 `Observer observe.Observer`로 전환 (하위 호환을 위해 `slog.Logger` 전달 시 어댑터 자동 래핑 지원)
  - `internal/observe/port_test.go` [신규]: `slogadapter`, `NoopObserver`, 원시 토큰 마스킹 및 어댑터 panic/오류 격리 단위 테스트
- **무영향**:
  - `stderr`로 출력되는 기존 `slog` 운영 로그 필드(`trace_id`, `stage`, `caller_id`, `duration_ms`)와 인가 판정 결과는 기존과 100% 동일하다.

---

## 3. 세부 명세

1. **`observe.Observer` 최소 연산**:
   - `StageSpan(ctx context.Context, stage string, attrs ...Attr) (end func(allowed bool, reason string, err error))`
   - 포트는 best-effort 경로이므로 어댑터 내부 오류가 PEP 인가 판정 결과를 바꾸지 못하도록 안전 래퍼(`SafeObserver`)를 제공한다 (감사 `internal/audit`의 Fail-Closed 경로와 철저히 분리).
2. **Zero Leakage 속성 필터 (`SanitizeAttrs`)**:
   - 모든 문자열 속성값에 대해 `eyJ...` 정규식 검사를 수행하여 원시 JWT가 들어오면 `[REDACTED_TOKEN]`으로 치환한다 ([ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md) B-7).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | `NoopObserver`를 주입한 `pep.Gateway.Execute` 호출 | 기존과 동일한 인가 판정 및 감사 기록 |
| **TC-010-02** | `slogadapter`를 주입한 `pep.Gateway.Execute` 호출 | `stderr`에 `stage`, `duration_ms`, `caller_id` 출력 유지 |
| **TC-010-03** | `Attr` 값에 원시 JWT 문자열을 넣어 `Observer` 호출 | 출력 로그에 원시 JWT 0건, `[REDACTED_TOKEN]`으로 마스킹 |
| **TC-010-04** | 고의로 panic을 일으키는 악성 `Observer` 주입 | `SafeObserver`가 복구하여 PEP 인가 판정 및 감사 기록 정상 완료 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/observe/...` PASS
2. `go test -v ./internal/authz/pep` PASS
3. `go test -race ./internal/observe/... ./internal/authz/pep` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `internal/observe` 포트, `slogadapter`, `NoopObserver`, `SanitizeAttrs` 구현 완료
- [ ] `pep.Gateway` 및 `app.BuildStack` 포트 전환 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
