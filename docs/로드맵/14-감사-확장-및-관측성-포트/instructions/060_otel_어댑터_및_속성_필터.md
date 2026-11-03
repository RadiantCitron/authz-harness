# [구현지시서 060] OTel 호환 스팬 어댑터 및 원시 토큰 속성 필터 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [14번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md)
> **선행 조건**: [050_위임_트리_뷰_및_상관_필드.md](050_위임_트리_뷰_및_상관_필드.md) 완료
> **후속 단계**: [070_g13_e2e_시나리오.md](070_g13_e2e_시나리오.md)

---

## 1. 목적 및 배경

`010`에서 정의한 `internal/observe.Observer` 포트의 두 번째 구현체로 W3C Trace Context(`trace_id` 32-hex, `span_id` 16-hex) 및 OTLP JSON 호환 스팬 레코더 어댑터(`internal/observe/oteladapter`)를 구현한다.
특히 본 레포의 **외부 서드파티 의존성 0개 원칙(`go.mod` 순수 표준 라이브러리 유지)**과 오프라인 샌드박스 빌드 호환성을 지키기 위해, 무거운 외부 SDK를 `go get`하지 않고 표준 라이브러리만으로 W3C/OTLP 호환 `SpanSnapshot` 및 `SpanExporter`를 구현한다. 이를 통해 코어 패키지의 무의존성(`TC-140-01`)을 유지하면서 합성 루트(`internal/app`)에서 어댑터만 교체하면 PEP 관문별 스팬이 구조화 수집되고 원시 JWT 토큰은 속성에서 100% 차단됨을 실증한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/observe/oteladapter/adapter.go` [신규]: `observe.Observer` 인터페이스를 구현하는 W3C/OTLP 호환 스팬 레코더 어댑터(`InMemoryExporter`, `JSONLExporter` 포함, `go.mod` 외부 의존성 추가 0건)
  - `internal/observe/oteladapter/adapter_test.go` [신규]: 어댑터 교체 시 PEP 인가 결과 불변, W3C 32-hex `TraceID` / 16-hex `SpanID` 정규화 검증 및 스팬 속성 내 원시 JWT 유출 0건 검증 테스트
- **무영향**:
  - 코어 패키지 코드 수정이 단 1줄도 필요하지 않으며 `go.mod` 또한 변경되지 않는다.

---

## 3. 세부 명세

1. **표준 라이브러리 기반 W3C Trace Context 정규화 및 스팬 수집**:
   - 임의 문자열인 도메인 `traceID`(예: `"trc-unified-777"`)가 이미 32자리 소문자 hex이면 그대로 사용하고, 아닐 경우 SHA-256 앞 16바이트(32-hex)로 결정론적 매핑하여 W3C `trace-id` 규격을 충족한다(원본 `traceID`는 스팬 속성 `authz.trace_id`에 보존).
   - `pep.Gateway` 코드를 전혀 수정하지 않고 `pep.Config{Observer: oteladapter.New(exporter)}` 주입만으로 Gate 0 ~ Stage 5 관문별 스팬(`SpanSnapshot{TraceID, SpanID, ParentSpanID, Name, Status, Attributes}`)이 수집되는지 검증한다.
2. **원시 토큰 차단 (`SanitizeAttrs` 강제)**:
   - 모든 스팬 속성(`Attributes`) 및 이벤트에 `observe.SanitizeAttrs`가 강제 적용되어 `eyJ...` 형태의 원시 JWT가 절대 익스포터에 도달하지 않도록 보장한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-060-01** | `oteladapter`를 주입하여 `pep.Gateway.Execute` 실행 | 인가 결과 및 `audit.jsonl` 불변, 익스포터에 관문별 W3C 호환 스팬 정상 수집 |
| **TC-060-02** | 수집된 모든 스팬 직렬화 결과에 JWT 정규식 검사 실행 | 유출 0건 (`ContainsRawToken == false`) |
| **TC-060-03** | `TC-140-01` AST 가드레일 및 `go.mod` 검사 실행 | 코어 패키지 오염 0건 및 외부 의존성 추가 0건 `PASS` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/observe/oteladapter` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] 표준 라이브러리 기반 `internal/observe/oteladapter` 구현 및 코어 무수정 교체 테스트 완료
- [ ] 스팬 속성 원시 토큰 비노출 검증 통과 후 단독 커밋
