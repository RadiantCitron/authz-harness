# [구현지시서 060] OTel 호환 스팬 어댑터 및 원시 토큰 속성 필터 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [14번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0002](../../../adr/0002-관측성-포트-분리-및-오픈텔레메트리-전환.md)
> **선행 조건**: [050_위임_트리_뷰_및_상관_필드.md](050_위임_트리_뷰_및_상관_필드.md) 완료
> **후속 단계**: [070_g13_e2e_시나리오.md](070_g13_e2e_시나리오.md)

---

## 1. 목적 및 배경

`010`에서 정의한 `internal/observe.Observer` 포트의 두 번째 구현체로 W3C Trace Context(`trace_id` 32-hex, `span_id` 16-hex) 호환 스팬 레코더 어댑터(`internal/observe/oteladapter`)를 구현한다.
코어 패키지의 무의존성(`TC-140-01`)을 그대로 유지하면서, 합성 루트(`internal/app`)에서 `slogadapter` 대신 `oteladapter`를 꽂기만 하면 PEP·오케스트레이터의 모든 관문 스팬이 구조화 수집되고 원시 JWT 토큰은 속성에서 100% 차단됨을 증명한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/observe/oteladapter/adapter.go` [신규]: `observe.Observer` 인터페이스를 구현하는 OTel 스팬/이벤트 어댑터(인메모리/JSON 스팬 익스포터 포함, 외부 Collector 네트워크 불필요)
  - `internal/observe/oteladapter/adapter_test.go` [신규]: 어댑터 교체 시 PEP 인가 결과 불변 및 스팬 속성 내 원시 JWT 유출 0건 검증 테스트
- **무영향**:
  - 코어 패키지 코드 수정이 단 1줄도 필요하지 않음을 통해 포트·어댑터 분리의 유효성을 실증한다.

---

## 3. 세부 명세

1. **코어 무수정 교체 실증**:
   - `pep.Gateway` 코드를 전혀 수정하지 않고 `Config{Observer: oteladapter.New(exporter)}` 주입만으로 Gate 0 ~ Stage 5 스팬이 수집되는지 검증한다.
2. **원시 토큰 차단**:
   - 스팬 속성(`Attributes`) 및 이벤트에 `SanitizeAttrs`가 강제 적용되어 `eyJ...` 형태의 JWT가 절대 익스포터에 도달하지 않도록 보장한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-060-01** | `oteladapter`를 주입하여 `pep.Gateway.Execute` 실행 | 인가 결과 및 `audit.jsonl` 불변, 익스포터에 관문별 스팬 정상 수집 |
| **TC-060-02** | 수집된 모든 스팬 직렬화 결과에 JWT 정규식 검사 실행 | 유출 0건 (`ContainsRawToken == false`) |
| **TC-060-03** | `TC-140-01` AST 가드레일 실행 | 코어 패키지 오염 0건 `PASS` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/observe/oteladapter` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `internal/observe/oteladapter` 구현 및 코어 무수정 교체 테스트 완료
- [ ] 스팬 속성 원시 토큰 비노출 검증 통과 후 단독 커밋
