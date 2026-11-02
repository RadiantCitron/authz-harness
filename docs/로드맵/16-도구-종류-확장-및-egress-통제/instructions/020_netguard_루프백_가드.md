# [구현지시서 020] `netguard` (루프백 전용 URL·호스트 정규화 및 Egress 가드) 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [16번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_action_스코프_문법_확장_설계.md](010_action_스코프_문법_확장_설계.md) 완료
> **후속 단계**: [030_execguard_allowlist_가드.md](030_execguard_allowlist_가드.md)

---

## 1. 목적 및 배경

`net:fetch` 도구 실행 시 URL 파서 착시를 노린 SSRF·Egress 우회 공격(`http://127.0.0.1@evil`, 10진수/16진수/8진수 정수 IP 표기, IPv6 `[::1]` 포트 미지정, 외부 리다이렉트 `301`/`302`, DNS 리바인딩)을 원천 차단하고, 오직 사전에 등록된 로컬 루프백(`127.0.0.1:<allowed_port>`) 엔드포인트로만 단일 `GET` 요청을 허용하는 `internal/netguard` 패키지를 구현한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/netguard/guard.go` [신규]: `Target` 정규화 파서(`ParseAndNormalizeTarget`), 루프백 및 포트 Allow-List 검증기, DNS 조회 및 HTTP 리다이렉트를 원천 차단한 안전 실행기(`FetchLoopback`) 구현
  - `internal/netguard/guard_test.go` 및 `internal/netguard/fuzz_test.go` [신규]: 우회 URL 패턴 Table-Driven 테스트 및 `FuzzNetTarget` 퍼징 테스트
- **무영향**:
  - 아직 PEP에 연결하지 않은 독립 패키지이므로 기존 코드에 영향 없음.

---

## 3. 세부 명세

1. **URL·호스트 엄격 정규화 (`ParseAndNormalizeTarget(rawURL string)`)**:
   - 스킴은 `http`만 허용한다.
   - `u.User != nil` (`userinfo` `@` 포함) 즉시 거부(`ReasonEgressDenied`).
   - `net.SplitHostPort(u.Host)`가 실패하거나 포트가 명시되지 않으면 즉시 거부.
   - 호스트는 DNS 조회(`net.LookupHost`)를 절대 수행하지 않고, 오직 리터럴 `"127.0.0.1"` 또는 `"::1"`(정규화 후 `"127.0.0.1:<port>"` 또는 `"[::1]:<port>"`)만 허용한다. `2130706433`(정수 IP), `0x7f000001`(16진수 IP), `localhost.` 등 비표준 표기는 모두 거부한다.
2. **Allow-List 및 HTTP 클라이언트 안전 장치**:
   - 정규화된 `host:port`가 Allow-List에 없으면 소켓 연결을 시도하기 전에 `ReasonEgressDenied`(`ExitAuthzDenied = 12`)로 거부한다.
   - `http.Client.CheckRedirect`에서 모든 리다이렉트(`3xx`)를 즉시 에러(`ReasonEgressDenied`)로 차단한다.
   - 응답 본문 읽기에 로드맵 10의 `MaxOutputBytes` 상한(`io.LimitReader`)을 강제한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | Allow-List에 등록된 `http://127.0.0.1:18080/status` 호출 | 정규화된 타겟 `"127.0.0.1:18080"` 반환 및 로컬 테스트 서버 응답 수신 |
| **TC-020-02** | `http://127.0.0.1:18080@evil/`, `http://2130706433:18080/`, `http://8.8.8.8:80/` 입력 | 소켓 연결 0건, 전부 `ReasonEgressDenied`(`12`) 반환 |
| **TC-020-03** | Allow-List에 없는 루프백 포트(`http://127.0.0.1:22/`) 입력 | 소켓 연결 0건, `ReasonEgressDenied`(`12`) 반환 |
| **TC-020-04** | 로컬 서버가 외부 URL로 `302 Found` 리다이렉트 응답 반환 | 리다이렉트 추종 0건, 즉시 `ReasonEgressDenied`(`12`) 차단 |
| **TC-020-05** | `FuzzNetTarget` 시드 코퍼스 실행 | 패닉 0건, 비허용 호스트 통과 0건 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/netguard` PASS
2. `go test -race ./internal/netguard` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `netguard` URL 정규화·Allow-List·리다이렉트 차단·응답 상한 구현 완료
- [ ] SSRF 우회 표기 부정 테스트 및 `FuzzNetTarget` 통과 후 단독 커밋
