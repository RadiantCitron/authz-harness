# [구현지시서 020] `netguard` (루프백 전용 URL 정규화와 egress 가드)

> **문서 상태**: `Draft`
> **상위 대시보드**: [16번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [025번 보고서](../../../보고서/025-16번로드맵_구조결함_및_진행가능성_검증보고서.md) T-1·T-4·T-8
> **선행 조건**: [010](010_action_스코프_문법_확장_설계.md) 완료
> **후속 단계**: [030_execguard_allowlist_가드.md](030_execguard_allowlist_가드.md)

---

## 1. 목적 및 배경

`net:fetch`의 URL을 한 가지 모양(`host:port` + 정규 URL)으로 바꾸는 **순수 정규화**와, allow-list에 있는 루프백 주소에만 GET을 보내는 **안전 실행기**를 독립 패키지 `internal/netguard`로 만든다. 정규화는 PEP Gate 0에서, allow-list 대조는 Gate 2c에서, GET은 Stage 5에서 쓰인다(040). 이 단계는 PEP에 연결하지 않는다.

검사한 주소와 실제로 연결하는 주소가 같아야 한다(025번 T-8). 그래서 DNS 조회, 리다이렉트 추종, 환경변수 프록시를 모두 막고, 연결 함수가 검증된 주소만 연결하게 고정한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/netguard/guard.go` [신규]: `Target`, `ParseTarget`, `Guard`, `NewGuard`, `Check`, `Fetch`.
  - `internal/netguard/guard_test.go`, `internal/netguard/fuzz_test.go` [신규].
- **의존**: 표준 라이브러리와 `internal/domain`만. `internal/authz/...`·`internal/audit`를 import하지 않는다.
- **무영향**: 아직 아무도 import하지 않는 독립 패키지다.

---

## 3. 세부 명세

1. **`ParseTarget(raw string) (Target, error)`** — 순수 함수, 소켓·allow-list 없음.
   - `Target{HostPort string, URL string}`. `HostPort`는 `"127.0.0.1:<port>"` 또는 `"[::1]:<port>"`, `URL`은 `"http://" + HostPort + <path>[?query]`로 다시 조립한 정규 URL이다(fragment 제거).
   - 입력이 `http://`로 시작하지 않으면 `"http://" + raw`로 보고 파싱한다(`127.0.0.1:18080` 허용). 그 밖의 스킴(`https`, `file`, `ftp`, 대문자 변형 포함)은 거부한다.
   - `u.User != nil`, `u.Opaque != ""`, 원문에 `\`·공백·제어 문자 포함, 포트 없음, 포트가 1~65535의 10진수가 아님 → 거부.
   - 호스트(`u.Hostname()`)는 **문자열로 정확히** `"127.0.0.1"` 또는 `"::1"`이어야 한다. `localhost`, `127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`, `127.0.0.1.`, `[::ffff:127.0.0.1]`, `[0:0:0:0:0:0:0:1]`은 모두 거부한다. DNS 조회를 하지 않는다.
   - 거부는 모두 `domain.NewError(domain.ReasonEgressDenied, "netguard", …)`(12)다.
2. **`NewGuard(allow []string, maxBytes int64, timeout time.Duration) (*Guard, error)`**
   - `allow`의 각 항목은 `ParseTarget`을 통과한 `HostPort`와 같은 모양이어야 한다(아니면 생성 오류). 빈 목록은 허용하되 모든 `Check`가 거부된다(Fail-Closed).
   - `maxBytes <= 0`, `timeout <= 0`이면 기본값(1 MiB, 5초)을 쓴다.
3. **`(*Guard).Check(hostPort string) error`** — Gate 2c용. allow-list에 정확히 있으면 nil, 없으면 `EGRESS_DENIED`. 소켓을 열지 않는다.
4. **`(*Guard).Fetch(ctx, t Target) ([]byte, error)`** — Stage 5용.
   - 먼저 `Check(t.HostPort)`를 다시 부른다.
   - 전용 `http.Transport{Proxy: nil, DialContext: …}`. `DialContext`는 넘어온 주소가 `t.HostPort`와 정확히 같을 때만 `net.Dialer`로 연결하고, 다르면 연결 전에 `EGRESS_DENIED`다.
   - `http.Client{Transport: …, Timeout: g.timeout, CheckRedirect: 항상 EGRESS_DENIED 반환}`. 요청은 `GET t.URL`, 본문 없음.
   - 상태 코드 3xx는 `EGRESS_DENIED`다(CheckRedirect가 오류를 내지 않는 경로 대비). 그 밖의 상태 코드는 본문과 함께 그대로 성공으로 본다(가짜 도구의 응답 내용은 판정 대상이 아니다).
   - 본문은 `io.LimitReader(resp.Body, maxBytes+1)`로 읽고, `maxBytes`를 넘으면 본문을 버리고 `TOOL_LIMIT_EXCEEDED`(12)다. 시간 초과(`context.DeadlineExceeded`·`Timeout()`)도 `TOOL_LIMIT_EXCEEDED`다. 17을 내지 않는다(D-06: 자식의 17은 스포너가 16으로 바꾼다).
   - 그 밖의 연결 실패는 `INTERNAL_ERROR`(16)다.

---

## 4. 인수 테스트 시나리오

시험 서버는 `httptest.NewServer`(무작위 포트)이며 요청 수를 센다.

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | `ParseTarget`: `http://127.0.0.1:18080/status?x=1#f`, `127.0.0.1:18080`, `http://[::1]:18080/` | `HostPort` = `127.0.0.1:18080`·`127.0.0.1:18080`·`[::1]:18080`, `URL`에 fragment 없음 |
| **TC-020-02** | `ParseTarget`: `http://127.0.0.1:18080@evil/`, `http://evil@127.0.0.1:18080/`, `http://2130706433:80/`, `http://0x7f000001:80/`, `http://127.1:80/`, `http://localhost:80/`, `http://127.0.0.1.:80/`, `https://127.0.0.1:443/`, `http://127.0.0.1/`, `http://127.0.0.1:0/`, `http:\\127.0.0.1:80\` | 전부 `EGRESS_DENIED`(12) |
| **TC-020-03** | allow-list = 서버 주소. `Fetch`로 서버 호출 | 본문 수신, 서버 요청 1 |
| **TC-020-04** | allow-list에 없는 루프백 포트로 `Check`·`Fetch` | `EGRESS_DENIED`, 서버 요청 0 |
| **TC-020-05** | 서버 A가 서버 B로 `302`를 응답 | `EGRESS_DENIED`, 서버 B 요청 0 |
| **TC-020-06** | `HTTP_PROXY`·`http_proxy`를 다른 시험 서버(프록시 역할)로 설정한 뒤 allow-list 서버 호출 | 성공, 프록시 요청 0 |
| **TC-020-07** | `maxBytes` = 16, 서버 본문 17바이트 / 서버가 `timeout`보다 오래 지연 | 둘 다 `TOOL_LIMIT_EXCEEDED`(12), 본문 반환 없음 |
| **TC-020-08** | `FuzzNetTarget`: 임의 문자열 → `ParseTarget` | 패닉 0. 성공했다면 `HostPort`의 호스트는 `127.0.0.1`·`[::1]` 중 하나이고, `ParseTarget(t.URL)`이 같은 `Target`을 낸다(멱등) |

---

## 5. 4층위 검증 기준

1. `go test -race ./internal/netguard` PASS
2. `go test -run=^$ -fuzz=FuzzNetTarget -fuzztime=30s ./internal/netguard` 패닉 0
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `ParseTarget`·`Guard.Check`·`Guard.Fetch` 구현, `Proxy: nil`·`DialContext` 고정·리다이렉트 거부
- [ ] 상한 초과 = `TOOL_LIMIT_EXCEEDED`(12), 17 미사용
- [ ] 부정 테스트·퍼징 통과 후 변경 파일만 단독 커밋
