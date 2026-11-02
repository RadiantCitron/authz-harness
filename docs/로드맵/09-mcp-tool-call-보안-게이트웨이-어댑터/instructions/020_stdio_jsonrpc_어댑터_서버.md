# [구현지시서 020] stdio JSON-RPC 2.0 어댑터 서버 구현

> **문서 상태**: `Done`
> **상위 대시보드**: [09번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_도구_집행_도메인_모델_및_프로토콜_명세.md](010_도구_집행_도메인_모델_및_프로토콜_명세.md) 완료
> **후속 단계**: [030_서브프로세스_위임_집행_배선.md](030_서브프로세스_위임_집행_배선.md)

---

## 1. 목적 및 배경
`authz-harness mcp serve`가 stdin/stdout으로 JSON-RPC 2.0 요청을 받아 `initialize`, `tools/list`, `tools/call`을 처리하게 한다. 이 단계의 `tools/call`은 집행기를 인터페이스로 주입받기만 하고, 실제 집행 배선은 030에서 한다.

## 2. 파급 범위와 무영향 근거
- **변경**: `internal/mcp/server.go` [신규], `internal/cli`에 `mcp serve` 서브커맨드 등록.
- **무영향**: 기존 서브커맨드 동작과 종료 코드 체계는 변경하지 않는다. 출력 삼분 원칙을 따른다(프로토콜 응답은 `stdout`, 운영 로그는 `slog`→`stderr`).

## 3. 세부 명세
1. 한 줄당 JSON 프레임 1개를 읽고 응답 1개를 쓴다. 알림(`id` 없음)에는 응답하지 않는다.
2. `initialize`: 서버 이름, 버전, `tools` capability를 반환한다.
3. `tools/list`: `file_read`, `file_write` 2종과 입력 스키마를 반환한다.
4. `tools/call`: 010의 검증을 통과한 요청만 `Executor` 인터페이스로 전달한다.
5. 미지원 `method`는 `-32601`, 파싱 실패는 `-32700`, 스키마 위반은 `-32602`로 응답하며 어떤 경우에도 집행기를 호출하지 않는다.
6. stdin EOF나 `ctx` 취소 시 정상 종료한다.

## 4. 인수 테스트 시나리오
| ID | 입력 | 기대 결과 |
|:---:|---|---|
| TC-020-01 | `initialize` | 서버 정보와 `tools` capability |
| TC-020-02 | `tools/list` | 정확히 2종 도구 |
| TC-020-03 | 깨진 JSON | `-32700`, 집행기 호출 0회 |
| TC-020-04 | 미지원 method | `-32601` |
| TC-020-05 | 스키마 위반 `tools/call` | `-32602`, 집행기 호출 0회 |
| TC-020-06 | 알림 프레임(`id` 없음) | 응답 없음 |

## 5. 4층위 검증 기준
1. `go test -race ./internal/mcp` PASS (가짜 `Executor`로 호출 횟수 검증)
2. `go test ./internal/cli` PASS (`mcp serve` 파이프 입출력 계약)
3. `go test ./...` 회귀 0건

## 6. 완료 판정 체크리스트
- [x] 서버 3개 메서드 구현
- [x] 오류 코드 매핑 및 부정 테스트
- [x] 변경 파일 단독 커밋
