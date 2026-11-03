# [구현지시서 030] `execguard` (Allow-List 바이너리 ID 및 인자 스키마 실행 가드) 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [16번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [020_netguard_루프백_가드.md](020_netguard_루프백_가드.md) 완료
> **후속 단계**: [040_pep_도구_디스패처_통합.md](040_pep_도구_디스패처_통합.md)

---

## 1. 목적 및 배경

`exec:run` 도구 실행 시 임의 셸(`sh -c`), 경로 조작(`../../bin/...`), 환경변수 오염, 위험 플래그 주입(`-e`, `--exec`)을 원천 차단하고, 오직 **사전 등록된 논리적 바이너리 ID(`allowlist-id`)와 정형 인자 스키마**만 허용하는 `internal/execguard` 패키지를 구현한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/execguard/guard.go` [신규]: `AllowedCommandSpec` 레지스트리(기본 등록 ID `"echo-safe"` → `/bin/echo` 고정 절대경로 매핑, 허용 인자 정규식 `^[a-zA-Z0-9_.-]{1,64}$`), 인자 검증기(`ValidateRequest`), 격리 실행기(`Run`) 구현
  - `internal/execguard/guard_test.go` [신규]: 미등록 ID, 경로 문자 포함 ID, 인자 메타문자(`;`, `|`, `&&`, `` ` ``, `$()`, `-flag`) 주입 및 출력 상한 초과 거부 단위 테스트
- **무영향**:
  - 독립 패키지로 기존 코드에 영향 없음.

---

## 3. 세부 명세

1. **논리 ID 기반 매핑 (`ValidateRequest(commandID string, arg string)`)**:
   - 호출자는 실행 파일 경로가 아니라 논리적 ID(예: `"echo-safe"`)만 `Resource`로 지정할 수 있다.
   - `commandID`에 `/`, `\`, `..`, 공백, 널 바이트가 포함되거나 Allow-List 레지스트리에 없으면 프로세스를 기동하기 전에 즉시 `domain.NewError(domain.ReasonExecNotAllowed, "execguard", "...", nil)`(`ExitAuthzDenied = 12`)를 반환한다.
2. **인자 스키마 검증 (`ReasonExecArgRejected`)**:
   - `arg`(PEP `req.Data`를 문자열로 변환한 값)가 비어 있지 않을 때, 선행 하이픈(`-`)으로 시작하는 옵션 플래그이거나 허용 패턴(`^[a-zA-Z0-9_.-]{1,64}$`)을 벗어나면(셸 메타문자 `;`, `|`, `&`, `$`, `` ` ``, 공백, 개행 등 포함 시) 프로세스를 기동하기 전에 즉시 `domain.NewError(domain.ReasonExecArgRejected, "execguard", "...", nil)`(`ExitAuthzDenied = 12`)로 거부한다.
3. **실행 경계 및 자원 한계 강제 (`Run`)**:
   - `cmd.Dir`은 반드시 검증된 `WorkspaceDir`(Jail 루트)로 고정하고, `cmd.Env`는 빈 슬라이스(`[]string{}`)로 고정한다.
   - 로드맵 10의 실행 시간(`Timeout`, 초과 시 `ReasonResourceTimeout` / `ExitResourceExhausted = 17`)과 출력 바이트 상한(`MaxOutputBytes`, 초과 시 `ReasonResourceOutputLimit` / `ExitResourceExhausted = 17`)을 강제 적용한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | 등록된 ID `"echo-safe"` + 허용 인자 `"hello_123"` 실행 | 정상 실행 및 표준 출력 `"hello_123\n"` 반환 |
| **TC-030-02** | 미등록 ID `"sh"`, `"/bin/sh"`, `"../bin/echo"` 입력 | 프로세스 기동 0건, `ReasonExecNotAllowed`(`12`) 반환 |
| **TC-030-03** | 등록된 ID `"echo-safe"` + 위험 인자 `"-n"` 또는 `"hello; rm -rf /"` 입력 | 프로세스 기동 0건, `ReasonExecArgRejected`(`12`) 반환 |
| **TC-030-04** | `MaxOutputBytes: 4`로 설정하고 `"hello_123"` 실행 | 출력 상한 초과로 `ReasonResourceOutputLimit`(`17`) 반환 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/execguard` PASS
2. `go test -race ./internal/execguard` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `execguard` ID 매핑·인자 스키마 검증·Workspace 작업 디렉터리 고정·출력 상한 구현 완료
- [ ] 부정 테스트 전수 통과 후 단독 커밋
