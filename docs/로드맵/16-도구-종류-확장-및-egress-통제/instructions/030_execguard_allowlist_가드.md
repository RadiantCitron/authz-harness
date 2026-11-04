# [구현지시서 030] `execguard` (코드 고정 allow-list 실행 가드)

> **문서 상태**: `Draft`
> **상위 대시보드**: [16번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [025번 보고서](../../../보고서/025-16번로드맵_구조결함_및_진행가능성_검증보고서.md) T-1
> **선행 조건**: [020](020_netguard_루프백_가드.md) 완료 (서로 독립이지만 번호순 실행)
> **후속 단계**: [040_pep_도구_디스패처_통합.md](040_pep_도구_디스패처_통합.md)

---

## 1. 목적 및 배경

`exec:run`은 실행 파일 경로가 아니라 **코드에 적어 둔 논리 ID**만 받는다. 셸을 거치지 않고, 인자는 하나 이하이며 형식이 고정돼 있고, 환경변수를 물려받지 않는다. 이 검사와 실행을 독립 패키지 `internal/execguard`로 만든다. 검사는 PEP Gate 2c에서, 실행은 Stage 5에서 쓰인다(040). 이 단계는 PEP에 연결하지 않는다.

실행 파일 목록을 설정(플래그·파일)으로 받지 않는 이유: 목록을 바깥에서 넣을 수 있으면 「임의 실행 금지」가 설정 한 줄에 달린다(D-05).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/execguard/guard.go` [신규]: 고정 레지스트리, `Validate`, `Runner`, `NewRunner`, `Run`.
  - `internal/execguard/guard_test.go` [신규].
- **의존**: 표준 라이브러리(`os/exec` 포함)와 `internal/domain`만.
- **무영향**: 아직 아무도 import하지 않는 독립 패키지다.

---

## 3. 세부 명세

1. **고정 레지스트리**: 패키지 수준 비공개 맵 `{"echo-safe": {Path: "/bin/echo", MaxArgs: 1}}`. 외부에서 추가·변경하는 API를 두지 않는다.
2. **`Validate(id, arg string) error`** — 순수 함수, 프로세스 없음.
   - `id`가 레지스트리에 정확히 없으면 `EXEC_NOT_ALLOWED`(12). 경로 문자(`/`, `\`, `..`)·공백·널 바이트가 든 ID는 레지스트리에 있을 수 없으므로 같은 사유다.
   - `arg != ""`이고 `^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}$`에 맞지 않으면 `EXEC_ARG_REJECTED`(12). 선행 `-`(옵션 주입), 셸 메타문자, 공백, 개행, 65자 이상이 모두 여기 걸린다.
   - 빈 `arg`는 인자 0개로 실행한다.
3. **`NewRunner(dir string, maxBytes int64, timeout time.Duration) *Runner`** — `dir`은 작업 디렉터리(워크스페이스 루트, 040에서 주입). `maxBytes <= 0`, `timeout <= 0`이면 기본값(64 KiB, 5초).
4. **`(*Runner).Run(ctx, id, arg string) ([]byte, error)`**
   - 먼저 `Validate`를 다시 부른다.
   - `exec.CommandContext(ctx2, spec.Path, args...)`(셸 없음), `cmd.Dir = r.dir`, `cmd.Env = []string{}`(nil이면 부모 환경을 물려받으므로 반드시 빈 슬라이스), `cmd.Stdin = nil`, `cmd.WaitDelay`를 짧게 둔다.
   - 표준 출력은 `maxBytes+1`에서 끊는 버퍼에 담는다. 넘으면 출력을 버리고 `TOOL_LIMIT_EXCEEDED`(12). `timeout` 초과도 `TOOL_LIMIT_EXCEEDED`. 17을 내지 않는다(D-06).
   - 0이 아닌 종료 코드나 실행 실패는 `INTERNAL_ERROR`(16).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | `Run("echo-safe", "hello_123")` / `Run("echo-safe", "")` | `"hello_123\n"` / `"\n"` |
| **TC-030-02** | `Validate`: `"sh"`, `"/bin/echo"`, `"../bin/echo"`, `"echo-safe "`, `"ECHO-SAFE"` | 전부 `EXEC_NOT_ALLOWED`(12) |
| **TC-030-03** | `Validate("echo-safe", …)`: `"-n"`, `"--help"`, `"a;b"`, `"$(id)"`, `` "`id`" ``, `"a b"`, `"a\nb"`, 65자 | 전부 `EXEC_ARG_REJECTED`(12) |
| **TC-030-04** | `maxBytes` = 4, `Run("echo-safe", "hello_123")` | `TOOL_LIMIT_EXCEEDED`(12), 출력 반환 없음 |
| **TC-030-05** | `timeout`을 매우 짧게(예: 1ns) 두고 실행 | `TOOL_LIMIT_EXCEEDED`(12) |
| **TC-030-06** | 시험 전용 레지스트리 항목 없이, `Run`이 만드는 `exec.Cmd`를 검사하는 내부 헬퍼(`buildCmd`)로 확인 | `Env`가 nil이 아닌 길이 0, `Dir` = 주입한 디렉터리, `Path` = `/bin/echo` |

---

## 5. 4층위 검증 기준

1. `go test -race ./internal/execguard` PASS
2. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] 고정 레지스트리·`Validate`·`Runner.Run` 구현, 빈 환경·작업 디렉터리 고정
- [ ] 상한 초과 = `TOOL_LIMIT_EXCEEDED`(12), 17 미사용
- [ ] 부정 테스트 통과 후 변경 파일만 단독 커밋
