# [구현지시서 030] Linux Landlock 어댑터, 신뢰 런처(`confine-exec`) 및 검증 환경 판정

> **문서 상태**: `Draft` (2026-11-04 [020번 보고서](../../../보고서/020-11번로드맵_구조결함_및_진행가능성_검증보고서.md) 기준 교정)
> **상위 대시보드**: [11번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0003](../../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md)
> **선행 조건**: [020_macos_seatbelt_어댑터.md](020_macos_seatbelt_어댑터.md) 완료
> **후속 단계**: [040_스포너_배선_및_fail_closed_모드.md](040_스포너_배선_및_fail_closed_모드.md)

---

## 1. 목적 및 배경

Linux에서 010의 `Policy`를 Landlock LSM(커널 5.13+)과 `PR_SET_NO_NEW_PRIVS`로 집행하는 어댑터를 만든다.

**왜 런처가 필요한가**: `landlock_restrict_self`는 **호출한 프로세스 자신**에만 걸린다. Go `os/exec`에는 fork 후 exec 전에 코드를 실행할 훅이 없다. 그래서 부모가 `cmd`를 고치는 것만으로는 자식에 Landlock을 걸 수 없다. 워커가 스스로 거는 방식은 악의 워커가 걸지 않으면 그만이므로 증명이 되지 않는다(020번 보고서 L-7).

그래서 **신뢰 런처**를 둔다. 프로덕션 CLI의 숨김 하위명령 `authz-harness confine-exec`가 정책을 받아 자기 자신에 Landlock을 건 뒤 `syscall.Exec`로 대상 바이너리로 바뀐다. 이는 macOS의 `sandbox-exec`와 같은 형태다. 런처는 결함 모드가 아니라 **프로덕션 격리 기능**이므로 ADR 0003 C-7(결함 워커 분리)과 충돌하지 않는다.

현재 개발 호스트는 macOS다. 실제 Linux 커널에서 실행 검증을 할 수 없다면 "구현 완료"로 허위 표기하지 않고 런타임 검증 상태를 분리해 기록한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/confinement/landlock_linux.go` [신규]: Landlock ABI 프로브, 규칙 적용 함수 `ApplySelf(p Policy) error`, `LandlockConfiner`, linux용 `Platform()`
  - `internal/confinement/launcher.go` [신규, 플랫폼 공통]: 정책 직렬화(`EncodePolicy`/`DecodePolicy`, JSON → base64 단일 인자)
  - `internal/confinement/launcher_other.go` [신규, `//go:build !linux`]: `ApplySelf`가 항상 `16` 반환
  - `internal/confinement/platform_noop.go`: 빌드 제약을 `!darwin && !linux`로 좁힘
  - `internal/cli/confine_exec.go` [신규]: 숨김 하위명령 `confine-exec -policy <encoded> -- <target> <args...>`. `DecodePolicy` → `ApplySelf` → `syscall.Exec(target, args, os.Environ())`. 어느 단계든 실패하면 stderr에 사유를 쓰고 exit `16`. **대상 실행 전에는 어떤 파일도 열지 않는다**
  - `internal/confinement/platform_test.go` [신규]: 교차 컴파일 테스트
- **무영향**: macOS 런타임 동작 무변경. `confine-exec`는 사용법(help)에 노출하지 않으며 다른 하위명령의 동작을 바꾸지 않는다.

---

## 3. 세부 명세

1. **Landlock 규칙** (`ApplySelf`):
   - `prctl(PR_SET_NO_NEW_PRIVS, 1)` → `landlock_create_ruleset`(파일시스템 접근 전체를 handled로 선언) → 규칙 추가 → `landlock_restrict_self`.
   - 읽기·실행 허용: 시스템 경로(`/usr`, `/lib`, `/lib64`, `/bin`, `/etc`, `/proc/self`), 대상 바이너리 경로, `p.ReadPaths`.
   - 읽기·쓰기 허용: `p.WritePaths`, `/dev/null`.
   - `p.ProtectedRoot`가 위 시스템 허용 경로 아래에 있으면 Landlock으로 보호할 수 없으므로 `16`으로 거부한다(Landlock은 허용된 상위 경로 아래를 다시 막을 수 없다).
   - 네트워크: ABI v4+(커널 6.7+)이면 TCP bind/connect를 handled로 선언하고 허용 규칙을 두지 않는다. ABI가 v4 미만인데 `AllowNetwork == false`이면 **네트워크를 막을 수 없으므로** `16`으로 거부한다(침묵 폴백 금지).
2. **`LandlockConfiner`**:
   - `Name() == "linux-landlock"`, `Available()`는 ABI 프로브(`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`) ≥ 1.
   - `Prepare(cmd, p)`: `!Available()`이면 `16`. 아니면 `cmd.Path = 런처 경로`, `cmd.Args = [런처, "confine-exec", "-policy", EncodePolicy(p), "--", 원래 cmd.Path, 원래 cmd.Args[1:]...]`. 런처 경로는 `LandlockConfiner.LauncherPath` 필드로 주입받는다(하네스는 프로덕션 바이너리 경로를 넣는다). 비어 있으면 `16`.
3. **교차 컴파일 및 검증 상태 투명화**:
   - `platform_test.go`: `exec.LookPath("go")`로 찾은 툴체인으로 `GOOS=linux GOARCH=amd64 go vet ./internal/confinement/... ./internal/cli/...`와 `go test -c -o /dev/null ./internal/confinement`를 실행해 오류 0건을 확인한다. 툴체인이 없으면 Skip.
   - 실제 Linux 커널 실행 검증을 못 하면 [11번 README.md](../README.md)와 060 보증 표에 「Linux: 교차 컴파일만 검증, 런타임 미검증」으로 기록한다.

---

## 4. 인수 테스트 시나리오 (요구사항에서 도출)

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | `GOOS=linux GOARCH=amd64` vet·테스트 컴파일 | 오류 0건 |
| **TC-030-02** | 비-Linux 호스트에서 `ApplySelf(p)` | `ReasonConfinementUnavailable(16)` |
| **TC-030-03** | `EncodePolicy` → `DecodePolicy` 왕복 | 원본과 동일. 깨진 입력은 `14` |
| **TC-030-04** | (macOS) `authz-harness confine-exec -policy <valid> -- /usr/bin/true` | exit `16`, 대상 미실행 |
| **TC-030-05** | (Linux 가용 시) 020의 TC-020-04~07과 같은 실험군·대조군 | 부모 관찰로 차단 확인. 비가용 시 보증 표에 미검증 명시 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/confinement -run 'TestCrossCompileLinux|TestPolicyCodec'` PASS
2. `go test -v ./internal/cli -run 'TestConfineExec'` PASS
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
4. `go test ./...` 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `landlock_linux.go`, `launcher.go`, `launcher_other.go`, `cli/confine_exec.go` 작성
- [ ] 교차 컴파일 테스트 통과
- [ ] 호스트 검증 가능 여부에 따른 정직한 상태 기록 (`Done` 허위 표기 금지)
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
