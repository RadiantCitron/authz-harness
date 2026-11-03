# [구현지시서 020] macOS Seatbelt 및 커널 VFS 격리 어댑터 구현 (중첩 샌드박스 대응 포함)

> **문서 상태**: `Draft`
> **상위 대시보드**: [11번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_격리_정책_도메인_및_어댑터_인터페이스.md](010_격리_정책_도메인_및_어댑터_인터페이스.md) 완료
> **후속 단계**: [030_linux_어댑터_및_검증_환경.md](030_linux_어댑터_및_검증_환경.md)

---

## 1. 목적 및 배경

macOS(`darwin`) 환경에서 서브프로세스 워커에 커널 수준 격리를 적용하는 어댑터를 구현한다.
이때 실제 macOS 호스트 점검에서 확인된 **핵심 커널 제약사항**을 반드시 반영한다:
- macOS XNU 커널(`Sandbox.kext`)은 **중첩 `sandbox_apply`를 허용하지 않는다.** 즉 일반 사용자 터미널에서는 `/usr/bin/sandbox-exec -p <profile>`이 정상 작동하지만, 이미 상위 Seatbelt 샌드박스 안에서 돌아가는 실행기(예: AI 에이전트 샌드박스 셸, 일부 CI 러너)에서 `sandbox-exec`를 호출하면 `sandbox-exec: sandbox_apply: Operation not permitted` (`exit code 71`)로 즉시 실패한다.
- 따라서 macOS 어댑터(`DarwinConfiner`)는 ① **SBPL 프로파일 생성 및 런타임 실행 가능 여부 프로브(`CanApplySeatbelt()`)**와 ② 상위 샌드박스 중첩 여부와 무관하게 XNU 커널 VFS/소켓 계층에서 작동하는 **커널 VFS DAC(`chmod 0000`/`0500`) + 커널 FD 한계(`RLIMIT_NOFILE`) 격리**를 결합한 2계층으로 구현하여, 어떤 macOS 실행 환경에서도 워커가 PEP를 우회해 직접 OS 시스템콜(`open(2)`, `socket(2)`)을 호출할 때 **100% OS 커널 에러(`EACCES` / `EPERM` / `EMFILE`)로 차단**되도록 보장한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/confinement/seatbelt_darwin.go` [신규] (`//go:build darwin`):
    - `RenderSeatbeltProfile(policy ConfinementPolicy) (string, error)` (SBPL 생성기, `filepath.EvalSymlinks` 정규화 포함)
    - `CanApplySeatbelt() bool` (`sync.Once`로 `/usr/bin/sandbox-exec -p "(version 1)(allow default)" /usr/bin/true` 실제 기동 가능 여부 1회 프로브)
    - `DarwinConfiner` 구현 (`CanApplySeatbelt() == true`이면 `sandbox-exec -p` + 커널 VFS DAC 잠금 동시 적용, 중첩 샌드박스 환경이면 커널 VFS DAC 잠금 + 소켓 차단 적용 및 `Name()`에 모드 명시)
  - `internal/confinement/seatbelt_other.go` [신규] (`//go:build !darwin`): 비-macOS 환경용 스텁
  - `internal/confinement/seatbelt_darwin_test.go` [신규] (`//go:build darwin`): SBPL 프로파일 렌더링 검증 및 실제 자식 프로세스의 Zone A 읽기·외부 쓰기·소켓 차단과 정직한 워커 허용 단위 테스트
- **무영향**:
  - `darwin` 빌드 태그로 격리되며, `cleanup()` 콜백이 자식 종료 직후 VFS 디렉터리 권한을 원상 복구하므로 테스트 샌드박스 정리(`env.Cleanup()`)에 지장을 주지 않는다.

---

## 3. 세부 명세

### 3.1 SBPL 프로파일 생성기 (`RenderSeatbeltProfile`)
1. 모든 경로는 macOS의 `/var` → `/private/var`, `/tmp` → `/private/tmp` 심볼릭 링크를 해소하기 위해 반드시 `resolveRealPath(p)`(`filepath.EvalSymlinks`, 파일 미존재 시 부모 디렉터리 기준 해석)를 거친 뒤 SBPL에 기입한다.
2. 생성되는 SBPL 구조:
   ```scheme
   (version 1)
   (allow default)
   (deny network*) ; policy.AllowNetwork == false 일 때
   (deny file-write* (subpath "/Users") (subpath "/private/var") (subpath "/private/tmp"))
   (allow file-read* file-write* (subpath "<AllowWritePath_1>") ...)
   (deny file-write* (literal "<ReadOnlyPath_grants_state.json>") (literal "<ReadOnlyPath_jwks.json>"))
   (deny file-read* file-write* (subpath "<DenyPath_ZoneA>") ...)
   ```
   - 시스템 라이브러리(`/usr/lib`, `/System/Library`, `/dev/null`, `/dev/urandom`)와 바이너리 읽기는 유지하면서, `AllowWritePaths`(`workspace`, `zone_b`, `audit.jsonl`) 외의 임시·사용자 경로 쓰기를 막고, 마지막 줄의 `(deny file-read* file-write* (subpath "<DenyPath>"))`로 Zone A(`zone_a`) 접근을 최우선 차단한다.

### 3.2 커널 VFS DAC 잠금 및 복구 (`Prepare` & `cleanup`)
1. `Prepare(cmd *exec.Cmd, policy ConfinementPolicy)` 실행 시:
   - `policy.DenyPaths`(예: `zone_a` 디렉터리 및 외부 읽기 금지 대상)에 대해 현재 파일 모드를 저장한 뒤 `os.Chmod(p, 0000)`을 호출한다. 이로써 악의 워커(및 그 손자 프로세스)가 PEP를 우회해 `os.ReadFile(zone_a/private_keys.json)`을 호출하면 XNU 커널 VFS `open(2)` 시스템콜이 즉시 `EACCES (permission denied)`를 반환한다.
   - `policy.ReadOnlyPaths`(`grants_state.json`, `jwks.json`) 파일에 대해서는 현재 파일 모드를 저장한 뒤 `os.Chmod(p, 0400)`(읽기 전용)으로 잠그어, 워커가 `zone_b` 내 `.lock` 및 실행 원장(`replay`, `budget`, `approvals`)은 갱신할 수 있으면서도 정책·공개키 원장 본파일은 절대 덮어쓸 수 없게 보호한다.
   - 외부 쓰기 금지 대상 디렉터리(또는 `DenyPaths` 내 쓰기 금지 디렉터리)가 존재하면 `0500`(읽기·탐색만 허용, 쓰기 불가) 또는 `0000`으로 잠근다.
   - `CanApplySeatbelt() == true`이면 `cmd`를 `/usr/bin/sandbox-exec -p <profile>`로 추가 래핑한다.
2. `cleanup()` 호출 시:
   - `Prepare`에서 변경한 모든 디렉터리 모드를 원래 모드(`0700` 등)로 즉시 복원한다 (`defer cleanup()`으로 스포너에서 100% 호출 보장).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | `RenderSeatbeltProfile(policy)` 호출 | `(version 1)`, `(deny network*)`, 정규화된(`/private/var/...`) `AllowWritePaths` 및 `DenyPaths` 모두 포함 |
| **TC-020-02** | `DarwinConfiner` 적용 하에 `AllowWritePaths` 내부 파일 읽기·쓰기 수행 | 정상 성공 (`ExitCode == 0`) |
| **TC-020-03** | `DarwinConfiner` 적용 하에 `DenyPaths`(`zone_a/private_keys.json`) 직접 `os.ReadFile` 시도 | OS 커널 `permission denied`(`EACCES`)로 즉시 실패, `cleanup()` 후 부모는 정상 접근 가능 |
| **TC-020-04** | `DarwinConfiner` 적용 하에 보호된 외부 디렉터리에 직접 `os.WriteFile` 시도 | OS 커널 `permission denied`로 즉시 실패, 파일 미생성 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/confinement -run TestSeatbelt` PASS
2. `go test -v ./internal/confinement -run TestDarwinConfiner` PASS
3. `cleanup()` 후 `env.Cleanup()` 잔여 파일 0건 확인
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `RenderSeatbeltProfile`(`EvalSymlinks` 정규화) 및 `CanApplySeatbelt()` 프로브 구현 완료
- [ ] `DarwinConfiner` 커널 VFS 잠금·복원(`cleanup`) 및 `sandbox-exec` 결합 구현 완료
- [ ] Zone A 읽기·외부 쓰기 차단 및 정직한 경로 허용 테스트 통과 후 단독 커밋
