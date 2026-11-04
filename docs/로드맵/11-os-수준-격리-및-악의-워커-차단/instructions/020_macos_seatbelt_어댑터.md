# [구현지시서 020] macOS Seatbelt 격리 어댑터 구현

> **문서 상태**: `Draft` (2026-11-04 [020번 보고서](../../../보고서/020-11번로드맵_구조결함_및_진행가능성_검증보고서.md) 기준 교정)
> **상위 대시보드**: [11번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_격리_정책_도메인_및_어댑터_인터페이스.md](010_격리_정책_도메인_및_어댑터_인터페이스.md) 완료
> **후속 단계**: [030_linux_어댑터_및_검증_환경.md](030_linux_어댑터_및_검증_환경.md)

---

## 1. 목적 및 배경

macOS에서 010의 `Policy`를 Seatbelt 프로파일(SBPL)로 바꿔 `/usr/bin/sandbox-exec -p <profile>`로 자식을 감싸는 어댑터를 만든다. Seatbelt는 커널 확장(`Sandbox.kext`)이 시스템콜 단계에서 집행하며 자손 프로세스에 상속된다. 같은 UID의 프로세스가 스스로 풀 수 없다.

**단일 계층이다.** 교정 전 설계의 커널 VFS DAC(`chmod 0000`/`0400`)와 `RLIMIT_NOFILE` 계층은 폐기했다. 워커는 부모와 같은 UID라서 소유자로서 `chmod`를 되돌릴 수 있고, 파일 모드는 부모와 동시 시나리오까지 영향을 주는 전역 상태이며, 부모가 죽으면 `zone_a`가 잠긴 채 남는다(020번 보고서 L-1).

**중첩 샌드박스**: 이미 Seatbelt 안에서 도는 실행기(일부 에이전트 셸·CI)에서는 `sandbox-exec`가 `sandbox_apply: Operation not permitted`(exit `71`)로 실패할 수 있다. 이 경우 어댑터는 `Available() == false`가 되고, 격리 필수 모드는 스폰을 거부하며(`16`), G10은 `Skipped`가 된다. **폴백은 없다.** 2026-11-04 이 레포의 실행 세션에서 실측한 프로브 결과는 exit `0`(적용 가능)이었다(L-10).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/confinement/seatbelt_darwin.go` [신규]: `RenderSeatbeltProfile`, `CanApplySeatbelt`, `SeatbeltConfiner`, darwin용 `Platform()`
  - `internal/confinement/seatbelt_darwin_test.go` [신규]: 렌더링 table-driven 테스트, 실제 자식 차단 테스트
  - `internal/confinement/platform_noop.go`: 010의 `//go:build !darwin` 유지(변경 없음)
- **무영향**: darwin 파일 접미사로만 분리된다. 스포너에 아직 연결하지 않는다. 부모 프로세스·파일시스템 상태를 바꾸지 않으므로 `env.Cleanup()`에 영향이 없다.

---

## 3. 세부 명세

### 3.1 `RenderSeatbeltProfile(p Policy) (string, error)`

1. `p.Validate()` 실패 시 그대로 반환한다.
2. 모든 경로는 `resolveRealPath`(`filepath.EvalSymlinks`, 파일이 없으면 부모 디렉터리를 해석한 뒤 이름을 붙임)로 정규화한다. macOS의 `/var` → `/private/var`, `/tmp` → `/private/tmp` 때문이다.
3. 경로 문자열은 SBPL 문자열 리터럴로 이스케이프한다(`\`와 `"`). 경로에 개행이 있으면 `14`.
4. 생성 구조 (Seatbelt는 **뒤 규칙이 앞 규칙을 덮는다**):
   ```scheme
   (version 1)
   (allow default)
   (deny network*)                                   ; AllowNetwork == false
   (deny file-write*)                                ; 쓰기는 기본 거부
   (allow file-write* (literal "/dev/null") (literal "/dev/tty"))
   (allow file-write* (subpath "<WritePath>") ...)   ; 파일이면 literal
   (deny file-read* (subpath "<ProtectedRoot>"))     ; 보호 루트 읽기 기본 거부
   (allow file-read* (subpath "<ReadPath|WritePath>") ...)
   ```
   - `ProtectedRoot` 자체의 디렉터리 항목 탐색(`file-read-metadata`)이 필요하면 `(allow file-read-metadata (literal "<ProtectedRoot>"))`를 둔다. 실제 자식 테스트로 필요 여부를 확인하고 결과를 주석에 남긴다.
5. `sandbox-exec`는 Apple이 deprecated로 표기한 도구다. 포트 뒤에 있으므로 교체 가능하다는 점을 파일 주석과 060 보증 표에 남긴다.

### 3.2 `CanApplySeatbelt() bool`

- `sync.Once`로 1회만 `/usr/bin/sandbox-exec -p "(version 1)(allow default)" /usr/bin/true`를 실행하고 exit `0`이면 `true`. 실패 사유(exit `71` 등)는 `slog.Debug`로 남긴다(stderr 운영 로그).

### 3.3 `SeatbeltConfiner`

- `Name() == "darwin-seatbelt"`, `Available() == CanApplySeatbelt()`.
- `Prepare(cmd, p)`: `!Available()`이면 `16`. 아니면 프로파일을 렌더링하고 `cmd.Path = "/usr/bin/sandbox-exec"`, `cmd.Args = ["sandbox-exec", "-p", profile, 원래 cmd.Path, 원래 cmd.Args[1:]...]`로 바꾼다. `sandbox-exec`는 프로파일 적용 후 대상을 `exec`하므로 PID가 유지된다.
- darwin용 `Platform()`은 `SeatbeltConfiner{}`를 반환한다.

### 3.4 실제 자식 차단 테스트

- [`spawner_test.go`](../../../../internal/orchestrator/spawner_test.go) 22행의 `TestHelperProcess`(`HELPER_MODE`) 패턴을 `confinement` 패키지에 둔다. 헬퍼는 `read <path>`, `write <path>`, `chmod_then_read <path>`, `dial <addr>`을 수행하고 결과(`ok`/`err=<errno>`)와 읽은 내용을 stdout에 쓴다.
- 판정은 **부모(테스트)** 가 한다: 읽은 canary가 stdout에 있는가, 대상 파일이 생겼는가, 리스너가 accept했는가.
- `CanApplySeatbelt() == false`이면 `t.Skip("seatbelt unavailable: nested sandbox")`. 거짓 PASS도 거짓 FAIL도 만들지 않는다.

---

## 4. 인수 테스트 시나리오 (요구사항에서 도출)

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | `/tmp`·`/var` 아래 경로를 담은 정책으로 `RenderSeatbeltProfile` | `(version 1)`, `(deny network*)`, `(deny file-write*)`, `/private/...`로 정규화된 `ProtectedRoot`·`WritePaths` 포함. `zone_a` 문자열 0회 |
| **TC-020-02** | `"`가 들어간 경로 | 이스케이프된 리터럴. 개행이 든 경로는 `14` |
| **TC-020-03** | 격리된 헬퍼가 `WritePaths` 안의 파일을 쓰고 다시 읽음 | 부모가 파일 내용 일치를 확인 |
| **TC-020-04** | 격리된 헬퍼가 `root/zone_a/canary` 읽기, 그리고 `chmod_then_read` | 두 경우 모두 stdout에 canary 없음. 부모는 같은 파일을 읽을 수 있음 |
| **TC-020-05** | 격리된 헬퍼가 `root` 밖 임시 디렉터리에 쓰기 | 부모가 확인한 파일 미생성 |
| **TC-020-06** | 부모가 연 `127.0.0.1` 리스너에 격리된 헬퍼가 접속 | 부모 리스너 accept 0건(짧은 deadline) |
| **TC-020-07** | 격리하지 않은 같은 헬퍼로 TC-020-04~06 (대조군) | canary 있음, 파일 생성, accept 1건 — 테스트 자체의 유효성 증명 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/confinement -run 'TestRenderSeatbelt'` PASS
2. `go test -v ./internal/confinement -run 'TestSeatbeltConfiner'` PASS 또는 프로브 실패 시 SKIP(사유 출력)
3. `go test -race ./internal/confinement` PASS
4. `go test ./...` 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `RenderSeatbeltProfile`(정규화·이스케이프), `CanApplySeatbelt`, `SeatbeltConfiner` 구현
- [ ] 실험군·대조군 자식 테스트 통과(또는 SKIP 사유 기록)
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
