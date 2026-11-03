# [구현지시서 020] 프로세스 그룹 일괄 종료 및 WaitDelay 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [10번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_자원_한계_도메인_모델_및_테스트_전용_워커.md](010_자원_한계_도메인_모델_및_테스트_전용_워커.md) 완료
> **후속 단계**: [030_출력_상한_리더_및_rlimit_적용.md](030_출력_상한_리더_및_rlimit_적용.md)

---

## 1. 목적 및 배경

기존 [`spawner.go`](../../../../internal/orchestrator/spawner.go)는 `exec.CommandContext`의 기본 동작만 사용하여 타임아웃 시 직계 자식 프로세스 1개에만 `SIGKILL`을 보낸다. 만약 워커가 손자 프로세스를 생성한 채 멈추거나 파이프를 열어 두면, 부모의 `cmd.Run()`이 블로킹되거나 타임아웃 이후에도 손자 프로세스가 호스트에 고아(orphan)로 잔존한다.
본 단계에서는 서브프로세스를 **독립 프로세스 그룹(`Setpgid: true`)**으로 기동하고, 컨텍스트 만료·취소 시 **프로세스 그룹 전체(`-pgid`)에 `SIGKILL`**을 전송하며, `cmd.WaitDelay`를 설정해 I/O 파이프 대기가 무한정 길어지지 않도록 차단한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/orchestrator/procgroup_unix.go` [신규] (`//go:build unix || darwin || linux`):
    - `configureProcessGroup(cmd *exec.Cmd, waitDelay time.Duration)`
    - `KillProcessGroup(cmd *exec.Cmd) error`
    - `WaitForProcessGone(pid int, timeout time.Duration) bool` (`syscall.Kill(pid, 0) == syscall.ESRCH` 폴링)
    - ` wasSignaled(err error) bool` (`syscall.WaitStatus.Signaled()` 판별)
  - `internal/orchestrator/spawner.go`:
    - `SpawnConfig`에 `Limits domain.Limits` 추가. 생성자 `NewSubprocessSpawner(cfg)`에서 1회 정규화 수행: `cfg.Limits.Timeout == 0 && cfg.Timeout > 0`이면 `cfg.Limits.Timeout = cfg.Timeout`으로 병합한 뒤 `normLimits, err := cfg.Limits.Normalize()`를 호출(음수 값이면 생성자에서 즉시 에러 반환)하고 `cfg.Limits = normLimits`, `cfg.Timeout = normLimits.Timeout`으로 일원화 ([016번 보고서](../../../보고서/016-다중로드맵_일괄설계_안티패턴_진단_및_10번로드맵_단독집중_구조정제_보고서.md) `R10-03`)
    - `SpawnResult`에 `Reason domain.Reason` 필드 추가
    - 프로세스 그룹 설정·`WaitDelay` 배선, 타임아웃/시그널 종료 시 `ExitResourceLimit(17)` 및 `ReasonResourceTimeout` / `ReasonResourceSignalKilled` 판정 반영
  - `internal/orchestrator/multi_hop.go`: `MultiHopConfig`에 `Limits domain.Limits` 전달 지원
  - `internal/orchestrator/spawner_group_test.go` [신규]: 멈춘 워커, 손자 프로세스 생성 워커(`CHILD_PID=<pid>` 파싱 후 `WaitForProcessGone` 확인), 외부 시그널 종료 검증 테스트
- **무영향**:
  - 정상 종료(`ExitCode == 0`) 및 인가 거부(`11`~`16`) 워커는 만료 전에 스스로 종료하므로 기존 동작과 100% 동일하다.
  - 기존 [`spawner_test.go`](../../../../internal/orchestrator/spawner_test.go)의 `TestTC01`~`TestTC10`(`TestTC09_TimeoutKill`은 `res.TimedOut == true && res.ExitCode != 0`만 검사함)과 100% 호환된다.

---

## 3. 세부 명세

### 3.1 프로세스 그룹 격리 및 일괄 종료 (`internal/orchestrator/procgroup_unix.go`)
1. `configureProcessGroup(cmd *exec.Cmd, waitDelay time.Duration)`:
   - `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}`를 설정하여 자식의 `PID`가 곧 새로운 프로세스 그룹 `PGID`가 되게 한다.
   - `cmd.Cancel = func() error { return KillProcessGroup(cmd) }`로 설정한다.
   - `cmd.WaitDelay = waitDelay`를 설정한다.
2. `KillProcessGroup(cmd *exec.Cmd) error`:
   - `cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0`이면 `nil`을 반환한다.
   - `err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)`을 호출하여 프로세스 그룹 전체에 `SIGKILL`을 보낸다. `errors.Is(err, syscall.ESRCH)`이면 이미 소멸된 상태이므로 `nil`을 반환한다.
3. `WaitForProcessGone(pid int, timeout time.Duration) bool`:
   - 고정 `time.Sleep` 추측을 금지한다 ([ROADMAP.md](../ROADMAP.md) §4 방어책).
   - 10ms 주기로 `err := syscall.Kill(pid, 0)`을 확인하여 `errors.Is(err, syscall.ESRCH)`이면 즉시 `true`를 반환하고, `timeout`까지 소멸하지 않으면 `false`를 반환한다.

### 3.2 `SubprocessSpawner` 종료 사유 및 JSON 프레임 오염 방지 (`internal/orchestrator/spawner.go`)
1. 종료 판정 우선순위:
   - `execCtx.Err() == context.DeadlineExceeded || (ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded))`인 경우:
     - `result.TimedOut = true`
     - `result.ExitCode = int(domain.ExitResourceLimit)` (`17`)
     - `result.Reason = domain.ReasonResourceTimeout`
   - 타임아웃이 아닌데 `wasSignaled(runErr)`(`exitErr.Sys().(syscall.WaitStatus).Signaled()`)가 참인 경우:
     - `result.ExitCode = int(domain.ExitResourceLimit)` (`17`)
     - `result.Reason = domain.ReasonResourceSignalKilled`
2. **`stdout` JSON 파싱 가드 (핵심 주의사항)**:
   - `result.ExitCode != int(domain.ExitResourceLimit)`일 때만 `stdoutBuf`를 `SubagentResponse`로 파싱하고, 파싱된 `resp.Reason != ""`이면 `result.Reason = domain.Reason(resp.Reason)`으로 설정한다.
   - 자원 한계(`ExitCode == 17`)로 강제 종료된 경우에는 자식의 불완전한 출력이 `result.Reason`이나 `result.Response`를 덮어쓰지 못하게 차단한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | `hang` 워커 기동 + `Timeout: 100ms` | 약 100ms 내 종료, `ExitCode == 17`, `Reason == RESOURCE_TIMEOUT`, `TimedOut == true` |
| **TC-020-02** | `spawn_child_hang` 워커 기동(`CHILD_PID=<pid>` 출력 후 대기) + `Timeout: 150ms` | `ExitCode == 17`, `Reason == RESOURCE_TIMEOUT`, `WaitForProcessGone(childPID, 1s) == true` (손자 프로세스 생존 0) |
| **TC-020-03** | 기동된 워커 프로세스에 외부 `SIGTERM` 전송 | `ExitCode == 17`, `Reason == RESOURCE_SIGNAL_KILLED` |
| **TC-020-04** | 기존 `spawner_test.go` (`TestTC01`~`TestTC10`) 전체 실행 | 전수 `PASS` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/orchestrator` PASS
2. `go test -v -tags testworker ./internal/orchestrator -run TestProcessGroup` PASS
3. `go test -race -tags testworker ./internal/orchestrator` 데이터 레이스 0건
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `Setpgid: true` 및 `-pgid` 그룹 종료(`KillProcessGroup`) 구현 완료
- [ ] `WaitDelay` 설정 및 `WaitForProcessGone`(`ESRCH` 폴링) 구현 완료
- [ ] 손자 프로세스 잔존 0 단위 테스트(`TC-020-02`) 통과
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
