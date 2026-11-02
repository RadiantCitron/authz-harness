# [구현지시서 020] 프로세스 그룹 일괄 종료 및 WaitDelay 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [10번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_자원_한계_도메인_모델_및_테스트_전용_워커.md](010_자원_한계_도메인_모델_및_테스트_전용_워커.md) 완료
> **후속 단계**: [030_출력_상한_리더_및_rlimit_적용.md](030_출력_상한_리더_및_rlimit_적용.md)

---

## 1. 목적 및 배경

기존 [`spawner.go`](../../../../internal/orchestrator/spawner.go)는 `exec.CommandContext`만 사용하여 타임아웃 시 직계 자식 프로세스 1개에만 `SIGKILL`을 보낸다. 만약 워커가 손자 프로세스를 생성한 채 멈추거나 파이프를 열어 두면, 부모의 `cmd.Run()`이 블로킹되거나 타임아웃 이후에도 손자 프로세스가 호스트에 고아(orphan)로 잔존한다.
본 단계에서는 서브프로세스를 **독립 프로세스 그룹(`Setpgid: true`)**으로 기동하고, 컨텍스트 만료·취소 시 **프로세스 그룹 전체(`-pgid`)에 `SIGKILL`**을 전송하며, `cmd.WaitDelay`를 설정해 I/O 파이프 대기가 무한정 길어지지 않도록 차단한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/orchestrator/procgroup_unix.go` [신규] (`//go:build unix || darwin || linux`): `SysProcAttr{Setpgid: true}` 설정, `cmd.Cancel`에서 `syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)` 호출, `IsProcessAlive(pid int) bool` (`syscall.Kill(pid, 0)` 기반 생존 확인) 구현
  - `internal/orchestrator/spawner.go`: `SpawnConfig`에 `Limits domain.Limits` 통합(기존 `Timeout` 필드 하위 호환 유지), 프로세스 그룹 설정·`WaitDelay` 배선, 종료 시 `ExitResourceLimit(17)` 및 `ReasonResourceTimeout` / `ReasonResourceSignalKilled` 판정 반영
  - `internal/orchestrator/multi_hop.go`: `MultiHopConfig`에서 `Limits`를 하위 `SubprocessSpawner`로 전달
  - `internal/orchestrator/spawner_group_test.go` [신규] (`//go:build testworker`): 멈춘 워커 및 손자 프로세스 생성 워커에 대한 그룹 일괄 종료·잔존 PID 0 검증 테스트
- **무영향**:
  - 정상 종료(`ExitCode == 0`) 및 인가 거부(`11`~`16`) 워커는 만료 전에 스스로 종료하므로 기존 동작과 100% 동일하다.
  - `SpawnConfig.Timeout`만 지정한 기존 호출부는 `Limits.Timeout`으로 자동 승계되어 시그니처가 깨지지 않는다.

---

## 3. 세부 명세

### 3.1 프로세스 그룹 격리 및 일괄 종료 (`internal/orchestrator/procgroup_unix.go`)
1. `configureProcessGroup(cmd *exec.Cmd, waitDelay time.Duration)`:
   - `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}`를 설정하여 자식의 `PID`가 곧 새로운 `PGID`가 되게 한다.
   - `cmd.Cancel = func() error`: `cmd.Process != nil`일 때 `syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)`을 호출하여 직계 자식과 그 자식이 생성한 모든 하위 프로세스를 동시에 강제 종료한다. (`ESRCH`는 이미 종료된 상태이므로 정상 처리)
   - `cmd.WaitDelay = waitDelay`를 설정하여 강제 종료 후 열려 있는 파이프 디스크립터로 인한 무한 대기를 방지한다.
2. `WaitForProcessGone(pid int, timeout time.Duration) bool`:
   - 고정 `time.Sleep` 추측을 금지한다 ([ROADMAP.md](../ROADMAP.md) §4 방어책).
   - 10ms 주기로 `syscall.Kill(pid, 0)`을 폴링하여 `errors.Is(err, syscall.ESRCH)`가 확인되면 즉시 `true`(완전 소멸)를 반환하고, `timeout` 내 소멸하지 않으면 `false`를 반환한다.

### 3.2 `SubprocessSpawner` 종료 사유 및 코드 정교화 (`internal/orchestrator/spawner.go`)
1. `SpawnResult` 확장:
   - `Reason domain.Reason` 필드를 추가하여 자원 한계 종료 시 사유(`RESOURCE_TIMEOUT`, `RESOURCE_SIGNAL_KILLED` 등)를 명시적으로 담는다.
2. 종료 판정 우선순위:
   - `execCtx.Err() == context.DeadlineExceeded`이면 `result.TimedOut = true`, `result.ExitCode = int(domain.ExitResourceLimit)`(`17`), `result.Reason = domain.ReasonResourceTimeout`으로 설정한다.
   - 타임아웃이 아닌데 `exitErr`의 `Sys()`(`syscall.WaitStatus`)가 `Signaled()`이면 `result.ExitCode = int(domain.ExitResourceLimit)`(`17`), `result.Reason = domain.ReasonResourceSignalKilled`로 설정한다.
   - 정상 JSON 프레임(`result.Response`)이 수신된 경우 `result.Reason = domain.Reason(result.Response.Reason)`을 유지한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | `hang` 모드 워커 기동 + `Timeout: 100ms` | 약 100ms 내 종료, `ExitCode == 17`, `Reason == RESOURCE_TIMEOUT`, `TimedOut == true` |
| **TC-020-02** | `spawn_child_hang` 모드 워커 기동(손자 PID 출력 후 대기) + `Timeout: 150ms` | `ExitCode == 17`, `Reason == RESOURCE_TIMEOUT`, `WaitForProcessGone(childPID, 1s) == true` (손자 프로세스 생존 0) |
| **TC-020-03** | 기동된 워커 프로세스에 외부 `SIGTERM` 전송 | `ExitCode == 17`, `Reason == RESOURCE_SIGNAL_KILLED` |
| **TC-020-04** | 기존 정상 워커 요청 실행 | `ExitCode == 0`, 기존 `spawner_test.go` 전수 통과 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/orchestrator` PASS (일반 빌드)
2. `go test -v -tags testworker ./internal/orchestrator -run TestProcessGroup` PASS (손자 PID 소멸 확인)
3. `go test -race -tags testworker ./internal/orchestrator` 데이터 레이스 0건
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `Setpgid: true` 및 `-pgid` 그룹 종료 구현 완료
- [ ] `WaitDelay` 설정 및 `syscall.Kill(pid, 0) == ESRCH` 폴링 검증 함수 구현 완료
- [ ] 손자 프로세스 잔존 0 단위 테스트(`TC-020-02`) 통과
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
