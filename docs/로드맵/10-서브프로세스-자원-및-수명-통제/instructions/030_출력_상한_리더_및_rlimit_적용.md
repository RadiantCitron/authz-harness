# [구현지시서 030] 출력 상한 리더(`limitedBuffer`) 및 단일 취소 트리거(`onExceed = cancel`) 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [10번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [020_프로세스_그룹_일괄_종료_및_waitdelay.md](020_프로세스_그룹_일괄_종료_및_waitdelay.md) 완료
> **후속 단계**: [040_감사_이벤트_ui_및_mcp_오류_매핑.md](040_감사_이벤트_ui_및_mcp_오류_매핑.md)

---

## 1. 목적 및 배경

자식 워커가 무한 루프로 `stdout`이나 `stderr`에 대량 데이터를 쏟아낼 경우, 부모 스포너의 `bytes.Buffer`가 호스트 메모리를 고갈시킬 수 있다(OOM 공격면).
본 단계에서는 바이트 상한을 초과하는 순간 즉시 실행 컨텍스트의 `cancel()`을 트리거하여 [`020`](020_프로세스_그룹_일괄_종료_및_waitdelay.md)에서 등록한 `cmd.Cancel`(`KillProcessGroup`) 단일 경로로 프로세스 그룹을 즉시 사살하고, 부모 버퍼 보관량을 `MaxOutputBytes` 이하로 엄격히 제한하는 `limitedBuffer`를 구현한다.
([016번 보고서](../../../보고서/016-다중로드맵_일괄설계_안티패턴_진단_및_10번로드맵_단독집중_구조정제_보고서.md) `R10-01`·`R10-02`에 따라, 부모에서 자식에 강제할 수 없는 플라시보 `rlimit_unix.go` 코드는 배제하고 100% 부모 강제 메커니즘에만 집중한다.)

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/orchestrator/limited_writer.go` [신규]: 바이트 상한을 초과하는 순간 `once.Do(onExceed)`를 호출하고 버퍼 보관량을 `MaxOutputBytes` 이하로 엄격히 캡핑하는 스레드 안전 `limitedBuffer` 구현
  - `internal/orchestrator/limited_writer_test.go` [신규]: 경계값(상한-1, 상한 일치, 상한+1바이트, 대량 청크 연속 입력) 단위 테스트
  - `internal/orchestrator/spawner.go`:
    - `SpawnResult`에 `OutputExceeded bool` 추가
    - `stdout`/`stderr`에 `newLimitedBuffer(s.cfg.Limits.MaxOutputBytes, cancel)` 연결 (`onExceed`에 `execCtx`의 `cancel` 함수를 직접 전달하여 `cmd.Cancel` 단일 경로로 프로세스 그룹 종료)
    - 출력 초과 시 `ExitCode = 17`(`ExitResourceLimit`), `Reason = RESOURCE_OUTPUT_LIMIT` 부여
- **무영향**:
  - 정상 JSON 프레임 응답(수백 바이트~수십 KiB)은 기본 상한(1 MiB)보다 훨씬 작으므로 정상 실행 경로에는 영향을 주지 않는다.

---

## 3. 세부 명세

### 3.1 바이트 상한 버퍼 및 단일 종료 트리거 (`internal/orchestrator/limited_writer.go`)
1. `type limitedBuffer struct`:
   - 필드: `mu sync.Mutex`, `buf bytes.Buffer`, `maxBytes int64`, `exceeded bool`, `once sync.Once`, `onExceed func()`
2. `Write(p []byte) (int, error)`:
   - `int64(buf.Len()) + int64(len(p)) > maxBytes`인 경우:
     - 남은 여유 바이트(`remaining = maxBytes - int64(buf.Len())`)가 0보다 크면 그만큼만 `buf`에 기록하여 **부모 프로세스의 버퍼 보관량이 절대로 `maxBytes`를 넘지 않게** 한다.
     - `exceeded = true`로 설정하고, `onExceed != nil`이면 `once.Do(onExceed)`를 호출한다.
     - **동시성 안전성 (`R10-02`)**: `spawner.go`에서 `onExceed`로 `KillProcessGroup(cmd)`를 직접 넘기지 않고 **`execCtx`의 `cancel` 함수**를 넘긴다. 그러면 `cancel()` 호출 시 Go 표준 `os/exec`의 감시 고루틴이 스레드 안전하게 `cmd.Cancel`(`KillProcessGroup(cmd)`)을 호출하므로 `cmd.Process`에 대한 데이터 레이스가 원천 차단된다.
     - `errOutputLimitExceeded` 에러를 반환하여 파이프 복사 루프를 즉시 중단시킨다.
3. `Exceeded() bool`, `Len() int`, `String() string`, `Bytes() []byte` 메서드를 제공한다.

### 3.2 `SubprocessSpawner` 출력 초과 판정 우선순위 (`internal/orchestrator/spawner.go`)
- `stdoutBuf.Exceeded() || stderrBuf.Exceeded()`가 참이면:
  - `onExceed`(`cancel()`)에 의해 컨텍스트가 취소되었더라도 타임아웃보다 **출력 상한 초과가 원인이므로** 최우선으로 `result.OutputExceeded = true`, `result.TimedOut = false`, `result.ExitCode = int(domain.ExitResourceLimit)`(`17`), `result.Reason = domain.ReasonResourceOutputLimit`으로 판정한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | `maxBytes = 1024`인 `limitedBuffer`에 1024바이트 기록 | `Exceeded() == false`, 보관량 정확히 1024바이트 |
| **TC-030-02** | `maxBytes = 1024`인 `limitedBuffer`에 1025바이트(또는 64 KiB 청크) 기록 | `Exceeded() == true`, `onExceed` 정확히 1회 호출, `buf.Len() <= 1024` |
| **TC-030-03** | `flood` 모드 워커 기동 + `MaxOutputBytes: 16 * 1024` (16 KiB) | 즉시 그룹 종료, `ExitCode == 17`, `Reason == RESOURCE_OUTPUT_LIMIT`, `len(res.StdoutRaw) <= 16384` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/orchestrator -run TestLimitedBuffer` PASS
2. `go test -v -tags testworker ./internal/orchestrator -run TestSpawnOutputLimit` PASS
3. `go test -race -tags testworker ./internal/orchestrator` 데이터 레이스 0건
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `limitedBuffer` 상한 초과 시 `once.Do(cancel)` 트리거 및 보관량 상한 보장 구현
- [ ] `flood` 워커 연동 출력 상한 초과(`17`, `RESOURCE_OUTPUT_LIMIT`) 및 `-race` 테스트 통과
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
