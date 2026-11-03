# [구현지시서 030] 출력 상한 리더(`limitedBuffer`) 및 자식 워커 `rlimit`(best-effort) 적용

> **문서 상태**: `Draft`
> **상위 대시보드**: [10번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [020_프로세스_그룹_일괄_종료_및_waitdelay.md](020_프로세스_그룹_일괄_종료_및_waitdelay.md) 완료
> **후속 단계**: [040_감사_이벤트_ui_및_mcp_오류_매핑.md](040_감사_이벤트_ui_및_mcp_오류_매핑.md)

---

## 1. 목적 및 배경

자식 워커가 무한 루프로 `stdout`이나 `stderr`에 대량 데이터를 쏟아낼 경우, 부모 스포너의 `bytes.Buffer`가 호스트 메모리를 고갈시킬 수 있다(OOM 공격면).
또한 OS 커널 자원 한계(`rlimit`)는 플랫폼(macOS vs Linux)마다 지원 범위가 다르므로, 지원되는 항목(`RLIMIT_NOFILE`, `RLIMIT_CPU`)을 best-effort로 적용하되 **부모 프로세스 자신이 오염되지 않도록 주의**하고, 적용 성공·미지원 결과를 구조화하여 감사 메타데이터에 남겨야 허위 보증을 막을 수 있다 ([ROADMAP.md](../ROADMAP.md) §4).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/orchestrator/limited_writer.go` [신규]: 바이트 상한을 초과하는 순간 즉시 콜백(`onExceed`)을 호출하여 프로세스 그룹을 종료시키고, 버퍼 보관량을 `MaxOutputBytes` 이하로 엄격히 제한하는 스레드 안전 `limitedBuffer` 구현
  - `internal/orchestrator/limited_writer_test.go` [신규]: 경계값(상한-1, 상한 일치, 상한+1바이트, 대량 청크 연속 입력) 단위 테스트
  - `internal/orchestrator/rlimit_unix.go` [신규] (`//go:build unix || darwin || linux`): `RLimitStatus` 구조체 및 플랫폼별 `rlimit` 가능 여부 점검·자식 워커 전용 적용 헬퍼 구현
  - `internal/orchestrator/spawner.go`:
    - `SpawnResult`에 `OutputExceeded bool` 및 `RLimitStatus *RLimitStatus` 추가
    - `stdout`/`stderr`에 `limitedBuffer` 연결, 출력 초과 시 즉시 `KillProcessGroup(cmd)` 및 `cancel()` 트리거 후 `ExitCode = 17`(`ExitResourceLimit`), `Reason = RESOURCE_OUTPUT_LIMIT` 부여
- **무영향**:
  - 정상 JSON 프레임 응답(수백 바이트~수십 KiB)은 기본 상한(1 MiB)보다 훨씬 작으므로 정상 실행 경로에는 영향을 주지 않는다.

---

## 3. 세부 명세

### 3.1 바이트 상한 버퍼 (`internal/orchestrator/limited_writer.go`)
1. `type limitedBuffer struct`:
   - 필드: `mu sync.Mutex`, `buf bytes.Buffer`, `maxBytes int64`, `exceeded bool`, `once sync.Once`, `onExceed func()`
2. `Write(p []byte) (int, error)`:
   - `int64(buf.Len()) + int64(len(p)) > maxBytes`인 경우:
     - 남은 여유 바이트(`remaining = maxBytes - int64(buf.Len())`)가 0보다 크면 그만큼만 `buf`에 기록하여 **부모 프로세스의 버퍼 보관량이 절대로 `maxBytes`를 넘지 않게** 한다.
     - `exceeded = true`로 설정하고 `once.Do(onExceed)`를 호출하여 즉시 프로세스 그룹에 `SIGKILL`을 보낸다.
     - `errOutputLimitExceeded` 에러를 반환하여 `os/exec` 복사 루프를 즉시 종료시킨다.
3. `Exceeded() bool`, `Len() int`, `String() string`, `Bytes() []byte` 메서드를 제공한다.

### 3.2 플랫폼별 `rlimit` best-effort 적용 및 부모 프로세스 오염 방지 (`internal/orchestrator/rlimit_unix.go`)
1. **부모 프로세스 보호 불변식 (핵심 주의사항)**:
   - Go 표준 `os/exec`는 자식 생성 시 `setrlimit`을 대신 호출해주는 `SysProcAttr` 필드가 없다. 만약 부모 프로세스(`SubprocessSpawner.Spawn`) 안에서 `syscall.Setrlimit`을 직접 호출하면 **부모(오케스트레이터/테스트 러너) 자신의 파일 디스크립터·CPU 한계가 깎여 전체 테스트가 죽는다.**
   - 따라서 부모 프로세스에서는 `EvaluateRLimitSupport(limits domain.Limits) RLimitStatus`로 현재 커널의 `Getrlimit` 조회 가능 여부와 플랫폼 지원 상태(`RLIMIT_CPU`, `RLIMIT_NOFILE` 지원, `darwin`에서 `RLIMIT_AS` 미지원 등)를 점검해 `RLimitStatus`를 생성하고, 실제 `syscall.Setrlimit` 호출은 `limits.ApplyRLimit == true`일 때 자식 워커 프로세스 내부(`ApplySelfRLimit`)에서만 수행한다.
2. `type RLimitStatus struct`:
   - `Requested bool` (`json:"requested"`)
   - `Applied []string` (`json:"applied,omitempty"`, 예: `["RLIMIT_CPU", "RLIMIT_NOFILE"]`)
   - `Skipped []string` (`json:"skipped,omitempty"`, 예: `["RLIMIT_AS: unsupported_on_darwin"]`)

### 3.3 `SubprocessSpawner` 출력 초과 판정 우선순위 (`internal/orchestrator/spawner.go`)
- `stdoutBuf.Exceeded() || stderrBuf.Exceeded()`가 참이면:
  - `onExceed`에 의해 컨텍스트가 취소되었더라도 타임아웃보다 **출력 상한 초과가 원인이므로** `result.OutputExceeded = true`, `result.TimedOut = false`, `result.ExitCode = int(domain.ExitResourceLimit)`(`17`), `result.Reason = domain.ReasonResourceOutputLimit`으로 판정한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | `maxBytes = 1024`인 `limitedBuffer`에 1024바이트 기록 | `Exceeded() == false`, 보관량 정확히 1024바이트 |
| **TC-030-02** | `maxBytes = 1024`인 `limitedBuffer`에 1025바이트(또는 64 KiB 청크) 기록 | `Exceeded() == true`, `onExceed` 정확히 1회 호출, `buf.Len() <= 1024` |
| **TC-030-03** | `flood` 모드 워커 기동 + `MaxOutputBytes: 16 * 1024` (16 KiB) | 즉시 그룹 종료, `ExitCode == 17`, `Reason == RESOURCE_OUTPUT_LIMIT`, ` len(res.StdoutRaw) <= 16384` |
| **TC-030-04** | `ApplyRLimit: true`로 스폰 실행 후 부모 프로세스의 `RLIMIT_NOFILE` 확인 | 부모 프로세스의 `rlimit`은 변경되지 않고 `RLimitStatus` 메타데이터가 정상 생성됨 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/orchestrator -run TestLimitedBuffer` PASS
2. `go test -v -tags testworker ./internal/orchestrator -run TestSpawnOutputLimit` PASS
3. `go test -race -tags testworker ./internal/orchestrator` 데이터 레이스 0건
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `limitedBuffer` 상한 초과 즉시 그룹 종료 및 보관량 상한 보장 구현
- [ ] `flood` 워커 연동 출력 상한 초과(`17`, `RESOURCE_OUTPUT_LIMIT`) 테스트 통과
- [ ] 부모 오염 없는 `RLimitStatus` 구조화 및 자식 적용 헬퍼 구현 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
