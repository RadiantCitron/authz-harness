# [구현지시서 030] 출력 상한 리더 및 rlimit(best-effort) 적용

> **문서 상태**: `Draft`
> **상위 대시보드**: [10번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [020_프로세스_그룹_일괄_종료_및_waitdelay.md](020_프로세스_그룹_일괄_종료_및_waitdelay.md) 완료
> **후속 단계**: [040_감사_이벤트_ui_및_mcp_오류_매핑.md](040_감사_이벤트_ui_및_mcp_오류_매핑.md)

---

## 1. 목적 및 배경

자식 워커가 무한 루프로 `stdout`이나 `stderr`에 대량 데이터를 쏟아낼 경우, 부모 스포너의 `bytes.Buffer`가 호스트 메모리를 고갈시킬 수 있다(OOM 공격면).
또한 OS 커널 자원 한계(`rlimit`)는 플랫폼(macOS vs Linux)마다 지원 범위가 다르므로, 지원되는 항목(`RLIMIT_NOFILE`, `RLIMIT_CPU`)은 best-effort로 적용하되 **실제 적용 성공·미지원 여부를 구조화된 결과로 남겨 감사에 기록**해야 허위 보증을 막을 수 있다 ([ROADMAP.md](../ROADMAP.md) §4).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/orchestrator/limited_writer.go` [신규]: 바이트 상한을 초과하는 순간 즉시 콜백(`onExceed`)을 호출하여 프로세스 그룹을 종료시키고, 버퍼 보관량을 `MaxOutputBytes` 이하로 엄격히 제한하는 `limitedBuffer` 구현
  - `internal/orchestrator/limited_writer_test.go` [신규]: 경계값(상한-1, 상한 일치, 상한+1바이트, 대량 청크 연속 입력) 단위 테스트
  - `internal/orchestrator/rlimit_unix.go` [신규]: 서브프로세스 워커 진입 시 또는 스폰 옵션에서 `RLIMIT_NOFILE`, `RLIMIT_CPU` best-effort 적용 및 `RLimitStatus` 결과 구조체 반환
  - `internal/orchestrator/spawner.go`: `stdout`/`stderr`에 `limitedBuffer` 연결, 출력 초과 시 즉시 그룹 종료(`Cancel`) 트리거 후 `ExitCode = 17`(`ExitResourceLimit`), `Reason = RESOURCE_OUTPUT_LIMIT` 부여
- **무영향**:
  - 정상 JSON 프레임 응답(수백 바이트~수십 KiB)은 기본 상한(1 MiB)보다 훨씬 작으므로 정상 실행 경로에는 영향을 주지 않는다.

---

## 3. 세부 명세

### 3.1 바이트 상한 버퍼 (`internal/orchestrator/limited_writer.go`)
1. `type limitedBuffer struct`:
   - 필드: `mu sync.Mutex`, `buf bytes.Buffer`, `maxBytes int64`, `exceeded bool`, `onExceed func()` (`sync.Once`로 1회만 호출 보장)
2. `Write(p []byte) (int, error)`:
   - 이미 `exceeded == true`이거나 `int64(buf.Len()) + int64(len(p)) > maxBytes`인 경우:
     - 남은 여유 바이트(`remaining = maxBytes - int64(buf.Len())`)만큼만 `buf`에 기록하여 **부모 프로세스의 버퍼 보관량이 절대로 `maxBytes`를 넘지 않게** 한다.
     - `exceeded = true`로 표시하고 `onExceed()`(프로세스 그룹 종료 함수)를 즉시 호출한다.
     - `io.ErrShortWrite` 대신 `errOutputLimitExceeded` 센티넬 에러를 반환하여 `os/exec` 복사 고루틴을 즉시 중단시킨다.
3. `Exceeded() bool`, `String() string`, `Bytes() []byte` 메서드를 제공한다.

### 3.2 플랫폼별 `rlimit` best-effort 적용 (`internal/orchestrator/rlimit_unix.go`)
1. `type RLimitResult struct`:
   - `Requested bool` (`json:"requested"`)
   - `Applied []string` (`json:"applied,omitempty"`, 예: `["RLIMIT_CPU", "RLIMIT_NOFILE"]`)
   - `Skipped []string` (`json:"skipped,omitempty"`, 예: `["RLIMIT_AS: unsupported_on_darwin"]`)
2. macOS(`darwin`)에서 `RLIMIT_AS`가 커널 수준에서 무시·실패하는 한계를 문서와 코드에 명시하고, `RLIMIT_NOFILE` 및 `RLIMIT_CPU`를 대상으로 현재 하드 한계(`Cur <= Max`) 범위 안에서 best-effort 설정을 수행하거나 적용 가능 여부를 점검해 `RLimitResult`에 기록한다.
3. 보증의 핵심은 `rlimit`이 아니라 **프로세스 그룹 강제 종료(`020`)와 출력 상한(`030`)**임을 `RLimitResult` 메타데이터로 투명하게 남긴다.

### 3.3 `SubprocessSpawner` 연동 (`internal/orchestrator/spawner.go`)
1. `stdout`과 `stderr`에 각각 `MaxOutputBytes` 상한을 가진 `limitedBuffer`를 바인딩한다.
2. 어느 한쪽이라도 `Exceeded() == true`가 되면 `onExceed` 콜백이 즉시 프로세스 그룹을 종료(`cancel()`)하고, 수거 결과에 `result.OutputExceeded = true`, `result.ExitCode = int(domain.ExitResourceLimit)`(`17`), `result.Reason = domain.ReasonResourceOutputLimit`을 기록한다 (`TimedOut`보다 `OutputExceeded`가 먼저 발생한 경우 `RESOURCE_OUTPUT_LIMIT`이 우선).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | `maxBytes = 1024`인 `limitedBuffer`에 1024바이트 기록 | `Exceeded() == false`, 보관량 정확히 1024바이트 |
| **TC-030-02** | `maxBytes = 1024`인 `limitedBuffer`에 1025바이트(또는 64 KiB 청크) 기록 | `Exceeded() == true`, `onExceed` 정확히 1회 호출, `buf.Len() <= 1024` |
| **TC-030-03** | `flood` 모드 워커 기동 + `MaxOutputBytes: 64 * 1024` (64 KiB) | 즉시 그룹 종료, `ExitCode == 17`, `Reason == RESOURCE_OUTPUT_LIMIT`, 부모 보관량 `<= 64 KiB` |
| **TC-030-04** | `rlimit` 적용 함수 호출 | 패닉·치명 오류 없이 `RLimitResult`(적용 항목 및 미지원 사유) 반환 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/orchestrator -run TestLimitedBuffer` PASS
2. `go test -v -tags testworker ./internal/orchestrator -run TestSpawnOutputLimit` PASS
3. `go test -race -tags testworker ./internal/orchestrator` 데이터 레이스 0건
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `limitedBuffer` 상한 초과 즉시 차단 및 보관량 상한 보장 구현
- [ ] `flood` 워커 연동 출력 상한 초과(`17`, `RESOURCE_OUTPUT_LIMIT`) 테스트 통과
- [ ] `RLimitResult` best-effort 적용 및 상태 구조화 구현
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
