# [구현지시서 030] Linux 커널 격리 어댑터 설계 및 검증 환경 판정

> **문서 상태**: `Draft`
> **상위 대시보드**: [11번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0003](../../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md)
> **선행 조건**: [020_macos_seatbelt_어댑터.md](020_macos_seatbelt_어댑터.md) 완료
> **후속 단계**: [040_스포너_배선_및_fail_closed_모드.md](040_스포너_배선_및_fail_closed_모드.md)

---

## 1. 목적 및 배경

Linux(`//go:build linux`) 환경에서 Landlock LSM(커널 5.13+) 및 `PR_SET_NO_NEW_PRIVS`를 사용하는 격리 어댑터 인터페이스를 구성하고, 현재 개발·검증 환경(macOS 호스트)에서 Linux 커널 실행 검증이 가능한지 판정하여 기록한다.
[ROADMAP.md](../ROADMAP.md) §4 및 §6 원칙에 따라, 실제 Linux 커널 위에서 실행 검증을 수행할 수 없는 환경이라면 "구현 완료"로 허위 표기하지 않고 Linux 어댑터의 런타임 검증 상태를 명시적으로 분리 기록한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/confinement/landlock_linux.go` [신규] (`//go:build linux`): Linux Landlock 시스템콜(`SYS_LANDLOCK_CREATE_RULESET`, `SYS_LANDLOCK_ADD_RULE`, `SYS_LANDLOCK_RESTRICT_SELF`) 또는 워커 초기화 훅 기반 어댑터 구현
  - `internal/confinement/landlock_other.go` [신규] (`//go:build !linux`): 비-Linux 환경용 스텁(`Available() == false`)
  - `internal/confinement/platform_test.go` [신규]: `GOOS=linux GOARCH=amd64 go build ./...` 및 `GOOS=darwin go build ./...` 교차 컴파일 무결성 검증 테스트
- **무영향**:
  - macOS(`darwin`) 런타임 동작에는 영향을 주지 않으며, 교차 컴파일이 깨지지 않음을 보장한다.

---

## 3. 세부 명세

1. **방식 선택 근거 기록**:
   - 경로 단위 읽기/쓰기 허용(`AllowReadPaths`, `AllowWritePaths`)을 커널 파일시스템 객체 규칙으로 표현하기에 가장 적합한 **Landlock LSM (+ `PR_SET_NO_NEW_PRIVS`)**을 기본 방식으로 채택한다.
2. **Fail-Closed 보장**:
   - 구형 Linux 커널이나 미지원 환경에서 `RequireConfinement: true`로 호출되면 침묵 폴백 없이 `ReasonConfinementUnavailable`(`ExitInternalError = 16`)을 반환한다.
3. **교차 컴파일 및 검증 상태 투명화**:
   - `platform_test.go`에서 `GOOS=linux` 빌드가 에러 없이 통과하는지 자동 검증한다.
   - 호스트가 macOS여서 실제 Linux 커널 시스템콜 실행을 검증할 수 없는 경우, [11번 README.md](../README.md)에 Linux 런타임 검증이 환경 제약으로 보류(`Blocked` / 교차 컴파일만 검증)되었음을 정직하게 기록한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-030-01** | `GOOS=linux GOARCH=amd64 go test -c ./internal/confinement` 실행 | 컴파일 오류 0건 |
| **TC-030-02** | 비-Linux 호스트에서 Linux 어댑터 `Available()` 호출 | `false` 반환, `RequireConfinement: true` 시 `ReasonConfinementUnavailable` 반환 |
| **TC-030-03** | (Linux 커널 가용 시) `020`과 동일한 Zone A 읽기·외부 쓰기 시도 | 커널 `EACCES` 거부 (비가용 시 보증 표에 미검증 명시) |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/confinement -run TestCrossCompileLinux` PASS
2. `go test -v ./internal/confinement` PASS
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `landlock_linux.go` 및 `landlock_other.go` 작성 및 교차 컴파일 테스트 통과
- [ ] 호스트 검증 가능 여부에 따른 정직한 상태 기록 (`Done` 허위 표기 금지 준수)
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
