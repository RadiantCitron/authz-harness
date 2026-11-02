# [구현지시서 020] macOS Seatbelt 커널 격리 어댑터 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [11번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_격리_정책_도메인_및_어댑터_인터페이스.md](010_격리_정책_도메인_및_어댑터_인터페이스.md) 완료
> **후속 단계**: [030_linux_어댑터_및_검증_환경.md](030_linux_어댑터_및_검증_환경.md)

---

## 1. 목적 및 배경

macOS(`darwin`) 환경에서 서브프로세스 워커에 커널 샌드박스 프로파일(SBPL, Seatbelt Profile Language)을 생성·적용하는 `SeatbeltConfiner` 어댑터를 구현한다.
정직한 워커가 PEP 관문을 거쳐 수행하는 합법적인 작업(Workspace 내부 읽기·쓰기, Zone B 검증, 감사 기록)은 정상 동작하면서, PEP를 건너뛰어 Zone A 개인키(`signing_keys.priv.json`)를 읽거나 Workspace 밖에 파일을 쓰거나 네트워크 소켓을 여는 행위는 **OS 커널(`EPERM`/`EACCES`)에 의해 즉시 차단**되도록 프로파일을 구성한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/confinement/seatbelt_darwin.go` [신규] (`//go:build darwin`): SBPL 프로파일 문자열 생성기(`RenderProfile(policy Policy)`) 및 `sandbox-exec -p <profile>` 래핑 어댑터 구현
  - `internal/confinement/seatbelt_other.go` [신규] (`//go:build !darwin`): 비-macOS 환경용 스텁(`Available() == false`)
  - `internal/confinement/seatbelt_darwin_test.go` [신규] (`//go:build darwin`): 프로파일 생성 규칙 단위 테스트 및 실제 자식 프로세스 차단·허용 검증 테스트
- **무영향**:
  - `darwin` 빌드 태그로 격리되어 타 OS 빌드에 영향을 주지 않는다.

---

## 3. 세부 명세

### 3.1 SBPL 프로파일 생성 규칙 (`RenderProfile`)
1. 기본 정책: `(version 1)` 선언 후 프로세스 기동 및 시스템 동적 라이브러리 로드에 필수적인 최소 권한만 열고, 파일 쓰기·네트워크·Zone A 읽기는 차단한다:
   - `(deny default)` 기반으로 구성하거나 파일 읽기·쓰기·네트워크를 명시 통제한다.
   - `(deny network*)`: `Policy.AllowNetwork == false`일 때 루프백을 포함한 모든 소켓 바인딩·연결을 커널에서 거부한다.
   - 시스템 런타임 필수 읽기 경로: `/usr/lib`, `/System/Library`, `/Library/Preferences`, `/dev/null`, `/dev/urandom`, `/dev/zero`, `/private/var/db/timezone` 및 워커 실행 바이너리 경로(`filepath.EvalSymlinks` 해석 후 경로 포함).
   - `Policy.AllowReadPaths`: `(allow file-read* (subpath "<real_path>"))`로 추가한다.
   - `Policy.AllowWritePaths`: `(allow file-read* file-write* (subpath "<real_path>"))`로 추가한다 (macOS `/var` → `/private/var`, `/tmp` → `/private/tmp` 심볼릭 링크를 반드시 `filepath.EvalSymlinks`로 정규화하여 SBPL에 기입해야 커널 경로 매칭이 어긋나지 않는다).
   - `Policy.DenyPaths` (최우선 차단): Zone A 개인키 디렉터리(`private/`) 등은 `(deny file-read* file-write* (subpath "<real_path>"))`로 마지막에 배치하여 상위 디렉터리 읽기 허용보다 우선 차단되게 한다.

### 3.2 `SeatbeltConfiner.WrapCommand`
- `/usr/bin/sandbox-exec` 존재 여부를 확인(`Available()`)하고, 없을 경우 `ReasonConfinementUnavailable` 에러를 반환한다.
- 원본 `cmd.Path`와 `cmd.Args` 앞에 `/usr/bin/sandbox-exec`, `-p`, `<profile_string>`을 결합하여 자식 프로세스와 그 손자 프로세스까지 동일 커널 프로파일을 상속받게 한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | `Policy`로 생성된 SBPL 문자열 검사 | `(deny network*)`, `AllowWritePaths`(심볼릭 링크 정규화 경로), `DenyPaths`(Zone A 차단) 포함 |
| **TC-020-02** | `SeatbeltConfiner` 적용 자식 프로세스가 `AllowWritePaths` 내부 파일 쓰기 시도 | 정상 성공 (`ExitCode == 0`) |
| **TC-020-03** | `SeatbeltConfiner` 적용 자식 프로세스가 `DenyPaths`(Zone A) 파일 직접 읽기 시도 | 커널 `operation not permitted` 오류로 즉시 실패 |
| **TC-020-04** | `SeatbeltConfiner` 적용 자식 프로세스가 `AllowWritePaths` 외부 임시 파일 쓰기 시도 | 커널 거부로 실패, 외부 파일 미생성 |
| **TC-020-05** | `SeatbeltConfiner` 적용 자식 프로세스가 `127.0.0.1` TCP 리스닝/연결 시도 (`AllowNetwork: false`) | 커널 네트워크 거부로 실패 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/confinement -run TestSeatbelt` PASS (macOS)
2. 프로파일 경로 정규화(`/var` → `/private/var`) 검증 PASS
3. 외부 파일 부작용 0바이트 검증 PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `filepath.EvalSymlinks` 기반 SBPL 프로파일 생성기 구현 완료
- [ ] Zone A 읽기·외부 쓰기·네트워크 차단 커널 실증 테스트 통과
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
