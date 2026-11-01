# 010. Workspace File Jail 격리 모듈 구현지시서

> **상태**: `Draft`
> **선행 조건**: Phase 2 (OAuth 2.1 토큰 및 축소위임 엔진) 완료
> **상위 대시보드**: [README.md](../README.md) | **마스터 설계**: [ROADMAP.md](../ROADMAP.md)

---

## 1. 목적 (Context & Why)

본 지시서는 인가 판정을 거친 파일 I/O 요청을 물리적으로 안전하게 집행하기 위한 신뢰 경계(Trust Boundary)의 핵심 컴포넌트인 **Workspace File Jail (`internal/jail`)** 모듈을 구축하는 작업이다.

보안 불변식에 따라:
1. 지정된 작업 영역(`workspaceRoot`) 외부의 파일이나 디렉터리는 어떤 경우에도 읽거나 쓸 수 없어야 한다.
2. 상위 디렉터리 탈출(`../`), 절대 경로 지정(`/etc/passwd`), 널 바이트(`\x00`) 삽입, 유사 접두사 디렉터리(`workspace-evil`) 등의 모든 경로 탐색(Path Traversal) 공격을 I/O 발생 전에 원천 차단한다.
3. 작업 공간 내부에서 외부를 가리키는 **심볼릭 링크(Symlink)** 및 아직 생성되지 않은 새 파일 쓰기 시 조상 디렉터리의 심볼릭 링크를 `filepath.EvalSymlinks`로 끝까지 추적하여 탈출을 차단한다.
4. **거부 시 무부작용 원칙 (Zero Side-Effects on Deny)**: 경로 검증 실패 시 대상 파일 열기(`os.OpenFile`)나 파일 시스템 쓰기 부작용이 단 1바이트도 발생하지 않아야 한다.

---

## 2. 패키지 배치 및 6계층 DAG 구조

```text
Layer 3:  [internal/authz/pep] (이후 020 단계에서 Jail 인터페이스 호출)
                │
                v
Layer 2C: [internal/jail] (Workspace Jail: Clean, Rel, EvalSymlinks, Confined I/O)
                │
                v
Layer 0:  [internal/domain] (ReasonPathViolation, ExitPathViolation 등)
```

- **Layer 0 (`internal/domain`)**: `ReasonPathViolation`, `ExitPathViolation`, 세분화된 경로 에러 사유 정의.
- **Layer 2C (`internal/jail`)**: 외부 계층(PDP, PEP, Authn, Audit)에 일체 의존하지 않는 순수 파일 경계 격리 엔진.
- **엄격한 단방향 DAG 준수 (AP-03)**: `internal/jail`은 PDP나 토큰 검증 로직을 참조하지 않으며, 오직 파일 시스템 경로 검증 및 안전한 I/O 격리만을 담당한다.

---

## 3. 세부 설계 및 인터페이스 계약

### 3.1 핵심 인터페이스 계약 (`internal/jail`)

```go
package jail

import "authz-harness/internal/domain"

// Jail 은 지정된 Workspace Root 디렉터리 내에 한정된 안전한 파일 접근 경계를 강제하는 인터페이스다.
type Jail interface {
    // ResolvePath 는 사용자가 입력한 경로(상대/절대)를 검증하고,
    // Workspace Root 내부의 정규화된 안전 물리 절대 경로를 반환한다.
    // 경계를 벗어나거나 유효하지 않은 경로인 경우 ErrPathViolation 및 세부 사유를 반환한다.
    ResolvePath(rawPath string, forWrite bool) (string, error)

    // ReadFile 은 Workspace Root 내부의 파일을 안전하게 읽어 바이트 슬라이스로 반환한다.
    ReadFile(rawPath string) ([]byte, error)

    // WriteFile 은 Workspace Root 내부의 파일에 데이터를 안전하게 기록한다.
    // 중간 디렉터리가 없을 경우 0755 퍼미션으로 자동 생성하며, 파일은 0644 퍼미션으로 원자적 기록된다.
    WriteFile(rawPath string, data []byte) error

    // WorkspaceRoot 는 현재 Jail 인스턴스에 바인딩된 기준 루트의 절대 경로를 반환한다.
    WorkspaceRoot() string
}
```

### 3.2 안전 경로 해석(ResolvePath) 알고리즘 불변식

1. **입력 무결성 검사**:
   - `rawPath`에 널 바이트(`\x00`)가 포함되어 있는지 검사 (`ErrInvalidPathCharacters`).
   - 빈 문자열이거나 공백만 있는 경로 거부.
2. **루트 절대 경로 정규화**:
   - `workspaceRoot`에 대해 `filepath.Abs` 및 `filepath.Clean`을 수행하고, 루트 디렉터리의 실제 심볼릭 링크를 `filepath.EvalSymlinks`로 해석하여 `realRoot`를 확정한다.
3. **요청 경로 결합 및 정규화**:
   - `rawPath`가 절대 경로인 경우: `filepath.Clean(rawPath)`
   - `rawPath`가 상대 경로인 경우: `filepath.Join(realRoot, rawPath)` 결합 후 `filepath.Clean`
4. **접두사 비교 금지 (Anti-Pattern AP-04 방어)**:
   - `strings.HasPrefix(target, realRoot)` 단독 사용 절대 금지.
   - 반드시 `filepath.Rel(realRoot, target)`를 계산하여 결과가 `.`이거나 상위 디렉터리(`..` 또는 `../`로 시작)가 아닌지 검사한다.
5. **읽기 요청 검증 (`forWrite == false`)**:
   - 파일이 물리적으로 존재하는지 확인 (`os.Stat`). 존재하지 않으면 `os.ErrNotExist` 반환.
   - `filepath.EvalSymlinks(target)`를 호출하여 링크가 최종적으로 가리키는 실제 물리 경로 `realTarget` 취득.
   - `filepath.Rel(realRoot, realTarget)`를 계산하여 결과가 `..`로 시작하면 `ErrSymlinkEscape` 반환.
6. **쓰기 요청 검증 (`forWrite == true`)**:
   - 파일이 이미 존재하는 경우: 읽기 요청과 동일하게 `EvalSymlinks` 후 `filepath.Rel` 검증.
   - 파일이 아직 존재하지 않는 경우 (새 파일 생성):
     - 대상 경로의 상위 부모 디렉터리(`filepath.Dir`)를 재귀적으로 역순 탐색하여 디스크에 **실제 존재하는 가장 가까운 조상 디렉터리(`existingAncestor`)**를 찾는다.
     - 찾은 조상 디렉터리에 대해 `filepath.EvalSymlinks(existingAncestor)`를 수행하여 실제 물리 경로 `realAncestor`를 취득.
     - `filepath.Rel(realRoot, realAncestor)`가 `..`로 시작하면 조상 심볼릭 링크 탈출로 판정하여 `ErrSymlinkEscape` 반환.
     - 아직 생성되지 않은 나머지 하위 디렉터리 세그먼트와 최종 파일명을 `realAncestor`와 결합한 후, 전체 경로의 `filepath.Rel(realRoot, finalPath)`가 여전히 안전한지 2차 확인.

---

## 4. 작업 내역 및 산출물 (구현 대상)

1. `internal/domain/constants.go`:
   - 세분화된 경로 거부 사유 코드 추가:
     - `ReasonPathTraversal` (`"PATH_TRAVERSAL"`): `../` 또는 절대 경로 순회 시도
     - `ReasonSymlinkEscape` (`"SYMLINK_ESCAPE"`): 심볼릭 링크를 통한 샌드박스 외부 접근 시도
     - `ReasonInvalidPath` (`"INVALID_PATH"`): 널 바이트 등 경로 문자열 결함
2. `internal/jail/errors.go`:
   - 센티넬 에러 정의:
     - `ErrPathViolation`: 기본 경로 위반 에러
     - `ErrPathTraversal`: 상위/외부 경로 순회 에러
     - `ErrSymlinkEscape`: 심볼릭 링크 탈출 에러
     - `ErrInvalidPathCharacters`: 널 바이트 등 불법 문자 에러
   - 에러와 `domain.Reason`을 매핑하는 헬퍼 함수 (`ReasonFromError(err error) domain.Reason`)
3. `internal/jail/jail.go`:
   - `Jail` 인터페이스 및 `workspaceJail` 구현체.
   - `New(workspaceRoot string) (Jail, error)` 생성자.
   - `ResolvePath(rawPath string, forWrite bool) (string, error)` 구현.
   - `ReadFile(rawPath string) ([]byte, error)`: `ResolvePath` 통과 후 `os.ReadFile`.
   - `WriteFile(rawPath string, data []byte) error`: `ResolvePath` 통과 후 부모 디렉터리 `os.MkdirAll` (퍼미션 `0755`), 임시 파일 원자적 교체(`AtomicWrite`) 또는 안전 `os.WriteFile` (퍼미션 `0644`).
4. `internal/jail/jail_test.go`:
   - Table-Driven 단위 테스트 스위트:
     - 정상 케이스: 루트 바로 아래 파일 읽기/쓰기, 다중 중첩 디렉터리(`a/b/c/d.txt`), 정규화 가능한 상대 경로(`a/./b/../c.txt`).
     - 순회 공격 차단: `../secret.txt`, `../../etc/passwd`, `foo/../../bar`, `/etc/shadow`.
     - 디렉터리 접두사 공격 차단: `workspace-evil/leak.txt`.
     - 심볼릭 링크 탈출 차단: Workspace 내 심볼릭 링크가 외부(`/tmp` 또는 홈 디렉토리)를 가리킬 때 읽기 차단.
     - 새 파일 쓰기 시 조상 디렉터리가 외부 심볼릭 링크인 경우 쓰기 차단.
     - 널 바이트 공격(`test.txt\x00.evil`) 즉시 차단.
     - 실패 시 파일 부작용 0바이트 불변식 검증.
5. `internal/jail/fuzz_test.go`:
   - `FuzzPathJail(f *testing.F)`:
     - 시드 코퍼스: 정상 상대 경로, 널 바이트, `..` 다중 중첩, URL 인코딩 잔여물(`%2e%2e`), 4096자 초장문 경로 등.
     - 퍼징 불변식: 임의의 바이트 스트림 입력에 대해 크래시/패닉이 발생하지 않으며, `ResolvePath`가 에러 없이 반환한 모든 경로는 반드시 `filepath.Rel(realRoot, resolved)`가 `..`로 시작하지 않음을 수학적으로 보장.

---

## 5. 사전 인수 테스트 시나리오 (Acceptance Scenarios)

| 번호 | 테스트 명칭 | 입력 경로 및 조건 | 기대 결과 | 검증 포인트 |
|---|---|---|---|---|
| **AC-01** | 정상 격리 읽기/쓰기 | `rawPath: "docs/report.txt"`, `data: "hello"` | 성공 (에러 `nil`), 파일 생성 확인, `ReadFile` 동일 바이트 반환 | 정상 워크플로 및 하위 디렉터리 자동 생성 |
| **AC-02** | 상위 디렉터리 순회 차단 | `rawPath: "../../etc/passwd"`, `forWrite: false` | `ErrPathTraversal` 반환, I/O 0회 | 상위 탈출 원천 차단 |
| **AC-03** | 중첩 순회 경로 차단 | `rawPath: "safe/dir/../../../secret.key"` | `ErrPathTraversal` 반환 | `filepath.Clean` 후 경계 이탈 탐지 |
| **AC-04** | 유사 디렉터리 착시 차단 | `rawPath: filepath.Dir(root) + "-evil/attack.txt"` | `ErrPathViolation` 반환 | `strings.HasPrefix` 취약점 방어 |
| **AC-05** | 외부 대상 심볼릭 링크 읽기 차단 | Workspace 내 `link -> /tmp/system_secret.txt` 생성 후 읽기 시도 | `ErrSymlinkEscape` 반환, 대상 파일 비접근 | `EvalSymlinks` 물리 경로 추적 검증 |
| **AC-06** | 조상 심볼릭 링크 쓰기 차단 | Workspace 내 `link_dir -> /tmp` 생성 후 `link_dir/new_file.txt` 쓰기 시도 | `ErrSymlinkEscape` 반환, `/tmp`에 파일 미생성 | 미존재 파일 조상 역추적 검증 |
| **AC-07** | 널 바이트 삽입 차단 | `rawPath: "safe.txt\x00.evil"` | `ErrInvalidPathCharacters` 반환 | 악의적 문자열 사전 차단 |
| **AC-08** | L2 경로 퍼징 불변식 | `go test -fuzz=FuzzPathJail -fuzztime=5s` | 패닉 0건, 격리 불변식 위반 0건 | 무작위 바이트 스트림 견고성 |

---

## 6. 4층위 검증 방법

1. **1층위 (자동화 스크립트)**: `python3 scripts/public_safety_scan.py --tree` 시크릿 스캔 통과 및 `go vet ./...` 무결성 검증.
2. **2층위 (단위 및 퍼징 검증)**:
   - `go test -v -race ./internal/jail/...` 100% 통과.
   - `go test -fuzz=FuzzPathJail -fuzztime=5s ./internal/jail/...` 크래시 제로(0) 통과.
3. **3층위 (상태 및 정합성 검증)**:
   - 거부 시나리오(AC-02 ~ AC-07) 실행 후 Workspace 외부(`os.TempDir()` 등)에 생성되거나 수정된 파일이 0바이트임을 물리 디렉터리 검사로 확인.
4. **4층위 (인터페이스 호환성)**:
   - `internal/jail.Jail` 인터페이스가 향후 020 단계의 PEP(`internal/authz/pep`) 관문과 완벽히 바인딩될 수 있는지 확인.
