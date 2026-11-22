# authz-harness: Enterprise Authorization & Downscoping Test Harness

[![Go Version](https://img.shields.io/badge/Go-1.27%2B-00ADD8?style=flat&logo=go)](go.mod)
[![Architecture](https://img.shields.io/badge/Architecture-3--Zone%20Isolation-blueviolet)](docs/로드맵/MASTER_ROADMAP.md)
[![OAuth 2.1](https://img.shields.io/badge/OAuth-2.1%20%2F%20RFC%208693-blue)](https://datatracker.ietf.org/doc/html/rfc8693)
![Quad-Assertion](https://img.shields.io/badge/E2E%20Coverage-80%2F80%20PASS%20(100%25)-brightgreen)
![Zero Leakage](https://img.shields.io/badge/Security-Zero%20Leakage-success)

> **"비인가된 요청이 정확히 의도된 사유와 종료 코드로 실패함을 증명하는 Go 기반 권한 검증 및 테스트 하네스"**  
> OAuth 2.1 기반 워크로드 인증(AuthN) · RFC 8693 최소 권한 축소 위임(Downscoping) · NIST SP 800-162 4대 인가 분리(PAP/PIP/PDP/PEP) · 3-Zone 상태 격리 · OS 서브프로세스 IPC · OS 커널 격리 · MCP/Tool-Call 보안 게이트웨이 어댑터 · 관측성 삼분(Audit/Ops/UI) 및 80개 공격·인가 방어 시나리오 하네스를 외부 의존성 없는 로컬 완결형으로 구현하고 증명합니다.

---

## ⚡ 1분 퀵스타트 (1-Minute Quickstart)

외부 네트워크, 서드파티 IdP, Docker 데몬 설정 없이 **Go 단일 환경에서 수 초 만에 80개 전 구간 공격·인가 시나리오를 검증**할 수 있습니다.

```bash
# 1. 80개 전 구간 E2E 시나리오 일괄 실행 및 Quad-Assertion 검증
go run ./cmd/authz-harness run --scenario all

# 2. MCP stdio JSON-RPC 2.0 보안 게이트웨이 어댑터 기동
go run ./cmd/authz-harness mcp serve

# 3. 초보자용 단계 파이프라인 Explain UX 및 부정 테스트 역설 해설 체험 (E2E-22 축소 위임 위반)
go run ./cmd/authz-harness run --scenario E2E-22 --output-format explain

# 4. 디렉터리 경로 탈출 공격 시나리오 단독 실행 (E2E-25)
go run ./cmd/authz-harness run --scenario E2E-25

# 5. 감사 무결성: 해시 체인 검증, 서명 체크포인트 생성·대조(꼬리 절단·재작성·삭제 탐지), 위임 트리
go run ./cmd/authz-harness audit verify
go run ./cmd/authz-harness audit checkpoint
go run ./cmd/authz-harness audit verify --checkpoint .authz-state/public/audit_checkpoint.json
go run ./cmd/authz-harness audit tree --trace-id <trace-id>

# 6. 전 패키지 동시성(-race) 및 단위 무결성 테스트
go test -race ./...
```

> **실행 환경 안내**
> - **필요 환경**: Go 1.27 이상(`go.mod` 기준 1.27.2)이 필요합니다. 외부 서비스는 필요 없습니다.
> - **제한된 환경**: 샌드박스·컨테이너처럼 로컬 소켓 연결(루프백)이나 중첩 `sandbox-exec`가 막힌 환경에서는 일부 시나리오(G10 OS 격리, G15 네트워크 가드)가 실패하거나 건너뛰어질 수 있습니다. 이는 환경 제약 때문이며, 제약이 없는 일반 환경(macOS 개발 호스트)에서 80개 전체 통과를 확인했습니다.

---

## 🎯 왜 이 프로젝트를 만들었는가? (Why)

### 현대 분산 에이전트 및 MSA의 3대 권한 위기
1. **과도한 권한 위임 (Over-Privileged Delegation)**:
   - 복잡한 작업을 수행하는 팀장(Orchestrator) 에이전트가 하위 워커에게 작업을 위임할 때 자신의 권한 전체를 복제해 넘김으로써, 하위 워커 탈취 시 전체 시스템이 장악됩니다.
2. **권한 회수(Revoke)의 실시간 집행 단절 (TOCTOU)**:
   - 관리자가 중앙에서 권한을 회수하더라도, 이미 발급된 단기 토큰이 만료될 때까지 워커가 작업을 계속 강행하여 비인가 데이터 수정이 일어납니다.
3. **감사 증거의 오염 및 입증 불가 (Audit Trail Failure)**:
   - 보안 차단 사유가 수만 줄의 운영 디버그 로그(`stderr`)에 파묻히거나, 비신뢰 프로세스가 감사 장부(`audit.jsonl`)를 직접 수정하여 사후 증거로 채택되지 못합니다.

### `authz-harness`의 엔지니어링 해답
- **수학적 축소 위임 ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693))**: 팀장은 자신이 가진 권한의 부분집합($S_{child} \subseteq S_{parent}$), 단축된 수명($exp_{child} \le exp_{parent}$), 제한된 깊이, 잔여 이하 예산($B_{child} \le B_{parent\_remaining}$)으로만 자식 토큰을 교환 발급할 수 있습니다.
- **NIST SP 800-162 4각 분리**: 정책 결정(PDP)과 도구 집행(PEP)을 물리적으로 격리하여, 파일·네트워크·명령 접근 직전 실시간 활성 Grant 및 계보 Epoch 상태를 재검증합니다.
- **3-Zone 상태 토폴로지**: 워커 프로세스에는 Zone A(개인키) 경로를 넘기지 않고(`VerifyOnly`), 실제 파일 작업은 Zone C(Workspace Jail) 안으로 한정합니다. OS 커널 격리(Seatbelt/Landlock)는 `orchestrate spawn -confine`, `orchestrate chain -confine`, `mcp serve -confine` 플래그로 켜며 기본값은 꺼짐입니다([009번 문서 Q16](docs/작동원리/009-키_토큰_ID_클레임과_승인티켓_해설.md)).
- **감사 증거 무결성 (Hash-Chained Audit & Signed Checkpoint)**: 모든 판정 이벤트를 SHA-256 해시 체인으로 연결하고, 디스크 쓰기 실패 시 실행을 즉각 중단하는 Strict Fail-Closed를 집행합니다.

---

## 🏛️ 시스템 아키텍처 & 신뢰 경계

### 1. 3-Zone 물리·논리 상태 격리 토폴로지

본 시스템은 최소 권한 원칙(PoLP)에 따라 로컬 상태 디렉터리를 3개의 보안 신뢰 영역으로 엄격히 분리합니다:

```mermaid
flowchart LR
    subgraph ZoneA ["Zone A: Secrets & Authority (0600 Private)"]
        PrivKeys["signing_keys.priv.json<br/>(Ed25519 서명 개인키)"]
        AuditKeys["audit_keys.priv.json<br/>(감사 체크포인트 전용 개인키)"]
        ClientCreds["client_credentials.json<br/>(클라이언트 시크릿)"]
    end

    subgraph ZoneB ["Zone B: Public Ledger & Registry (Shared Read-Only)"]
        PubKeys["jwks.pub.json<br/>(공개 서명 키 링)"]
        Grants["grants_state.json<br/>(Grant & Subject Epoch 원장)"]
        Replay["replay_ledger.json<br/>(jti Replay 방지 원장)"]
        Budget["budget_ledger.json<br/>(예산 차감 원장)"]
    end

    subgraph ZoneC ["Zone C: Isolated Execution & Workspace (Sandboxed)"]
        Jail["./workspace<br/>(Workspace Jail 파일 격리)"]
        Audit["audit.jsonl<br/>(SHA-256 해시 체인 감사 원장)"]
    end

    ZoneA -.->|서명 발급 시에만 참조| Issuer["Token Issuer (Layer 2)"]
    ZoneB -->|공개키/원장 검증| PDP["PDP Engine & Verifier"]
    PDP -->|결정 전달 (allow/ask/deny)| PEP["PEP Gateway"]
    PEP -->|Jail 내 I/O만 집행| Jail
    PEP -->|원자적 Append| Audit

    classDef zoneA fill:#ffebee,stroke:#c62828,stroke-width:2px;
    classDef zoneB fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    classDef zoneC fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    class ZoneA zoneA;
    class ZoneB zoneB;
    class ZoneC zoneC;
```

- **Zone A (권원 전용 영역)**: 토큰 서명용 Ed25519 개인키, 감사 체크포인트 전용 개인키, 자격증명이 저장되며 `0600` 권한으로 보호됩니다. 하위 워커 프로세스는 이 디렉터리에 접근할 수 없습니다.
- **Zone B (공개 원장 영역)**: 서명 검증용 공개키(`jwks.pub.json`), 활성 권한·승인 원장(`grants_state.json`), 토큰 재사용 방지 원장(`replay_ledger.json`), 예산 원장(`budget_ledger.json`)이 위치하며, 파일 잠금(`flock`) 기반으로 동시성 정합성을 유지합니다.
- **Zone C (격리 작업 영역)**: 에이전트의 실제 파일 읽기/쓰기가 일어나는 `./workspace`와 감사 증거 `audit.jsonl`이 위치합니다. PEP가 경로를 정규화하여 탈출 시도를 원천 차단합니다.

### 2. 6계층 비순환 의존성 구조 (DAG)

본 시스템은 상위 계층이 하위 계층에만 단방향으로 의존하며, 순환 의존성이 0건인 6계층 클린 아키텍처를 준수합니다:

| 계층 | 패키지 경로 | 주요 역할 및 책임 | 금지 사항 (Invariants) |
|:---:|---|---|---|
| **Layer 5** | `cmd/authz-harness`<br>`internal/harness`<br>`internal/ui` | CLI 진입점, 80개 시나리오 하네스, Quad-Assertion 검증 엔진, Explain UX | 인가 비즈니스 규칙 직접 구현 금지 |
| **Layer 4** | `internal/orchestrator`<br>`internal/subagent`<br>`internal/mcp` | 부모-자식 OS 프로세스 격리 생성, `stdin` JSON 프레임 IPC, MCP 어댑터, 종료 코드 수거 | 자식 프로세스에 부모 전체 환경변수 상속 금지 |
| **Layer 3** | `internal/authz/pep` | 정책 집행점 (PEP), 사전 커밋 감사 기록, 도구 집행 직전 강제 | PDP 검증을 건너뛰고 파일·네트워크·명령 집행 금지 |
| **Layer 2** | `internal/authn`<br>`internal/authz/pdp`<br>`internal/authz/pap`<br>`internal/jail` | RFC 9068 토큰 발급/검증, RFC 8693 교환, PDP 정책 결정, Jail 경로 정규화 | PDP 내부에서 파일 I/O나 개인키를 직접 참조하는 것 금지 |
| **Layer 1** | `internal/audit`<br>`internal/authz/state`<br>`internal/confinement` | Append-only 해시 체인 감사 기록기, 원자적 파일 잠금(`flock`) 상태 저장소, OS 커널 격리 | 원시 Bearer 토큰 전체를 로그에 평문으로 남기는 것 금지 |
| **Layer 0** | `internal/domain`<br>`internal/clock`<br>`internal/pipeline` | 표준 에러, 표준 종료 코드, 공통 도메인 엔티티, 결정론적 가상 시계, 제네릭 파이프라인 엔진 | 외부 패키지에 대한 역의존 금지 |

---

## 🛡️ 파이프라인 단계 & 표준 종료 코드

요청이 들어와서 도구가 집행되기까지 PEP는 **단계(stage) 10개**를 정해진 순서로 거칩니다. 단계는 성격(`check`·`decide`·`consume`·`record`·`execute`·`settle`)을 가지며, 부작용이 있는 단계(`consume` 이상)는 모든 검사 단계 뒤에만 옵니다. 아래는 단계별 차단 사유와 표준 종료 코드입니다 (`approval`·`budget`·`settle`은 조건부 단계):

```text
[요청 인입] ─▶ input ─▶ authn ─▶ authz ─▶ boundary ─▶ replay ─▶ approval ─▶ budget ─▶ precommit_audit ─▶ execute ─▶ settle
```

| 단계 | 검증 내용 | 차단 사유 (Reason) | 표준 종료 코드 |
|:---:|---|---|:---:|
| **`input`** | 추적 ID 누락(`RequireTraceID`), 지원하지 않는 행동·잘못된 인자 | `MISSING_TRACE_CONTEXT`, `INVALID_ARGUMENTS` | **`14`** (`ExitBadInput`) |
| **`authn`** | 토큰 형식 파손, 헤더 `typ`·허용 알고리즘 위반, 서명 불일치, 폐기·미등록 키, 만료·미래 토큰, `iss`/`aud` 불일치, `jti` 재사용 확인 | `INVALID_TOKEN`, `TOKEN_MALFORMED`, `TOKEN_INVALID_TYPE`, `TOKEN_ALG_NOT_ALLOWED`, `TOKEN_INVALID_SIGNATURE`, `TOKEN_KEY_RETIRED`, `TOKEN_KEY_NOT_FOUND`, `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`, `TOKEN_INVALID_ISS_AUD`, `TOKEN_SUBJECT_MISMATCH`, `TOKEN_REPLAY_DETECTED` | **`11`** (`ExitTokenInvalid`) |
| **`authz`** | 활성 Grant 없음, Grant 회수, 본인·조상 Epoch 불일치, 스코프 부족 | `NO_ACTIVE_GRANT`, `GRANT_REVOKED`, `SUBJECT_EPOCH_REVOKED`, `TOKEN_INSUFFICIENT_SCOPE` | **`12`** (`ExitAuthzDenied`) |
| **`authz`** (ask) | 승인이 필요한 Grant에 유효한 사람 승인이 없음·만료·바인딩 불일치 | `APPROVAL_REQUIRED`, `APPROVAL_EXPIRED`, `APPROVAL_MISMATCH` | **`18`** (`ExitApprovalRequired`) |
| **`boundary`** | 상대 경로(`../`), 작업 폴더 밖 경로, 심볼릭 링크 탈출, 허용 목록 밖 주소·명령·인자 | `PATH_VIOLATION`, `PATH_TRAVERSAL`, `SYMLINK_ESCAPE`, `INVALID_PATH`, `EGRESS_DENIED`, `EXEC_NOT_ALLOWED`, `EXEC_ARG_REJECTED`, `TOOL_LIMIT_EXCEEDED` | 경로 위반은 **`13`** (`ExitPathViolation`), 나머지는 **`12`** |
| **`replay`** | `jti` 소비 경합에서 진 요청 | `TOKEN_REPLAY_DETECTED` | **`11`** (`ExitTokenInvalid`) |
| **`approval`** | 승인 소비 실패(이미 소비·만료·불일치) | `APPROVAL_EXPIRED`, `APPROVAL_MISMATCH` | **`18`** (`ExitApprovalRequired`) |
| **`budget`**, **`settle`** | 예산 사전 차감 실패, 사후 정산 실패 | `BUDGET_EXHAUSTED` | **`12`** (`ExitAuthzDenied`) |
| **`precommit_audit`** | 실행 전 감사 기록 실패 (Strict Fail-Closed, 실행 건너뜀) | `AUDIT_LOG_FAILED` | **`15`** (`ExitAuditFailure`) |
| **`execute`** | 도구 실행 중 내부 오류 | `INTERNAL_ERROR` | **`16`** (`ExitInternalError`) |
| **특수** | 부모 스포너가 강제한 시간·출력 한계 초과 (인가 단계와 별개, 원인 불명 종료는 `16`) | `RESOURCE_TIMEOUT`, `RESOURCE_OUTPUT_LIMIT` | **`17`** (`ExitResourceLimit`) |
| **성공** | 모든 단계 통과 및 도구 집행 완결 | `AUTHORIZED` | **`0`** (`ExitSuccess`) |

---

## 🧪 15대 그룹 80개 E2E 시나리오 카탈로그 & Quad-Assertion

단순히 프로세스 종료 코드만 확인하는 겉핥기 테스트를 배제하고, 다음의 **4가지 보안 불변식을 동시에 증명(Quad-Assertion)**해야만 비로소 `PASS`로 판정합니다:

1. **Exit Code Assert**: 기대한 표준 종료 코드(`0`, `11`~`18`)와 100% 일치하는가?
2. **File Mutation Assert**: 거부(Deny) 시 파일 시스템에 **0바이트 무변화**가 유지되는가? (허용 시 데이터 일치)
3. **Audit Reason Assert**: 감사 장부에 정확히 의도된 `Decision`과 `Reason` 코드가 기록되었는가?
4. **Hash Chain Assert**: 감사 장부의 SHA-256 해시 체인이 손상되지 않았고 민감한 원시 토큰이 누출되지 않았는가?

### 80개 시나리오 전수 매핑표

| 그룹 | 시나리오 ID | 시나리오 명칭 | 기대 종료 코드 | 보안 검증 목적 |
|:---:|:---:|---|:---:|---|
| **G1**<br>(생명주기) | `E2E-01`<br>`E2E-02`<br>`E2E-03` | 정상 단일 파일 읽기<br>정상 단일 파일 쓰기<br>동적 전환 [거부→허용→회수 후 즉시 거부] | `0`<br>`0`<br>`12` | 기본 I/O 흐름 및 Grant 동적 추가/회수의 실시간 PEP 즉시 반영 증명 |
| **G2**<br>(워크로드 AuthN) | `E2E-04`<br>`E2E-05`<br>`E2E-06` | 미등록 클라이언트 토큰 요청 거부<br>잘못된 클라이언트 시크릿 거부<br>정지된(Suspended) 클라이언트 거부 | `11`<br>`11`<br>`11` | OAuth 2.1 Confidential Client 워크로드 자격증명 엄격 검증 |
| **G3**<br>(토큰 무결성 & 키) | `E2E-07`<br>`E2E-08`<br>`E2E-09`<br>`E2E-10`<br>`E2E-11`<br>`E2E-12`<br>`E2E-13` | 토큰 누락 차단<br>형식 파손(Malformed) 토큰 차단<br>페이로드 Scope 변조 토큰 차단<br>`alg: none` 공격 차단<br>`typ != at+jwt` 불일치 토큰 차단<br>서명 키 무중단 회전 후 검증 성공<br>폐기된 서명 키(`retired`) 즉시 거부 | `11`<br>`11`<br>`11`<br>`11`<br>`11`<br>`0`<br>`11` | RFC 9068 및 RFC 8725 토큰 불변식, Ed25519 키 링 무중단 회전 및 폐기 강제 |
| **G4**<br>(시간·바인딩·Replay) | `E2E-14`<br>`E2E-15`<br>`E2E-16`<br>`E2E-17`<br>`E2E-18` | 만료된 토큰 즉시 거부<br>미래 발급/활성(nbf) 토큰 거부<br>`iss`/`aud` 불일치 토큰 거부<br>타 주체 토큰 도용(`sub` 불일치) 거부<br>일회성 토큰 재사용(`jti` Replay) 거부 | `11`<br>`11`<br>`11`<br>`11`<br>`11` | 결정론적 가상 시계 기반 토큰 시간 경계값 및 Replay 블랙리스트 방어 |
| **G5**<br>(RFC 8693 위임 & PDP) | `E2E-19`<br>`E2E-20`<br>`E2E-21`<br>`E2E-22`<br>`E2E-23`<br>`E2E-24`<br>`E2E-31`<br>`E2E-32` | 팀장 Scope 초과 위임 시도 거부<br>팀장 수명(TTL) 초과 위임 시도 거부<br>최대 위임 깊이(`depth`) 초과 거부<br>Read 전용 자식 토큰으로 Write 시도 거부<br>미허가 리소스 경로 접근 거부<br>Subject Epoch 증가를 통한 일괄 철회<br>2-Hop 다단계 정상 위임 및 권한 축소 실행<br>2-Hop 중간 관리자의 권한 초과 위임 차단 | `12`<br>`12`<br>`12`<br>`12`<br>`12`<br>`12`<br>`0`<br>`12` | RFC 8693 축소 위임 불변식($S_c \subseteq S_p$, $exp_c \le exp_p$), Epoch 일괄 철회, 2-Hop OS 서브프로세스 연쇄 위임 및 차단 실증 |
| **G6**<br>(파일 Jail & 경로 보안) | `E2E-25`<br>`E2E-26`<br>`E2E-27` | 상대 경로 탈출(`../../etc/passwd`) 차단<br>루트 접두사 착시(`/workspace-evil`) 차단<br>심볼릭 링크 외부 탈출 시도 차단 | `13`<br>`13`<br>`13` | `filepath.EvalSymlinks` 기반 Workspace Jail 경계 엄격 강제 (부작용 0바이트) |
| **G7**<br>(관측성 & Fail-Closed) | `E2E-28`<br>`E2E-29`<br>`E2E-30` | `trace_id` 누락 요청 차단<br>감사 기록 실패 시 파일 쓰기 중단 (Fail-Closed)<br>사후 감사 로그 변조 적발 | `14`<br>`15`<br>`15` | 분산 추적 식별자 강제, Strict Fail-Closed 디스크 쓰기 중단, 해시 체인 무결성 |
| **G8**<br>(MCP 보안 어댑터) | `E2E-33`<br>`E2E-34`<br>`E2E-35`<br>`E2E-36`<br>`E2E-37`<br>`E2E-38`<br>`E2E-39` | MCP 읽기 토큰으로 file_read 정상 호출<br>MCP 읽기 토큰으로 file_write 시도 차단<br>만료된 토큰으로 MCP tools/call 호출 차단<br>MCP tools/call 경로 순회 탈출 차단<br>Grant 회수 후 MCP tools/call 실시간 차단<br>_meta.authz_token 누락 MCP 호출 차단<br>미지원 도구(shell_exec) 호출 차단 | `0`<br>`12`<br>`11`<br>`13`<br>`12`<br>`14`<br>`14` | MCP stdio JSON-RPC 2.0 어댑터의 격리 서브프로세스 도구 집행, Reason-to-Error 매핑, Zero Leakage 토큰 비노출 증명 |
| **G9**<br>(자원·수명 통제) | `E2E-40`<br>`E2E-41`<br>`E2E-42`<br>`E2E-43`<br>`E2E-44` | 멈춘 워커 시간 초과 강제 종료<br>손자를 남기고 멈춘 워커의 그룹 일괄 소멸<br>출력 폭주 워커의 바이트 상한 즉시 차단<br>MCP tools/call 시간 초과와 토큰 비노출<br>기본 한계 아래 정상 위임 워커 비회귀 | `17`<br>`17`<br>`17`<br>`17`<br>`0` | 프로세스 그룹 일괄 소멸, 출력 상한, 종료 코드 `17`, 결함 워커 별도 실행 파일 감독 (서브프로세스 모드 전용, inproc에서는 Skipped) |
| **G10**<br>(OS 커널 격리) | `E2E-45`<br>`E2E-46`<br>`E2E-47`<br>`E2E-48`<br>`E2E-49`<br>`E2E-80` | PEP 우회 Zone A 개인키 영역 직접 읽기 차단<br>PEP 우회 샌드박스 밖 직접 쓰기 차단<br>PEP 우회 네트워크 소켓 연결 차단<br>손자 프로세스의 격리 상속<br>격리 필수 모드 Fail-Closed<br>2-Hop 다단계 위임의 마지막 워커를 OS 격리 아래에서 실행 | `13`<br>`13`<br>`13`<br>`13`<br>`16`<br>`0` | 악의 워커를 격리 끔(대조군: 공격 성공)→켬(실험군: 차단) 쌍으로 대조하고 부모 관찰(canary·파일·리스너)로만 판정. 격리 불가 환경에서는 Skipped (서브프로세스 모드 전용). `E2E-80`은 정직한 다단계 위임이 격리 아래에서도 성공하고 격리 적용이 감사에 남는지를 검증 |
| **G11**<br>(예산 축소 위임) | `E2E-50`<br>`E2E-51`<br>`E2E-52`<br>`E2E-53`<br>`E2E-54` | 부모 잔여 초과 위임 거부<br>쓰기 바이트 예산 소진 차단<br>다중 서브프로세스 동시 경합 방어<br>자식 만료 후 예약 자동 회수 및 재위임<br>2-Hop 분할 위임 및 합계 보존 | `12`<br>`12`<br>`12`<br>`0`<br>`0` | 호출 횟수·읽기/쓰기 바이트 예산이 권한·수명·깊이에 이은 4번째 단조 축소 축($B_{child} \le B_{parent\_remaining}$)임을 증명. 소비는 토큰이 아닌 Zone B 원장에서 원자 차감하며, 6개 프로세스 경합에서도 합계가 예산을 넘지 않음 (서브프로세스 모드: E2E-52) |
| **G12**<br>(장기 세션·토큰 수명) | `E2E-55`<br>`E2E-56`<br>`E2E-57`<br>`E2E-58`<br>`E2E-59`<br>`E2E-60` | 세션 중 토큰 시간 만료 차단<br>상위 위임자 Epoch 증가로 하위 토큰 연쇄 차단<br>서명 키 회전(유지) 후 폐기 즉시 차단<br>세션 내 일회성 토큰 2회차 재사용 차단<br>자식 만료 후 유효 부모로 재교환해 세션 재개<br>부모 만료 후 재교환 거부 | `11`<br>`12`<br>`11`<br>`11`<br>`0`<br>`11` | 하나의 MCP 세션 안에서 시간 경과·계보 회수(`act` 조상 Epoch 동등 비교)·키 폐기·재사용이 일어난 뒤의 호출이 정확한 사유로 거부됨을 증명하고, Refresh Token 없이 부모 기반 재교환으로 세션이 재개되되 부모 수명을 넘지 못함을 확인 |
| **G13**<br>(감사 확장·관측성 포트) | `E2E-61`<br>`E2E-62`<br>`E2E-63`<br>`E2E-64`<br>`E2E-65`<br>`E2E-66` | 감사 꼬리 절단 적발<br>해시 전체 재작성 적발<br>체크포인트 검증 재료 부재 Fail-Closed<br>인자·결과 지문 기록과 원문 비노출<br>관측성 포트 장애 격리<br>v1·v2 혼합 체인 하위 호환 | `15`<br>`15`<br>`15`<br>`0`<br>`0`<br>`0` | 체인이 유효해도 서명 체크포인트(Zone A 감사 전용 키)가 절단·재작성·검증 재료 부재를 잡고, 감사에는 SHA-256 지문만 남으며, 텔레메트리 장애가 판정·감사를 바꾸지 못하고, 기존 v1 기록 뒤에 v2가 이어져도 체인이 유효함을 증명 |
| **G14**<br>(PDP 승인 결정 ask) | `E2E-67`<br>`E2E-68`<br>`E2E-69`<br>`E2E-70`<br>`E2E-71`<br>`E2E-72`<br>`E2E-73` | 승인 필수 작업의 미승인 ask 차단<br>ask 후 승인, 같은 토큰 재시도 성공<br>승인 1회 소비 후 재사용 차단<br>다른 토큰(jti)의 승인 도용 차단<br>승인 후 인자 바꿔치기 차단<br>TTL 만료 승인 차단<br>승인 후 Grant 회수 시 승인 우회 차단 | `18`<br>`0`<br>`18`<br>`18`<br>`18`<br>`18`<br>`12` | 권한이 있어도 사람 승인이 없으면 거부와 똑같이 실패하고, 승인은 `(sub, action, resource, jti)` + 선택적 인자 지문에 묶인 1회용·TTL 한정이며, ask·deny에서는 jti를 소비하지 않아 승인 뒤 같은 토큰으로 재시도할 수 있고, Grant 회수가 승인보다 우선함을 증명 |
| **G15**<br>(도구 확장·egress 통제) | `E2E-74`<br>`E2E-75`<br>`E2E-76`<br>`E2E-77`<br>`E2E-78`<br>`E2E-79` | 루프백 allow-list net:fetch 정상 실행<br>표기 우회와 비허용 포트 차단<br>리다이렉트 차단<br>exec:run 정상 실행 뒤 주입·미등록 ID 차단<br>부모 출력 상한이 새 도구에도 걸림<br>포트 단위 격리 대조군 쌍 | `0`<br>`12`<br>`12`<br>`12`<br>`17`<br>`13` | `net:fetch`(루프백 전용 GET)와 `exec:run`(코드 고정 allow-list)도 기존 PEP 단일 입출구로만 집행되고, URL 표기 우회·리다이렉트·인자 주입은 서버·워크스페이스에 닿기 전에 막히며, OS 격리는 허용 포트만 열고 PEP를 건너뛴 연결은 커널이 막음을 증명 |

### OS 커널 격리 플랫폼 보증 표

| 플랫폼 | 어댑터 | 보증 내용 | 검증 상태 |
|---|---|---|---|
| macOS | `darwin-seatbelt` (`sandbox-exec`, Apple deprecated 도구 — `Confiner` 포트 뒤 교체 가능) | `ProtectedRoot` 목록 외 읽기 거부, `WritePaths` 외 쓰기 거부, 네트워크 거부, 자손 상속, `chmod` 우회 불가 | **실행 검증 PASS**: G10. 중첩 샌드박스(`sandbox-exec` exit `71`)에서는 `Available()==false`로 G10 Skipped |
| Linux | `linux-landlock` (+ `confine-exec` 신뢰 런처) | 같은 최소 보장 계약. 네트워크 차단은 Landlock ABI v4+(커널 6.7+)에서만 가능하며 미만이면 필수 모드 거부 | **교차 컴파일(`GOOS=linux`)만 검증, 런타임 미검증** (개발 호스트가 macOS) |
| 기타 | `none` (`NoopConfiner`) | 보장 없음. 필수 모드는 항상 `16`(`CONFINEMENT_UNAVAILABLE`) | 단위 테스트 |

---

## 🔍 Explain UX & 관측성의 삼분 (Tri-Separation)

보안 시스템의 출력은 목적에 따라 엄격히 분리되어야 합니다. 본 시스템은 3개의 독립된 채널을 유지합니다:

```text
[요청 실행] ──┬──▶ stdout      : 초보자용 단계 파이프라인 시각화 및 한국어 역설 해설
              ├──▶ stderr      : 개발자/운영자용 log/slog 구조화 로그
              └──▶ audit.jsonl : 불변의 SHA-256 해시 체인 감사 원장
```

### Explain UX: 부정 테스트의 역설 (Paradox of Negative Testing)

`--output-format explain` 옵션은 차단된 단계와 함께 **"왜 이 실패가 시스템을 지켜낸 성공인가"**를 시각화합니다:

```bash
go run ./cmd/authz-harness run --scenario E2E-22 --output-format explain
```

```text
================================================================================
 시나리오 [E2E-22]: Read 전용 자식 토큰으로 Write 시도 거부
================================================================================
 [기본 정보]
  - 그룹: G5 (RFC 8693 위임 및 PDP 스코프 검증)
  - 판정 결과: PASS (보안 방어 성공) [소요시간: 7.1ms]
  - Quad-Assertion: [종료코드: 12(기대 12)] [파일상태: 무결성 유지] [감사사유: TOKEN_INSUFFICIENT_SCOPE] [해시체인: true]

 [단계 상태 파이프라인]
  [입력 검사] ──▶ 통과
  [신원 확인] ──▶ 통과
  [권한 판정] ──▶ 차단
  [경계 검사] ──▶ 건너뜀
  [재사용 방지] ──▶ 건너뜀
  [승인 소비] ──▶ 건너뜀
  [예산 차감] ──▶ 건너뜀
  [실행 전 감사 기록] ──▶ 건너뜀
  [실행] ──▶ 건너뜀
  [사후 정산] ──▶ 건너뜀

 [💡 초보자를 위한 보안 원리 해설 (부정 테스트의 역설)]
  - 질문: 왜 프로세스는 실패(Exit Code 12)했는데 하네스는 PASS(통과)라고 하나요?
  - 해설: 위임 범위를 벗어난 권한 초과(Privilege Escalation) 공격입니다.
          부모 토큰보다 큰 권한을 자식이 행사하려 했으나 권한 판정에서 이를 적발하여
          종료 코드 12로 방어했습니다.
================================================================================
```

---

## 📚 문서 색인 및 로드맵 안내

공개 저장소에는 핵심 설계 로드맵(`docs/로드맵/`)과 프로그램 작동원리 설명서(`docs/작동원리/`)가 함께 포함되어 있습니다:

- 🧭 **[마스터 청사진 (MASTER_ROADMAP.md)](docs/로드맵/MASTER_ROADMAP.md)**: OAuth 2.1 워크로드 인증, RFC 8693 축소 위임, 3-Zone 토폴로지, 전체 아키텍처 설계도.
- 🎯 **[전체 로드맵 색인 (docs/로드맵/README.md)](docs/로드맵/README.md)**: Phase 00부터 Phase 19까지의 단계별 로드맵(`ROADMAP.md`, `WHY.md`, `결과정리및리뷰.md`, `instructions/`).
- 📖 **[프로그램 작동원리 설명서 (docs/작동원리/README.md)](docs/작동원리/README.md)**: 코드를 읽지 않는 사람도 프로그램 내부 동작 순서와 설계 이유(Why)를 이해할 수 있게 안내하는 001~012편 해설서 ([001편 프로그램 정체성과 전체 생애주기](docs/작동원리/001-프로그램_정체성과_전체_생애주기.md), [010편 요청 하나의 일생 — 건물 방문기로 보는 전체 지도](docs/작동원리/010-요청_하나의_일생_건물방문기로_보는_전체_지도.md), [012편 인증과 인가·OAuth2·OIDC·PKCE 개념 해설](docs/작동원리/012-인증과_인가_OAuth2_OIDC_PKCE_개념_해설.md) 등).

> **참고**: 이 저장소는 비공개 개발 저장소에서 공개 대상 코드와 핵심 문서만 추출한 정제 사본입니다. 일부 과거 로드맵·설명서 본문에 남아 있는 내부 문서 링크나 커밋 해시는 비공개 개발 저장소 기준일 수 있습니다.

---

## 📄 저작권 및 이용 안내 (Copyright)

Copyright © 2026 RadiantCitron. **All Rights Reserved.**

본 저장소에는 별도의 오픈소스 라이선스가 부여되어 있지 않습니다. 저작자(`RadiantCitron`)의 사전 서면 허가 없이 본 코드 및 문서의 무단 복제, 수정, 재배포 또는 상업적 이용을 금합니다.
