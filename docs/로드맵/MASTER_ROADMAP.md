# authz-harness 마스터 로드맵 (Master Blueprint & Roadmap)

> **상위 안내**: 본 문서는 `authz-harness` 전체 아키텍처 및 Phase 0~18의 통합 청사진을 보존하는 **마스터 설계도**입니다.
> - **타 에이전트 이관 대비 설계 정합성 검증 보고서**: [012-타에이전트_구현이관대비_전체설계정합성_및_코어구조_위험요소_검증보고서.md](../보고서/012-타에이전트_구현이관대비_전체설계정합성_및_코어구조_위험요소_검증보고서.md)
> - **코어 권한·파이프라인 5대 기본기 진단 보고서**: [011-권한관리_본질_코어파이프라인_안티패턴_및_분산적응형_기본구조_전문가진단_보고서.md](../보고서/011-권한관리_본질_코어파이프라인_안티패턴_및_분산적응형_기본구조_전문가진단_보고서.md)
> - **로드맵 거버넌스 및 실행 절차**: [ROADMAP_정책.md](ROADMAP_정책.md)
> - **전체 로드맵 색인 및 진행 대시보드**: [README.md](README.md)
> - **엔터프라이즈 아키텍처 심층 검토 보고서**: [003-엔터프라이즈_인가_보강_기술보고서.md](../보고서/003-엔터프라이즈_인가_보강_기술보고서.md)
> - **최상위 프로젝트 헌장**: [AGENTS.md](../../AGENTS.md)

---

## 1) 한 줄 정의
OAuth 2.1 기반 워크로드 인증(AuthN)·토큰 무결성·축소 위임([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) Downscoping)·[NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-162.pdf) 4대 인가 분리(PAP/PIP/PDP/PEP)·OS 서브프로세스 격리·감사 추적(Audit Trail)이 실제로 작동하고 실패해야 할 때 정확히 실패하는지 증명하는 Go 기반 단일 리포지토리 로컬 **권한 검증 및 테스트 하네스(Authorization Test Harness)**.

## 2) 배경 / 동기 / 포트폴리오에서 보여주고 싶은 역량
### 배경 및 동기
현대 멀티 에이전트 시스템과 마이크로서비스 환경에서는 오케스트레이터(팀장)가 하위 워커나 서브에이전트에게 작업을 위임할 때 과도한 권한이 전달되거나, 권한 회수(Revoke)가 실시간 집행에 반영되지 않거나, 실패 원인이 운영 로그에 묻혀 사후 감사(Audit)가 불가능해지는 문제가 빈번하게 발생한다. 많은 프로젝트가 에이전트의 지능(LLM 프롬프트, 추론 능력)에 집중하지만, 엔터프라이즈 환경에서 시스템을 실제로 신뢰할 수 있게 만드는 핵심 기반은 **"권한이 없을 때 확실하게 실패하는 구조"**와 **"누가 어떤 근거로 무엇을 허용·거부했는지 시계열로 증명하는 구조"**다.

본 프로젝트는 상용 클라우드 IdP나 거대한 분산 인프라 없이도, 로컬 단일 바이너리/리포지토리 환경에서 [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)의 핵심 보안 정신과 엔터프라이즈 인증·인가 아키텍처(Dual-Gate AuthN/AuthZ, PAP/PIP/PDP/PEP 분리, 최소 권한 위임, 3-Zone 상태 격리, OS 프로세스 격리, 감사 배선 분리)를 처음부터 끝까지 직접 설계·구현·검증하기 위해 기획되었다.

### 포트폴리오에서 보여주고 싶은 핵심 역량
* **OAuth 2.1 및 토큰 기반 접근 통제 이해**: 암시적 흐름(Implicit Flow) 배제, 단기 만료 Bearer Access Token([RFC 9068](https://www.rfc-editor.org/info/rfc9068/) `typ: at+jwt`), 서명 키 수명주기([RFC 7517](https://www.rfc-editor.org/info/rfc7517/) `kid` 회전·폐기), 클레임(`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope`, `act`, `epoch`) 검증 및 알고리즘 혼동 차단([RFC 8725](https://www.rfc-editor.org/info/rfc8725/)).
* **결정(PDP)과 집행(PEP) 및 정책 관리/정보(PAP/PIP)의 엄격한 분리**: [NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-162.pdf) 표준에 따라 관리(PAP), 상태 공급(PIP), 순수 결정(PDP: `allow/deny + reason`), 로컬 집행(PEP: 파일 I/O 직전 강제 및 Jail 격리)을 컴파일 타임 패키지 경계로 분리하는 아키텍처 역량.
* **최소 권한 원칙(Least Privilege)과 축소 위임(Downscoping)**: [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) Token Exchange 개념을 적용하여 팀장(Orchestrator)이 자신의 권한 범위를 초과하여 자식(Subagent)에게 위임할 수 없도록 통제($S_{child} \subseteq S_{parent}$, $exp_{child} \le exp_{parent}$)하고, 위임 계보(`act` 클레임 및 `delegation_depth`)를 추적하는 설계 능력.
* **OS 프로세스 수준 격리 및 3-Zone 상태 격리**: 서브에이전트를 독립된 OS 서브프로세스로 분리하여 메모리 공간을 격리하고, 로컬 상태를 권원 전용(Zone A)·검증 조회(Zone B)·격리 실행 및 감사(Zone C)로 나누어 비신뢰 워커의 개인키 접근을 차단하는 시스템 프로그래밍 역량.
* **감사 추적(Audit Trail)과 운영 로그(Ops Log)와 CLI 출력의 삼분**: 실행 경로와 감사 경로를 분리하고, 디버깅용 운영 로그([log/slog](https://pkg.go.dev/log/slog))와 보안 증거인 감사 이벤트(해시 체인 기반 JSONL), 그리고 초보자 친화적 CLI 설명 출력(`stdout`)을 물리적으로 분리하여 동일 `trace_id` 아래 전 과정을 시계열로 재구성하는 능력.
* **다층 테스트(L1~L5) 및 부정 테스트(Negative Testing) 하네스 설계 능력**: 단위·퍼징·동시성(`-race`)·CLI 계약 테스트는 물론, 30개의 전 구간 E2E 시나리오에서 토큰 변조·만료·권한 회수·경로 탈출·초과 위임 등 실패해야 하는 시나리오가 **정확히 의도된 이유와 종료 코드로 실패함**을 자동 증명하는 엔지니어링 역량.

## 3) 목표 (Goals)
1. **단일 리포지토리·로컬 완결형 권한 하네스 구축**: 외부 네트워크나 서드파티 IdP 없이 Go 표준 환경과 최소한의 로컬 구성만으로 즉시 빌드·실행·검증 가능한 CLI 기반 권한 하네스를 완성한다.
2. **이중 관문(Gate 1 AuthN → Gate 2 AuthZ) 및 PAP/PIP/PDP/PEP 분리 구현**: 워크로드 인증과 토큰 무결성을 검증하는 Gate 1과, Grant/Epoch 상태를 조회(PIP)하여 결정(PDP)하고 파일 I/O 직전에 집행(PEP)하는 Gate 2를 단방향 상태 머신으로 확립한다.
3. **오케스트레이터→서브에이전트 축소 위임(Downscoping) 증명**: 오케스트레이터가 보유한 권한 내에서만 서브에이전트용 축소 토큰을 교환·발급받아 OS 서브프로세스로 실행시키는 위임 체인을 구현한다.
4. **권한 생명주기 실시간 검증 (Grant → Allow → Revoke → Deny)**: 권한 부여 전 거부, 부여 후 허용, 회수(Revoke) 또는 주체 Epoch 갱신 직후 재요청 시 즉시 거부가 실제로 작동함을 관찰 가능한 결과와 감사 로그로 입증한다.
5. **안전한 파일 도메인 격리(Workspace Jail)**: 서브에이전트의 능력을 지정된 Workspace 루트 내부의 파일 읽기(`file:read`)와 쓰기(`file:write`)로 엄격히 제한하고, `../`, 절대 경로, Prefix 착시, 심볼릭 링크를 이용한 경로 탈출 시도를 차단한다.
6. **전 과정 시계열 감사(Audit) 기록 및 무결성 확보**: 하나의 시나리오 실행 연쇄를 단일 `trace_id`로 묶어 Append-only JSONL 및 해시 체인(`prev_hash`)으로 기록하고, 초보자도 한눈에 볼 수 있는 시각적 관문 파이프라인과 `audit timeline` 뷰를 제공한다.
7. **5계층 테스트 스위트 및 단일 명령 E2E 하네스 제공**: L1(단위), L2(퍼징), L3(통합/동시성), L4(CLI 계약), L5(`run --scenario all` 30대 E2E 시나리오)를 완비하여 기대한 실패가 실제로 실패했을 때 `PASS`로 판정하는 자동화 검증 체계를 제공한다.

## 4) 비목표 (Non-Goals) — 명시적으로 하지 않는 것
1. **실제 LLM 연동 및 에이전트 지능 구현**: 프롬프트 엔지니어링, 추론 루프, 외부 LLM API 호출은 일절 포함하지 않는다. 에이전트는 지정된 파일 읽기/쓰기 명령을 수행하는 결정론적 실행기다.
2. **상용 대규모 분산 IAM/IdP 구축**: 멀티 리전 복제, 고가용성 클러스터링, 외부 OIDC 연합(Federation), LDAP/AD 연동, 엔터프라이즈 외부 DB 서버 의존은 다루지 않는다.
3. **브라우저 기반 UI 및 대화형 로그인 플로우**: OAuth 2.1의 Authorization Code + 브라우저 리다이렉트 + 로그인 웹 UI + 동의 화면(Consent Screen)은 하네스 목적에 불필요하므로 생략한다.
4. **복잡한 파일/시스템 작업 (ADR 0003 C-2 조건부 해제 반영)**: 초기(Phase 0~9)에는 `file:read`와 `file:write`로만 한정하며, Phase 16([16-도구-종류-확장-및-egress-통제](16-도구-종류-확장-및-egress-통제/README.md))에 한해 [ADR 0003](../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md) C-2 조건 하에서 결정론적 루프백 전용 `net:fetch`와 allow-list ID 전용 `exec:run` 가짜 도구만 PEP 단일 입출구 위로 허용한다(외부 인터넷 접속 및 임의 셸 명령 실행은 영구 금지).
5. **컨테이너·가상머신 제품화 (ADR 0003 C-1 조건부 해제 반영)**: 전체 시스템 컨테이너 런타임이나 VM 구축은 비목표로 유지하되, Phase 11([11-os-수준-격리-및-악의-워커-차단](11-os-수준-격리-및-악의-워커-차단/README.md))에서 [ADR 0003](../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md) C-1에 따라 서브프로세스 워커 한정 커널 격리 어댑터(`internal/confinement`: macOS Seatbelt, Linux Landlock + 신뢰 런처)를 검증한다([020번 보고서](../보고서/020-11번로드맵_구조결함_및_진행가능성_검증보고서.md)로 VFS DAC 폐기).
6. **Refresh Token 회전 (ADR 0003 C-4 조건부 해제 반영)**: Refresh Token 발급 및 회전 메커니즘은 영구 비목표로 유지하되, Phase 13([13-장기-실행-및-토큰-수명-검증](13-장기-실행-및-토큰-수명-검증/README.md))에서 만료 임박 시 부모 토큰의 현재 유효성과 Epoch/예산을 재검증하여 새 단기 자식 토큰을 발급받는 **부모 기반 재교환(`re-exchange`)** 흐름만 허용한다.

## 5) 성공 정의 (Definition of Success) — 데모·종료 조건
1. **단일 명령 전체 시나리오 통과**: 로컬 터미널에서 단일 CLI 명령(`authz-harness run --scenario all`)을 실행했을 때, 정의된 30개 긍정(Allow) 및 부정(Deny/Error) E2E 시나리오 전체가 실행되고 최종 요약에서 모든 시나리오가 `PASS`로 출력되며 프로세스 종료 코드가 `0`이다.
2. **기대 실패의 정확한 포착 (Quad-Assertion)**: 권한 없는 접근, 만료/변조된 토큰, 폐기된 서명 키(`kid`), 회수된 권한, 경로 탈출(`../` 및 심볼릭 링크), 초과 위임 시도 시 서브프로세스가 절대 파일을 읽거나 쓰지 못하고, 사전에 정의된 비정상 종료 코드(`11`~`15`)를 반환하며, 하네스가 종료 코드·파일 무변화·감사 사유 코드·출력 비오염의 4중 기준을 대조해 `PASS`로 판정한다.
3. **권한 부여-회수 동적 전환 증명**: 동일 리소스에 대해 `Grant 전 실패 → Grant 후 성공 → Revoke 후 즉시 실패`가 하나의 연속된 시나리오 안에서 재빌드나 재시작 없이 순차적으로 입증된다.
4. **파일 시스템 부작용 없음 증명**: 모든 거부(Deny) 시나리오 실행 직후 대상 Workspace 디렉토리를 검사했을 때, 인가되지 않은 파일 생성이나 내용 변경이 단 1바이트도 발생하지 않는다.
5. **완전한 시계열 감사 재구성 및 무결성 검증**: 시나리오 실행 후 `audit timeline` 및 `audit verify`를 실행했을 때, 단일 `trace_id`로 묶인 일련의 이벤트가 누락 없이 시간순으로 정렬되어 출력되고 해시 체인 검증이 `VALID`로 통과하며 운영 로그(`stderr`)와 섞이지 않는다.
6. **Go 표준 테스트 스위트 완주**: `go test -race ./...` 실행 시 L1(Unit), L2(Fuzz 시드), L3(동시성/가상시계), L4(CLI 계약) 테스트가 Data Race 없이 100% 통과한다.

## 6) 용어집 (Glossary)
| 용어 | 본 프로젝트에서의 정의 및 역할 |
| :--- | :--- |
| **Subject (`sub`)** | 권한이 부여되고 행위를 수행하는 주체 식별자 (`orchestrator-main`, `subagent-reader-01` 등). |
| **Actor (`act`)** | [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) 위임 체인에서 하위 주체에게 권한을 위임한 상위 주체(팀장 오케스트레이터) 및 상위 토큰 맥락을 기록하는 클레임. |
| **Client (`client_id`)** | OAuth 2.1 관점에서 중앙 인가 서버에 토큰 발급/교환을 요청하는 등록된 워크로드 애플리케이션 단위. |
| **Token (`at+jwt`)** | 중앙 서버가 발급하는 [RFC 9068](https://www.rfc-editor.org/info/rfc9068/) 프로파일 기반 서명된 단기 자격 증명(Bearer Access Token). |
| **Key ID (`kid`)** | 토큰 서명에 사용된 암호화 키의 고유 식별자([RFC 7517](https://www.rfc-editor.org/info/rfc7517/)). 무중단 키 회전(`verify-only`) 및 폐기(`retired`) 검증에 사용된다. |
| **Scope** | 토큰이 허용하는 최대 권한 범위를 나타내는 구조화된 문자열 표현 (`file:read:docs/plan.txt` 등). |
| **Grant & Epoch** | 특정 Subject에게 특정 Resource에 대한 Action을 허용하는 중앙 상태 레코드(Grant)와, 주체 단위의 일괄 권한 무효화를 위한 버전 번호(Security Epoch). |
| **Downscoping (축소 위임)** | 상위 주체(팀장)가 하위 주체(서브에이전트)에게 작업을 위임할 때, 자신이 가진 권한과 수명의 부분집합($S_{child} \subseteq S_{parent}$, $exp_{child} \le exp_{parent}$)으로만 제한된 새 토큰을 교환받아 전달하는 행위. |
| **PAP (Policy Administration Point)** | Grant의 생성(`grant create`), 회수(`grant revoke`), 주체 Epoch 증가를 관리하는 정책 관리점. |
| **PIP (Policy Information Point)** | PDP가 결정을 내리기 직전 실시간 활성 Grant 상태, 현재 Subject Epoch, 공개키 상태, 일회성 `jti` 사용 여부를 조회해 공급하는 정책 정보점. |
| **PDP (Policy Decision Point)** | 검증된 토큰 클레임과 PIP 실시간 상태를 대조하여 부작용(파일 I/O 등) 없이 순수하게 `allow/deny + reason`만 계산하는 정책 결정점. |
| **PEP (Policy Enforcement Point)** | 실제 파일 I/O 직전에 위치하여 Gate 1(AuthN) 및 Gate 2(PDP) 결정을 강제하고 Workspace Jail 경로 검증을 통과했을 때만 파일 읽기/쓰기를 집행하는 관문. |
| **Orchestrator (팀장)** | 시나리오를 통제하고 중앙 서버에 축소 위임 토큰 교환을 요청한 뒤 서브에이전트 OS 서브프로세스를 생성(Spawn)하고 종료 코드를 수거하는 부모 조정자 프로세스. |
| **Subagent (서브에이전트)** | 오케스트레이터에 의해 생성된 독립 OS 자식 프로세스. `stdin` 프레임으로 전달받은 토큰을 제시하고 PEP를 통해서만 파일 작업을 수행한다. |
| **Workspace Jail** | 파일 접근이 허용되는 로컬 최상위 디렉토리(`./workspace`). 모든 경로는 정규화 및 심볼릭 링크 해석 후 이 디렉토리 내부로만 제한된다. |
| **Audit (감사 로그)** | 보안 통제 및 인가 결정의 사후 증명을 위해 실행 경로와 분리되어 기록되는 해시 체인 기반 Append-only JSONL 레코드. |
| **Ops Log (운영 로그)** | 개발 및 런타임 진단을 위해 `stderr`로 출력되는 일반 구조화 로그([log/slog](https://pkg.go.dev/log/slog)). 감사 증거를 대체하지 않는다. |
| **Trace (`trace_id`)** | 한 시나리오 또는 한 오케스트레이터 실행 연쇄에서 파생된 모든 부모·자식 프로세스의 이벤트를 묶는 상관관계 식별자. |

## 7) 액터와 신뢰 경계 (Trust Boundaries) 및 3-Zone 상태 토폴로지
### 주요 액터
1. **사용자 / 시나리오 러너 (User / Test Runner)**: CLI 명령 또는 `run --scenario all`을 실행하는 최상위 외부 트리거.
2. **중앙 인가 코어 (Central AuthN/AuthZ Core)**: 클라이언트 인증기, 토큰 발급/교환기(STS), PAP, PIP, PDP를 포함하는 신뢰의 기준점(Root of Trust).
3. **오케스트레이터 (Orchestrator / 팀장)**: 권한의 소유자가 아닌 조정자로서, 자신의 자격 증명으로 부모 토큰을 발급받고 자식용 축소 토큰을 교환받아 자식 프로세스를 띄우는 부모 프로세스.
4. **서브에이전트 (Subagent / 워커 서브프로세스)**: 독립된 OS 프로세스 공간에서 실행되는 반신뢰/비신뢰 워커.
5. **PEP & Workspace Jail 게이트웨이**: 파일 시스템 직전에서 토큰 검증·PDP 결정·경로 격리를 강제하는 집행 경계.
6. **감사 기록기 (Audit Sink)**: 모든 보안 이벤트를 원자적 파일 잠금(`flock`)과 해시 체인으로 기록하는 독립 증거 파이프라인.

### 3-Zone 로컬 상태 및 프로세스 신뢰 경계 구조
로컬 단일 바이너리 환경에서도 권한 권원과 비신뢰 서브에이전트 간의 물리적·논리적 경계를 보장하기 위해 로컬 상태를 3개 영역(Zone)으로 분리한다.
* **Zone A (Root Authority Private State — `./.authz-state/private/`)**: JWK 개인 서명 키(`signing_keys.priv.json`)와 클라이언트 시크릿 해시 레지스트리. 오직 중앙 토큰 발급기 및 키 관리 명령만 접근하며, **서브에이전트 워커 프로세스나 PDP/PEP는 이 영역을 절대 메모리에 로드하지 않는다.**
* **Zone B (Verification & PIP Shared Read State — `./.authz-state/public/`)**: JWK 공개 검증 키(`jwks.pub.json`), 활성/회수된 Grant 및 주체별 Epoch 스냅샷(`grants_state.json`), 일회성 토큰 사용 원장(`replay_ledger.json`). 갱신 시에는 원자적 쓰기 후 이름 변경(Atomic Write-and-Rename)과 배타적 파일 락(`flock`)을 사용하고, PIP/검증기는 읽기 전용으로 참조한다.
* **Zone C (Execution Sandbox & Evidence Sink — `./workspace/` 및 `./audit.jsonl`)**: PEP가 경계를 강제하는 Workspace 루트 디렉토리와, 부모·자식 프로세스가 `O_APPEND` + 파일 잠금으로 기록하는 감사 로그 파일.

## 8) 시스템 컨텍스트, 6계층 의존성(DAG) 및 상태 머신 다이어그램
### 8.1 시스템 컨텍스트 및 3-Zone 실행 구조도
```text
+-----------------------------------------------------------------------------------+
|                               User / Scenario CLI                                 |
|                      (e.g., authz-harness run --scenario all)                     |
+-----------------------------------------+-----------------------------------------+
                                          | (1) CLI Command & Fault Injection Flags
                                          |     [trace_id generated]
                                          v
+-----------------------------------------------------------------------------------+
|                            Orchestrator (Team Leader)                             |
|  - Authenticates as Confidential Client to obtain Parent Token                    |
|  - Requests RFC 8693 Downscoped Child Token (Never owns signing keys)             |
|  - Spawns Subagent OS subprocess (Clean Env + Stdin JSON Frame) & reaps Exit Code |
+-----------------+-------------------------------+---------------------------------+
                  | (2) Client AuthN,             | (4) Spawn OS Subprocess
                  |     PAP Grant/Revoke,         |     Stdin Frame: [Child Token,
                  |     Token Issue & Exchange    |     trace_id, action, resource]
                  v                               v
+-----------------------------------+   +===========================================+
|   Central AuthN/AuthZ Core        |   |       OS Process Isolation Boundary       |
|  +-----------------------------+  |   |                                           |
|  | AuthN & Token Service (STS) |  |   |  +-------------------------------------+  |
|  | [Zone A: Private Keys]      |  |   |  |      Subagent Worker Process        |  |
|  +-----------------------------+  |   |  |  - ZERO access to Zone A Priv Keys  |  |
|  | PAP / PIP (Grants & Epochs) |  |   |  |  - Invokes PEP Gateway with Token   |  |
|  | [Zone B: Public State/JWKS] |  |   |  +------------------+------------------+  |
|  +--------------+--------------+  |   |                     | (5) Request I/O     |
|                 |                 |   |                     v                     |
|  +--------------v--------------+  |   |  +-------------------------------------+  |
|  | PDP (Pure Decision Engine)  |<-+---+--+   PEP (Policy Enforcement Point)    |  |
|  | - Gate 1: Verify JWT+kid    |  |   |  |  - Calls Gate 1 (AuthN) + Gate 2    |  |
|  | - Gate 2: Match Scope+PIP   |  |   |  |  - Enforces Workspace Jail (Path)   |  |
|  | - Output: Allow/Deny+Reason |  |   |  +------------------+------------------+  |
|  +-----------------------------+  |   |                     | (6) Confined I/O    |
+-----------------------------------+   +=====================|=====================+
                                                              v
                                        +-------------------------------------------+
                                        |     [Zone C] Workspace File System        |
                                        |        (Strict Jail: ./workspace/...)     |
                                        +-------------------------------------------+

=====================================================================================
                  Orthogonal Observability & Evidence Planes (Tri-Separation)
=====================================================================================
  [Audit Wiring] ---> ./audit.jsonl (Zone C) : Append-only JSONL + SHA-256 Hash Chain
  [Ops Logging]  ---> stderr (log/slog)      : Diagnostic runtime logs (Tokens masked)
  [CLI Output]   ---> stdout (UI Formatter)  : Visual Gate Pipeline, Explain & Timeline
```

### 8.2 6계층 비순환 의존성 그래프 (6-Layer Strict Acyclic Dependency Graph)
모든 내부 패키지는 **자신보다 낮은 번호의 계층(Lower Layer)만 단방향으로 참조**할 수 있으며, `pdp`가 `jail`이나 OS 파일 I/O를 참조하는 것은 컴파일 타임에 원천 금지된다.
* **Layer 5 (Entry, Composition Root & Harness)**: `cmd/authz-harness`, `internal/app` (단일 합성 루트 `BuildStack`), `internal/cli`, `internal/harness`, `internal/ui`, `internal/mcp`
* **Layer 4 (Process Coordinators & OS Confinement)**: `internal/orchestrator` (부모 스포너·세션 러너), `internal/subagent` (자식 워커 엔트리), `internal/confinement` (Phase 11 OS 커널 격리 어댑터 — 코어 패키지에서 import 금지 `TC-110-01`)
* **Layer 3 (Enforcement Gateway)**: `internal/authz/pep` (AuthN 검증 + PDP 결정 + 도구 경계 검증 + Pre-Commit 원장/감사 + I/O 실행 SESE 단일 입출구 조율, Phase 17 `ToolHandler` 전략 포트)
* **Layer 2 (Core Security Domains — 수평 상호 참조 금지)**:
  * **Layer 2A**: `internal/authn/{keys,token,exchange,budget}` (클라이언트 인증, JWK 키 링, 토큰 발급·교환·검증, Replay 원장, Phase 12 Zone B `budget_ledger.json` 예산 원장)
  * **Layer 2B**: `internal/authz/{pap,pip,pdp,state}` (인가 관리·상태 공급·순수 결정 코어 — `pdp`는 파일/OS 의존성 0% 및 Phase 17에서 `domain.SubjectSnapshot` DIP로 전이적 인프라 의존성 0% 달성 `TC-170-01`)
  * **Layer 2C**: `internal/jail` (파일 경로 격리), `internal/netguard` (Phase 16 루프백 Egress 가드), `internal/execguard` (Phase 16 Allow-List 실행 가드)
* **Layer 1 (Persistence, Observability & Evidence)**: `internal/storage` (`AtomicFileStore[T]` 단일 `flock` 원장 엔진 `TC-081-01`), `internal/audit` (JSONL + 해시 체인 + Phase 14 v2 해시·서명 체크포인트), `internal/observe` (Phase 14 관측성 포트 + `slogadapter`, OTel 어댑터는 `Dropped` — `internal/opslog` 가칭 폐기)
* **Layer 0 (Pure Primitives & Domain Ports)**: `internal/domain` (순수 도메인 엔티티, `Clock` 가상/실제 시계 인터페이스 `TC-130-01`, `AuditContext`/`TraceID`, `*domain.Error` 및 `ExitCode` 상수, `Budget`(Phase 12), Phase 17 `SubjectSnapshot`/`SnapshotProvider`/`AuditWriter` 포트)

## 9) 핵심 원칙 (Core Architectural Principles)
1. **이중 관문(Dual-Gate: AuthN before AuthZ) 및 기본 거부(Fail-Closed)**: 신원 및 암호학적 무결성(Gate 1)이 검증되기 전에는 인가 정책(Gate 2)을 평가하지 않으며, 감사 기록 실패를 포함한 모든 경계 오류 시 즉시 거부하고 중단한다.
2. **최소 권한 및 단조 축소 위임 원칙 (Least Privilege & Monotonic Downscoping)**: 위임 시 권한·수명·예산은 오직 단조 감소($S_{child} \subseteq S_{parent}$, $exp_{child} \le exp_{parent}$, $B_{child} \le B_{parent\_remaining}$)해야 하며, 팀장이 자기보다 큰 권한을 자식에게 부여하는 것은 원천 차단된다.
3. **PAP·PIP·PDP·PEP 4각 분리 ([NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-162.pdf))**: 관리(PAP), 실시간 상태 조회(PIP), 순수 결정(PDP), 실제 파일 I/O 집행(PEP)은 각각의 패키지 경계를 넘지 않는다.
4. **중앙 정책 권원과 조정자의 분리 (Authority vs. Coordinator)**: 팀장(Orchestrator)은 권한 상점의 주인이 아니라 작업을 분배하고 토큰 교환을 요청하는 조정자일 뿐이며, Zone A의 서명 키에 절대 직접 접근할 수 없다.
5. **OS 프로세스 격리 및 클린 환경 전달**: 서브에이전트는 독립된 OS 프로세스로 실행되며, 부모 환경변수를 무분별하게 상속하지 않고 `stdin` 단일 프레임을 기본 채널로 사용한다.
6. **실행 경로와 감사 경로의 분리 및 출력 삼분 (Audit ≠ Ops Log ≠ CLI Output)**: 감사(`audit.jsonl`), 운영 로그(`stderr`), 사용자 친화적 설명 출력(`stdout`)은 목적·스키마·출력 스트림이 완전히 분리된다.

## 10) 권한 모델 (Authorization & Permission Model)
### 권한의 기본 단위 (5-Tuple Context)
* **Subject (`sub`)**: 권한을 행사하는 주체 (`orchestrator-main`, `subagent-reader-01` 등).
* **Actor (`act`)**: 위임 체인에서 상위 권원을 위임한 부모 주체 정보 (`parent_sub`, `parent_jti`, `delegation_depth`).
* **Action (`action`)**: `file:read` (파일 내용 읽기), `file:write` (파일 생성/덮어쓰기).
* **Resource (`resource`)**: Workspace Root 기준의 정규화된 논리적 상대 경로 (예: `docs/plan.txt`).
* **Security Epoch & Grant State**: 주체별 일괄 철회 버전(`epoch`) 및 개별 Grant 레코드의 활성 상태(`active` vs `revoked`).

### 최종 허용 불변식 (Master Allow Invariant — Phase 0~17 통합 9대 조건)
요청이 최종 허용(`ALLOW`, `EXIT_SUCCESS = 0`)되어 실제 도구 I/O가 집행되려면 다음 9가지 조건이 동시에 참(True)이어야 한다:
1. **토큰 무결성 및 수명 유효 (Gate 1)**: `typ == "at+jwt"`, 허용된 `alg`, 활성 또는 `verify-only` 상태인 `kid` 서명 일치, $iat \le now < exp$, 올바른 `iss` 및 `aud`.
2. **주체 바인딩 및 비재사용 (Gate 1 & Pre-Commit)**: 토큰의 `sub`가 실행 주체와 일치하며, 일회성 토큰인 경우 `jti`가 Replay 원장에 소비되지 않은 상태(단, Gate 2에서 `DecisionAsk(18)` 반환 시에는 재시도를 위해 `jti`를 소진하지 않음).
3. **본인 및 다단계 위임(`act`) 조상 계보 전원의 Security Epoch 일치 (Gate 2 — Phase 01 & 13)**: 토큰의 `epoch`가 해당 주체의 현재 `CurrentEpoch`와 일치할 뿐 아니라, `act` 위임 체인의 모든 상위 조상(`ActorClaim`)에 기록된 `Epoch`가 각 조상의 현재 `SubjectEpochs[ancestor]`와 **일치**해야 하며 고리 Epoch가 1 미만이면 거부함(상위 에이전트 Epoch 갱신 시 하위 위임 트리 전체 즉시 차단).
4. **Scope 포함 (Gate 2 — Phase 01 & 16)**: 토큰의 `scope` 클레임이 요청된 `(action, resource)`(2단 또는 3단 스코프)를 포함.
5. **실시간 활성 Grant 존재 (Gate 2)**: PIP에서 조회한 중앙 상태 저장소에 `(sub, action, resource)`에 대한 `active`(Revoke되지 않은) Grant가 존재.
6. **예산(Budget) 잔량 충분 (PEP `StageBudget`·읽기 직후 — Phase 12)**: 토큰에 `Budget`이 설정된 경우 Zone B 예산 원장(`budget_ledger.json`)의 잔여 호출 횟수·읽기/쓰기 바이트가 충분하고 PEP의 원자적 차감(`Consume`: 쓰기는 사전 차감, 읽기는 `ReadFile` 직후 사후 차감)을 통과함. PDP·PIP는 예산을 판정하지 않음.
7. **고위험 작업 사람 승인(`RequiresApproval`) 충족 및 5요소 바인딩 일치 (Gate 2 & Pre-Commit — Phase 15)**: 매칭된 Grant가 `RequiresApproval == true`인 경우, `(sub, action, resource, token_jti)` 4요소와 (`ArgHash != ""` 지정 시) 5번째 실행 인자 해시(`sha256(req.Data)`)까지 일치하는 미소비·미만료 승인이 존재하고 `ConsumeMatching` 원자적 1회 소비를 통과함(미충족 시 `DecisionAsk`, `ExitApprovalRequired = 18`).
8. **도구별 실행 경계(Boundary) 검증 통과 (Gate 2c — Phase 03 & 16)**: `file:*`는 Workspace Jail 내부 경로(`ResolvePath`), `net:fetch`는 루프백 리터럴 및 허용 포트(`netguard`), `exec:run`은 허용 바이너리 ID 및 인자 정규식(`execguard`) 검증을 통과함.
9. **사전 커밋 감사(Pre-Commit Audit) 기록 성공 (Stage 4)**: I/O 실행 직전 `audit.jsonl`에 사전 커밋 이벤트 기록이 성공함(실패 시 차감된 예산을 즉시 `Refund`하고 I/O 진입 없이 `ExitAuditFailure = 15`로 중단).

## 11) 토큰 / OAuth 2.1 범위 (채택 부분집합과 의도적 생략)
### 채택하는 OAuth 2.1 및 표준 프로파일 핵심 요소
1. **클라이언트 워크로드 인증 (Client AuthN)**: 오케스트레이터가 토큰을 발급·교환받을 때 등록된 `client_id`와 `client_secret`을 검증하며, 미등록·시크릿 불일치·정지된(`suspended`) 클라이언트를 차단한다.
2. **Bearer Access Token & [RFC 9068](https://www.rfc-editor.org/info/rfc9068/) 프로파일**: 헤더에 `typ: at+jwt`와 `kid`를 강제하고, `alg: none` 및 알고리즘 혼동 공격([RFC 8725](https://www.rfc-editor.org/info/rfc8725/))을 원천 차단한다.
3. **서명 키 수명주기 ([RFC 7517](https://www.rfc-editor.org/info/rfc7517/) JWK Key Ring)**: `active`(서명+검증), `verify-only`(검증만 허용 — 무중단 키 회전용), `retired/revoked`(즉시 거부)의 3단계 키 상태를 지원한다.
4. **필수 클레임 구성**: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `client_id`, `scope`, `epoch`, `one_time`, 그리고 위임 시 포함되는 `act`(`parent_sub`, `parent_jti`, `depth`).

### 세분화된 토큰/인증 검증 실패 코드 (`EXIT_TOKEN_INVALID = 11`)
* 클라이언트 인증 실패: `AUTHN_UNKNOWN_CLIENT`, `AUTHN_INVALID_SECRET`, `AUTHN_CLIENT_SUSPENDED`
* 토큰 구조/헤더 실패: `TOKEN_MISSING`, `TOKEN_MALFORMED`, `TOKEN_INVALID_TYPE`, `TOKEN_ALG_NOT_ALLOWED`
* 암호학적 키/서명 실패: `TOKEN_UNKNOWN_OR_RETIRED_KEY`, `TOKEN_INVALID_SIGNATURE`
* 시간/클레임/바인딩 실패: `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`, `TOKEN_INVALID_ISS_AUD`, `TOKEN_SUBJECT_MISMATCH`, `TOKEN_REPLAY_DETECTED`

### 의도적 생략 항목과 근거
* **브라우저 리다이렉트(Authorization Code UI) 및 동의 화면 생략**: 인간 사용자의 웹 로그인이 아닌 에이전트 간 프로그래밍 방식 인가 하네스이므로 생략한다.
* **장기 Refresh Token 생략**: 단기 과업 수행 후 종료되는 서브프로세스 특성상 단기 Access Token과 즉시 교환(Token Exchange)만으로 목적을 달성한다.

## 12) 위임 모델 (팀장 → 서브에이전트 [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) Downscoping)
1. **비소유 조정자 원칙**: 오케스트레이터(팀장)는 Zone A의 개인 서명 키에 접근할 수 없으며 스스로 토큰을 만들 수 없다. 반드시 중앙 토큰 서비스(STS)에 자신의 부모 토큰(`subject_token`)을 제시하고 토큰 교환(`token exchange`)을 요청해야 한다.
2. **Scope 단조 축소 불변식 ($S_{child} \subseteq S_{parent}$)**: 자식 토큰으로 요청된 Scope가 부모 토큰의 Scope를 하나라도 벗어나면 중앙 서버가 `DELEGATION_SCOPE_ESCALATION`으로 즉시 발급을 거부한다.
3. **수명 단조 축소 불변식 ($exp_{child} \le exp_{parent}$)**: 자식 토큰의 요청 만료 시각이 부모 토큰의 남은 만료 시각을 초과하면 `DELEGATION_TTL_EXCEEDED`로 거부한다.
4. **위임 깊이 제한 (`delegation_depth <= max_depth`)**: `act` 클레임 내 `depth`를 추적하여 허용된 위임 단계(기본 1단계: Orchestrator → Subagent)를 초과하는 다단계 무단 재위임을 `DELEGATION_DEPTH_EXCEEDED`로 차단한다.

## 13) 실행 모델 (CLI, 서브프로세스, 토큰 전달 방식, 종료 코드 규약)
### 서브프로세스 격리 및 토큰 전달 채널
* 서브에이전트는 고루틴이 아닌 독립된 **OS 서브프로세스**로 구동된다.
* **기본 전달 채널 (`stdin` 파이프 단일 JSON 프레임)**: 부모 환경변수(`os.Environ()`) 자동 상속을 차단하고, `stdin` 파이프로 토큰·`trace_id`·요청 파라미터를 담은 프레임을 전달한 뒤 즉시 닫는다. (단, 비교 테스트를 위해 `--token-channel env|file|arg` 옵션을 시뮬레이션 스위치로 지원한다.)

### 표준 종료 코드(Exit Code) 규약
| 종료 코드 상수명 | 코드 번호 | 의미 및 발생 관문 | 대표 사유 코드 (`Reason`) |
| :--- | :---: | :--- | :--- |
| **`EXIT_SUCCESS`** | `0` | 인가 허용 및 파일 I/O 정상 완료 | `AUTHORIZED` |
| **`EXIT_TOKEN_INVALID`** | `11` | **Gate 1 (AuthN & Token)** 검증 실패 | `TOKEN_MISSING`, `TOKEN_INVALID_SIGNATURE`, `TOKEN_EXPIRED`, `TOKEN_KEY_RETIRED`, `TOKEN_REPLAY_DETECTED` 등 |
| **`EXIT_AUTHZ_DENIED`** | `12` | **Gate 2 (PDP & Delegation)** 인가/위임 거부 | `NO_ACTIVE_GRANT`, `GRANT_REVOKED`, `SUBJECT_EPOCH_REVOKED`, `TOKEN_INSUFFICIENT_SCOPE`, `DELEGATION_SCOPE_ESCALATION` 등 |
| **`EXIT_PATH_VIOLATION`** | `13` | **Gate 2c (PEP & Jail)** 경로 격리 위반 | `PATH_TRAVERSAL_DETECTED`, `PATH_OUTSIDE_WORKSPACE`, `SYMLINK_ESCAPE_DETECTED` |
| **`EXIT_BAD_INPUT`** | `14` | **Stage 0** 입력/컨텍스트 누락 오류 | `MISSING_TRACE_CONTEXT`, `UNSUPPORTED_ACTION`, `MALFORMED_CLI_ARGS` |
| **`EXIT_AUDIT_FAILURE`** | `15` | **Stage 4/5** 감사 기록 실패 또는 무결성 파손 | `AUDIT_WRITE_FAILED`, `AUDIT_INTEGRITY_BROKEN`, `AUDIT_TRUNCATION_DETECTED` |
| **`EXIT_INTERNAL_ERROR`** | `16` | 예기치 않은 런타임/시스템 내부 오류 및 격리 불가 | `INTERNAL_RUNTIME_ERROR`, `STATE_LOCK_TIMEOUT`, `CONFINEMENT_UNAVAILABLE` |
| **`EXIT_RESOURCE_LIMIT`** | `17` | **Phase 10** 부모 스포너가 강제한 자원·수명 한계 초과 (원인 불명 종료는 `16` + `SUBPROCESS_ABNORMAL_EXIT`) | `RESOURCE_TIMEOUT`, `RESOURCE_OUTPUT_LIMIT` |
| **`EXIT_APPROVAL_REQUIRED`** | `18` | **Phase 15** Gate 2 사람 승인 필요(`ask`) 및 승인 불일치/만료 | `APPROVAL_REQUIRED`, `APPROVAL_EXPIRED`, `APPROVAL_MISMATCH` |

## 14) 파일 접근 모델 (Workspace Jail, Read/Write, 경로 규칙)
* **허용 작업**: Workspace Root(`./workspace`) 내부 파일에 대한 `file:read` 및 `file:write`만 허용하며, 삭제·실행·권한 변경·네트워크 접근은 배제한다.
* **다중 방어 경로 검증 (`internal/jail`)**:
  1. 단순 문자열 Prefix 비교(`strings.HasPrefix`)를 금지한다(`/workspace` vs `/workspace-evil` 착시 방지).
  2. 경로 정규화(`filepath.Clean`) 후 Workspace Root 기준 상대 경로(`filepath.Rel`)가 `..`로 시작하거나 루트 자체를 덮어쓰려 하면 `PATH_TRAVERSAL_DETECTED` 또는 `PATH_OUTSIDE_WORKSPACE`로 차단한다.
  3. 심볼릭 링크를 실제 물리 경로로 해석(`EvalSymlinks`)한 뒤에도 최종 경로가 Workspace Root 내부에 속하는지 재검증하여 심볼릭 링크 탈출(`SYMLINK_ESCAPE_DETECTED`)을 원천 차단한다.

## 15) 감사(Audit) 모델 (시계열/Trace, 해시 체인, 운영 로그와의 분리)
* **독립 배선 및 원시 토큰 비노출 원칙**: 감사는 운영 로그 레벨(`--ops-log-level none`)과 무관하게 항상 `./audit.jsonl`에 기록되며, 보안상 원시 토큰 문자열이나 시크릿은 절대 기록하지 않고 오직 `token_jti`만 기록한다.
* **표준 감사 스키마 필드**: `timestamp`, `trace_id`, `span_seq`, `event_type`(`step`), `actor`, `subject`(`agent_id`), `delegator`(`act`), `action`, `resource`, `decision`(`allow|deny|n/a`), `reason`, `token_jti`, `kid`, `epoch`, `success`, `error_class`, `prev_hash`, `curr_hash`.
* **필수 기록 시점**: `grant.created`, `grant.revoked`, `epoch.bumped`, `key.rotated`, `key.revoked`, `token.issued`, `token.exchanged`, `token.issue_denied`, `agent.start`, `pdp.decide`, `pep.allow`, `pep.deny`, `agent.exit`, `scenario.pass`, `scenario.fail`.
* **변조 방지 해시 체인(Hash Chain)**: 각 레코드는 직전 레코드의 SHA-256 해시(`prev_hash`)를 포함하여 `curr_hash`를 계산하며, `audit verify` 명령을 통해 사후에 단 1글자의 수정이나 줄 삭제도 즉시 적발(`AUDIT_INTEGRITY_BROKEN`)한다.

## 16) 운영 로그 모델 및 초보자 친화적 CLI 출력 모델 (삼분 구조)
| 구분 | 감사 로그 (`./audit.jsonl`) | 운영 로그 (`stderr` - `log/slog`) | CLI 사용자 출력 (`stdout` - `internal/ui`) |
| :--- | :--- | :--- | :--- |
| **핵심 목적** | 보안 통제 및 인가 결정의 **불변 증거 증명** | 시스템 내부 동작 **디버깅 및 런타임 진단** | **초보자도 한눈에 이해하는 관문 진행 상태 및 검증 리포트** |
| **핵심 기능** | 해시 체인 무결성 검증(`audit verify`), `trace_id` 상관관계 | 로그 레벨 필터링, 민감 토큰 자동 마스킹 | **6단계 관문 파이프라인 뷰**, 부정 테스트 역설 해설 박스, **`audit timeline` 시계열 스토리텔링 뷰** |

## 17) 실패·부정 시나리오 및 30대 전 구간 E2E 카탈로그
기본 로드맵의 17개 실패 요소를 엔터프라이즈 인증(AuthN), 키 수명주기, RFC 8693 위임, 재사용(Replay) 방어, 심볼릭 링크 탈출, 감사 해시 체인 검증까지 포괄하는 **7개 그룹 30개 표준 E2E 시나리오(E2E-01 ~ E2E-30)**로 통합한다.

* **그룹 G1 (기본 생명주기, E2E-01 ~ E2E-03)**: 단일 읽기 성공(`E2E-01`), 단일 쓰기 성공(`E2E-02`), 단일 Trace 내 `[Grant 전 거부 → Grant 후 성공 → Revoke 후 즉시 거부]` 동적 전환(`E2E-03`).
* **그룹 G2 (워크로드 AuthN, E2E-04 ~ E2E-06)**: 미등록 클라이언트 거부(`E2E-04`), 잘못된 클라이언트 시크릿 거부(`E2E-05`), 정지된(Suspended) 클라이언트 거부(`E2E-06`).
* **그룹 G3 (토큰 무결성 & 키 관리, E2E-07 ~ E2E-13)**: 토큰 누락(`E2E-07`), 형식 파손(`E2E-08`), 페이로드 Scope 변조(`E2E-09`), `alg: none` 공격(`E2E-10`), `typ != at+jwt` 불일치(`E2E-11`), 서명 키 무중단 회전(`key-v1` → `key-v2`, `E2E-12`), 폐기된 서명 키(`retired`) 즉시 거부(`E2E-13`).
* **그룹 G4 (시간·클레임·바인딩·Replay, E2E-14 ~ E2E-18)**: 만료된 토큰(`E2E-14`), 미래 발급/활성 토큰(`E2E-15`), `iss`/`aud` 불일치(`E2E-16`), 타 주체 토큰 도용(`sub` 불일치, `E2E-17`), 일회성 토큰 재사용(`jti` Replay, `E2E-18`).
* **그룹 G5 (RFC 8693 위임 & PDP, E2E-19 ~ E2E-24)**: 팀장 권한 초과 위임 시도(`E2E-19`), 팀장 수명 초과 위임 시도(`E2E-20`), 최대 위임 깊이(`depth`) 초과(`E2E-21`), 축소된 Read 자식 토큰으로 Write 시도(`E2E-22`), 미허가 리소스 경로 접근(`E2E-23`), Subject Epoch 증가를 통한 일괄 철회(`E2E-24`).
* **그룹 G6 (파일 Jail & 경로 보안, E2E-25 ~ E2E-27)**: 상대 경로 탈출(`../../etc/passwd`, `E2E-25`), 절대 경로 및 루트 접두사 착시(`/workspace-evil`, `E2E-26`), 심볼릭 링크 외부 탈출(`E2E-27`).
* **그룹 G7 (관측성·감사 Fail-Closed·무결성, E2E-28 ~ E2E-30)**: `trace_id` 누락 차단(`E2E-28`), 감사 기록 실패 시 파일 I/O 중단(Fail-Closed, `E2E-29`), 사후 감사 파일 변조 시 `audit verify` 해시 체인 적발(`E2E-30`).

## 18) 검증 전략 (5계층 테스트 피라미드 및 CLI 시뮬레이션 제어)
### 1. 5계층 검증 피라미드 (5-Tier Testing Pyramid)
* **L1 (Deterministic Unit Tests)**: `go test ./internal/...` — 외부 I/O 없이 클레임 경계값, Downscoping 부분집합 불변식, 순수 PDP 결정표, 경로 정규화 로직을 테이블 주도 테스트로 1초 내 검증.
* **L2 (Security Fuzzing)**: `go test -fuzz=Fuzz...` — `FuzzPathJail`, `FuzzTokenParser`, `FuzzScopeParser`를 통해 기형적 입력에서 패닉 0건 및 Jail 외부 허용 0건 보장.
* **L3 (Integration, Concurrency & Simulated Clock)**: `go test -race ./...` — 동시 Revoke/I/O 경합(TOCTOU), 다중 프로세스 `audit.jsonl` 동시 Append, 가상 시계(`--clock-offset`) 기반 즉시 만료 전이 검증.
* **L4 (Black-Box CLI Contract & Golden Tests)**: 컴파일된 바이너리의 Exit Code(`0`, `11`~`16`), 3채널(`stdout`/`stderr`/`audit.jsonl`) 격리, 초보자용 `explain` 및 `timeline` 골든 출력 검증.
* **L5 (Full E2E Scenario Harness)**: `authz-harness run --scenario all` — 30개 시나리오 전 구간 실행 및 **4중 검증(Exit Code + 파일 무변화/일치 + 감사 사유 코드 + 해시 체인 무결성)**.

### 2. 전수 테스트를 위한 8대 CLI 명령 그룹 및 결함 주입(Fault Injection) 백로그
* **전역 옵션**: `--workspace-dir`, `--state-dir`, `--audit-file`, `--ops-log-level`, `--output-format (pretty|explain|json|compact)`, `--trace-id`, `--clock-offset`, `--fail-audit-mode`.
* **8대 명령 그룹**: `env (init/reset)`, `keys (list/rotate/revoke)`, `grant (create/revoke/list/inspect)`, `token (issue/exchange/inspect/tamper)`, `pdp (decide/explain)`, `pep (read/write)`, `orchestrate (spawn)`, `audit (show/timeline/verify)` 및 `run (--scenario <id|all>)`.
* **공격·결함 주입 플래그**: `--tamper-payload-scope`, `--tamper-alg-none`, `--tamper-typ`, `--tamper-kid`, `--inject-missing-trace`, `--inject-audit-failure`, `--inject-symlink-escape`, `--inject-revoke-before-io`.

## 19) Phase 로드맵 (Phase 0 .. Phase 6) 및 후속 에이전트 인계 계약

### Phase 0: 기반 골격, 6계층 구조, 가상 시계 및 삼분(Audit / OpsLog / UI) 배선 구축
* **목적**: 비즈니스 로직 구현 전에 6계층 패키지 구조를 확립하고, `Clock`/`trace_id` 전파 체계와 해시 체인 기반 JSONL Audit Writer, `slog` 운영 로거, 초보자용 UI 출력 배선을 물리적으로 분리한다.
* **진입 조건**: 프로젝트 초기 상태.
* **포함 능력 매핑**: `골격/CLI/감사 writer` (Layer 0, Layer 1, Layer 5 기본 골격)
* **완료 조건 (관찰 가능한 행동)**:
  1. `env init/reset` 및 기본 CLI 라우팅이 작동하고, 표준 종료 코드(`0`, `11`~`16`)로 종료됨을 확인할 수 있다.
  2. 명령 실행 시 `trace_id`가 생성되고, `stdout`(UI), `stderr`(운영 로그), `audit.jsonl`(해시 체인 감사 로그)이 섞이지 않고 각각 기록된다.
  3. `audit timeline` 및 `audit verify` 실행 시 시계열 출력이 정상 렌더링되고, 파일 임의 수정 시 `AUDIT_INTEGRITY_BROKEN(15)`으로 변조가 탐지된다.
* **주요 산출물**: Layer 0(`domain`, `clock`, `trace`), Layer 1(`audit`, `opslog`), Layer 5(`cmd`, `ui` 기본 포매터), L1 기반 단위 테스트.
* **의존성 / 금지 결합**: 의존성 없음. `audit`와 `opslog`가 출력 스트림을 공유하는 것 절대 금지.
* **리스크**: 다중 프로세스가 동시에 `audit.jsonl`에 쓸 때 해시 체인이 깨지지 않도록 `flock` 기반 직렬화를 Phase 0에서 반드시 구현해야 함.
* **데모 한 줄**: `"CLI 명령 한 번으로 고유 trace_id가 발급되고 해시 체인으로 보호되는 JSONL 감사 파일에 기록되며, 1글자만 수정해도 audit verify가 즉시 변조를 잡아낸다."`

### Phase 1: PAP/PIP/PDP 권한 코어 및 실시간 Revoke/Epoch 구현
* **목적**: Zone B 상태 저장소(`grants_state.json`)를 관리하는 PAP, 실시간 상태를 공급하는 PIP, 그리고 파일 I/O 의존성이 0%인 순수 결정 엔진 PDP를 구축한다.
* **진입 조건**: Phase 0 완료.
* **포함 능력 매핑**: `grant-revoke-PDP` (Layer 2B: `authz/pap`, `authz/pip`, `authz/pdp`)
* **완료 조건 (관찰 가능한 행동)**:
  1. Grant 생성 전 `pdp decide` 질의 시 `DENY (NO_ACTIVE_GRANT)`가 반환되고 감사에 기록된다.
  2. `grant create` 직후 동일 질의 시 `ALLOW (AUTHORIZED)`가 반환된다.
  3. `grant revoke` 또는 `--bump-epoch` 직후 동일 질의 시 즉시 `DENY (GRANT_REVOKED / SUBJECT_EPOCH_REVOKED)`가 반환되고 초보자용 `pdp explain` 뷰에 차단 사유가 출력된다.
* **주요 산출물**: 원자적 파일 락 기반 Grant/Epoch 저장소, PAP/PIP/PDP 모듈, `grant` 및 `pdp` CLI 명령, L1 PDP 결정표 단위 테스트.
* **의존성 / 금지 결합**: Phase 0 의존. **`internal/authz/pdp`가 OS 파일 I/O나 `internal/jail`을 참조하는 것 절대 금지.**
* **리스크**: 프로세스 간 상태 공유 시 반쯤 쓰인 JSON을 읽지 않도록 Atomic Rename + Advisory Lock 적용 필수.
* **데모 한 줄**: `"권한 부여 전 거부 → 부여 후 허용 → 회수(Revoke) 직후 즉시 거부가 순수 PDP 시뮬레이션과 초보자용 해설 뷰로 즉시 증명된다."`

### Phase 2: 워크로드 AuthN, JWK 키 수명주기(`kid`) 및 RFC 8693 축소 위임 구현
* **목적**: 클라이언트 인증, [RFC 9068](https://www.rfc-editor.org/info/rfc9068/) `at+jwt` 발급·검증, [RFC 7517](https://www.rfc-editor.org/info/rfc7517/) 키 회전·폐기, [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) 축소 위임 교환(`act` 클레임), 일회성 `jti` Replay 차단을 완성한다.
* **진입 조건**: Phase 1 완료.
* **포함 능력 매핑**: `token issue-validate` (Layer 2A: `internal/authn`, Zone A/B 키 분리)
* **완료 조건 (관찰 가능한 행동)**:
  1. 미등록/잘못된 시크릿 클라이언트의 토큰 발급 요청이 `AUTHN_*` 사유로 거부된다.
  2. `keys rotate` 시 기존 키(`verify-only`) 토큰이 유지되다가, `keys revoke`(`retired`) 즉시 기존 미만료 토큰이 `TOKEN_KEY_RETIRED`로 거부된다.
  3. 오케스트레이터가 자신의 Scope/TTL 이내로 요청한 자식 토큰(`token exchange`)은 `act` 클레임을 담아 정상 발급되지만, 권한/수명/깊이 초과 요청은 `DELEGATION_*` 사유로 즉시 거부된다.
  4. `--clock-offset` 및 `--tamper-*` 스위치로 만료·변조·`alg: none`·`typ` 불일치·Replay 공격이 각각 정확한 사유 코드로 차단된다.
* **주요 산출물**: Client Registry, JWK Key Ring, Token Service & Verifier, Replay Ledger, `keys` 및 `token` CLI 명령, L1/L2(`FuzzTokenParser`) 테스트.
* **의존성 / 금지 결합**: Phase 0, 1 의존. 하위 워커가 Zone A 개인키 파일에 접근하거나 로그에 원시 JWT를 남기는 것 금지.
* **리스크**: 시간 경계값($now == exp$) 처리 불일치 방지를 위해 주입된 `Clock` 인터페이스만 사용해야 함.
* **데모 한 줄**: `"팀장의 초과 위임 시도는 발급 단계에서 차단되고, 정상 발급된 토큰도 서명 변조·만료·키 폐기·재사용 시 Gate 1에서 정확한 사유로 차단된다."`

### Phase 3: PEP 집행 게이트웨이 및 Workspace File Jail 구현
* **목적**: Gate 1(AuthN)과 Gate 2(PDP)를 통과한 요청에 한해 경로 정규화 및 심볼릭 링크 검증을 수행하고 안전하게 파일 읽기/쓰기를 집행하는 PEP와 Jail을 구축한다.
* **진입 조건**: Phase 2 완료.
* **포함 능력 매핑**: `PEP+file jail` (Layer 2C: `internal/jail`, Layer 3: `internal/authz/pep`)
* **완료 조건 (관찰 가능한 행동)**:
  1. 유효한 토큰과 활성 Grant가 있을 때만 `pep read/write`가 성공하고 Workspace 내부 파일이 읽히거나 기록된다.
  2. `../../etc/passwd`, `/etc/hosts`, `/workspace-evil/a.txt`, 외부 대상 심볼릭 링크 접근 시 파일 I/O 발생 전에 `EXIT_PATH_VIOLATION(13)`으로 차단된다.
  3. `--inject-audit-failure` 주입 시 인가가 허용이어도 파일 쓰기가 중단되고 `EXIT_AUDIT_FAILURE(15)`를 반환한다(Fail-Closed).
* **주요 산출물**: `WorkspaceJail` 모듈, `PEP` 게이트웨이, `pep` CLI 명령, L1/L2(`FuzzPathJail`) 퍼징 테스트.
* **의존성 / 금지 결합**: Phase 1, 2 의존. PEP가 PDP 호출을 생략하거나 감사 실패를 무시하고 파일을 여는 것 금지.
* **리스크**: 심볼릭 링크가 가리키는 대상이 아직 존재하지 않는 파일(쓰기 요청)일 때 부모 디렉토리 기준 `EvalSymlinks` 검증을 수행해야 우회를 막을 수 있음.
* **데모 한 줄**: `"유효한 토큰을 가졌더라도 ../나 심볼릭 링크로 Workspace 밖을 건드리려 하면 파일이 열리기 전에 PEP에서 즉시 차단된다."`

### Phase 4: 오케스트레이터 서브프로세스 생성(Spawn) 및 서브에이전트 격리 실행
* **목적**: 오케스트레이터가 축소 토큰을 교환받아 독립된 OS 자식 프로세스로 서브에이전트를 실행하고, `stdin` 프레임으로 토큰과 `trace_id`를 전달한 뒤 종료 코드를 수거하는 전체 실행 사슬을 완성한다.
* **진입 조건**: Phase 3 완료.
* **포함 능력 매핑**: `orchestrator spawn+subagent process` (Layer 4: `internal/orchestrator`, `internal/subagent`)
* **완료 조건 (관찰 가능한 행동)**:
  1. `orchestrate spawn` 실행 시 별도 PID를 가진 OS 자식 프로세스가 생성되며 부모의 `trace_id`가 자식 감사 이벤트까지 하나의 체인으로 이어진다.
  2. 자식 프로세스는 Zone A 개인키에 접근하지 않으며, 권한 거부/토큰 무효/경로 위반 시 정확한 Exit Code(`11`~`15`)로 종료되고 부모가 이를 수집한다.
  3. `--inject-revoke-before-io` 및 `go test -race` 실행 시 토큰 발급 직후 파일 열기 직전에 Revoke가 일어나도 즉시 차단되며 Data Race가 발생하지 않는다.
* **주요 산출물**: 오케스트레이터 Spawner, `stdin` JSON 프레임 프로토콜, 서브에이전트 워커 모드, L3(`-race`) 동시성 통합 테스트.
* **의존성 / 금지 결합**: Phase 0 ~ 3 의존. 서브에이전트를 고루틴으로 실행하거나 원시 `os.Open`을 직접 호출하는 것 금지.
* **리스크**: 자식 프로세스의 `stdout`/`stderr`와 부모의 출력이 섞이지 않도록 파이프 캡처 및 구조화된 결과 수집 설계 필요.
* **데모 한 줄**: `"팀장이 축소 토큰을 담아 독립된 OS 자식 프로세스를 띄우고, 권한 회수나 위조 시 자식 프로세스가 정확한 종료 코드로 죽는 것을 부모가 확인한다."`

### Phase 5: 30대 E2E 시나리오 테스트 하네스(`run --scenario all`) 및 설명 UX 완성
* **목적**: 7개 그룹 30개 전 구간 E2E 시나리오(E2E-01 ~ E2E-30)를 단일 명령으로 실행하고, 4중 검증(Exit Code + 파일 상태 + 감사 사유 + 해시 체인)과 초보자용 시각적 관문 파이프라인 뷰를 완성한다.
* **진입 조건**: Phase 4 완료.
* **포함 능력 매핑**: `scenario harness` (Layer 5: `internal/harness`, `internal/ui` 고도화)
* **완료 조건 (관찰 가능한 행동)**:
  1. `authz-harness run --scenario all` 실행 시 30개 긍정·부정 시나리오가 격리된 상태로 실행되고 전 항목 `PASS` 요약 표와 함께 종료 코드 `0`을 반환한다.
  2. `--output-format explain` 및 `audit timeline` 실행 시 초보자도 이해할 수 있는 6단계 관문 통과/차단 상태도와 한국어 원리 해설이 출력된다.
  3. L4 블랙박스 CLI 계약 및 골든 파일 테스트가 100% 통과한다.
* **주요 산출물**: 30대 시나리오 카탈로그 러너, Quad-Assertion 검증 엔진, 초보자용 Explain/Timeline 포매터, L4/L5 테스트 스위트.
* **의존성 / 금지 결합**: Phase 0 ~ 4 의존. 시나리오 간 잔여 상태 오염 방치 금지.
* **리스크**: 시나리오 실행 속도를 높이기 위해 각 시나리오는 대기 시간(`sleep`) 대신 가상 시계 오프셋과 결정론적 훅을 사용해야 함.
* **데모 한 줄**: `"run --scenario all 명령 한 줄로 30가지 엔터프라이즈 인증·인가·위임·경로·감사 공격 시나리오가 자동 실행되고 전 항목 방어 성공(PASS)이 증명된다."`

### Phase 6: 문서화, 아키텍처 다이어그램 및 포트폴리오 패키징
* **목적**: 면접관과 외부 리뷰어가 리포지토리를 클론한 뒤 1분 안에 아키텍처 의도와 30대 시나리오 검증 결과를 재현할 수 있도록 최종 패키징한다.
* **진입 조건**: Phase 5 완료.
* **포함 능력 매핑**: `문서/포트폴리오 포장`
* **완료 조건 (관찰 가능한 행동)**:
  1. `README.md`에 1분 퀵스타트, 3-Zone 토폴로지, 6계층 DAG, 6단계 관문 상태 머신, 30대 시나리오 요약표, 샘플 출력 화면이 완비된다.
  2. 클린 환경에서 `go test -race ./...`와 `authz-harness run --scenario all`이 1분 이내에 무결하게 통과한다.
* **주요 산출물**: 최종 `README.md`, 면접 데모 치트시트, 전 계층 테스트 검증 완료 리포지토리.
* **의존성 / 리스크**: Phase 5 의존. 구현된 동작과 문서 설명 간의 수치/옵션명 불일치 제로(0)화.
* **데모 한 줄**: `"문서의 명령 한 줄만 복사해 실행하면 엔터프라이즈 권한 분리 아키텍처와 30개 부정 테스트 통과 결과가 눈앞에 재현된다."`

### Phase 7: 도메인 보호, 의존성 역전(DIP) 및 단일입출구(SESE) 감사 배선 고도화
* **목적**: 12대 안티패턴을 전수 제거하고, 순수 도메인 보호, SESE 단일 입출구 이벤트 감사 파이프라인, 결함 주입 데코레이터 격리, 엄격한 4중 검증을 완성한다.
* **진입 조건**: Phase 6 완료.
* **포함 능력 매핑**: `도메인 보호 / SESE 파이프라인 / 엔터프라이즈 리팩토링`
* **주요 산출물**: [07-도메인보호-및-단일입출구-배선-고도화](07-도메인보호-및-단일입출구-배선-고도화/README.md), AST 가드레일 4종.

### Phase 8: 서브프로세스 전 구간 E2E 통합 및 다단계(Multi-Hop) 프로세스 위임 실증 [완료]
* **목적**: 30대 카탈로그의 실제 OS 서브프로세스 격리 실행 모드(`--execution-mode subprocess`) 전면 도입, 루트→중간자→워커 2-Hop 다단계 위임 시나리오(`E2E-31`, `E2E-32`), 프로세스 계보 및 시계열 감사 시각화(`audit timeline`)를 완성한다.
* **진입 조건**: Phase 7 완료.
* **포함 능력 매핑**: `OS 서브프로세스 통합 / RFC 8693 다단계 위임 / 시계열 타임라인 관측성`
* **완료 조건 (관찰 가능한 행동)**:
  1. `authz-harness run --scenario all`이 기본 서브프로세스 모드에서 32/32 Quad-Assertion PASS를 달성한다. [완료]
  2. `authz-harness audit timeline --trace-id <id>` 실행 시 프로세스 계보 트리와 시계열 파이프라인이 터미널에 시각화된다. [완료]
  3. `internal/app/builder.go` 단일 합성 루트로 스택 조립이 일원화되고 Control Plane 감사 에러 무시 잔재가 전면 제거된다. [완료]
* **주요 산출물**: [08-서브프로세스-전구간-e2e-통합-및-다단계-위임-실증](08-서브프로세스-전구간-e2e-통합-및-다단계-위임-실증/README.md), `internal/app/builder.go`, `internal/storage/atomic.go`, `internal/orchestrator/multi_hop.go`, `internal/ui/timeline.go`.
* **데모 한 줄**: `"단일 명령으로 실제 격리된 OS 서브프로세스 3대의 다단계 권한 축소 사슬과 실시간 차단 과정을 시계열 타임라인으로 눈앞에 증명한다."`

### Phase 9: 다중 에이전트(MCP / Tool-Call) 보안 게이트웨이 어댑터 [완료]
* **목적**: 외부 LLM/에이전트 프레임워크와의 표준 연결 규격인 MCP stdio JSON-RPC 2.0 보안 게이트웨이(`authz-harness mcp serve`)를 제공하고, 격리된 OS 서브프로세스 도구 집행, Zero Leakage 토큰 비노출 및 G8 카탈로그(`E2E-33`~`39`) 총 39대 완주를 달성한다.
* **진입 조건**: Phase 8 완료.
* **포함 능력 매핑**: `MCP 호환 프로토콜 / stdio JSON-RPC 2.0 / Zero Leakage 토큰 비노출 / G8 E2E 39대 완결`
* **완료 조건 (관찰 가능한 행동)**:
  1. `mcp serve`를 통해 `tools/list`, `tools/call` 명령이 위임 토큰과 함께 서브프로세스 PEP로 안전 집행된다. [완료]
  2. 어댑터 프로세스 자체의 파일 I/O 0건 및 감사/로그 내 원시 토큰 유출 0건(`TC-090-01`)을 보장한다. [완료]
  3. 39대 전체 시나리오 Quad-Assertion 100% 통과(`PASS`)를 달성한다. [완료]
* **주요 산출물**: [09-mcp-tool-call-보안-게이트웨이-어댑터](09-mcp-tool-call-보안-게이트웨이-어댑터/README.md), `internal/mcp`, `internal/cli/mcp.go`, `internal/harness/catalog/g8_mcp.go`.
* **데모 한 줄**: `"표준 MCP 프로토콜 도구 호출 요청이 격리된 서브프로세스 보안 게이트웨이를 거치며 권한 축소와 감사 해시 체인이 완결된다."`

### Phase 10: 서브프로세스 자원·수명 통제 (`G9`: `E2E-40`~`E2E-44`) [완료]
* **목적**: 허가받은 워커가 무한 루프에 빠지거나 손자 프로세스를 남기거나 대량 출력을 쏟아낼 때, 프로세스 그룹(`Setpgid`, `-pgid` 시그널) 일괄 소멸, `WaitDelay` 파이프 대기 상한, `limitedBuffer` 출력 바이트 상한(`onExceed=cancel`) 및 전용 종료 코드 `17`(`ExitResourceLimit`)로 통제함을 증명한다.
* **주요 산출물**: [10-서브프로세스-자원-및-수명-통제](10-서브프로세스-자원-및-수명-통제/README.md), 결함 워커 별도 실행 파일(`internal/harness/faultworker`, [ADR 0003](../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md) C-7 개정), `G9` 시나리오(`E2E-40`~`44`).

### Phase 11: OS 수준 커널 격리 및 악의 워커 차단 (`G10`: `E2E-45`~`E2E-49`) [완료: macOS 실행 검증, Linux는 교차 컴파일만]
* **목적**: PEP 배선을 우회해 직접 OS 시스템콜(`open`, `socket`, `fork`)을 호출하는 악의 워커가 격리를 껐을 때(대조군)는 성공하지만 커널 격리(`internal/confinement`: macOS Seatbelt, Linux Landlock + `confine-exec` 신뢰 런처, 허용 목록 정책)를 켰을 때(실험군)는 차단됨을 쌍 대조로 증명한다. 차단 판정은 부모가 관찰한 사실(canary 미유출·파일 미생성·리스너 accept 0건)로만 내리고, 시나리오가 `Exit 13`을 반환한다([020번 보고서](../보고서/020-11번로드맵_구조결함_및_진행가능성_검증보고서.md)).
* **주요 산출물**: [11-os-수준-격리-및-악의-워커-차단](11-os-수준-격리-및-악의-워커-차단/README.md), `internal/confinement`, `TC-110-01` AST 가드, `G10` 시나리오(`E2E-45`~`49`).

### Phase 12: 예산(Budget) 단조 축소 위임 및 원장 정산 (`G11`: `E2E-50`~`E2E-54`) [완료: 2026-11-04]
* **목적**: 호출 횟수(`MaxCalls`)·읽기/쓰기 바이트(`MaxReadBytes`/`MaxWriteBytes`) 예산의 단조 축소 위임($B_{child} \le B_{parent\_rem}$), Zone B 원자적 예산 원장(`budget_ledger.json`, `AtomicFileStore` 배타 잠금 임계 구역), 만료 자식 예약 자동 회수(Lazy Reclaim)를 증명한다.
* **주요 산출물**: [12-예산-축소-위임](12-예산-축소-위임/README.md), `internal/domain/budget.go`(`Budget`), [ADR 0004](../adr/0004-예산-축소-위임-예약-및-정산-모델.md), `internal/authn/budget`, `G11` 시나리오(`E2E-50`~`54`).

### Phase 13: 장기 실행 세션 수명주기, `act` 계보 연쇄 회수 및 재교환 (`G12`: `E2E-55`~`E2E-60`)
* **목적**: 다회차 장기 세션(`SessionDriver`) 중 토큰 만료·Grant 회수·서명키 폐기·상위 에이전트 Epoch 갱신(`ActorClaim.Epoch` 분리 및 `pdp.Evaluate` 조상 계보 연쇄 검증)에 따른 실시간 차단과 부모 기반 재교환(`re-exchange`), 결정론적 TOCTOU 창 측정을 증명한다. 코어 패키지 `time.Now()` 직접 호출을 전면 제거하고 `TC-130-01` AST 가드로 고정한다.
* **주요 산출물**: [13-장기-실행-및-토큰-수명-검증](13-장기-실행-및-토큰-수명-검증/README.md), `internal/harness/catalog/session_helper.go`, `G12` 시나리오(`E2E-55`~`60`).

### Phase 14: 감사 확장(v2 해시·서명 체크포인트·위임 트리) 및 관측성 포트 분리 (`G13`: `E2E-61`~`E2E-66`)
* **목적**: 코어에서 `log/slog` 의존을 끊고 `internal/observe`(포트 + `slogadapter`) 포트로 분리하며(`TC-140-01`), authn 감사 오류 무시 제거(`TC-080-01` 전 패키지 확대), 감사 스키마 v2(`ArgHash`, `ResultHash`), Zone A Ed25519 서명 체크포인트(꼬리 절단·전체 재작성 탐지), `audit tree` 위임 계보 시각화를 완성한다.
* **주요 산출물**: [14-감사-확장-및-관측성-포트](14-감사-확장-및-관측성-포트/README.md), `internal/observe`, `internal/audit/checkpoint/` 패키지, `G13` 시나리오(`E2E-61`~`66`).

### Phase 15: PDP 3값 승인 결정(`ask`) 및 5요소 바인딩 1회용 승인 원장 (`G14`: `E2E-67`~`E2E-72`)
* **목적**: 순수 PDP 결정을 `allow`/`deny`/`ask` 3값으로 확장하고, `(sub, action, resource, token_jti)` 4요소 및 선택적 5번째 요소 `ArgHash`(`sha256(req.Data)`, Confused Deputy 페이로드 바꿔치기 방어)에 바인딩된 Zone B 1회용 승인 원장(`approvals_state.json`)과 종료 코드 `18`(`ExitApprovalRequired`)을 증명한다.
* **주요 산출물**: [15-pdp-승인-결정-ask](15-pdp-승인-결정-ask/README.md), `internal/authz/state/approval_store.go`, `approval grant/list` CLI, `G14` 시나리오(`E2E-67`~`72`).

### Phase 16: 도구 종류 확장(`net:fetch`, `exec:run`) 및 Egress/실행 가드 (`G15`: `E2E-73`~`E2E-78`) — [기능 동결선]
* **목적**: 루프백 전용 `net:fetch`(`internal/netguard`: DNS 리바인딩·userinfo·리다이렉트·비루프백 차단)와 allow-list ID 전용 `exec:run`(`internal/execguard`: 셸 메타문자·위험 플래그 차단) 가짜 도구를 기존 PEP 단일 입출구에 통합하고 78대 E2E 시나리오를 완주한 뒤 **일체의 기능 추가를 동결(Feature Freeze)**한다.
* **주요 산출물**: [16-도구-종류-확장-및-egress-통제](16-도구-종류-확장-및-egress-통제/README.md), `internal/netguard`, `internal/execguard`, `G15` 시나리오(`E2E-73`~`78`).

### Phase 17: [포스트 로드맵 1] 도메인 순수성 및 전이적 의존성 역전(DIP) 완결
* **목적**: 신규 기능 추가 없이 `SubjectSnapshot`/`SnapshotProvider`/`AuditWriter`를 `internal/domain`으로 역전시켜 `pdp`의 전이적 인프라 의존성을 0%로 만들고(`TC-170-01`), PEP 도구 실행을 `ToolHandler` 전략 포트로 추상화하며, 전 CLI 러너의 `app.BuildStack` 일원화(`TC-170-02`) 및 카탈로그 중복 제거를 완결한다.
* **주요 산출물**: [17-도메인-순수성-및-의존성-역전-완결](17-도메인-순수성-및-의존성-역전-완결/README.md), `internal/domain/snapshot.go`, `internal/authz/pep/handler.go`.

### Phase 18: [포스트 로드맵 2] 아키텍처·패턴 교보재 및 코드리딩 가이드 편찬
* **목적**: 코드 변경 없이 본 레포지토리의 5단계 코드리딩 동선, 4계층 의존성 역전(DIP) 실물 해부, 7대 디자인 패턴 및 12대 안티패턴 대조 교본, SESE 감사·권한 무결성 해설, 멀티·분산 에이전트 SDK 이식 가이드를 `docs/교보재/`에 편찬하여 프로젝트를 최종 완결한다.
* **주요 산출물**: [18-아키텍처-패턴-교보재-및-코드리딩-가이드](18-아키텍처-패턴-교보재-및-코드리딩-가이드/README.md), `docs/교보재/01..04.md`.

## 20) 크로스커팅 관심사 (Cross-Cutting Concerns)
1. **설정 관리**: 외부 설정 서버 없이 기본 플래그 값만으로 즉시 동작하며, `--workspace-dir`, `--state-dir`, `--audit-file`로 모든 경로를 격리 지정할 수 있다.
2. **시크릿 및 서명 키 보호**: Zone A 개인키(`signing_keys.priv.json`)는 `0600` 권한으로 보호되며 서브에이전트에 노출되지 않는다. 모든 로그에는 토큰 원문 대신 `jti`만 기록한다.
3. **결정론적 시간 제어 (`Clock` 추상화)**: 전 계층이 `internal/clock` 인터페이스를 사용하며, `--clock-offset` 플래그로 `sleep` 없이 즉시 만료/미래 토큰을 시뮬레이션한다.
4. **고유 ID 및 추적 전파 (`trace_id` / `span_seq` / `jti`)**: 모든 실행 연쇄는 고유 `trace_id`와 단조 증가하는 `span_seq`를 가지며, 부모에서 자식 OS 프로세스로 강제 전파된다.
5. **표준 에러 및 종료 코드 매핑**: 문자열 에러 비교를 금지하고 도메인 상수(`Reason`, `ErrorClass`, `ExitCode`)로만 판정한다.

## 21) 위협 모델 요약 (Threat Model Summary) 및 대응 원칙
1. **토큰 위조·변조 및 알고리즘 혼동 ([RFC 8725](https://www.rfc-editor.org/info/rfc8725/))**: `typ: at+jwt` 강제, 허용 알고리즘 화이트리스트(`alg: none` 거부), `kid` 기반 서명 검증으로 Gate 1에서 즉시 차단.
2. **권한 확대 위임 ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693/))**: 팀장의 직접 서명 불가(Zone A 격리), 중앙 토큰 교환기에서 $S_{child} \subseteq S_{parent}$, $exp_{child} \le exp_{parent}$, `depth <= max_depth` 불변식 강제.
3. **회수된 토큰 및 폐기된 서명 키 재사용**: PIP 실시간 Grant 상태 조회, Subject Epoch 버전 대조, 폐기된 `kid`(`retired`) 즉시 거부로 만료 전 토큰이라도 즉시 차단.
4. **주체 도용 및 토큰 재사용(Replay)**: 실행 에이전트 ID와 `sub` 바인딩 대조 및 일회성 토큰 `jti` 소비 원장(Anti-Replay Ledger)으로 차단.
5. **경로 탈출 (Path Traversal & Symlink Escape)**: 경로 정규화, `filepath.Rel` 검증, 심볼릭 링크 실제 경로 해석(`EvalSymlinks`)으로 Workspace 외부 접근 원천 차단.
6. **PEP 우회 (Direct OS Syscall 한계 명시)**: 서브에이전트 코드에서 원시 파일 I/O 참조를 금지하여 아키텍처적으로 방지하되, OS 커널 샌드박스(`seccomp`/컨테이너)가 아니므로 악의적으로 재컴파일된 바이너리 자체의 커널 시스템 콜은 막을 수 없음을 한계로 투명하게 명시.
7. **감사 로그 누락·오염·사후 변조**: 전용 JSONL 파일 분리, 감사 실패 시 파일 I/O를 중단하는 Fail-Closed 정책, 그리고 SHA-256 해시 체인(`prev_hash` → `curr_hash`) 및 `audit verify`로 사후 변조를 100% 적발.

## 22) 포트폴리오 스토리라인 (면접/문서에서 설명할 순서)
1. **문제 정의 (Why)**: "에이전트 지능보다 기업 도입에서 더 치명적인 문제는 하위 워커에 대한 과도한 권한 위임과 권한 회수 미반영, 그리고 사후 추적 불가입니다. 저는 지능 대신 **통제와 실패 증명**에 집중한 하네스를 설계했습니다."
2. **3-Zone 격리와 이중 관문 아키텍처 (What)**: "외부 클라우드 없이도 로컬에서 완벽한 신뢰 경계를 만들기 위해 상태를 3-Zone(개인키 Zone A / 검증·PIP Zone B / 실행 Jail 및 감사 Zone C)으로 분리하고, Gate 1(AuthN/서명/키 수명주기)과 Gate 2([NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-162.pdf) PAP/PIP/PDP/PEP) 이중 관문을 세웠습니다."
3. **RFC 8693 축소 위임과 OS 프로세스 격리 (How)**: "팀장은 권한의 주인이 아니라 조정자입니다. 자식 워커를 별도 OS 서브프로세스로 띄울 때 [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) 기반 축소 위임 토큰을 `stdin` 프레임으로 전달하며, Revoke나 Epoch 갱신 시 만료 전 토큰이라도 즉시 차단됩니다."
4. **초보자 친화적 관측성과 해시 체인 감사 (Evidence)**: "운영 로그(`stderr`), 해시 체인 감사 증거(`audit.jsonl`), 초보자용 6단계 관문 상태도 및 시계열 스토리텔러(`stdout`)를 3채널로 분리해 누구나 왜 막혔는지 즉시 이해할 수 있습니다."
5. **5계층 테스트와 30대 E2E 하네스 (Proof)**: "단위·퍼징·`-race` 동시성 테스트부터 `run --scenario all` 30개 E2E 공격 시나리오까지, 기대한 실패가 정확한 종료 코드와 감사 사유로 실패해야만 PASS를 주는 검증 체계를 완성했습니다."

## 23) 열린 결정 사항 (Open Decisions) — 권고 기본값 및 명세 확정 지점
후속 구현지시서 작성 시 혼선을 줄이기 위해 각 항목의 **권고 기본값(Recommended Default)**과 대안을 함께 명시한다.
1. **OD-01 (Revoke 후 기존 토큰 즉시 무효화 방식)**: **권고 기본값 = 선택지 2+3 결합 (PIP 실시간 Grant 활성 확인 + Subject Epoch 대조)**. (순수 Stateless 만료 대기는 옵션 플래그로만 비교 가능하게 제공).
2. **OD-02 (리소스 경로 매칭 범위)**: **권고 기본값 = Exact Match (정규화된 경로 1:1 일치)**. Prefix/Wildcard 허용은 보안 위험 비교용 선택 옵션으로 분리.
3. **OD-03 (서브프로세스 토큰 전달 채널)**: **권고 기본값 = `stdin` 파이프 단일 JSON 프레임**. (`--token-channel env|file|arg` 플래그로 타 채널 취약점 비교 시연 지원).
4. **OD-04 (클라이언트 인증 수준)**: **권고 기본값 = 로컬 Confidential Client (`client_id` + `client_secret` 검증)**.
5. **OD-05 (감사 기록 실패 시 정책)**: **권고 기본값 = Strict Fail-Closed (`--fail-audit-mode closed`)** — 감사 기록 실패 시 파일 I/O 즉시 중단 및 `EXIT_AUDIT_FAILURE(15)` 반환.
6. **OD-06 (프로세스 간 상태 공유 방식)**: **권고 기본값 = 단일 바이너리 + 3-Zone 로컬 상태 디렉토리(`flock` 원자적 잠금 및 Atomic Rename)**. 별도 데몬 관리 복잡도 없이 즉시 실행 보장.
7. **OD-07 (감사 로그 변조 방지 해시 체인)**: **권고 기본값 = 기본 탑재 (`prev_hash`, `curr_hash` 포함 및 `audit verify` 제공)**.

## 24) 가정 (Assumptions)
1. 실행 환경은 Go 툴체인이 설치된 단일 로컬 머신(macOS 또는 Linux)이며 로컬 파일 읽기/쓰기, 파일 잠금(`flock`), 자식 프로세스 생성(`fork/exec`) 권한이 있다.
2. 시스템 시간은 주입 가능한 `Clock` 인터페이스를 통해 조회되며, 만료 및 시계 오차 테스트는 `--clock-offset`으로 결정론적으로 제어한다.
3. E2E 시나리오 하네스는 시나리오 시작 전 또는 시나리오별 격리 공간에서 상태를 초기화하여 외부 비결정적 간섭 없이 재현 가능하게 동작한다.

## 25) 제약 (Constraints)
1. **언어 및 외부 의존성 제약**: 반드시 **Go** 언어로 작성하며 외부 클라우드 IdP, 외부 DB 서버, Docker 데몬에 의존하지 않는다.
2. **단일 리포지토리 및 즉시 실행성 제약**: 클론 직후 단일 빌드와 단일 명령(`run --scenario all`)으로 전 과정을 실행·검증할 수 있어야 한다.
3. **도메인 및 인터페이스 제약**: 에이전트 작업은 `file:read`와 `file:write`로만 한정하며, 웹 UI 없이 명령행 CLI와 초보자 친화적 터미널 출력으로만 모든 제어와 설명을 제공한다.

## 26) 마일스톤 체크리스트 (사람용 / 누락 검사용 최종 요약)
- [x] **아키텍처 경계 & 3-Zone 격리**: Zone A(개인키/시크릿), Zone B(공개키/Grant/Epoch/Replay), Zone C(Workspace Jail/Audit JSONL) 물리·논리 분리 및 6계층 비순환 의존성(DAG) 확립 완료.
- [x] **엔터프라이즈 AuthN + AuthZ 통합**: 워크로드 클라이언트 인증(Gate 1), [RFC 9068](https://www.rfc-editor.org/info/rfc9068/) `typ: at+jwt`, [RFC 7517](https://www.rfc-editor.org/info/rfc7517/) `kid` 키 회전·폐기, [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) `act` 클레임 축소 위임, [NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-162.pdf) PAP/PIP/PDP/PEP 4각 분리 반영 완료.
- [x] **OS 서브프로세스 & 파일 Jail**: 클린 환경변수 + `stdin` 프레임 기반 자식 프로세스 실행, 표준 종료 코드(`0`, `11`~`16`), 상대 경로/절대 경로/심볼릭 링크 탈출 방어 완료.
- [x] **삼분 관측성 & 초보자 친화적 UX**: `audit.jsonl`(해시 체인) ≠ `stderr`(`slog`) ≠ `stdout`(6단계 시각적 관문 파이프라인 뷰, 부정 테스트 해설 박스, `audit timeline` 시계열 스토리텔러) 설계 완료.
- [x] **전수 CLI 스위치 & 5계층(L1~L5) 30대 E2E 하네스**: 8대 명령 그룹, 결함 주입 플래그(`--tamper-*`, `--inject-*`), L1(Unit)~L2(Fuzz)~L3(Race/Clock)~L4(CLI Contract)~L5(30개 E2E 시나리오) 및 Phase 0~6 인계 계약 정의 완료.
