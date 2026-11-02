# ROADMAP — 10 서브프로세스 자원·수명 통제 (마스터 설계)

> 상위 색인: [전체 로드맵 색인](../README.md) | 대시보드: [README.md](README.md) | 계획: [PLAN.md](PLAN.md) | 배경: [WHY.md](WHY.md) | 결정: [ADR 0003](../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md)

## 1. As-Is / To-Be

| 구분 | As-Is (Phase 09 완료 시점, 코드 확인) | To-Be (Phase 10) |
|---|---|---|
| 수명 통제 | [`spawner.go`](../../../internal/orchestrator/spawner.go)의 `context.WithTimeout`(기본 10초)과 `CommandContext`만 사용. 종료 대상은 자식 프로세스 1개 | 자식을 **새 프로세스 그룹**으로 띄우고 만료 시 **그룹 전체**에 종료 신호. `WaitDelay`로 파이프 대기 상한 부여 |
| 출력 통제 | 자식 stdout/stderr를 버퍼에 수집, 크기 상한 없음 | 바이트 상한 리더. 초과 시 즉시 종료·차단 |
| 자원 한계 | 없음 | CPU·열린 파일 수 등 rlimit을 best-effort 적용, 적용 결과를 감사에 기록 |
| 종료 사유 | 종료 코드 `0`, `11`~`16`만 존재 | 신규 `17`(자원·수명 한계)과 Reason 3종(시간 초과, 출력 초과, 신호 종료) |
| 다단계 위임 | [`multi_hop.go`](../../../internal/orchestrator/multi_hop.go)에 `Timeout` 전달 | 중간 프로세스가 만든 손자까지 그룹 종료로 정리 |
| 시나리오 | 39대(G1~G8) | 신규 G9 그룹(번호는 직전 마지막 시나리오+1부터 부여) |

## 2. 아키텍처 및 신뢰 경계

```mermaid
flowchart LR
  O["오케스트레이터 (스포너)"] -->|"새 프로세스 그룹으로 spawn"| W["subagent worker"]
  W --> G["손자 프로세스 (있을 수 있음)"]
  O -->|"만료 / 출력 초과 시 그룹 종료"| W
  O -->|"사유 기록"| A[("audit.jsonl")]
```

- 통제 주체는 **부모(스포너)** 하나뿐이다. 자식은 자기 한계를 스스로 푸는 수단이 없다.
- 한계 값(`Limits`)은 순수 도메인 값이다. OS 호출(Setpgid, kill, setrlimit)은 `orchestrator` 안의 플랫폼 파일(빌드 태그)로 격리한다.
- 감사는 기존 경로(`audit.Writer`)로만 기록한다. 감사 실패 시 fail-closed 원칙은 변경하지 않는다.

## 3. 파급 범위와 무영향 근거

- **변경**: `internal/domain`(Reason, ExitCode, Limits), `internal/orchestrator`(그룹 종료, 출력 상한), `internal/mcp`(오류 매핑 확장), `internal/ui`(사유 표시), `internal/harness/catalog`(G9), 테스트 전용 워커(빌드 태그).
- **무영향**: PDP, PEP 판정 로직, 토큰 발급·검증, jail, 기존 종료 코드 `11`~`16`의 의미와 기존 `E2E-01`~`E2E-39` 판정 기준. 060 단계의 전체 회귀로 증명한다.

## 4. 사전 점검 (Pre-Mortem): 이 로드맵이 실패한다면 무엇 때문인가

| 위험 | 방어책 |
|---|---|
| macOS에서 `RLIMIT_AS` 등 일부 rlimit이 동작하지 않아 "제한했다"는 허위 증명이 됨 | rlimit은 best-effort로 명시. 적용 결과를 감사에 기록하고, 보증 근거는 그룹 종료와 출력 상한으로 한정. 플랫폼별 보증 표를 문서화 |
| 손자 프로세스 시나리오가 타이밍에 의존해 플레이키함 | 대기는 시간 추측이 아니라 **PID 생존 확인(kill 0 → ESRCH) 재시도 루프**로 판정. 고정 sleep 금지 |
| 기존 종료 코드 표 파손으로 MCP 매핑·UI·시나리오가 깨짐 | 신규 `17`은 추가만. 040 단계에서 `Reason→ExitCode→JSON-RPC` 매핑 표 테스트로 전수 확인 |
| 테스트 전용 워커(멈춤·대량 출력)가 프로덕션 바이너리에 섞여 공격면이 됨 | 빌드 태그로 격리, 릴리스 빌드에서 심볼 부재를 테스트로 증명 ([ADR 0003](../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md) C-7) |
| 출력 상한 판정이 늦어 메모리가 이미 소진됨 | 읽는 도중 누적량을 검사하고 상한 도달 즉시 종료. 상한+1청크 이상 보관하지 않음을 단위 테스트로 확인 |
| 자원 한계 종료 시 감사 기록이 누락됨 | 종료 처리 경로 마지막에 `agent.limit_exceeded` 기록. 감사 실패 시 `15`로 수렴 |
| 정상 워커가 기본 한계에 걸려 기존 시나리오 회귀 | 기본값을 기존 동작(10초)과 호환하게 두고 060에서 전체 회귀 |

## 5. 4층위 검증 설계

| 층위 | 대상 | 방법 |
|:---:|---|---|
| 1 | 반복 수동 검증 배제 | `go test ./internal/orchestrator/... ./internal/mcp/...`를 스크립트화 |
| 2 | 단위·구조 | `Limits` 기본값·경계 table-driven 테스트, 출력 상한 리더 단위 테스트, 릴리스 빌드 심볼 부재 테스트 |
| 3 | 상태·정합성 | 종료 후 PID 생존 0, `audit.jsonl` 해시 체인 `VALID`와 `agent.limit_exceeded` 존재, workspace 무변화 |
| 4 | 통합 | `run --scenario`로 G9 실행 및 기존 39대 회귀, `-race` |

## 6. 단계 의존 관계

`010 → 020 → 030 → 040 → 050 → 060` (번호순 = 실행순, 각 단계는 직전 단계 `Done`이 선행 조건)

## 7. 단계 분해표 (구현지시서 작성의 입력)

| 단계 | 목표 | 완료 기준 | 인수 시나리오 (입력 → 기대 결과) |
|:---:|---|---|---|
| **010** | `Limits`, Reason 3종(`RESOURCE_TIMEOUT`, `RESOURCE_OUTPUT_LIMIT`, `RESOURCE_SIGNAL_KILLED`), `ExitResourceLimit=17`, 빌드 태그 테스트 워커 모드(멈춤, 대량 출력, 손자 생성) | 도메인 단위 테스트 통과, 마스터 §13 종료 코드 표 개정안 확정, 기존 테스트 무변화 | 영값 `Limits` → 기본 10초·기본 출력 상한 적용. 음수 값 → `ExitBadInput`. 릴리스 빌드 → 테스트 워커 심볼 없음 |
| **020** | 새 프로세스 그룹 spawn, 만료 시 그룹 종료, `WaitDelay` | 멈춘 워커와 손자를 모두 정리 | 손자를 남기고 멈추는 워커 + 짧은 타임아웃 → 종료 코드 `17`, Reason `RESOURCE_TIMEOUT`, 손자 PID 생존 0 |
| **030** | 출력 바이트 상한, rlimit best-effort | 상한 초과 즉시 종료, rlimit 적용 결과가 기록됨 | 10MiB 출력 워커 + 1MiB 상한 → `17`, `RESOURCE_OUTPUT_LIMIT`, 부모 보관량 ≤ 상한+1청크. rlimit 미지원 플랫폼 → 미적용 사실이 감사에 기록 |
| **040** | 감사 이벤트 `agent.limit_exceeded`, UI 표시, MCP JSON-RPC 오류 매핑 | 매핑 표 table-driven 테스트 전수 통과, 원시 토큰 비노출 유지 | MCP `tools/call`이 멈춘 워커를 부름 → JSON-RPC 오류에 한계 사유 코드, 감사에 이벤트, 응답에 토큰 문자열 없음 |
| **050** | G9 시나리오(시간 초과, 손자 잔존 0, 출력 초과, MCP 경로, 정상 워커 비회귀) Quad-Assertion | 모든 시나리오 `PASS`, 거부·한계 종료 후 workspace 0바이트 변화 | 위 인수 시나리오를 `run --scenario`로 실행 → 4중 검증 통과 |
| **060** | 전체 회귀, 문서 동기화 | `go test -race ./...` 통과, 기존 39대 + G9 완주, 마스터 §13·README 색인 동기화 | `authz-harness run --scenario all` → 종료 코드 `0` |

## 8. 선행 조건·결정 필요 사항

- [ADR 0003](../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md) `Accepted` (C-5, C-7).
- 미결: ① 기본 출력 상한 값 ② rlimit 대상 항목 ③ 종료 사유 3종이 한 코드(`17`)로 충분한지 → 010 단계에서 확정한다.
- 설계 결정은 별도 ADR이 필요하면 `docs/adr/`에 추가한다(ADR 번호는 직전 번호+1).

## 9. 인수인계 (다음 에이전트용)

- **코드 사실 확인 포인터**: [`spawner.go`](../../../internal/orchestrator/spawner.go) 94행 부근 `WithTimeout`, [`multi_hop.go`](../../../internal/orchestrator/multi_hop.go) `Timeout`, [`executor.go`](../../../internal/mcp/executor.go), [`constants.go`](../../../internal/domain/constants.go) 종료 코드 정의. 문서가 아닌 실제 코드를 먼저 확인할 것.
- **금지 사항**: PEP·PDP 판정 로직 수정, 기존 종료 코드 의미 변경, 테스트 워커를 프로덕션 빌드에 포함, 고정 sleep 기반 판정, 감사 기록 에러 무시(`_ = err`).
- **착수 순서**: ADR 0003 상태 확인 → 010 지시서 작성 → 사용자의 「구현해라」 → 한 단계 실행·검증·커밋 후 정지·보고.
- **이후 로드맵과의 접점**: 테스트 전용 워커 모드는 [11](../11-os-수준-격리-및-악의-워커-차단/README.md), [15](../15-pdp-승인-결정-ask/README.md), [16](../16-도구-종류-확장-및-egress-통제/README.md)이 재사용한다. 설계를 바꾸면 이 문서들도 갱신할 것.
