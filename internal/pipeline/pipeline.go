// Package pipeline 은 단계(Step) 목록을 순서대로 실행하고 장애 시 역순 보상(Compensate)을 수행하는 순수 범용 파이프라인 엔진이다 (ADR 0008, 0007).
//
// [설계 철학과 의존성 역전 원칙(DIP)의 극치]
// 1. 도메인 지식 완전 배제:
//    - 본 패키지는 토큰, 인가(PDP/PEP), 감사 장부, 파일 I/O 등 본 하네스의 도메인 개념을 일절 알지 못한다.
//    - 외부 의존성 없이 Go 표준 라이브러리(context, errors, fmt)만으로 구현되어 결합도를 0으로 유지한다.
// 2. 시간 비의존성:
//    - 엔진 자체는 시스템 시각을 읽지 않으며, 모든 시간·상태 변화는 외부에서 주입되는 상태 객체 S 와 Step 클로저가 제어한다.
// 3. 상태 제약 없는 제네릭 추상화:
//    - Go 1.18+ 제네릭([S any])을 활용하여, 임의의 상태 포인터(*pep.Call, *exchange.Context 등)를
//      타입 캐스팅(any/interface{})이나 런타임 리플렉션 오버헤드 없이 컴파일 타임 타입 안정성을 유지한 채 전달한다.
//
// [시스템 내 조립처 및 상호 참조 (Cross-Referencing)]
// - PEP 인가 게이트웨이 10단계 조립처: internal/authz/pep/gateway.go 의 assemble()
//   (input ➔ authn ➔ authz ➔ boundary ➔ replay ➔ approval ➔ budget ➔ precommit_audit ➔ execute ➔ settle)
// - 토큰 축소 위임(Downscoping) 8단계 조립처: internal/authn/exchange/service.go
// - 아키텍처 및 파이프라인 상세 해설서: docs/작동원리/007-파이프라인_컨베이어벨트_양파패킷_DIP_관측_해설.md
package pipeline

import (
	"context"
	"errors"
	"fmt"
)

// Kind 는 파이프라인을 구성하는 각 단계의 보안적·기능적 성격 등급이다 (ADR 0007).
//
// [보안 불변식 (Security Invariant)]:
// 파이프라인 조립 시 단계들의 Kind 등급(rank)은 반드시 단조 증가(monotonic increase)해야 하며 절대 하강할 수 없다.
// 검증(Check) 및 판단(Decide)이 완전히 끝나기 전에 자원을 소비(Consume)하거나 외부 효과(Execute)를 발생시키는
// 순서 역전(TOCTOU 등 보안 취약점)을 New() 단계에서 컴파일 타임/부팅 시점에 원천 차단한다.
type Kind string

const (
	// Check 는 입력값, 서명, 형식 등을 검사하는 읽기 전용 단계다 (순위 0).
	Check Kind = "check"
	// Decide 는 정책에 따라 허용/거부를 수학적으로 판정하는 단계다 (순위 0).
	Decide Kind = "decide"
	// Consume 은 예산 차감, 리플레이 방지 jti 등록 등 되돌릴 수 있는 상태를 소모하는 단계다 (순위 1).
	Consume Kind = "consume"
	// Record 는 감사 로그, 불변 장부 등 영구 기록을 디스크에 커밋하는 단계다 (순위 2).
	Record Kind = "record"
	// Execute 는 OS 명령어, 파일 쓰기, 네트워크 호출 등 실제 도구를 실행하는 단계다 (순위 3).
	Execute Kind = "execute"
	// Settle 은 실행 후 잔여 예산 정산, 반환값 래핑 등 사후 정리 단계다 (순위 4).
	Settle Kind = "settle"
)

// rank 는 각 Kind 의 불변식 검증용 순위 가중치를 반환한다.
// Check 와 Decide 는 동일한 0순위로 취급되어 상호 배치가 자유롭다.
func (k Kind) rank() (int, bool) {
	switch k {
	case Check, Decide:
		return 0, true
	case Consume:
		return 1, true
	case Record:
		return 2, true
	case Execute:
		return 3, true
	case Settle:
		return 4, true
	}
	return 0, false
}

// Step 은 파이프라인의 단일 작업 단위다.
//
// [Go 관용구(Idiom)와 함수형 포트 설계]
// 무거운 인터페이스 다형성 대신 함수 필드(Run, Compensate, Applies)를 취하여,
// 각 단계를 별도 구조체로 분리하지 않고도 조립부(gateway.go 등)에서 간결한 클로저(Closure) 형태로 바인딩할 수 있다.
//
// [타입 파라미터 [S any]]
// S 는 파이프라인을 따라 흐르는 상태 패킷(Context Packet)이다.
// PEP 에서는 *pep.Call 이 S 로 전달되어 단계별 검증 결과(claims, tool, budget)가 누적된다.
type Step[S any] struct {
	// ID 는 단계의 고유 식별자다 (예: "authn", "authz", "budget", "execute").
	// audit.jsonl 의 stage 필드 및 관측(Hook) 이벤트의 키로 직접 활용된다.
	ID string

	// Kind 는 단계의 성격 등급이다. New() 시 rank 순서 검증에 쓰인다.
	Kind Kind

	// Applies 는 해당 요청 패킷 s 에 대해 이 단계의 실행 여부를 동적으로 판정하는 조건부 술어(Predicate)다.
	// nil 이면 무조건 실행한다. (예: 승인이 불필요한 요청은 approval 단계 건너뜀)
	Applies func(s *S) bool

	// Run 은 단계의 핵심 실행 규약이다.
	// 반드시 준수해야 할 규약: 성공 시 nil, 약속과 다르거나 검증 실패 시 error 를 즉시 반환한다 (Early Exit).
	Run func(ctx context.Context, s *S) error

	// Compensate 는 후속 단계에서 장애가 발생했을 때 호출되는 LIFO 역순 롤백(보상 트랜잭션) 함수다.
	// nil 이면 보상 동작이 없다 (읽기 전용 단계).
	// 예: 7단계 budget 에서 차감한 예산을 8단계 precommit_audit 실패 시 refund() 로 복구.
	Compensate func(ctx context.Context, s *S)
}

// Hook 은 파이프라인 엔진의 실행 과정을 외부로 통지하는 계측 포트(DIP Port Interface)다.
//
// 관측기(internal/observe.Observer)를 직접 참조하지 않고 이 훅을 둠으로써 엔진과 관측 계층이 분리된다.
// Applies 가 false 로 평가되어 건너뛴(skipped) 단계에는 호출되지 않는다.
type Hook[S any] interface {
	// OnStepStart 는 단계 진입 직전에 호출된다 (시작 시각 기록, 메트릭 카운터 증가 등).
	OnStepStart(ctx context.Context, id string, s *S)
	// OnStepEnd 는 단계 실행이 종료된 직후 호출되며, 단계 성공 여부(err == nil or != nil)를 전달받는다.
	OnStepEnd(ctx context.Context, id string, s *S, err error)
}

// Trace 는 파이프라인 1회 실행의 전체 궤적 기록이다.
// 사용자 보고서(UI) 생성 및 감사 검증에서 어떤 단계들을 통과했고 어디서 멈췄는지 추적하는 데 사용된다.
type Trace struct {
	// Passed 는 성공적으로 통과한 단계 ID 목록이다 (순서 보장).
	Passed []string
	// Failed 는 실패가 발생한 단계 ID 다 (모두 성공 시 빈 문자열 "").
	Failed string
	// Err 는 실패를 유발한 원인 에러다 (모두 성공 시 nil).
	Err error
}

// Engine 은 불변식 검증을 통과한 단계 목록을 보관하는 재사용 가능한 파이프라인 실행기다.
// 한 번 생성된 Engine 은 불변(Immutable) 객체이며, 동시성 환경에서 여러 요청 고루틴이 안전하게 공유할 수 있다.
// 요청별 가변 상태는 오직 Run 메서드의 s 파라미터로만 전달된다.
type Engine[S any] struct {
	steps []Step[S]
	hook  Hook[S]
}

// New 는 단계 목록의 무결성과 보안 불변식을 엄격히 검증하여 Engine 을 생성한다.
//
// [검증하는 5대 불변식]:
// 1. 빈 목록 금지 (len(steps) == 0)
// 2. 단계 ID 누락 금지 (ID == "")
// 3. 중복된 단계 ID 금지 (동일 ID 재사용 불가)
// 4. 실행 본체 누락 금지 (Run == nil)
// 5. 등급 순서 역전 금지 (r < prevRank: 예컨대 Consume 뒤에 Check 가 오는 역전 차단)
//
// [Go 메모리 안전성 (방어적 복사, Defensive Copy)]:
// steps 슬라이스를 그대로 보관하지 않고 append([]Step[S](nil), steps...) 로 얕은 복사본을 생성하여
// 호출자가 외부에서 원본 슬라이스를 조작하더라도 엔진 내부 상태가 오염되지 않도록 보장한다.
func New[S any](steps []Step[S], hook Hook[S]) (*Engine[S], error) {
	if len(steps) == 0 {
		return nil, errors.New("pipeline: empty step list")
	}
	seen := map[string]bool{}
	prevRank, prevID := -1, ""
	for _, st := range steps {
		if st.ID == "" {
			return nil, errors.New("pipeline: empty step ID")
		}
		if seen[st.ID] {
			return nil, fmt.Errorf("pipeline: duplicate step ID %q", st.ID)
		}
		seen[st.ID] = true
		if st.Run == nil {
			return nil, fmt.Errorf("pipeline: step %q has no Run", st.ID)
		}
		r, ok := st.Kind.rank()
		if !ok {
			return nil, fmt.Errorf("pipeline: step %q has unknown kind %q", st.ID, st.Kind)
		}
		if r < prevRank {
			return nil, fmt.Errorf("pipeline: step %q (%s) comes after %q with a higher rank", st.ID, st.Kind, prevID)
		}
		prevRank, prevID = r, st.ID
	}
	return &Engine[S]{steps: append([]Step[S](nil), steps...), hook: hook}, nil
}

// Run 은 주입된 단계들을 앞에서부터 순차적으로 실행(컨베이어 벨트)한다.
//
// [실행 흐름과 Fail-Closed & Early-Exit 원칙]:
// 1. Applies 조건 검사: 필요 없는 단계는 안전하게 건너뛴다.
// 2. Hook 시작 통지: OnStepStart 호출.
// 3. st.Run 실행: 상태 객체 s 를 조작하거나 검증.
// 4. Hook 종료 통지: OnStepEnd 호출.
// 5. 실패 시 즉시 중단 및 Saga LIFO 보상:
//    - err != nil 발생 시 즉시 루프를 탈출하고 이후 단계는 일절 실행하지 않는다.
//    - 이미 성공적으로 통과했던 단계들(done 슬라이스)을 역순(LIFO, len(done)-1 down to 0)으로 순회하며
//      Compensate 함수가 정의된 단계의 보상 트랜잭션을 실행한다.
//    - 단, 실패를 일으킨 바로 그 단계 자신은 보상하지 않는다 (아직 커밋되지 않은 상태로 간주).
// 6. 성공 축적: 성공한 단계는 tr.Passed 에 기록되고 done 스택에 적재된다.
//
// [주의사항]:
// 엔진은 내부에서 recover()로 panic 을 잡지 않고 상위로 전파한다.
// 관측 계층의 패닉은 observe.WrapSafe 에서 격리되고, 비즈니스 패닉은 CLI 최상위 런타임에서 포획된다.
func (e *Engine[S]) Run(ctx context.Context, s *S) Trace {
	var tr Trace
	var done []Step[S]
	for _, st := range e.steps {
		if st.Applies != nil && !st.Applies(s) {
			continue
		}
		if e.hook != nil {
			e.hook.OnStepStart(ctx, st.ID, s)
		}
		err := st.Run(ctx, s)
		if e.hook != nil {
			e.hook.OnStepEnd(ctx, st.ID, s, err)
		}
		if err != nil {
			tr.Failed, tr.Err = st.ID, err
			for i := len(done) - 1; i >= 0; i-- {
				if done[i].Compensate != nil {
					done[i].Compensate(ctx, s)
				}
			}
			return tr
		}
		tr.Passed = append(tr.Passed, st.ID)
		done = append(done, st)
	}
	return tr
}
