// Package pipeline 은 단계 목록을 순서대로 실행하는 범용 엔진이다(ADR 0008).
// 토큰·권한·감사를 모르며 표준 라이브러리만 쓴다. 시각은 읽지 않는다.
package pipeline

import (
	"context"
	"errors"
	"fmt"
)

// Kind 는 단계의 성격이다(ADR 0007). 등급은 조립 목록에서 내려가지 않아야 한다.
type Kind string

const (
	Check   Kind = "check"
	Decide  Kind = "decide"
	Consume Kind = "consume"
	Record  Kind = "record"
	Execute Kind = "execute"
	Settle  Kind = "settle"
)

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

// Step 은 단계 하나다. Applies 가 nil 이면 항상 실행하고, Compensate 가 nil 이면 보상이 없다.
type Step[S any] struct {
	ID         string
	Kind       Kind
	Applies    func(s *S) bool
	Run        func(ctx context.Context, s *S) error
	Compensate func(ctx context.Context, s *S)
}

// Hook 은 계측 포트다. 건너뛴 단계에는 호출하지 않는다.
type Hook[S any] interface {
	OnStepStart(ctx context.Context, id string, s *S)
	OnStepEnd(ctx context.Context, id string, s *S, err error)
}

// Trace 는 한 번의 실행 기록이다.
type Trace struct {
	Passed  []string
	Skipped []string
	Failed  string
	Err     error
}

// Engine 은 검증된 단계 목록이다. 한 번 만들어 재사용하며 요청별 값은 s 로만 전달한다.
type Engine[S any] struct {
	steps []Step[S]
	hook  Hook[S]
}

// New 는 조립을 검사한다: 빈 목록, 빈·중복 ID, 모르는 Kind, Run 없음, 등급 하강을 거부한다.
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

// Run 은 앞에서부터 실행한다. 실패하면 완료한 단계의 Compensate 를 역순으로 한 번씩 부르고 멈춘다.
// 실패한 단계 자신은 보상하지 않는다. panic 은 잡지 않는다.
func (e *Engine[S]) Run(ctx context.Context, s *S) Trace {
	var tr Trace
	var done []Step[S]
	for _, st := range e.steps {
		if st.Applies != nil && !st.Applies(s) {
			tr.Skipped = append(tr.Skipped, st.ID)
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
