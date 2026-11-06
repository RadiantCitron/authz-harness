package pipeline_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"authz-harness/internal/pipeline"
)

type st struct {
	val   int
	calls []string
}

func ok(string) func(context.Context, *st) error {
	return func(context.Context, *st) error { return nil }
}

func step(id string, k pipeline.Kind) pipeline.Step[st] {
	return pipeline.Step[st]{ID: id, Kind: k, Run: ok(id)}
}

func TestNewOrdering(t *testing.T) { // TC-020-01~03
	good := [][]pipeline.Step[st]{
		{step("a", pipeline.Check), step("b", pipeline.Consume), step("c", pipeline.Record), step("d", pipeline.Execute), step("e", pipeline.Settle)},
		{step("a", pipeline.Check), step("b", pipeline.Decide), step("c", pipeline.Check)},
	}
	for i, s := range good {
		if _, err := pipeline.New(s, nil); err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
	}
	_, err := pipeline.New([]pipeline.Step[st]{step("spend", pipeline.Consume), step("look", pipeline.Check)}, nil)
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "spend") || !strings.Contains(msg, "look") {
		t.Errorf("want error naming both IDs, got %v", err)
	}
}

func TestNewRejects(t *testing.T) { // TC-020-04
	noRun := step("a", pipeline.Check)
	noRun.Run = nil
	cases := map[string][]pipeline.Step[st]{
		"duplicate": {step("a", pipeline.Check), step("a", pipeline.Check)},
		"empty id":  {step("", pipeline.Check)},
		"empty":     nil,
		"no run":    {noRun},
		"bad kind":  {step("a", "bogus")},
	}
	for name, s := range cases {
		if _, err := pipeline.New(s, nil); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func rec(id string, k pipeline.Kind, fail bool, log *[]string) pipeline.Step[st] {
	s := pipeline.Step[st]{ID: id, Kind: k,
		Run: func(context.Context, *st) error {
			*log = append(*log, "run:"+id)
			if fail {
				return errors.New("boom")
			}
			return nil
		},
		Compensate: func(context.Context, *st) { *log = append(*log, "comp:"+id) },
	}
	return s
}

func TestFailureCompensation(t *testing.T) { // TC-020-05, 12
	var log []string
	e, _ := pipeline.New([]pipeline.Step[st]{
		rec("1", pipeline.Check, false, &log), rec("2", pipeline.Check, false, &log),
		rec("3", pipeline.Check, true, &log), rec("4", pipeline.Check, false, &log)}, nil)
	tr := e.Run(context.Background(), &st{})
	want := []string{"run:1", "run:2", "run:3", "comp:2", "comp:1"}
	if !reflect.DeepEqual(log, want) || tr.Failed != "3" || tr.Err == nil {
		t.Errorf("log=%v trace=%+v", log, tr)
	}
}

func TestSkippedNotCompensatedAndNoHook(t *testing.T) { // TC-020-06, 11
	var log []string
	skip := rec("s", pipeline.Check, false, &log)
	skip.Applies = func(*st) bool { return false }
	h := &hook{}
	e, _ := pipeline.New([]pipeline.Step[st]{rec("1", pipeline.Check, false, &log), skip, rec("3", pipeline.Check, true, &log)}, h)
	tr := e.Run(context.Background(), &st{})
	if !reflect.DeepEqual(tr.Skipped, []string{"s"}) || !reflect.DeepEqual(log, []string{"run:1", "run:3", "comp:1"}) {
		t.Errorf("trace=%+v log=%v", tr, log)
	}
	for _, ev := range h.events {
		if strings.Contains(ev, ":s:") {
			t.Errorf("hook called for skipped step: %v", h.events)
		}
	}
}

func TestSuccessAndNilHook(t *testing.T) { // TC-020-07, 08
	var log []string
	e, _ := pipeline.New([]pipeline.Step[st]{rec("1", pipeline.Check, false, &log), rec("2", pipeline.Execute, false, &log)}, nil)
	tr := e.Run(context.Background(), &st{})
	if !reflect.DeepEqual(tr.Passed, []string{"1", "2"}) || tr.Failed != "" || tr.Err != nil || len(log) != 2 {
		t.Errorf("trace=%+v log=%v", tr, log)
	}
}

type hook struct {
	events []string
	seen   []int
}

func (h *hook) OnStepStart(_ context.Context, id string, s *st) {
	h.events = append(h.events, "start:"+id+":")
	h.seen = append(h.seen, s.val)
}
func (h *hook) OnStepEnd(_ context.Context, id string, _ *st, _ error) {
	h.events = append(h.events, "end:"+id+":")
}

func TestHookSeesState(t *testing.T) { // TC-020-09, 10
	h := &hook{}
	set := step("1", pipeline.Check)
	set.Run = func(_ context.Context, s *st) error { s.val += 7; return nil }
	e, _ := pipeline.New([]pipeline.Step[st]{set, step("2", pipeline.Check)}, h)
	e.Run(context.Background(), &st{})
	if !reflect.DeepEqual(h.seen, []int{0, 7}) {
		t.Errorf("seen=%v", h.seen)
	}
	h.seen = nil
	e.Run(context.Background(), &st{val: 100})
	if !reflect.DeepEqual(h.seen, []int{100, 107}) {
		t.Errorf("second run seen=%v", h.seen)
	}
}
