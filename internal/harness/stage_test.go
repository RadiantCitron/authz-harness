package harness

import (
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

func evalStage(t *testing.T, events []audit.Event, a AuditExpectation) AssertionResult {
	t.Helper()
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer env.Cleanup()
	w, err := audit.NewJSONLWriter(env.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if err := w.Log(ev); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	return NewDefaultEvaluator().Evaluate(env, domain.ExitAuthzDenied, ExpectedAssertion{ExitCode: domain.ExitAuthzDenied, Audit: a})
}

func denyEvent(stage domain.Stage) audit.Event {
	return audit.Event{Timestamp: time.Now().UTC(), TraceID: "t", Actor: "a", Action: "pep.deny",
		Decision: "deny", Reason: string(domain.ReasonNoActiveGrant), Stage: string(stage)}
}

// TC-060-01·08: 사유는 맞고 단계가 다르면 FAIL, NoStageRecord 기대인데 단계가 있으면 FAIL.
func TestEvaluator_StageAssertion(t *testing.T) {
	base := AuditExpectation{RequireEvent: true, ExpectedAction: "pep.deny", ExpectedDecision: "deny", ExpectedReason: domain.ReasonNoActiveGrant}
	cases := []struct {
		name   string
		events []audit.Event
		stage  domain.Stage
		req    bool
		want   bool
		actual domain.Stage
	}{
		{"단계 일치", []audit.Event{denyEvent(domain.StageAuthz)}, domain.StageAuthz, true, true, domain.StageAuthz},
		{"사유는 맞고 단계가 다름", []audit.Event{denyEvent(domain.StageBoundary)}, domain.StageAuthz, true, false, domain.StageBoundary},
		{"NoStageRecord 기대, 단계 기록 있음", []audit.Event{denyEvent(domain.StageAuthz)}, NoStageRecord, true, false, domain.StageAuthz},
		{"NoStageRecord 기대, 단계 기록 없음", []audit.Event{denyEvent("")}, NoStageRecord, true, true, NoStageRecord},
		{"단계 기대인데 기록에 단계 없음", []audit.Event{denyEvent("")}, domain.StageAuthz, true, false, NoStageRecord},
		{"매칭 불요, 감사 비어 있음", nil, NoStageRecord, false, true, NoStageRecord},
		{"매칭 불요, 감사에 단계 기록 있음", []audit.Event{denyEvent(domain.StageInput)}, NoStageRecord, false, false, domain.StageInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			if !tc.req {
				a = AuditExpectation{}
			}
			a.ExpectedStage = tc.stage
			res := evalStage(t, tc.events, a)
			if res.AuditPassed != tc.want {
				t.Fatalf("AuditPassed=%v want %v reasons=%v", res.AuditPassed, tc.want, res.FailureReasons)
			}
			if res.AuditActualStage != tc.actual {
				t.Fatalf("AuditActualStage=%q want %q", res.AuditActualStage, tc.actual)
			}
		})
	}
}

// TC-060-02: 기대 단계가 없는 시나리오는 등록이 실패한다.
func TestRunner_RegisterRejectsMissingStage(t *testing.T) {
	r := NewDefaultRunner(WithBaseDir(t.TempDir()))
	t.Cleanup(func() { _ = r.Close() })
	sc := &dummyScenario{meta: ScenarioMetadata{ID: "E2E-NOSTAGE", Expected: ExpectedAssertion{ExitCode: domain.ExitSuccess}}}
	if err := r.Register(sc); err == nil {
		t.Fatal("Register must fail without ExpectedStage")
	}
}
