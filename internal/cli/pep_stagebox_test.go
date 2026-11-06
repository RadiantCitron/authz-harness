package cli

import (
	"context"
	"strings"
	"testing"

	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

// 화면은 domain.PEPStages() 의 10단계를 모두 그리고, 상태는 Result.Passed 로 정한다.
// 기대값은 계획 013 §3.1 시나리오 표(A1~A10)를 ADR 0007 의 열 단계 순서로 옮긴 것이다.

const (
	pass = boxPass
	fail = boxFail
	skip = boxSkipped
	na   = boxNA
)

// 10칸 순서: input, authn, authz, boundary, replay, approval, budget, precommit_audit, execute, settle
func statuses(boxes []stageBox) []string {
	out := make([]string, len(boxes))
	for i, b := range boxes {
		out[i] = b.Status
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stageList(s ...domain.Stage) []domain.Stage { return s }

func TestStageBoxes_AcceptanceTable(t *testing.T) {
	const (
		in, an, az, bn = domain.StageInput, domain.StageAuthn, domain.StageAuthz, domain.StageBoundary
		rp, ap, bd     = domain.StageReplay, domain.StageApproval, domain.StageBudget
		pa, ex, st     = domain.StagePrecommitAudit, domain.StageExecute, domain.StageSettle
	)
	tests := []struct {
		id   string
		res  pep.Result
		want []string
		more []string // 정식 10칸 뒤에 붙는 추가 칸
	}{
		{"A1 읽기 허가 (승인·예산 없음)",
			pep.Result{Allowed: true, Stage: ex, Passed: stageList(in, an, az, bn, rp, pa, ex)},
			[]string{pass, pass, pass, pass, pass, na, na, pass, pass, na}, nil},
		{"A2 input 실패",
			pep.Result{Stage: in, Reason: domain.ReasonInvalidArguments},
			[]string{fail, skip, skip, skip, skip, skip, skip, skip, skip, skip}, nil},
		{"A3 authz 범위 부족",
			pep.Result{Stage: az, Reason: domain.ReasonTokenInsufficientScope, Passed: stageList(in, an)},
			[]string{pass, pass, fail, skip, skip, skip, skip, skip, skip, skip}, nil},
		{"A4 boundary 실패",
			pep.Result{Stage: bn, Passed: stageList(in, an, az)},
			[]string{pass, pass, pass, fail, skip, skip, skip, skip, skip, skip}, nil},
		{"A5 approval 실패",
			pep.Result{Stage: ap, Passed: stageList(in, an, az, bn, rp)},
			[]string{pass, pass, pass, pass, pass, fail, skip, skip, skip, skip}, nil},
		{"A6 budget 실패 (승인 없음)",
			pep.Result{Stage: bd, Passed: stageList(in, an, az, bn, rp)},
			[]string{pass, pass, pass, pass, pass, na, fail, skip, skip, skip}, nil},
		{"A7 승인+예산 허가 (정산까지)",
			pep.Result{Allowed: true, Stage: ex, Passed: stageList(in, an, az, bn, rp, ap, bd, pa, ex, st)},
			[]string{pass, pass, pass, pass, pass, pass, pass, pass, pass, pass}, nil},
		{"A8 precommit_audit 실패 (예산 토큰)",
			pep.Result{Stage: pa, Passed: stageList(in, an, az, bn, rp, bd)},
			[]string{pass, pass, pass, pass, pass, na, pass, fail, skip, skip}, nil},
		{"A9 목록에 없는 실패 단계",
			pep.Result{Stage: "stage9_future", Passed: stageList(in, an, az)},
			[]string{pass, pass, pass, na, na, na, na, na, na, na}, []string{fail}},
		{"A10 Passed 가 빈 거부 결과 (목)",
			pep.Result{Stage: bn},
			[]string{na, na, na, fail, skip, skip, skip, skip, skip, skip}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			res := tc.res
			boxes := stageBoxes(&res)
			want := append(append([]string(nil), tc.want...), tc.more...)
			if got := statuses(boxes); !eq(got, want) {
				t.Fatalf("statuses = %v\nwant       %v", got, want)
			}
			if n := len(domain.PEPStages()); len(boxes) != n+len(tc.more) {
				t.Fatalf("boxes = %d, want %d", len(boxes), n+len(tc.more))
			}
		})
	}
}

// 실제 pep 명령 출력: 줄 수와 상태를 화면 문자열에서 읽는다. 칸 이름은 domain.PEPStages() 의 Label 이다.
func boxLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		for _, sp := range domain.PEPStages() {
			if strings.HasPrefix(l, sp.Label) && strings.Contains(l, ": [") {
				lines = append(lines, l)
				break
			}
		}
	}
	return lines
}

func lineStatus(t *testing.T, lines []string, label string) string {
	t.Helper()
	for _, l := range lines {
		if strings.HasPrefix(l, label) {
			for _, s := range []string{boxPass, boxFail, boxSkipped, boxNA} {
				if strings.Contains(l, ": "+s) {
					return s
				}
			}
		}
	}
	t.Fatalf("no line with prefix %q in:\n%s", label, strings.Join(lines, "\n"))
	return ""
}

func labelOf(id domain.Stage) string {
	for _, sp := range domain.PEPStages() {
		if sp.ID == id {
			return sp.Label
		}
	}
	return ""
}

func TestPEPCLI_RealRun_InvalidTokenShowsInputPassAuthnFail(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	rig.out.Reset()
	code := rig.runner.Run(context.Background(), []string{"read", "notes.txt", "--token", "invalid.jwt.token"})
	if code != domain.ExitTokenInvalid {
		t.Fatalf("exit = %d\n%s", code, rig.out.String())
	}
	lines := boxLines(rig.out.String())
	if len(lines) != len(domain.PEPStages()) {
		t.Fatalf("box lines = %d, want %d:\n%s", len(lines), len(domain.PEPStages()), rig.out.String())
	}
	for _, sp := range domain.PEPStages() {
		want := boxSkipped
		switch sp.ID {
		case domain.StageInput:
			want = boxPass
		case domain.StageAuthn:
			want = boxFail
		}
		if got := lineStatus(t, lines, sp.Label); got != want {
			t.Errorf("%s = %s, want %s", sp.ID, got, want)
		}
	}
}

func TestPEPCLI_RealRun_AllowedWriteMarksConditionalStagesNA(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	rig.createGrant(t, "worker-01", "operator", "file:write", "reports/summary.txt")
	tok := rig.issueToken(t, "worker-01", "file:write", "authz-harness")
	rig.out.Reset()
	code := rig.runner.Run(context.Background(), []string{"write", "reports/summary.txt", "--token", tok, "--data", "hello"})
	if code != domain.ExitSuccess {
		t.Fatalf("exit = %d\n%s", code, rig.out.String())
	}
	lines := boxLines(rig.out.String())
	if len(lines) != len(domain.PEPStages()) {
		t.Fatalf("box lines = %d, want %d:\n%s", len(lines), len(domain.PEPStages()), rig.out.String())
	}
	for _, sp := range domain.PEPStages() {
		want := boxPass
		if sp.Conditional {
			want = boxNA // 승인·예산·정산은 이 요청에 해당 없음
		}
		if got := lineStatus(t, lines, labelOf(sp.ID)); got != want {
			t.Errorf("%s = %s, want %s", sp.ID, got, want)
		}
	}
}
