package cli

import (
	"context"
	"strings"
	"testing"

	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

// 계획 013 S2: pep 명령 화면은 pep.Stages() 의 9단계를 모두 그리고, 상태는 Result.Passed 로 정한다.
// 기대값은 계획 013 §3.1 의 시나리오 표(A1~A10)에서 가져왔다.

const (
	pass = boxPass
	fail = boxFail
	skip = boxSkipped
	na   = boxNA
)

// 9칸 순서: Gate0, Gate1, Gate2, 2b, 2c, 3a, 3b, Stage4, Stage5
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

func stageList(s ...pep.Stage) []pep.Stage { return s }

func TestStageBoxes_AcceptanceTable(t *testing.T) {
	const (
		g0, g1, g2, rp = pep.StageGate0Input, pep.StageGate1AuthN, pep.StageGate2AuthZ, pep.StageReplay
		jl, ap, bd     = pep.StageGate2cJail, pep.StageApproval, pep.StageBudget
		s4, s5         = pep.Stage4Audit, pep.Stage5FileIO
	)
	tests := []struct {
		id   string
		res  pep.Result
		want []string
		more []string // 정식 9칸 뒤에 붙는 추가 칸
	}{
		{"A1 읽기 허가 (승인·예산 없음)",
			pep.Result{Allowed: true, Stage: s5, Passed: stageList(g0, g1, g2, rp, jl, s4, s5)},
			[]string{pass, pass, pass, pass, pass, na, na, pass, pass}, nil},
		{"A2 Gate 0 실패",
			pep.Result{Stage: g0, Reason: domain.ReasonInvalidArguments},
			[]string{fail, skip, skip, skip, skip, skip, skip, skip, skip}, nil},
		{"A3 Gate 2 범위 부족",
			pep.Result{Stage: g2, Reason: domain.ReasonTokenInsufficientScope, Passed: stageList(g0, g1)},
			[]string{pass, pass, fail, skip, skip, skip, skip, skip, skip}, nil},
		{"A4 Replay 실패",
			pep.Result{Stage: rp, Passed: stageList(g0, g1, g2)},
			[]string{pass, pass, pass, fail, skip, skip, skip, skip, skip}, nil},
		{"A5 Approval 실패",
			pep.Result{Stage: ap, Passed: stageList(g0, g1, g2, rp, jl)},
			[]string{pass, pass, pass, pass, pass, fail, skip, skip, skip}, nil},
		{"A6 Budget 실패 (승인 없음)",
			pep.Result{Stage: bd, Passed: stageList(g0, g1, g2, rp, jl)},
			[]string{pass, pass, pass, pass, pass, na, fail, skip, skip}, nil},
		{"A7 승인+예산 허가",
			pep.Result{Allowed: true, Stage: s5, Passed: pep.Stages()},
			[]string{pass, pass, pass, pass, pass, pass, pass, pass, pass}, nil},
		{"A8 Stage 4 감사 실패 (예산 토큰)",
			pep.Result{Stage: s4, Passed: stageList(g0, g1, g2, rp, jl, bd)},
			[]string{pass, pass, pass, pass, pass, na, pass, fail, skip}, nil},
		{"A9 목록에 없는 실패 단계",
			pep.Result{Stage: "stage9_future", Passed: stageList(g0, g1, g2)},
			[]string{pass, pass, pass, na, na, na, na, na, na}, []string{fail}},
		{"A10 Passed 가 빈 거부 결과 (목)",
			pep.Result{Stage: jl},
			[]string{na, na, na, na, fail, skip, skip, skip, skip}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			res := tc.res
			boxes := stageBoxes(&res)
			want := append(append([]string(nil), tc.want...), tc.more...)
			if got := statuses(boxes); !eq(got, want) {
				t.Fatalf("statuses = %v\nwant       %v", got, want)
			}
			if n := len(pep.Stages()); len(boxes) != n+len(tc.more) {
				t.Fatalf("boxes = %d, want %d", len(boxes), n+len(tc.more))
			}
		})
	}
}

// 새 단계가 pep.Stages() 에 생기면 화면 라벨도 있어야 한다 (라벨이 없으면 단계 문자열로 그려지지만 시험이 실패한다).
func TestStageLabels_CoverEveryStage(t *testing.T) {
	for _, s := range pep.Stages() {
		if stageLabels[s] == "" {
			t.Errorf("stage %q has no screen label in stageLabels", s)
		}
	}
	if len(stageLabels) != len(pep.Stages()) {
		t.Errorf("stageLabels has %d entries, pep.Stages() has %d", len(stageLabels), len(pep.Stages()))
	}
}

// 라벨이 없어도 칸은 사라지지 않는다.
func TestStageBoxes_MissingLabelStillRendered(t *testing.T) {
	saved := stageLabels[pep.StageApproval]
	delete(stageLabels, pep.StageApproval)
	defer func() { stageLabels[pep.StageApproval] = saved }()

	boxes := stageBoxes(&pep.Result{Allowed: true, Passed: pep.Stages()})
	if len(boxes) != len(pep.Stages()) {
		t.Fatalf("boxes = %d, want %d", len(boxes), len(pep.Stages()))
	}
	if boxes[5].Label != string(pep.StageApproval) {
		t.Errorf("fallback label = %q", boxes[5].Label)
	}
}

// 실제 pep 명령 출력: 줄 수와 상태를 화면 문자열에서 읽는다.
func boxLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "[") && strings.Contains(l, ": [") {
			lines = append(lines, l)
		}
	}
	return lines
}

func lineStatus(t *testing.T, lines []string, labelPrefix string) string {
	t.Helper()
	for _, l := range lines {
		if strings.HasPrefix(l, labelPrefix) {
			for _, s := range []string{boxPass, boxFail, boxSkipped, boxNA} {
				if strings.Contains(l, ": "+s) {
					return s
				}
			}
		}
	}
	t.Fatalf("no line with prefix %q in:\n%s", labelPrefix, strings.Join(lines, "\n"))
	return ""
}

func TestPEPCLI_RealRun_InvalidTokenShowsGate0PassGate1Fail(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	rig.out.Reset()
	code := rig.runner.Run(context.Background(), []string{"read", "notes.txt", "--token", "invalid.jwt.token"})
	if code != domain.ExitTokenInvalid {
		t.Fatalf("exit = %d\n%s", code, rig.out.String())
	}
	lines := boxLines(rig.out.String())
	if len(lines) != len(pep.Stages()) {
		t.Fatalf("box lines = %d, want %d:\n%s", len(lines), len(pep.Stages()), rig.out.String())
	}
	want := map[string]string{
		"[Gate 0]": boxPass, "[Gate 1]": boxFail, "[Gate 2]": boxSkipped, "[Gate 2b]": boxSkipped,
		"[Gate 2c]": boxSkipped, "[Stage 3a]": boxSkipped, "[Stage 3b]": boxSkipped,
		"[Stage 4]": boxSkipped, "[Stage 5]": boxSkipped,
	}
	for prefix, st := range want {
		if got := lineStatus(t, lines, prefix+" "); got != st {
			t.Errorf("%s = %s, want %s", prefix, got, st)
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
	if len(lines) != len(pep.Stages()) {
		t.Fatalf("box lines = %d, want %d:\n%s", len(lines), len(pep.Stages()), rig.out.String())
	}
	for _, p := range []string{"[Gate 0] ", "[Gate 1] ", "[Gate 2] ", "[Gate 2b] ", "[Gate 2c] ", "[Stage 4] ", "[Stage 5] "} {
		if got := lineStatus(t, lines, p); got != boxPass {
			t.Errorf("%s = %s, want PASS", p, got)
		}
	}
	for _, p := range []string{"[Stage 3a] ", "[Stage 3b] "} {
		if got := lineStatus(t, lines, p); got != boxNA {
			t.Errorf("%s = %s, want N/A", p, got)
		}
	}
}
