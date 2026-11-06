package catalog

import (
	"context"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// expectedStages 는 시나리오별 기대 단계 표다. 로드맵 19 지시서 060 부록 표와 1:1 이며,
// 매칭한 감사 기록에 어떤 단계가 적혀 있어야 하는지를 요구사항에서 도출한 값이다.
var expectedStages = map[string]domain.Stage{
	"E2E-01": domain.StageExecute,
	"E2E-02": domain.StageExecute,
	"E2E-03": domain.StageAuthz,
	"E2E-04": harness.NoStageRecord,
	"E2E-05": harness.NoStageRecord,
	"E2E-06": harness.NoStageRecord,
	"E2E-07": domain.StageAuthn,
	"E2E-08": domain.StageAuthn,
	"E2E-09": domain.StageAuthn,
	"E2E-10": domain.StageAuthn,
	"E2E-11": domain.StageAuthn,
	"E2E-12": domain.StageExecute,
	"E2E-13": domain.StageAuthn,
	"E2E-14": domain.StageAuthn,
	"E2E-15": domain.StageAuthn,
	"E2E-16": domain.StageAuthn,
	"E2E-17": domain.StageAuthn,
	"E2E-18": domain.StageAuthn,
	"E2E-19": harness.NoStageRecord,
	"E2E-20": harness.NoStageRecord,
	"E2E-21": harness.NoStageRecord,
	"E2E-22": domain.StageAuthz,
	"E2E-23": domain.StageAuthz,
	"E2E-24": domain.StageAuthz,
	"E2E-25": domain.StageBoundary,
	"E2E-26": domain.StageBoundary,
	"E2E-27": domain.StageBoundary,
	"E2E-28": domain.StageInput,
	"E2E-29": harness.NoStageRecord,
	"E2E-30": domain.StageExecute,
	"E2E-31": domain.StageExecute,
	"E2E-32": harness.NoStageRecord,
	"E2E-33": domain.StageExecute,
	"E2E-34": domain.StageAuthz,
	"E2E-35": domain.StageAuthn,
	"E2E-36": domain.StageBoundary,
	"E2E-37": domain.StageAuthz,
	"E2E-38": harness.NoStageRecord,
	"E2E-39": harness.NoStageRecord,
	"E2E-40": harness.NoStageRecord,
	"E2E-41": harness.NoStageRecord,
	"E2E-42": harness.NoStageRecord,
	"E2E-43": harness.NoStageRecord,
	"E2E-44": domain.StageExecute,
	"E2E-45": harness.NoStageRecord,
	"E2E-46": harness.NoStageRecord,
	"E2E-47": harness.NoStageRecord,
	"E2E-48": harness.NoStageRecord,
	"E2E-49": harness.NoStageRecord,
	"E2E-50": harness.NoStageRecord,
	"E2E-51": domain.StageBudget,
	"E2E-52": domain.StageBudget,
	"E2E-53": domain.StageSettle,
	"E2E-54": domain.StageSettle,
	"E2E-55": domain.StageAuthn,
	"E2E-56": domain.StageAuthz,
	"E2E-57": domain.StageAuthn,
	"E2E-58": domain.StageAuthn,
	"E2E-59": domain.StageExecute,
	"E2E-60": harness.NoStageRecord,
	"E2E-61": domain.StagePrecommitAudit,
	"E2E-62": domain.StageExecute,
	"E2E-63": domain.StageExecute,
	"E2E-64": domain.StageExecute,
	"E2E-65": domain.StageExecute,
	"E2E-66": domain.StageExecute,
	"E2E-67": domain.StageAuthz,
	"E2E-68": domain.StageExecute,
	"E2E-69": domain.StageAuthz,
	"E2E-70": domain.StageAuthz,
	"E2E-71": domain.StageAuthz,
	"E2E-72": domain.StageAuthz,
	"E2E-73": domain.StageAuthz,
	"E2E-74": domain.StageExecute,
	"E2E-75": domain.StageBoundary,
	"E2E-76": domain.StageExecute,
	"E2E-77": domain.StageBoundary,
	"E2E-78": harness.NoStageRecord,
	"E2E-79": harness.NoStageRecord,
}

// stagedScenario 는 시나리오의 기대 감사 단계를 표에서 채운다. 표에 없는 시나리오는 단계가 비어 등록이 실패한다.
type stagedScenario struct{ harness.Scenario }

func (s stagedScenario) Metadata() harness.ScenarioMetadata {
	m := s.Scenario.Metadata()
	m.Expected.Audit.ExpectedStage = expectedStages[m.ID]
	return m
}

func (s stagedScenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return s.Scenario.Setup(ctx, env)
}

func (s stagedScenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	return s.Scenario.Execute(ctx, env)
}

// withStages 는 그룹 단위로 시나리오에 기대 단계를 채운다. 직접 그룹 목록을 등록하는 경로도 같은 값을 받는다.
func withStages(list []harness.Scenario) []harness.Scenario {
	for i, s := range list {
		list[i] = stagedScenario{s}
	}
	return list
}
