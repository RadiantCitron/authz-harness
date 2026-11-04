package catalog

import (
	"authz-harness/internal/harness"
)

// AllScenarios 는 E2E-01 부터 E2E-44 까지 9대 그룹 44개 전체 시나리오 인스턴스를 반환한다.
func AllScenarios() []harness.Scenario {
	var list []harness.Scenario
	list = append(list, g1Scenarios()...)
	list = append(list, g2Scenarios()...)
	list = append(list, g3Scenarios()...)
	list = append(list, g4Scenarios()...)
	list = append(list, g5Scenarios()...)
	list = append(list, g6Scenarios()...)
	list = append(list, g7Scenarios()...)
	list = append(list, g8Scenarios()...)
	list = append(list, g9Scenarios()...)
	return list
}

// RegisterAll 은 주어진 하네스 러너에 32개 시나리오를 일괄 등록한다.
func RegisterAll(r harness.Runner) error {
	for _, s := range AllScenarios() {
		if err := r.Register(s); err != nil {
			return err
		}
	}
	return nil
}
