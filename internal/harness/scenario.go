package harness

import (
	"context"

	"authz-harness/internal/domain"
)

// ScenarioMetadata 는 시나리오의 정적 설명 및 카탈로그 정보이다.
type ScenarioMetadata struct {
	ID                 string            `json:"id"`                  // "E2E-01" ~ "E2E-30"
	Group              string            `json:"group"`               // "G1" ~ "G7"
	Name               string            `json:"name"`                // 시나리오 명칭
	Description        string            `json:"description"`         // 시나리오 설명
	AttackClass        string            `json:"attack_class"`        // 정상 또는 공격 유형
	ParadoxExplanation string            `json:"paradox_explanation"` // 초보자용 역설 해설
	Expected           ExpectedAssertion `json:"expected"`            // 기대 4중 검증 스펙
}

// Scenario 는 하네스가 독립적으로 실행하고 검증할 수 있는 단위 시나리오 규약이다.
type Scenario interface {
	// Metadata 는 시나리오의 정적 정보와 기대 검증 스펙을 반환한다.
	Metadata() ScenarioMetadata

	// Setup 은 샌드박스 환경 내에 시나리오에 필요한 초기 상태(키, Grant, 파일 등)를 구성한다.
	Setup(ctx context.Context, env *SandboxEnvironment) error

	// Execute 는 시나리오의 실제 공격 또는 정상 워크플로를 실행하고 종료 코드를 반환한다.
	Execute(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error)
}
