// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(grant.go)은 인가 정책 관리점(PAP: Policy Administration Point)을 조작하는 `grant` 서브커맨드 러너를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. PAP 정책 관리 (Policy Administration):
//    - create: 주체(Subject), 액션(Action), 리소스(Resource), 승인 요구 여부(RequiresApproval)를 갖는 권한(Grant)을 신규 발급.
//    - revoke: 특정 Grant ID를 즉시 폐기(Revoked) 상태로 전이하여 후속 인가 요청을 차단.
//    - bump-epoch: 주체의 Security Epoch 카운터를 증가시켜, 이전 Epoch 로 발급된 모든 토큰/인가를 즉시 광역 무효화.
//    - list: 특정 주체 또는 상태(active, revoked)에 따른 등록된 Grant 목록 조회.
// 2. 의존성 주입 및 불필요 컴포넌트 배제:
//    - app.BuildStack 호출 시 WithoutGateway: true 로 설정하여 PAP 조작에 불필요한 PEP 게이트웨이 초기화를 건너뛴다.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
)

// GrantRunner 는 `grant` 하위 명령어(create, revoke, bump-epoch, list) 실행을 주관하는 러너다.
// 인가 관리점(PAP: Policy Administration Point) 서비스와 연동하여 정책 상태 파일 및 감사 로그를 다룬다.
type GrantRunner struct {
	out       io.Writer // 표준 출력 스트림
	errOut    io.Writer // 표준 에러 스트림
	auditPath string    // 감사 로그 파일 경로
	statePath string    // Zone B 상태(State) 파일 경로
}

// NewGrantRunner 는 지정된 입출력 스트림과 파일 경로로 GrantRunner를 생성한다.
func NewGrantRunner(out, errOut io.Writer, statePath, auditPath string) (*GrantRunner, error) {
	return &GrantRunner{
		out:       out,
		errOut:    errOut,
		auditPath: auditPath,
		statePath: statePath,
	}, nil
}

// Run 은 전달받은 인자(args)를 바탕으로 `grant` 서브커맨드를 라우팅하고 적절한 종료 코드를 반환한다.
func (r *GrantRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	stack, err := app.BuildStack(app.AppConfig{StatePath: r.statePath, AuditPath: r.auditPath, WithoutGateway: true})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to initialize grant runner: %v\n", err)
		return domain.ExitInternalError
	}
	defer stack.Close()

	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: grant subcommand required (create, revoke, bump-epoch, list)\n")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "create":
		return r.runCreate(ctx, stack.PAP, subArgs)
	case "revoke":
		return r.runRevoke(ctx, stack.PAP, subArgs)
	case "bump-epoch":
		return r.runBumpEpoch(ctx, stack.PAP, subArgs)
	case "list":
		return r.runList(ctx, stack.PAP, subArgs)
	default:
		fmt.Fprintf(r.errOut, "Error: unknown grant subcommand '%s'\n", subcmd)
		return domain.ExitBadInput
	}
}

// runCreate 는 주체, 액션, 리소스에 대한 신규 권한 부여(Grant)를 생성하고 고유 ID를 출력한다.
func (r *GrantRunner) runCreate(ctx context.Context, papSvc pap.Service, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("grant create", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var sub, act, res string
	var requiresApproval bool
	fs.BoolVar(&requiresApproval, "requires-approval", false, "이 Grant 로 허용되는 요청에 사람 승인을 요구한다")
	fs.StringVar(&sub, "sub", "", "권한 부여 대상 주체 (Subject)")
	fs.StringVar(&act, "action", "", "허용할 액션 (file:read, file:write, net:fetch, exec:run)")
	fs.StringVar(&res, "resource", "", "허용할 리소스 경로")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if strings.TrimSpace(sub) == "" || strings.TrimSpace(act) == "" || strings.TrimSpace(res) == "" {
		fmt.Fprintf(r.errOut, "Error: --sub, --action, --resource are all required\n")
		return domain.ExitBadInput
	}

	action, err := domain.ParseAction(act)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitBadInput
	}

	grant, err := papSvc.CreateGrant(ctx, pap.CreateGrantRequest{
		Subject:          sub,
		Action:           action,
		Resource:         res,
		RequiresApproval: requiresApproval,
	})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	fmt.Fprintf(r.out, "[GRANT CREATED] ID: %s | Subject: %s | Action: %s | Resource: %s\n",
		grant.ID, grant.Subject, grant.Action, grant.Resource)
	return domain.ExitSuccess
}

// runRevoke 는 특정 Grant ID 를 회수(Revoke)하여 더 이상 PDP 에서 유효하지 않도록 처리한다.
func (r *GrantRunner) runRevoke(ctx context.Context, papSvc pap.Service, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("grant revoke", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var id string
	fs.StringVar(&id, "id", "", "회수할 Grant ID")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if strings.TrimSpace(id) == "" {
		fmt.Fprintf(r.errOut, "Error: --id is required\n")
		return domain.ExitBadInput
	}

	revoked, err := papSvc.RevokeGrant(ctx, id)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	revokedAtStr := ""
	if revoked.RevokedAt != nil {
		revokedAtStr = revoked.RevokedAt.Format(time.RFC3339)
	}

	fmt.Fprintf(r.out, "[GRANT REVOKED] ID: %s | RevokedAt: %s\n", revoked.ID, revokedAtStr)
	return domain.ExitSuccess
}

// runBumpEpoch 는 특정 주체의 Security Epoch 카운터를 증가시켜, 이전 에포크를 지닌 모든 토큰을 광역 무효화한다.
func (r *GrantRunner) runBumpEpoch(ctx context.Context, papSvc pap.Service, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("grant bump-epoch", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var sub string
	fs.StringVar(&sub, "sub", "", "Epoch를 증가시킬 주체 (Subject)")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if strings.TrimSpace(sub) == "" {
		fmt.Fprintf(r.errOut, "Error: --sub is required\n")
		return domain.ExitBadInput
	}

	newEpoch, err := papSvc.BumpEpoch(ctx, sub)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	prevEpoch := newEpoch - 1
	fmt.Fprintf(r.out, "[EPOCH BUMPED] Subject: %s | Previous: %d -> Current: %d\n", sub, prevEpoch, newEpoch)
	return domain.ExitSuccess
}

// runList 는 조건(주체 및 상태 필터)에 부합하는 모든 Grant 목록을 출력한다.
func (r *GrantRunner) runList(ctx context.Context, papSvc pap.Service, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("grant list", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var sub, statusStr string
	fs.StringVar(&sub, "sub", "", "필터링할 주체 (Subject)")
	fs.StringVar(&statusStr, "status", "", "필터링할 상태 (active, revoked)")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	filter := pap.GrantFilter{
		Subject: strings.TrimSpace(sub),
	}
	if strings.TrimSpace(statusStr) != "" {
		st := domain.GrantStatus(statusStr)
		if st != domain.GrantStatusActive && st != domain.GrantStatusRevoked {
			fmt.Fprintf(r.errOut, "Error: invalid status '%s' (must be active or revoked)\n", statusStr)
			return domain.ExitBadInput
		}
		filter.Status = &st
	}

	grants, err := papSvc.ListGrants(ctx, filter)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitInternalError
	}

	if len(grants) == 0 {
		fmt.Fprintln(r.out, "No grants found.")
		return domain.ExitSuccess
	}

	for _, g := range grants {
		revokedStr := "-"
		if g.RevokedAt != nil {
			revokedStr = g.RevokedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(r.out, "ID: %s | Sub: %s | Action: %s | Status: %s | Resource: %s | RevokedAt: %s\n",
			g.ID, g.Subject, g.Action, g.Status, g.Resource, revokedStr)
	}

	return domain.ExitSuccess
}
