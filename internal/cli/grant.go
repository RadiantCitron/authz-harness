package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

// GrantRunner 는 `grant` 하위 명령어 실행을 주관하는 러너다.
type GrantRunner struct {
	papSvc    pap.Service
	out       io.Writer
	errOut    io.Writer
	auditPath string
	statePath string
}

// NewGrantRunner 는 지정된 입출력 스트림과 파일 경로로 GrantRunner를 생성한다.
func NewGrantRunner(out, errOut io.Writer, statePath, auditPath string) (*GrantRunner, error) {
	st, err := state.NewFileStore(statePath)
	if err != nil {
		return nil, fmt.Errorf("failed to init state store: %w", err)
	}

	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init audit writer: %w", err)
	}

	papSvc := pap.NewService(st, auditWriter)

	return &GrantRunner{
		papSvc:    papSvc,
		out:       out,
		errOut:    errOut,
		auditPath: auditPath,
		statePath: statePath,
	}, nil
}

// Run 은 전달받은 인자(args)를 바탕으로 `grant` 서브커맨드를 라우팅하고 적절한 종료 코드를 반환한다.
func (r *GrantRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: grant subcommand required (create, revoke, bump-epoch, list)\n")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "create":
		return r.runCreate(ctx, subArgs)
	case "revoke":
		return r.runRevoke(ctx, subArgs)
	case "bump-epoch":
		return r.runBumpEpoch(ctx, subArgs)
	case "list":
		return r.runList(ctx, subArgs)
	default:
		fmt.Fprintf(r.errOut, "Error: unknown grant subcommand '%s'\n", subcmd)
		return domain.ExitBadInput
	}
}

func (r *GrantRunner) runCreate(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("grant create", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var sub, act, res string
	fs.StringVar(&sub, "sub", "", "권한 부여 대상 주체 (Subject)")
	fs.StringVar(&act, "action", "", "허용할 액션 (file:read, file:write)")
	fs.StringVar(&res, "resource", "", "허용할 리소스 경로")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if strings.TrimSpace(sub) == "" || strings.TrimSpace(act) == "" || strings.TrimSpace(res) == "" {
		fmt.Fprintf(r.errOut, "Error: --sub, --action, --resource are all required\n")
		return domain.ExitBadInput
	}

	action := domain.Action(act)
	if action != domain.ActionFileRead && action != domain.ActionFileWrite {
		fmt.Fprintf(r.errOut, "Error: invalid action '%s' (must be file:read or file:write)\n", act)
		return domain.ExitBadInput
	}

	grant, err := r.papSvc.CreateGrant(ctx, pap.CreateGrantRequest{
		Subject:  sub,
		Action:   action,
		Resource: res,
	})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	fmt.Fprintf(r.out, "[GRANT CREATED] ID: %s | Subject: %s | Action: %s | Resource: %s\n",
		grant.ID, grant.Subject, grant.Action, grant.Resource)
	return domain.ExitSuccess
}

func (r *GrantRunner) runRevoke(ctx context.Context, args []string) domain.ExitCode {
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

	revoked, err := r.papSvc.RevokeGrant(ctx, id)
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

func (r *GrantRunner) runBumpEpoch(ctx context.Context, args []string) domain.ExitCode {
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

	newEpoch, err := r.papSvc.BumpEpoch(ctx, sub)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	prevEpoch := newEpoch - 1
	fmt.Fprintf(r.out, "[EPOCH BUMPED] Subject: %s | Previous: %d -> Current: %d\n", sub, prevEpoch, newEpoch)
	return domain.ExitSuccess
}

func (r *GrantRunner) runList(ctx context.Context, args []string) domain.ExitCode {
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

	grants, err := r.papSvc.ListGrants(ctx, filter)
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
