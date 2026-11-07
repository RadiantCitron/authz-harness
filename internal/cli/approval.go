package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
)

// ApprovalRunner 는 사람 승인자를 대역하는 `approval` 하위 명령어 러너다.
type ApprovalRunner struct {
	papSvc pap.Service
	stack  *app.AppStack
	out    io.Writer
	errOut io.Writer
}

// NewApprovalRunner 는 상태 파일·감사 파일 경로로 ApprovalRunner 를 생성한다.
func NewApprovalRunner(out, errOut io.Writer, statePath, auditPath string) (*ApprovalRunner, error) {
	stack, err := app.BuildStack(app.AppConfig{StatePath: statePath, AuditPath: auditPath, WithoutGateway: true})
	if err != nil {
		return nil, err
	}
	return &ApprovalRunner{papSvc: stack.PAP, stack: stack, out: out, errOut: errOut}, nil
}

// Close 는 러너가 소유한 합성 루트 자원(감사 파일 등)을 정리한다.
func (r *ApprovalRunner) Close() error {
	return r.stack.Close()
}

// Run 은 `approval grant|list` 를 라우팅한다.
func (r *ApprovalRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: approval subcommand required (grant, list)\n")
		return domain.ExitBadInput
	}
	switch args[0] {
	case "grant":
		return r.runGrant(ctx, args[1:])
	case "list":
		return r.runList(ctx, args[1:])
	default:
		fmt.Fprintf(r.errOut, "Error: unknown approval subcommand '%s'\n", args[0])
		return domain.ExitBadInput
	}
}

func (r *ApprovalRunner) runGrant(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("approval grant", flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	var sub, act, res, jti, argHash string
	var ttl time.Duration
	fs.StringVar(&sub, "subject", "", "승인 대상 주체")
	fs.StringVar(&act, "action", "", "승인할 액션 (file:read, file:write, net:fetch, exec:run, read, write)")
	fs.StringVar(&res, "resource", "", "승인할 리소스")
	fs.StringVar(&jti, "jti", "", "승인을 묶을 토큰 jti")
	fs.StringVar(&argHash, "arg-hash", "", "선택: 인자 지문 (sha256:<64 hex>)")
	fs.DurationVar(&ttl, "ttl", 0, "승인 유효 시간 (기본 5m, 상한 1h)")
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}
	action, err := domain.ParseAction(act)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitBadInput
	}
	a, err := r.papSvc.CreateApproval(ctx, pap.CreateApprovalRequest{
		Subject: sub, Action: action, Resource: res, TokenJTI: jti, ArgHash: argHash, TTL: ttl,
	})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}
	fmt.Fprintf(r.out, "[APPROVAL GRANTED] ID: %s | Subject: %s | Action: %s | Resource: %s | JTI: %s | ExpiresAt: %s\n",
		a.ID, a.Subject, a.Action, a.Resource, a.TokenJTI, a.ExpiresAt.Format(time.RFC3339))
	return domain.ExitSuccess
}

func (r *ApprovalRunner) runList(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("approval list", flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	var sub string
	fs.StringVar(&sub, "subject", "", "필터링할 주체")
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}
	list, err := r.papSvc.ListApprovals(ctx, sub)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitInternalError
	}
	if len(list) == 0 {
		fmt.Fprintln(r.out, "No approvals found.")
		return domain.ExitSuccess
	}
	for _, a := range list {
		fmt.Fprintf(r.out, "ID: %s | Sub: %s | Action: %s | Resource: %s | JTI: %s | ArgHash: %s | ExpiresAt: %s\n",
			a.ID, a.Subject, a.Action, a.Resource, a.TokenJTI, a.ArgHash, a.ExpiresAt.Format(time.RFC3339))
	}
	return domain.ExitSuccess
}
