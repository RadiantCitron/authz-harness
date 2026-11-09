// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(approval.go)은 사람 승인자(Human Approver)를 대역하여 권한 승인을 부여하고 조회하는 `approval` 서브커맨드 러너를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. HITL (Human-In-The-Loop) 사람 승인 대역:
//    - 높은 권한 작업이나 특정 Grant 에서 `RequiresApproval: true` 로 지정된 요청에 대해 외부 관리자가 사전 승인을 부여한다.
//    - grant: 주체(Subject), 액션(Action), 리소스(Resource), 토큰 식별자(TokenJTI), 인자 해시(ArgHash), 유효 기간(TTL)을 명시하여 승인 레코드를 생성.
//    - list: 특정 주체에 등록되어 있는 유효한 승인 목록 조회.
// 2. 바인딩 및 부인 방지 (Cryptographic & Token Binding):
//    - 승인은 특정 토큰(JTI) 및 인자 지문(ArgHash: sha256)에 강하게 결합(Binding)될 수 있어 토큰 탈취 및 매개변수 변조 공격을 방어한다.
// 3. TTL 시간 제한 (Strict TTL Enforcement):
//    - 승인은 기본 5분, 최대 1시간의 엄격한 만료 시간을 가지며, 만료된 승인은 PEP 단계에서 즉시 거부된다.
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

// ApprovalRunner 는 사람 승인자를 대역하는 `approval` 하위 명령어(grant, list) 러너다.
// PAP(Policy Administration Point) 서비스를 통해 승인 상태 레코드를 생성하고 조회한다.
type ApprovalRunner struct {
	out       io.Writer // 표준 출력 스트림
	errOut    io.Writer // 표준 에러 스트림
	statePath string    // Zone B 상태(State) 파일 경로
	auditPath string    // 감사 로그 파일 경로
}

// NewApprovalRunner 는 상태 파일·감사 파일 경로로 ApprovalRunner 를 생성한다.
func NewApprovalRunner(out, errOut io.Writer, statePath, auditPath string) (*ApprovalRunner, error) {
	return &ApprovalRunner{out: out, errOut: errOut, statePath: statePath, auditPath: auditPath}, nil
}

// Run 은 `approval grant|list` 서브커맨드를 라우팅하고 종료 코드를 반환한다.
func (r *ApprovalRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	stack, err := app.BuildStack(app.AppConfig{StatePath: r.statePath, AuditPath: r.auditPath, WithoutGateway: true})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to initialize approval runner: %v\n", err)
		return domain.ExitInternalError
	}
	defer stack.Close()

	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: approval subcommand required (grant, list)\n")
		return domain.ExitBadInput
	}
	switch args[0] {
	case "grant":
		return r.runGrant(ctx, stack.PAP, args[1:])
	case "list":
		return r.runList(ctx, stack.PAP, args[1:])
	default:
		fmt.Fprintf(r.errOut, "Error: unknown approval subcommand '%s'\n", args[0])
		return domain.ExitBadInput
	}
}

// runGrant 는 사람 승인 레코드를 신규 생성한다 (JTI 및 ArgHash 바인딩 지원).
func (r *ApprovalRunner) runGrant(ctx context.Context, papSvc pap.Service, args []string) domain.ExitCode {
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
	a, err := papSvc.CreateApproval(ctx, pap.CreateApprovalRequest{
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

// runList 는 주체별로 등록된 활성 승인 목록을 조회하여 출력한다.
func (r *ApprovalRunner) runList(ctx context.Context, papSvc pap.Service, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("approval list", flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	var sub string
	fs.StringVar(&sub, "subject", "", "필터링할 주체")
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}
	list, err := papSvc.ListApprovals(ctx, sub)
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
