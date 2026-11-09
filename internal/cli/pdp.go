package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"authz-harness/internal/app"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/domain"
)

// PDPRunner 는 `pdp` 하위 명령어(decide, explain) 실행을 주관하는 러너다.
type PDPRunner struct {
	out       io.Writer
	errOut    io.Writer
	auditPath string
	statePath string
}

// NewPDPRunner 는 지정된 입출력 스트림과 파일 경로로 PDPRunner를 생성한다.
func NewPDPRunner(out, errOut io.Writer, statePath, auditPath string) (*PDPRunner, error) {
	return &PDPRunner{
		out:       out,
		errOut:    errOut,
		auditPath: auditPath,
		statePath: statePath,
	}, nil
}

// Run 은 전달받은 인자(args)를 바탕으로 `pdp` 서브커맨드를 라우팅하고 적절한 종료 코드를 반환한다.
func (r *PDPRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	stack, err := app.BuildStack(app.AppConfig{StatePath: r.statePath, AuditPath: r.auditPath, VerifyOnly: true})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to initialize pdp runner: %v\n", err)
		return domain.ExitInternalError
	}
	defer stack.Close()

	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: pdp subcommand required (decide, explain)\n")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "decide":
		return r.runDecide(ctx, stack.PDP, subArgs)
	case "explain":
		return r.runExplain(ctx, stack.PDP, stack.PIP, subArgs)
	default:
		fmt.Fprintf(r.errOut, "Error: unknown pdp subcommand '%s'\n", subcmd)
		return domain.ExitBadInput
	}
}

func (r *PDPRunner) parsePDPRequest(cmdName string, args []string) (*pdp.Request, domain.ExitCode) {
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var sub, act, res, scope string
	var epoch int64
	fs.StringVar(&sub, "sub", "", "인가 대상 주체 (Subject)")
	fs.StringVar(&act, "action", "", "요청 액션 (file:read, file:write, net:fetch, exec:run)")
	fs.StringVar(&res, "resource", "", "요청 대상 리소스 경로")
	fs.StringVar(&scope, "scope", "", "제시된 토큰 스코프 (선택)")
	fs.Int64Var(&epoch, "epoch", 1, "제시된 Security Epoch (기본값: 1)")

	if err := fs.Parse(args); err != nil {
		return nil, domain.ExitBadInput
	}

	if strings.TrimSpace(sub) == "" || strings.TrimSpace(act) == "" || strings.TrimSpace(res) == "" {
		fmt.Fprintf(r.errOut, "Error: --sub, --action, --resource are all required\n")
		return nil, domain.ExitBadInput
	}

	action, err := domain.ParseAction(act)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return nil, domain.ExitBadInput
	}

	return &pdp.Request{
		Subject:      sub,
		Action:       action,
		Resource:     res,
		Epoch:        domain.Epoch(epoch),
		TokenScope:   scope,
		RequireScope: scope != "",
	}, domain.ExitSuccess
}

func (r *PDPRunner) runDecide(ctx context.Context, pdpSvc pdp.Service, args []string) domain.ExitCode {
	req, code := r.parsePDPRequest("pdp decide", args)
	if code != domain.ExitSuccess {
		return code
	}

	decision, err := pdpSvc.Decide(ctx, *req)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: decision evaluation failed: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	if decision.Decision == pdp.DecisionAllow {
		fmt.Fprintf(r.out, "[DECISION: ALLOW] Subject: %s | Action: %s | Resource: %s | Reason: %s | GrantID: %s\n",
			req.Subject, req.Action, req.Resource, decision.Reason, decision.GrantID)
		return domain.ExitSuccess
	}

	// 거부(DENY) 시 표준 포맷 출력 및 12 종료 코드 반환
	fmt.Fprintf(r.out, "[DECISION: DENY] Subject: %s | Action: %s | Resource: %s | Reason: %s\n",
		req.Subject, req.Action, req.Resource, decision.Reason)
	return domain.ExitCodeForReason(decision.Reason)
}

func (r *PDPRunner) runExplain(ctx context.Context, pdpSvc pdp.Service, pipSvc pip.Service, args []string) domain.ExitCode {
	req, code := r.parsePDPRequest("pdp explain", args)
	if code != domain.ExitSuccess {
		return code
	}

	// PIP로부터 현재 스냅샷 조회 (설명 뷰를 위한 상세 상태)
	snapshot, err := pipSvc.GetSubjectSnapshot(ctx, req.Subject)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to query pip snapshot: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	// 결정 수행 (감사 로그 자동 기록)
	decision, err := pdpSvc.Decide(ctx, *req)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: decision evaluation failed: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	// PDP 만 실행했으므로 판정 칸 하나만 그린다. 토큰 검증·경계·감사는 이 명령이 실행하지 않은 일이라 그리지 않는다.
	pdpGateStatus := "[PASS]"
	if decision.Decision != pdp.DecisionAllow {
		pdpGateStatus = fmt.Sprintf("[FAIL] Reason: %s", decision.Reason)
	}

	// 회수된 일시 등 매칭 Grant 상세
	matchedGrantInfo := "None"
	if decision.GrantID != "" {
		if decision.Decision == pdp.DecisionAllow {
			matchedGrantInfo = fmt.Sprintf("%s (Active)", decision.GrantID)
		} else {
			// 회수된 그랜트 일시 조회
			revokedAtStr := ""
			for _, g := range snapshot.RevokedGrants {
				if g.ID == decision.GrantID && g.RevokedAt != nil {
					revokedAtStr = fmt.Sprintf(" (Revoked at %s)", g.RevokedAt.Format("2006-01-02T15:04:05Z"))
					break
				}
			}
			matchedGrantInfo = fmt.Sprintf("%s%s", decision.GrantID, revokedAtStr)
		}
	}

	fmt.Fprintf(r.out, "================================================================================\n")
	fmt.Fprintf(r.out, "                    AUTHZ PIPELINE VERIFICATION REPORT\n")
	fmt.Fprintf(r.out, "================================================================================\n")
	fmt.Fprintf(r.out, " [%s] : %s\n", stageLabel(domain.StageAuthz), pdpGateStatus)
	fmt.Fprintf(r.out, "--------------------------------------------------------------------------------\n")
	fmt.Fprintf(r.out, " REQUEST CONTEXT:\n")
	fmt.Fprintf(r.out, "  - Subject         : %s\n", req.Subject)
	fmt.Fprintf(r.out, "  - Action          : %s\n", req.Action)
	fmt.Fprintf(r.out, "  - Resource        : %s\n", req.Resource)
	fmt.Fprintf(r.out, "  - Presented Epoch : %d\n", req.Epoch)
	fmt.Fprintf(r.out, "  - Current Epoch   : %d\n", snapshot.CurrentEpoch)
	fmt.Fprintf(r.out, "--------------------------------------------------------------------------------\n")
	fmt.Fprintf(r.out, " PDP EVALUATION RESULT:\n")
	fmt.Fprintf(r.out, "  - Final Decision  : %s\n", decision.Decision)
	fmt.Fprintf(r.out, "  - Primary Reason  : %s\n", decision.Reason)
	fmt.Fprintf(r.out, "  - Matched Grant   : %s\n", matchedGrantInfo)
	fmt.Fprintf(r.out, "  - Detail Message  : %s\n", decision.Details)
	fmt.Fprintf(r.out, "--------------------------------------------------------------------------------\n")
	if decision.Decision == pdp.DecisionDeny {
		fmt.Fprintf(r.out, " [안내: 부정 테스트 역설 해소 (Negative Test Resolution)]\n")
		fmt.Fprintf(r.out, "  * 본 인가 거부(DENY)는 하네스/엔진 오류가 아니라, 미인가 접근 시도를 성공적으로 차단한 정상 방어 결과입니다.\n")
	} else {
		fmt.Fprintf(r.out, " [안내: 긍정 인가 승인 (Positive Grant Resolution)]\n")
		fmt.Fprintf(r.out, "  * 본 인가 허용(ALLOW)은 등록된 활성 Grant 및 Security Epoch 일치에 기반한 정상 승인 결과입니다.\n")
	}
	fmt.Fprintf(r.out, "================================================================================\n")

	// explain 뷰는 설명 조회가 목적이므로 종료 코드 0 반환
	return domain.ExitSuccess
}

// stageLabel 은 정식 단계 목록에서 화면 이름을 읽는다.
func stageLabel(id domain.Stage) string {
	for _, s := range domain.PEPStages() {
		if s.ID == id {
			return s.Label
		}
	}
	return string(id)
}
