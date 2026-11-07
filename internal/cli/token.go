package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

// TokenRunner 는 `token` 하위 명령어(issue, inspect, verify, exchange) 실행을 주관하는 러너다.
type TokenRunner struct {
	stack      *app.AppStack
	exchange   exchange.Service
	out        io.Writer
	errOut     io.Writer
	statePath  string
	privPath   string
	pubPath    string
	replayPath string
	auditPath  string
}

// NewTokenRunner 는 TokenRunner 를 생성한다.
func NewTokenRunner(out, errOut io.Writer, statePath, privPath, pubPath, replayPath, auditPath string) (*TokenRunner, error) {
	stack, err := app.BuildStack(app.AppConfig{
		StatePath:      statePath,
		PrivKeyPath:    privPath,
		PubJWKSPath:    pubPath,
		ReplayPath:     replayPath,
		AuditPath:      auditPath,
		WithoutGateway: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build token stack: %w", err)
	}

	return &TokenRunner{
		stack:      stack,
		exchange:   stack.ExchangeService,
		out:        out,
		errOut:     errOut,
		statePath:  statePath,
		privPath:   privPath,
		pubPath:    pubPath,
		replayPath: replayPath,
		auditPath:  auditPath,
	}, nil
}

// Close 는 TokenRunner 내부 스택 리소스를 정리한다.
func (r *TokenRunner) Close() error {
	if r.stack != nil {
		return r.stack.Close()
	}
	return nil
}

// Run 은 token 하위 명령어를 파싱하고 라우팅한다.
func (r *TokenRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		r.printUsage()
		return domain.ExitBadInput
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "issue":
		return r.runIssue(ctx, subArgs)
	case "inspect":
		return r.runInspect(ctx, subArgs)
	case "verify":
		return r.runVerify(ctx, subArgs)
	case "exchange":
		return r.runExchange(ctx, subArgs)
	default:
		fmt.Fprintf(r.errOut, "Error: unknown token command '%s'\n", sub)
		r.printUsage()
		return domain.ExitBadInput
	}
}

func (r *TokenRunner) runIssue(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("token issue", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	clientID := fs.String("client-id", "", "클라이언트 ID (필수: client-orchestrator, client-subagent 등)")
	clientSecret := fs.String("client-secret", "", "클라이언트 시크릿 (필수)")
	sub := fs.String("sub", "", "토큰 주체 Subject (필수, 예: worker-01)")
	scope := fs.String("scope", "", "권한 스코프 (예: file:read:docs/plan.txt)")
	aud := fs.String("aud", domain.DefaultAudience, "수신 대상 Audience")
	ttl := fs.Duration("ttl", time.Hour, "토큰 유효 기간 (기본 1h)")
	epoch := fs.Int64("epoch", 1, "Security Epoch 번호 (기본 1)")

	tamperSig := fs.Bool("tamper-signature", false, "결함 주입: 서명 변조")
	tamperAlgNone := fs.Bool("tamper-alg-none", false, "결함 주입: alg: none 변조")
	tamperTyp := fs.String("tamper-typ", "", "결함 주입: typ 헤더 조작 (예: JWT)")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if *clientID == "" || *clientSecret == "" || *sub == "" {
		fmt.Fprintf(r.errOut, "Error: --client-id, --client-secret, and --sub are required\n")
		return domain.ExitBadInput
	}

	req := token.IssueRequest{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Subject:      *sub,
		Scope:        *scope,
		Audience:     *aud,
		TTL:          *ttl,
		Epoch:        domain.Epoch(*epoch),
	}

	opts := token.IssueOptions{
		TamperSignature: *tamperSig,
		TamperAlgNone:   *tamperAlgNone,
		TamperTyp:       *tamperTyp,
	}

	auditCtx := domain.AuditContext{
		TraceID: fmt.Sprintf("issue-%d", time.Now().UnixNano()),
		Actor:   *clientID,
	}

	result, err := r.stack.TokenIssuer.IssueToken(req, opts, auditCtx)
	if err != nil {
		fmt.Fprintf(r.errOut, "FAIL: [ISSUE_DENIED] %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitTokenInvalid)
	}

	// CLI stdout 출력: 토큰 문자열 및 메타데이터 안내
	fmt.Fprintf(r.out, "PASS: [TOKEN_ISSUED] RFC 9068 Bearer Access Token 발급 완료\n")
	fmt.Fprintf(r.out, "KID:       %s\n", result.KeyID)
	fmt.Fprintf(r.out, "Subject:   %s\n", result.Claims.Subject)
	fmt.Fprintf(r.out, "Audience:  %s\n", result.Claims.Audience)
	fmt.Fprintf(r.out, "Scope:     %s\n", result.Claims.Scope)
	fmt.Fprintf(r.out, "ExpiresAt: %s\n", time.Unix(result.Claims.ExpiresAt, 0).UTC().Format(time.RFC3339))
	fmt.Fprintf(r.out, "JTI:       %s\n", result.Claims.JWTID)
	fmt.Fprintf(r.out, "\nToken:\n%s\n", result.TokenString)

	return domain.ExitSuccess
}

func (r *TokenRunner) runInspect(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("token inspect", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	tokenStr := fs.String("token", "", "파싱할 원시 JWT 토큰 문자열 (필수)")
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if *tokenStr == "" {
		fmt.Fprintf(r.errOut, "Error: --token is required\n")
		return domain.ExitBadInput
	}

	header, claims, err := r.stack.TokenVerifier.InspectToken(*tokenStr)
	if err != nil {
		fmt.Fprintf(r.errOut, "FAIL: [INSPECT_FAILED] %v\n", err)
		return domain.ExitTokenInvalid
	}

	type InspectOutput struct {
		Header *token.JWTHeader    `json:"header"`
		Claims *domain.TokenClaims `json:"claims"`
	}

	out := InspectOutput{
		Header: header,
		Claims: claims,
	}

	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Fprintln(r.out, string(b))
	return domain.ExitSuccess
}

func (r *TokenRunner) runVerify(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("token verify", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	tokenStr := fs.String("token", "", "검증할 원시 JWT 토큰 문자열 (필수)")
	expectedAud := fs.String("expected-aud", "", "기대되는 수신자 Audience (선택)")
	expectedSub := fs.String("expected-sub", "", "기대되는 주체 Subject (선택)")
	clockOffsetStr := fs.String("clock-offset", "", "가상 시계 오프셋 (예: +2h, -10m)")
	recordReplay := fs.Bool("record-replay", false, "jti 를 Replay 방지 원장에 기록 및 소비 검사")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if *tokenStr == "" {
		fmt.Fprintf(r.errOut, "Error: --token is required\n")
		return domain.ExitBadInput
	}

	offset, err := parseNonNegativeClockOffset(*clockOffsetStr)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitBadInput
	}

	opts := token.VerifyOptions{
		ExpectedAudience: *expectedAud,
		ExpectedSubject:  *expectedSub,
		RecordReplay:     *recordReplay,
		ClockOffset:      offset,
	}

	auditCtx := domain.AuditContext{
		TraceID: fmt.Sprintf("verify-%d", time.Now().UnixNano()),
		Actor:   "cli-verifier",
	}

	verified, err := r.stack.TokenVerifier.VerifyToken(*tokenStr, opts, auditCtx)
	if err != nil {
		reason := extractReason(err)
		fmt.Fprintf(r.out, "FAIL: [TOKEN_VERIFY_BLOCKED] %s\n", reason)
		fmt.Fprintf(r.errOut, "Detail: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitTokenInvalid)
	}

	// authn 단계 통과 파이프라인 시각화
	fmt.Fprintf(r.out, "PASS: [TOKEN_VERIFIED] RFC 9068 Access Token 무결성 검증 통과\n")
	fmt.Fprintf(r.out, "  [✓] 1. JWT 포맷 및 헤더 구조 (typ: at+jwt, alg: %s)\n", verified.Algorithm)
	fmt.Fprintf(r.out, "  [✓] 2. 암호학적 디지털 서명 검증 (kid: %s, Ed25519)\n", verified.KeyID)
	fmt.Fprintf(r.out, "  [✓] 3. Zone B JWKS 키 활성 상태 확인\n")
	fmt.Fprintf(r.out, "  [✓] 4. 토큰 클레임 유효성 (iss: %s, sub: %s, aud: %s)\n",
		verified.Claims.Issuer, verified.Claims.Subject, verified.Claims.Audience)
	fmt.Fprintf(r.out, "  [✓] 5. 토큰 시간 유효성 (exp: %s)\n",
		time.Unix(verified.Claims.ExpiresAt, 0).UTC().Format(time.RFC3339))
	if *recordReplay {
		fmt.Fprintf(r.out, "  [✓] 6. 일회성 jti Replay 소비 확인 (jti: %s)\n", verified.Claims.JWTID)
	}
	fmt.Fprintf(r.out, "Scope: %s\n", verified.Claims.Scope)
	fmt.Fprintf(r.out, "Epoch: %d\n", verified.Claims.Epoch)

	return domain.ExitSuccess
}

func (r *TokenRunner) runExchange(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("token exchange", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	parentToken := fs.String("parent-token", "", "위임 주체(부모)의 유효한 Access Token 문자열 (필수)")
	childSub := fs.String("child-sub", "", "자식 토큰 주체 Subject (필수, 예: worker-01)")
	scope := fs.String("scope", "", "축소 위임할 스코프 (필수, 예: file:read:docs/plan.txt)")
	clientID := fs.String("client-id", "", "클라이언트 ID (필수: client-orchestrator, client-subagent 등)")
	clientSecret := fs.String("client-secret", "", "클라이언트 시크릿 (필수)")
	aud := fs.String("aud", "", "수신 대상 Audience (기본: 부모 토큰 aud 상속)")
	ttl := fs.Duration("ttl", 30*time.Minute, "자식 토큰 유효 기간 (기본 30m)")
	clockOffsetStr := fs.String("clock-offset", "", "가상 시계 오프셋 (예: +2h, -10m)")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if *parentToken == "" || *childSub == "" || *scope == "" || *clientID == "" || *clientSecret == "" {
		fmt.Fprintf(r.errOut, "Error: --parent-token, --child-sub, --scope, --client-id, and --client-secret are required\n")
		return domain.ExitBadInput
	}

	// 가상 시계 지원
	exchangeService := r.exchange
	if *clockOffsetStr != "" {
		d, err := parseNonNegativeClockOffset(*clockOffsetStr)
		if err != nil {
			fmt.Fprintf(r.errOut, "Error: %v\n", err)
			return domain.ExitBadInput
		}
		offsetClock := domain.NewOffsetClock(domain.RealClock{}, d)
		offsetStack, err := app.BuildStack(app.AppConfig{
			StatePath:      r.statePath,
			PrivKeyPath:    r.privPath,
			PubJWKSPath:    r.pubPath,
			ReplayPath:     r.replayPath,
			AuditPath:      r.auditPath,
			WithoutGateway: true,
			Clock:          offsetClock,
		})
		if err != nil {
			fmt.Fprintf(r.errOut, "Error: failed to build offset stack: %v\n", err)
			return domain.ExitInternalError
		}
		defer offsetStack.Close()

		exchangeService = offsetStack.ExchangeService
	}

	req := exchange.ExchangeRequest{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		ParentToken:  *parentToken,
		ChildSubject: *childSub,
		Scope:        *scope,
		Audience:     *aud,
		TTL:          *ttl,
	}

	auditCtx := domain.AuditContext{
		TraceID: fmt.Sprintf("exchange-%d", time.Now().UnixNano()),
		Actor:   *clientID,
	}

	res, err := exchangeService.Exchange(ctx, req, auditCtx)
	if err != nil {
		reason := extractReason(err)
		fmt.Fprintf(r.out, "FAIL: [EXCHANGE_DENIED] %s\n", reason)
		fmt.Fprintf(r.errOut, "Detail: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitTokenInvalid)
	}

	// CLI 표준 위임 성공 뷰 출력
	fmt.Fprintln(r.out, "┌─────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(r.out, "│ RFC 8693 Token Exchange & Downscoping Pipeline [SUCCESS]    │")
	fmt.Fprintln(r.out, "├─────────────────────────────────────────────────────────────┤")
	fmt.Fprintf(r.out, "│ Parent JTI:    %s\n", res.ParentJTI)
	fmt.Fprintf(r.out, "│ Child Subject: %s\n", res.Claims.Subject)
	fmt.Fprintf(r.out, "│ Granted Scope: %s\n", res.Claims.Scope)
	fmt.Fprintf(r.out, "│ Delegation:    Depth %d (Parent -> %s)\n", res.DelegationDepth, res.Claims.Subject)
	fmt.Fprintf(r.out, "│ Expires At:    %s\n", time.Unix(res.Claims.ExpiresAt, 0).UTC().Format(time.RFC3339))
	fmt.Fprintln(r.out, "├─────────────────────────────────────────────────────────────┤")
	fmt.Fprintln(r.out, "│ Delegated Child Token Issued:                               │")
	fmt.Fprintf(r.out, "│ %s\n", res.TokenString)
	fmt.Fprintln(r.out, "└─────────────────────────────────────────────────────────────┘")

	return domain.ExitSuccess
}

func extractReason(err error) string {
	if err == nil {
		return ""
	}
	r := domain.ReasonFromError(err, "")
	if r != "" {
		return string(r)
	}
	return "TOKEN_VERIFICATION_FAILED"
}

func (r *TokenRunner) printUsage() {
	fmt.Fprintln(r.errOut, "Usage: authz-harness token <command> [options]")
	fmt.Fprintln(r.errOut, "\nCommands:")
	fmt.Fprintln(r.errOut, "  issue    RFC 9068 Bearer Access Token 발급")
	fmt.Fprintln(r.errOut, "  inspect  서명 검증 없이 토큰 헤더 및 페이로드 덤프")
	fmt.Fprintln(r.errOut, "  verify   authn 단계 암호학적 무결성 및 클레임 검증")
	fmt.Fprintln(r.errOut, "  exchange RFC 8693 Token Exchange 축소 위임 토큰 발급")
}
