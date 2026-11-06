package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/domain"
)

// KeysRunner 는 `keys` 하위 명령어 실행을 주관하는 러너다.
type KeysRunner struct {
	mgr       keys.KeyManager
	stack     *app.AppStack
	out       io.Writer
	errOut    io.Writer
	privPath  string
	pubPath   string
	auditPath string
}

// NewKeysRunner 는 지정된 입출력 스트림과 키 파일 경로로 KeysRunner를 생성한다.
func NewKeysRunner(out, errOut io.Writer, privPath, pubPath, auditPath string) (*KeysRunner, error) {
	stack, err := app.BuildStack(app.AppConfig{PrivKeyPath: privPath, PubJWKSPath: pubPath, AuditPath: auditPath})
	if err != nil {
		return nil, err
	}

	return &KeysRunner{
		mgr:       stack.KeyManager,
		stack:     stack,
		out:       out,
		errOut:    errOut,
		privPath:  privPath,
		pubPath:   pubPath,
		auditPath: auditPath,
	}, nil
}

// Close 는 러너가 소유한 합성 루트 자원(감사 파일 등)을 정리한다.
func (r *KeysRunner) Close() error {
	return r.stack.Close()
}

// Run 은 전달받은 인자(args)를 바탕으로 `keys` 서브커맨드를 라우팅하고 적절한 종료 코드를 반환한다.
func (r *KeysRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: keys subcommand required (list, rotate, revoke)\n")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "list":
		return r.runList(subArgs)
	case "rotate":
		return r.runRotate(subArgs)
	case "revoke":
		return r.runRevoke(subArgs)
	default:
		fmt.Fprintf(r.errOut, "Error: unknown keys subcommand '%s'. Available: list, rotate, revoke\n", subcmd)
		return domain.ExitBadInput
	}
}

func (r *KeysRunner) runList(args []string) domain.ExitCode {
	fs := flag.NewFlagSet("keys list", flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	keyList, err := r.mgr.ListKeys()
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to list keys: %v\n", err)
		return domain.ExitInternalError
	}

	if len(keyList) == 0 {
		fmt.Fprintln(r.out, "No keys found in key ring.")
		return domain.ExitSuccess
	}

	w := tabwriter.NewWriter(r.out, 0, 4, 3, ' ', 0)
	fmt.Fprintln(w, "KID\tALGORITHM\tSTATUS\tCREATED_AT\tROTATED_AT\tRETIRED_AT")
	for _, k := range keyList {
		rotStr := "-"
		if k.RotatedAt != nil {
			rotStr = k.RotatedAt.Format(time.RFC3339)
		}
		retStr := "-"
		if k.RetiredAt != nil {
			retStr = k.RetiredAt.Format(time.RFC3339)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			k.KID,
			fmt.Sprintf("%s/%s", k.Algorithm, k.Curve),
			k.Status,
			k.CreatedAt.Format(time.RFC3339),
			rotStr,
			retStr,
		)
	}
	w.Flush()

	return domain.ExitSuccess
}

func (r *KeysRunner) runRotate(args []string) domain.ExitCode {
	fs := flag.NewFlagSet("keys rotate", flag.ContinueOnError)
	actor := fs.String("actor", "operator", "키 회전을 수행하는 행위자")
	reason := fs.String("reason", "manual rotation", "키 회전 사유")
	traceID := fs.String("trace-id", "", "추적 Trace ID (생략 시 자동 생성)")
	fs.SetOutput(r.errOut)

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	tid := *traceID
	if tid == "" {
		tid = fmt.Sprintf("rotate-%d", time.Now().UnixNano())
	}

	auditCtx := domain.AuditContext{
		TraceID: tid,
		Actor:   *actor,
		Reason:  *reason,
	}

	newKey, err := r.mgr.RotateKey(auditCtx)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to rotate key: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	fmt.Fprintf(r.out, "Key rotated successfully.\nNew Active KID: %s\nAlgorithm: %s/%s\nStatus: %s\n",
		newKey.KID, newKey.Algorithm, newKey.Curve, newKey.Status)

	return domain.ExitSuccess
}

func (r *KeysRunner) runRevoke(args []string) domain.ExitCode {
	fs := flag.NewFlagSet("keys revoke", flag.ContinueOnError)
	kid := fs.String("kid", "", "폐기할 키의 KID (필수)")
	actor := fs.String("actor", "operator", "키 폐기를 수행하는 행위자")
	reason := fs.String("reason", "key revocation", "키 폐기 사유")
	traceID := fs.String("trace-id", "", "추적 Trace ID (생략 시 자동 생성)")
	fs.SetOutput(r.errOut)

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if *kid == "" {
		fmt.Fprintf(r.errOut, "Error: --kid flag is required\n")
		return domain.ExitBadInput
	}

	tid := *traceID
	if tid == "" {
		tid = fmt.Sprintf("revoke-%d", time.Now().UnixNano())
	}

	auditCtx := domain.AuditContext{
		TraceID: tid,
		Actor:   *actor,
		Reason:  *reason,
	}

	if err := r.mgr.RevokeKey(*kid, auditCtx); err != nil {
		if errors.Is(err, keys.ErrKeyNotFound) {
			fmt.Fprintf(r.errOut, "Error: key not found: %s\n", *kid)
			return domain.ExitBadInput
		}
		fmt.Fprintf(r.errOut, "Error: failed to revoke key: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	fmt.Fprintf(r.out, "Key revoked successfully.\nRevoked KID: %s\n", *kid)
	return domain.ExitSuccess
}
