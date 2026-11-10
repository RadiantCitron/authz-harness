// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(keys.go)은 Zone A 암호화 키링(Keyring)의 생애주기를 관리하는 `keys` 서브커맨드 러너를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. 키 생애주기 관리 (Key Lifecycle):
//    - list: 현재 등록된 모든 키의 ID(KID), 알고리즘/곡선(EdDSA/Ed25519), 상태(active, verify-only, retired), 생성/회전/퇴역 시각을 표로 출력.
//    - rotate: 새로운 활성 서명 키를 생성하고 기존 키를 verify-only 상태로 전이 (RFC 7517/RFC 9068).
//    - revoke: 특정 KID를 즉시 강제 폐기(Retired) 상태로 전환.
// 2. Zone A 특권 격리 (Zone A Privilege):
//    - 키 회전 및 생성은 서명용 비공개키(Private Key)를 다루므로 Zone A 권한이 요구된다.
//    - app.BuildStack 호출 시 WithoutGateway: true 로 불필요한 PEP 게이트웨이 초기화를 건너뛰고 순수 KeyManager 만 조립한다.
// 3. 감사 추적 연동 (Audit Trail Integration):
//    - 키 회전 및 폐기는 보안 중대 사건이므로 domain.AuditContext(TraceID, Actor, Reason)를 반드시 수반한다.
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

// KeysRunner 는 `keys` 하위 명령어(list, rotate, revoke) 실행을 주관하는 CLI 러너다.
// 의존성 역전 원칙(DIP)에 따라 KeyManager 구체 구현 대신 인터페이스를 다루며,
// 테스트 환경 지원을 위해 mgrOverride 주입 필드를 갖추고 있다.
type KeysRunner struct {
	mgrOverride keys.KeyManager // 테스트 주입 지원 (D-07): nil 이 아닐 경우 스택 매니저 대신 사용
	out         io.Writer       // 표준 출력 스트림 (CLI 결과 렌더링)
	errOut      io.Writer       // 표준 에러 스트림 (에러 및 사용법 메시지)
	privPath    string          // Zone A 비공개키 원장 경로 (audit_signing_key 등)
	pubPath     string          // Zone B 공개 JWKS 경로
	auditPath   string          // 감사 로그 파일 경로
}

// NewKeysRunner 는 지정된 입출력 스트림과 키 파일 경로로 KeysRunner를 생성한다.
func NewKeysRunner(out, errOut io.Writer, privPath, pubPath, auditPath string) (*KeysRunner, error) {
	return &KeysRunner{
		out:       out,
		errOut:    errOut,
		privPath:  privPath,
		pubPath:   pubPath,
		auditPath: auditPath,
	}, nil
}

// Run 은 전달받은 인자(args)를 바탕으로 `keys` 서브커맨드를 라우팅하고 적절한 종료 코드를 반환한다.
// app.BuildStack 을 통해 컴포넌트를 조립하고, 실행 완료 시 stack.Close() 로 안전하게 자원을 해제한다.
func (r *KeysRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	// app.BuildStack 을 호출하여 의존성 주입 스택 구성 (게이트웨이 미사용 모드)
	stack, err := app.BuildStack(app.AppConfig{PrivKeyPath: r.privPath, PubJWKSPath: r.pubPath, AuditPath: r.auditPath, WithoutGateway: true})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to initialize keys runner: %v\n", err)
		return domain.ExitInternalError
	}
	defer stack.Close()

	mgr := stack.KeyManager
	if r.mgrOverride != nil {
		mgr = r.mgrOverride
	}

	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: keys subcommand required (list, rotate, revoke)\n")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "list":
		return r.runList(mgr, subArgs)
	case "rotate":
		return r.runRotate(mgr, subArgs)
	case "revoke":
		return r.runRevoke(mgr, subArgs)
	default:
		fmt.Fprintf(r.errOut, "Error: unknown keys subcommand '%s'. Available: list, rotate, revoke\n", subcmd)
		return domain.ExitBadInput
	}
}

// runList 는 키링에 등록된 모든 암호화 키를 조회하여 표(tabwriter) 형태로 stdout 에 출력한다.
func (r *KeysRunner) runList(mgr keys.KeyManager, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("keys list", flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	keyList, err := mgr.ListKeys()
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to list keys: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	if len(keyList) == 0 {
		fmt.Fprintln(r.out, "No keys found in key ring.")
		return domain.ExitSuccess
	}

	// 탭 정렬 기반의 가독성 높은 텍스트 표 출력
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

// runRotate 는 활성 서명 키를 교체(Rotate)하고 감사 로그를 남긴다.
func (r *KeysRunner) runRotate(mgr keys.KeyManager, args []string) domain.ExitCode {
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

	newKey, err := mgr.RotateKey(auditCtx)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to rotate key: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	fmt.Fprintf(r.out, "Key rotated successfully.\nNew Active KID: %s\nAlgorithm: %s/%s\nStatus: %s\n",
		newKey.KID, newKey.Algorithm, newKey.Curve, newKey.Status)

	return domain.ExitSuccess
}

// runRevoke 는 특정 KID 를 갖는 키를 즉시 폐기(Revoke/Retire)한다.
func (r *KeysRunner) runRevoke(mgr keys.KeyManager, args []string) domain.ExitCode {
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

	if err := mgr.RevokeKey(*kid, auditCtx); err != nil {
		if errors.Is(err, keys.ErrKeyNotFound) {
			fmt.Fprintf(r.errOut, "Error: key not found: %s\n", *kid)
			return domain.ExitCodeFromError(err, domain.ExitBadInput)
		}
		fmt.Fprintf(r.errOut, "Error: failed to revoke key: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitInternalError)
	}

	fmt.Fprintf(r.out, "Key revoked successfully.\nRevoked KID: %s\n", *kid)
	return domain.ExitSuccess
}
