// Package cli 는 authz-harness 의 서브커맨드 러너 및 인간 대상 표준 출력 포매터를 제공한다.
//
// [출력 삼분 원칙 (Tri-Separation)]
// - CLI 출력 (os.Stdout): 사용자 및 하네스 러너 대상 포맷팅된 결과 출력.
// - 운영 로그 (os.Stderr): log/slog 기반의 디버깅 및 진단 로그 (원시 토큰 자동 마스킹).
// - 감사 증거 (audit.jsonl): audit.Writer 를 통한 불변의 보안 인가 판정 전용 해시 체인 이벤트.
package cli

import (
	"fmt"
	"io"
)

// Formatter 는 CLI 표준 출력(STDOUT) 포맷팅을 담당한다.
// 운영 로그(slog, STDERR) 및 감사 로그(audit.jsonl)와 물리적으로 분리된다.
type Formatter struct {
	out io.Writer
}

// NewFormatter 는 지정된 출력 스트림(보통 os.Stdout)을 받는 Formatter를 생성한다.
func NewFormatter(out io.Writer) *Formatter {
	return &Formatter{out: out}
}

// PrintBanner 는 하네스 기본 배너와 버전 정보를 출력한다.
func (f *Formatter) PrintBanner(version string) {
	fmt.Fprintf(f.out, "authz-harness v%s — Authorization & Delegation Test Harness\n", version)
}
