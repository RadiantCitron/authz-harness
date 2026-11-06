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
