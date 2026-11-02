package harness

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// jwtTokenPattern 은 서명된 Bearer 토큰(JWT eyJ...) 유출 여부를 검출하는 정규식이다.
var jwtTokenPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_\.\-]{10,}`)

// FileExpectation 은 파일 시스템 검증 명세다.
type FileExpectation struct {
	RelPath            string // 검증 대상 리소스 상대 경로
	ExpectExist        bool   // 파일 존재 여부 기대
	ExpectedContent    string // 허용 시 기대 파일 내용 (공백 시 내용 무검사)
	ExpectZeroMutation bool   // 거부 시 파일 생성 0건 또는 0바이트 유지 보장
}

// AuditExpectation 은 감사 로그 검증 명세다.
type AuditExpectation struct {
	RequireEvent     bool            // 감사 이벤트 기록 필수 여부
	ExpectedAction   string          // 기대 액션 (예: "pep.allow", "pep.deny", "agent.exit")
	ExpectedDecision string          // 기대 판정 ("allow", "deny", "")
	ExpectedReason   domain.Reason   // 기대 사유 코드 (예: domain.ReasonTokenExpired)
	ExpectedTraceID  string          // 단일 체인 trace_id 기대값
}

// HashChainExpectation 은 감사 해시 체인 및 데이터 무결성 검증 명세다.
type HashChainExpectation struct {
	RequireValidChain bool // SHA-256 해시 체인 무결성 검증 필수
	NoRawTokenLeak    bool // 원시 JWT Bearer 토큰 문자열 비노출 보장
}

// ExpectedAssertion 은 4중 불변식 검증 기준 명세다.
type ExpectedAssertion struct {
	ExitCode  domain.ExitCode      // 기대 표준 종료 코드 (0, 11~15)
	File      FileExpectation      // 파일 상태 기대값
	Audit     AuditExpectation     // 감사 로그 사유 기대값
	HashChain HashChainExpectation // 감사 해시 체인 기대값
}

// AssertionResult 는 4중 검증 수행 결과다.
type AssertionResult struct {
	Passed              bool            // 4가지 검증 모두 통과 시 true
	ExitCodePassed      bool            // 1. 종료 코드 검증 결과
	ExitCodeActual      domain.ExitCode // 실제 수거된 종료 코드
	FilePassed          bool            // 2. 파일 상태 검증 결과
	FileDetails         string          // 파일 상태 상세 내용
	AuditPassed         bool            // 3. 감사 로그 사유 검증 결과
	AuditActualReason   domain.Reason   // 실제 기록된 사유 코드
	AuditActualDecision string          // 실제 기록된 판정
	HashChainPassed     bool            // 4. 해시 체인 무결성 검증 결과
	FailureReasons      []string        // 실패 사유 목록
}

// Evaluator 는 샌드박스 실행 결과에 대해 Quad-Assertion을 수행하는 인터페이스다.
type Evaluator interface {
	Evaluate(env *SandboxEnvironment, actualExitCode domain.ExitCode, exp ExpectedAssertion) AssertionResult
}

// DefaultEvaluator 는 Quad-Assertion 4중 불변식 표준 판정기 구현체다.
type DefaultEvaluator struct{}

// NewDefaultEvaluator 는 DefaultEvaluator 를 생성한다.
func NewDefaultEvaluator() *DefaultEvaluator {
	return &DefaultEvaluator{}
}

// Evaluate 는 샌드박스 환경과 실행 결과, 기대 스펙을 기반으로 4중 불변식을 검증한다.
func (e *DefaultEvaluator) Evaluate(env *SandboxEnvironment, actualExitCode domain.ExitCode, exp ExpectedAssertion) AssertionResult {
	res := AssertionResult{
		Passed:         true,
		ExitCodeActual: actualExitCode,
		FailureReasons: make([]string, 0),
	}

	// ----------------------------------------------------
	// 1. Exit Code 검증
	// ----------------------------------------------------
	if actualExitCode == exp.ExitCode {
		res.ExitCodePassed = true
	} else {
		res.ExitCodePassed = false
		res.Passed = false
		res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("exit code mismatch: expected %d, got %d", exp.ExitCode, actualExitCode))
	}

	// ----------------------------------------------------
	// 2. File State (Zero Mutation or Expected Content) 검증
	// ----------------------------------------------------
	res.FilePassed = true
	if exp.File.RelPath != "" || exp.File.ExpectZeroMutation || exp.File.ExpectExist {
		relPath := exp.File.RelPath
		exists := env.WorkspaceFileExists(relPath)
		size := env.GetWorkspaceFileSize(relPath)

		if exp.File.ExpectZeroMutation {
			// 거부 시: 파일이 존재하지 않거나, 존재하더라도 크기가 0바이트여야 함
			if exists && size > 0 {
				res.FilePassed = false
				res.Passed = false
				msg := fmt.Sprintf("zero mutation violation: file %q was modified (%d bytes)", relPath, size)
				res.FileDetails = msg
				res.FailureReasons = append(res.FailureReasons, msg)
			} else {
				res.FileDetails = fmt.Sprintf("file %q unchanged (0 bytes or not exist)", relPath)
			}
		} else if exp.File.ExpectExist {
			if !exists {
				res.FilePassed = false
				res.Passed = false
				msg := fmt.Sprintf("expected file %q to exist, but not found", relPath)
				res.FileDetails = msg
				res.FailureReasons = append(res.FailureReasons, msg)
			} else if exp.File.ExpectedContent != "" {
				content, err := env.ReadWorkspaceFile(relPath)
				if err != nil {
					res.FilePassed = false
					res.Passed = false
					msg := fmt.Sprintf("failed to read expected file %q: %v", relPath, err)
					res.FileDetails = msg
					res.FailureReasons = append(res.FailureReasons, msg)
				} else if string(content) != exp.File.ExpectedContent {
					res.FilePassed = false
					res.Passed = false
					msg := fmt.Sprintf("file content mismatch for %q: expected %q, got %q", relPath, exp.File.ExpectedContent, string(content))
					res.FileDetails = msg
					res.FailureReasons = append(res.FailureReasons, msg)
				} else {
					res.FileDetails = fmt.Sprintf("file %q verified with expected content", relPath)
				}
			} else {
				res.FileDetails = fmt.Sprintf("file %q exists (%d bytes)", relPath, size)
			}
		}
	}

	// ----------------------------------------------------
	// 감사 이벤트 로딩 (3 & 4 공통)
	// ----------------------------------------------------
	events, err := env.ReadAuditEvents()
	if err != nil {
		res.AuditPassed = false
		res.HashChainPassed = false
		res.Passed = false
		res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("failed to read audit events: %v", err))
		return res
	}

	// ----------------------------------------------------
	// 3. Audit Reason 및 Decision 검증
	// ----------------------------------------------------
	res.AuditPassed = true
	if exp.Audit.RequireEvent || exp.Audit.ExpectedDecision != "" || exp.Audit.ExpectedReason != "" {
		if len(events) == 0 {
			res.AuditPassed = false
			res.Passed = false
			res.FailureReasons = append(res.FailureReasons, "expected audit event, but audit log is empty")
		} else {
			// 가장 최근 또는 일치하는 유의미한 결정/사유 이벤트 탐색 (역순)
			var matchedDecision string
			var matchedReason domain.Reason
			found := false

			for i := len(events) - 1; i >= 0; i-- {
				ev := events[i]
				if exp.Audit.ExpectedTraceID != "" && ev.TraceID != exp.Audit.ExpectedTraceID {
					continue
				}
				if exp.Audit.ExpectedAction != "" && ev.Action != exp.Audit.ExpectedAction {
					continue
				}
				evDecision := ev.Decision
				if evDecision == "" {
					if !ev.Success {
						evDecision = "deny"
					} else if ev.Success && ev.Decision == "" && ev.Reason == string(domain.ReasonAuthorized) {
						evDecision = "allow"
					}
				}
				evReason := ev.Reason
				if evReason == "" && ev.Metadata != nil {
					if r, ok := ev.Metadata["reason"].(string); ok {
						evReason = r
					}
				}

				// Decision 또는 Reason 이 기록된 이벤트
				if evDecision != "" || evReason != "" {
					matchedDecision = evDecision
					matchedReason = domain.Reason(evReason)
					found = true
					break
				}
			}

			if !found {
				res.AuditPassed = false
				res.Passed = false
				res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("no audit event matched ExpectedAction %q and ExpectedTraceID %q", exp.Audit.ExpectedAction, exp.Audit.ExpectedTraceID))
			} else {
				res.AuditActualDecision = matchedDecision
				res.AuditActualReason = matchedReason

				if exp.Audit.ExpectedDecision != "" && !strings.EqualFold(matchedDecision, exp.Audit.ExpectedDecision) {
					res.AuditPassed = false
					res.Passed = false
					res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("audit decision mismatch: expected %q, got %q", exp.Audit.ExpectedDecision, matchedDecision))
				}
				if exp.Audit.ExpectedReason != "" && matchedReason != exp.Audit.ExpectedReason {
					res.AuditPassed = false
					res.Passed = false
					res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("audit reason mismatch: expected %q, got %q", exp.Audit.ExpectedReason, matchedReason))
				}
			}
		}
	}

	// ----------------------------------------------------
	// 4. Hash Chain Integrity & No Raw Token Leak 검증
	// ----------------------------------------------------
	res.HashChainPassed = true

	// 4-1. No Raw Token Leak 검사
	if exp.HashChain.NoRawTokenLeak {
		for i, ev := range events {
			rawJSON, _ := json.Marshal(ev)
			if jwtTokenPattern.Match(rawJSON) {
				res.HashChainPassed = false
				res.Passed = false
				res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("raw token leak detected in audit event #%d", i+1))
				break
			}
		}
	}

	// 4-2. Hash Chain 검증 (가짜 통과 원천 제거 및 파일 체인 일체 검증)
	if exp.HashChain.RequireValidChain {
		if len(events) == 0 {
			res.HashChainPassed = false
			res.Passed = false
			res.FailureReasons = append(res.FailureReasons, "audit events empty but RequireValidChain is true")
		} else {
			var prevHash string
			for i, ev := range events {
				var evPrevHash, evCurrHash string
				evPrevHash = ev.PrevHash
				evCurrHash = ev.CurrHash
				if ev.Metadata != nil {
					if evPrevHash == "" {
						if ph, ok := ev.Metadata["prev_hash"].(string); ok {
							evPrevHash = ph
						}
					}
					if evCurrHash == "" {
						if ch, ok := ev.Metadata["curr_hash"].(string); ok {
							evCurrHash = ch
						}
					}
				}

				if evCurrHash == "" {
					res.HashChainPassed = false
					res.Passed = false
					res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("event #%d missing curr_hash (vacuous pass forbidden)", i+1))
					break
				}

				if evPrevHash != prevHash {
					res.HashChainPassed = false
					res.Passed = false
					res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("hash chain broken at event #%d: expected prev_hash %q, got %q", i+1, prevHash, evPrevHash))
					break
				}

				computedCurrHash := computeEventHash(evPrevHash, ev)
				if evCurrHash != computedCurrHash {
					res.HashChainPassed = false
					res.Passed = false
					res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("curr_hash mismatch at event #%d: expected %q, got %q", i+1, computedCurrHash, evCurrHash))
					break
				}
				prevHash = evCurrHash
			}

			if res.HashChainPassed && env != nil && env.AuditPath != "" {
				if err := audit.VerifyHashChain(env.AuditPath); err != nil {
					res.HashChainPassed = false
					res.Passed = false
					res.FailureReasons = append(res.FailureReasons, fmt.Sprintf("audit.VerifyHashChain failed: %v", err))
				}
			}
		}
	}

	return res
}

// computeEventHash 는 이벤트와 이전 해시를 바탕으로 정규화된 SHA-256 해시를 계산한다.
func computeEventHash(prevHash string, ev audit.Event) string {
	return audit.ComputeEventHash(prevHash, ev)
}

// ComputeEventCurrHash 는 이벤트 메타데이터에 주입할 curr_hash 계산 헬퍼 함수다.
func ComputeEventCurrHash(prevHash string, ev audit.Event) string {
	return audit.ComputeEventHash(prevHash, ev)
}
