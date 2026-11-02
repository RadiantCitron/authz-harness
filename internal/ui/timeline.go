package ui

import (
	"fmt"
	"io"
	"strings"

	"authz-harness/internal/audit"
)

// ProcessNode 는 프로세스 계보 트리의 단일 노드를 나타낸다.
type ProcessNode struct {
	PID      int
	Subject  string
	Role     string
	Caller   string
	Depth    int
	Children []*ProcessNode
}

// TimelineFormatter 는 단일 TraceID에 속한 감사 이벤트들을 프로세스 계보 및 시계열로 렌더링한다.
type TimelineFormatter struct {
	out io.Writer
}

// NewTimelineFormatter 는 TimelineFormatter 인스턴스를 생성한다.
func NewTimelineFormatter(out io.Writer) *TimelineFormatter {
	return &TimelineFormatter{out: out}
}

// RenderTimeline 은 traceID, 감사 무결성 판정 결과, 이벤트 목록을 받아 정형화된 CLI 뷰를 출력한다.
func (f *TimelineFormatter) RenderTimeline(traceID string, chainValid bool, events []audit.Event) {
	chainStatus := "VALID"
	if !chainValid {
		chainStatus = "BROKEN / TAMPERED"
	}

	fmt.Fprintln(f.out, "================================================================================")
	fmt.Fprintf(f.out, "AUDIT TRACE TIMELINE: %s (Hash Chain: %s)\n", traceID, chainStatus)
	fmt.Fprintln(f.out, "================================================================================")

	if len(events) == 0 {
		fmt.Fprintln(f.out, "No audit events recorded for this trace.")
		fmt.Fprintln(f.out, "================================================================================")
		return
	}

	// 1. 프로세스 및 위임 계보 트리 추출 및 렌더링
	f.renderProcessTree(events)

	// 2. 시계열 타임라인 렌더링
	fmt.Fprintln(f.out, "\nChronological Timeline:")
	for _, ev := range events {
		tsStr := ev.Timestamp.Local().Format("15:04:05.000")
		stepOrAction := ev.Step
		if stepOrAction == "" {
			stepOrAction = ev.Action
		}

		decisionTag := "ALLOW"
		if !ev.Success || ev.Decision == "deny" {
			decisionTag = "DENY"
		}

		var detailParts []string
		if ev.Actor != "" {
			detailParts = append(detailParts, fmt.Sprintf("Actor: %s", ev.Actor))
		}
		if ev.AgentID != "" {
			detailParts = append(detailParts, fmt.Sprintf("Agent: %s", ev.AgentID))
		}
		if ev.Resource != "" {
			detailParts = append(detailParts, fmt.Sprintf("Resource: %s", ev.Resource))
		}
		if ev.Reason != "" && decisionTag == "DENY" {
			detailParts = append(detailParts, fmt.Sprintf("Reason: %s", ev.Reason))
		}
		if ev.Metadata != nil {
			if depth, ok := ev.Metadata["delegation_depth"]; ok {
				detailParts = append(detailParts, fmt.Sprintf("Depth: %v", depth))
			}
			if caller, ok := ev.Metadata["caller_id"]; ok && caller != "" {
				detailParts = append(detailParts, fmt.Sprintf("Caller: %v", caller))
			}
			if exitCode, ok := ev.Metadata["exit_code"]; ok {
				detailParts = append(detailParts, fmt.Sprintf("Exit: %v", exitCode))
			}
		}

		details := strings.Join(detailParts, " | ")
		if details != "" {
			fmt.Fprintf(f.out, "[%s] %-22s | %s | %s\n", tsStr, stepOrAction, details, decisionTag)
		} else {
			fmt.Fprintf(f.out, "[%s] %-22s | %s\n", tsStr, stepOrAction, decisionTag)
		}
	}

	fmt.Fprintln(f.out, "================================================================================")
}

func (f *TimelineFormatter) renderProcessTree(events []audit.Event) {
	fmt.Fprintln(f.out, "Process Tree & Delegation Genealogy:")

	// 이벤트에서 주체 및 계보 정보 수집
	var actors []string
	seen := make(map[string]bool)
	for _, ev := range events {
		actor := ev.Actor
		if actor != "" && !seen[actor] {
			seen[actor] = true
			actors = append(actors, actor)
		}
		if ev.AgentID != "" && !seen[ev.AgentID] {
			seen[ev.AgentID] = true
			actors = append(actors, ev.AgentID)
		}
	}

	if len(actors) == 0 {
		fmt.Fprintln(f.out, "└─ [Process] Single Process Execution")
		return
	}

	indent := "└─ "
	for i, act := range actors {
		prefix := strings.Repeat("   ", i) + indent
		fmt.Fprintf(f.out, "%s[Subject: %s]\n", prefix, act)
	}
}
