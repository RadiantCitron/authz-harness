package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"authz-harness/internal/audit"
)

// TreeNode 는 위임 트리의 한 토큰(jti)이다. 주체(sub)가 아니라 토큰이 노드이므로,
// 같은 주체가 서로 다른 위임에서 받은 토큰은 별개 노드가 된다.
type TreeNode struct {
	JTI      string
	Subject  string
	Depth    int
	External bool // trace 안에 발급 기록이 없는 부모(trace 밖에서 발급)
	Events   []audit.Event
	Children []*TreeNode

	hasDepth bool
	first    time.Time
}

func metaStr(ev audit.Event, key string) string {
	if ev.Metadata == nil {
		return ""
	}
	s, _ := ev.Metadata[key].(string)
	return s
}

func metaInt(ev audit.Event, key string) (int, bool) {
	if ev.Metadata == nil {
		return 0, false
	}
	switch v := ev.Metadata[key].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	}
	return 0, false
}

// BuildDelegationTree 는 같은 trace 의 감사 이벤트로 토큰 단위 위임 트리를 만든다.
// 간선은 token.exchanged 의 parent_jti → child_jti 뿐이다.
// 주의: 간선 필드는 metadata 에 있어 해시로 보호되지 않는다(읽기 위한 보기).
func BuildDelegationTree(events []audit.Event) []*TreeNode {
	nodes := map[string]*TreeNode{}
	var order []string
	get := func(jti string, ts time.Time) *TreeNode {
		n, ok := nodes[jti]
		if !ok {
			n = &TreeNode{JTI: jti, first: ts}
			nodes[jti] = n
			order = append(order, jti)
		}
		if ts.Before(n.first) {
			n.first = ts
		}
		return n
	}
	parentOf := map[string]string{}

	for _, ev := range events {
		isExchange := ev.Action == "token.exchanged" || ev.Step == "token.exchanged"
		pj, cj := metaStr(ev, "parent_jti"), metaStr(ev, "child_jti")
		if isExchange && pj != "" && cj != "" && pj != cj {
			p := get(pj, ev.Timestamp)
			c := get(cj, ev.Timestamp)
			if _, dup := parentOf[cj]; !dup {
				parentOf[cj] = pj
				p.Children = append(p.Children, c)
			}
			if p.Subject == "" {
				p.Subject = metaStr(ev, "parent_sub")
			}
			if s := metaStr(ev, "child_sub"); s != "" {
				c.Subject = s
			}
			if d, ok := metaInt(ev, "delegation_depth"); ok {
				c.Depth, c.hasDepth = d, true
			}
			continue
		}
		if ev.TokenJTI != "" {
			n := get(ev.TokenJTI, ev.Timestamp)
			n.Events = append(n.Events, ev)
			if n.Subject == "" {
				n.Subject = ev.AgentID
			}
		}
	}

	var roots []*TreeNode
	for _, jti := range order {
		if _, child := parentOf[jti]; !child {
			n := nodes[jti]
			n.External = len(n.Events) == 0 && len(n.Children) > 0
			roots = append(roots, n)
		}
	}
	sortNodes(roots)
	for _, r := range roots {
		finalize(r, 0)
	}
	return roots
}

func sortNodes(ns []*TreeNode) {
	sort.SliceStable(ns, func(i, j int) bool { return ns[i].first.Before(ns[j].first) })
}

func finalize(n *TreeNode, depth int) {
	if !n.hasDepth {
		n.Depth = depth
	}
	sortNodes(n.Children)
	for _, c := range n.Children {
		finalize(c, depth+1)
	}
}

// TreeFormatter 는 위임 트리를 CLI 텍스트로 그린다.
type TreeFormatter struct{ out io.Writer }

// NewTreeFormatter 는 TreeFormatter 를 만든다.
func NewTreeFormatter(out io.Writer) *TreeFormatter { return &TreeFormatter{out: out} }

func shortJTI(j string) string {
	if len(j) > 8 {
		return j[:8]
	}
	return j
}

// Render 는 traceID 머리말과 함께 트리를 출력한다.
func (f *TreeFormatter) Render(traceID string, roots []*TreeNode) {
	fmt.Fprintf(f.out, "DELEGATION TREE: %s (view only; edge fields are not hash-protected)\n", traceID)
	f.RenderNodes(roots)
}

// RenderNodes 는 머리말 없이 트리 본문만 출력한다.
func (f *TreeFormatter) RenderNodes(roots []*TreeNode) {
	if len(roots) == 0 {
		fmt.Fprintln(f.out, "└─ [Process] Single Process Execution")
		return
	}
	for _, r := range roots {
		f.node(r, "", "", true)
	}
}

func (f *TreeFormatter) node(n *TreeNode, linePrefix, childPrefix string, root bool) {
	if n.External {
		sub := n.Subject
		if sub == "" {
			sub = "unknown"
		}
		fmt.Fprintf(f.out, "%s[jti: %s] %s (trace 밖에서 발급)\n", linePrefix, n.JTI, sub)
	} else {
		fmt.Fprintf(f.out, "%s[%s] jti=%s depth=%d\n", linePrefix, n.Subject, shortJTI(n.JTI), n.Depth)
	}
	evPrefix := childPrefix
	if len(n.Children) > 0 {
		evPrefix += "│   "
	} else {
		evPrefix += "    "
	}
	for _, ev := range n.Events {
		action := ev.Action
		if action == "" {
			action = ev.Step
		}
		parts := []string{action, ev.Decision}
		if ev.Reason != "" {
			parts = append(parts, ev.Reason)
		}
		fmt.Fprintf(f.out, "%s· %s\n", evPrefix, strings.Join(parts, " "))
	}
	for i, c := range n.Children {
		last := i == len(n.Children)-1
		conn, next := "├── ", "│   "
		if last {
			conn, next = "└── ", "    "
		}
		f.node(c, childPrefix+conn, childPrefix+next, false)
	}
}
