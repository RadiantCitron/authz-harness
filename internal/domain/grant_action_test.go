package domain

import (
	"testing"
	"time"
)

// 계획 020 V2: Grant 불변식은 정식 액션 4종만 허용한다(오타·미정의 액션 거부).
func TestGrantValidate_RejectsUnknownAction(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		action  Action
		wantErr bool
	}{
		{ActionFileRead, false}, {ActionFileWrite, false}, {ActionNetFetch, false}, {ActionExecRun, false},
		{"file:delete", true}, {"typo", true}, {"READ", true},
	} {
		g := Grant{ID: "g1", Subject: "w", Action: tc.action, Resource: "a.txt", Status: GrantStatusActive, CreatedAt: now}
		err := g.Validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("action %q: err=%v, wantErr=%v", tc.action, err, tc.wantErr)
		}
	}
}
