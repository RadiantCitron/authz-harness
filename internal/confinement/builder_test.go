package confinement

import (
	"path/filepath"
	"reflect"
	"testing"
)

// TestBuildWorkerPolicy (인수 시험 M1, M2, M3) 는 BuildWorkerPolicy 의 보안 불변식과
// 정책 조립 기능을 검증한다.
func TestBuildWorkerPolicy(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	zoneA := filepath.Join(root, ".authz-state", "private")
	zoneB := filepath.Join(root, ".authz-state", "public")
	ws := filepath.Join(root, "workspace")
	audit := filepath.Join(root, "audit.jsonl")

	privKey := filepath.Join(zoneA, "signing_keys.priv.json")
	stateFile := filepath.Join(zoneB, "grants_state.json")
	pubJWKS := filepath.Join(zoneB, "jwks.pub.json")
	replay := filepath.Join(zoneB, "replay_ledger.json")

	t.Run("M1: 상대 경로 전달 시 거부", func(t *testing.T) {
		_, err := BuildWorkerPolicy("relative/priv.json", stateFile, pubJWKS, replay, ws, audit, "")
		if err == nil {
			t.Fatal("expected error for relative privKeyPath")
		}

		_, err = BuildWorkerPolicy(privKey, "relative/state.json", pubJWKS, replay, ws, audit, "")
		if err == nil {
			t.Fatal("expected error for relative statePath")
		}
	})

	t.Run("M2: Zone A와 Zone B의 공통 조상이 루트뿐이면 거부", func(t *testing.T) {
		// 루트 바로 아래 독립 폴더
		sep := string(filepath.Separator)
		isolatedA := sep + "zone_a_unique_root" + sep + "priv.json"
		isolatedB := sep + "zone_b_unique_root" + sep + "state.json"

		_, err := BuildWorkerPolicy(isolatedA, isolatedB, pubJWKS, replay, ws, audit, "")
		if err == nil {
			t.Fatal("expected error when common ancestor is filesystem root")
		}
	})

	t.Run("M3: 정상 정책 생성 및 포트 파싱", func(t *testing.T) {
		pol, err := BuildWorkerPolicy(privKey, stateFile, pubJWKS, replay, ws, audit, "example.com:8080, 127.0.0.1:443, example.com:8080")
		if err != nil {
			t.Fatalf("BuildWorkerPolicy failed: %v", err)
		}

		wantRoot := filepath.Join(root, ".authz-state")
		if pol.ProtectedRoot != wantRoot {
			t.Errorf("ProtectedRoot = %s, want %s", pol.ProtectedRoot, wantRoot)
		}

		wantPorts := []int{8080, 443}
		if !reflect.DeepEqual(pol.AllowConnectPorts, wantPorts) {
			t.Errorf("AllowConnectPorts = %v, want %v", pol.AllowConnectPorts, wantPorts)
		}

		// 쓰기 경로에 workspace, zoneB, audit 포함 여부 확인
		foundWS := false
		foundZoneB := false
		foundAudit := false
		for _, p := range pol.WritePaths {
			if p == ws {
				foundWS = true
			}
			if p == zoneB {
				foundZoneB = true
			}
			if p == audit {
				foundAudit = true
			}
		}
		if !foundWS || !foundZoneB || !foundAudit {
			t.Errorf("missing write path: ws=%v, zoneB=%v, audit=%v, all=%v", foundWS, foundZoneB, foundAudit, pol.WritePaths)
		}

		if err := pol.Validate(); err != nil {
			t.Errorf("pol.Validate() failed: %v", err)
		}
	})
}

// TestCommonAncestor 는 공통 조상 디렉터리 산출 함수를 검증한다.
func TestCommonAncestor(t *testing.T) {
	tests := []struct {
		a, b string
		want string
	}{
		{"/a/b/c", "/a/b/d", "/a/b"},
		{"/a/b", "/a/b/c/d", "/a/b"},
		{"/foo/bar", "/baz/qux", "/"},
		{"/a/b/c", "/a/b/c", "/a/b/c"},
	}

	for _, tc := range tests {
		got := CommonAncestor(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("CommonAncestor(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestParseConnectPorts 는 포트 파싱 및 유효성 검사를 검증한다.
func TestParseConnectPorts(t *testing.T) {
	t.Run("빈 문자열은 nil 반환", func(t *testing.T) {
		ports, err := ParseConnectPorts("")
		if err != nil || ports != nil {
			t.Errorf("got %v, %v, want nil, nil", ports, err)
		}
	})

	t.Run("정상 파싱 및 중복 제거", func(t *testing.T) {
		ports, err := ParseConnectPorts("localhost:80, example.com:443, 10.0.0.1:80")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []int{80, 443}
		if !reflect.DeepEqual(ports, want) {
			t.Errorf("ports = %v, want %v", ports, want)
		}
	})

	t.Run("포트 형식 불량 거부", func(t *testing.T) {
		_, err := ParseConnectPorts("invalid-no-port")
		if err == nil {
			t.Fatal("expected error for missing port")
		}
	})

	t.Run("포트 번호 범위 초과 거부", func(t *testing.T) {
		_, err := ParseConnectPorts("localhost:0")
		if err == nil {
			t.Fatal("expected error for port 0")
		}
		_, err = ParseConnectPorts("localhost:70000")
		if err == nil {
			t.Fatal("expected error for port 70000")
		}
	})
}
