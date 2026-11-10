package cli

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCommonAncestor(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want string
	}{
		{"기본 배치: private 와 public 의 부모", "/p/.authz-state/private", "/p/.authz-state/public", "/p/.authz-state"},
		{"같은 폴더", "/p/state", "/p/state", "/p/state"},
		{"한쪽이 다른 쪽의 하위", "/p/state", "/p/state/sub", "/p/state"},
		{"접두사만 같은 형제는 조상이 아니다", "/p/state-a", "/p/state-b", "/p"},
		{"공통 폴더가 없으면 루트", "/a/x", "/b/y", "/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := commonAncestor(tc.a, tc.b); got != tc.want {
				t.Fatalf("commonAncestor(%q,%q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestParseConnectPorts(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []int
		wantErr bool
	}{
		{"빈 입력은 포트 없음", "", nil, false},
		{"공백과 빈 항목은 건너뜀", " , ", nil, false},
		{"여러 항목과 중복 제거", "127.0.0.1:8080, localhost:8080,example.com:443", []int{8080, 443}, false},
		{"포트가 없으면 모호하므로 거부", "example.com", nil, true},
		{"포트가 숫자가 아니면 거부", "example.com:https", nil, true},
		{"범위 밖 포트는 거부", "example.com:99999", nil, true},
		{"0번 포트는 거부", "example.com:0", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseConnectPorts(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ports = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildConfinementPolicy(t *testing.T) {
	root := t.TempDir()
	priv := filepath.Join(root, ".authz-state", "private", "signing_keys.priv.json")
	state := filepath.Join(root, ".authz-state", "public", "grants_state.json")
	jwks := filepath.Join(root, ".authz-state", "public", "jwks.pub.json")
	replay := filepath.Join(root, ".authz-state", "public", "replay_ledger.json")
	ws := filepath.Join(root, "workspace")
	audit := filepath.Join(root, "audit.jsonl")

	t.Run("기본 배치: 보호 루트는 .authz-state 이고 Zone A 는 어떤 목록에도 없다", func(t *testing.T) {
		pol, err := buildConfinementPolicy(priv, state, jwks, replay, ws, audit, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := filepath.Join(root, ".authz-state"); pol.ProtectedRoot != want {
			t.Fatalf("ProtectedRoot = %q, want %q", pol.ProtectedRoot, want)
		}
		if !pol.Require {
			t.Fatal("Require must be true: 격리를 적용할 수 없으면 거부해야 한다")
		}
		zoneA := filepath.Dir(priv)
		for _, list := range [][]string{pol.WritePaths, pol.ReadPaths} {
			for _, p := range list {
				if p == zoneA || strings.HasPrefix(p, zoneA+string(filepath.Separator)) {
					t.Fatalf("Zone A 경로 %q 가 허용 목록에 들어 있다: %v", p, list)
				}
			}
		}
		wantWrites := []string{ws, filepath.Dir(state), audit, audit + ".lock"}
		for _, w := range wantWrites {
			found := false
			for _, p := range pol.WritePaths {
				if p == w {
					found = true
				}
			}
			if !found {
				t.Fatalf("쓰기 허용 목록에 %q 가 없다: %v", w, pol.WritePaths)
			}
		}
		if pol.AllowNetwork || len(pol.AllowConnectPorts) != 0 {
			t.Fatalf("네트워크는 기본 거부여야 한다: %+v", pol)
		}
	})

	t.Run("net-allow 의 포트만 연결을 연다", func(t *testing.T) {
		pol, err := buildConfinementPolicy(priv, state, jwks, replay, ws, audit, "127.0.0.1:8080")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(pol.AllowConnectPorts, []int{8080}) || pol.AllowNetwork {
			t.Fatalf("AllowConnectPorts = %v AllowNetwork = %v", pol.AllowConnectPorts, pol.AllowNetwork)
		}
	})

	t.Run("공개키가 다른 폴더에 있으면 그 폴더도 쓰기 허용 목록에 더한다", func(t *testing.T) {
		otherJWKS := filepath.Join(root, ".authz-state", "keys-pub", "jwks.pub.json")
		pol, err := buildConfinementPolicy(priv, state, otherJWKS, replay, ws, audit, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Dir(otherJWKS)
		found := false
		for _, p := range pol.WritePaths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q 가 쓰기 허용 목록에 없다: %v", want, pol.WritePaths)
		}
	})

	t.Run("Zone A 와 Zone B 가 루트 외에 공통 폴더가 없으면 거부", func(t *testing.T) {
		if _, err := buildConfinementPolicy("/a/priv/k.json", "/b/pub/s.json", "/b/pub/j.json", "/b/pub/r.json", ws, audit, ""); err == nil {
			t.Fatal("공통 폴더가 없는데 정책이 만들어졌다 (시스템 전체를 보호 루트로 삼으면 안 된다)")
		}
	})

	t.Run("상대 경로는 거부", func(t *testing.T) {
		if _, err := buildConfinementPolicy("priv.json", state, jwks, replay, ws, audit, ""); err == nil {
			t.Fatal("상대 경로가 받아들여졌다")
		}
	})

	t.Run("모호한 net-allow 는 거부", func(t *testing.T) {
		if _, err := buildConfinementPolicy(priv, state, jwks, replay, ws, audit, "example.com"); err == nil {
			t.Fatal("포트 없는 net-allow 가 받아들여졌다")
		}
	})
}
