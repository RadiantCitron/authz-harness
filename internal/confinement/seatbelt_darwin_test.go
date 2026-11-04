//go:build darwin

package confinement_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
)

// TestHelperProcess 는 테스트 바이너리를 자식으로 재실행하는 헬퍼다.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("HELPER_MODE") == "" {
		return
	}
	a := os.Args
	for i, s := range a {
		if s == "--" {
			a = a[i+1:]
			break
		}
	}
	switch os.Getenv("HELPER_MODE") {
	case "read":
		b, err := os.ReadFile(a[0])
		if err != nil {
			fmt.Println("err=" + err.Error())
		} else {
			fmt.Println("ok " + string(b))
		}
	case "write":
		if err := os.WriteFile(a[0], []byte(a[1]), 0o644); err != nil {
			fmt.Println("err=" + err.Error())
		} else {
			fmt.Println("ok")
		}
	case "chmod_then_read":
		_ = os.Chmod(a[0], 0o644)
		b, err := os.ReadFile(a[0])
		if err != nil {
			fmt.Println("err=" + err.Error())
		} else {
			fmt.Println("ok " + string(b))
		}
	case "dial":
		c, err := net.DialTimeout("tcp", a[0], time.Second)
		if err != nil {
			fmt.Println("err=" + err.Error())
		} else {
			c.Close()
			fmt.Println("ok")
		}
	}
	os.Exit(0)
}

func helperCmd(mode string, args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=TestHelperProcess", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "HELPER_MODE="+mode)
	return cmd
}

func TestRenderSeatbelt(t *testing.T) { // TC-020-01, TC-020-02
	root := t.TempDir()
	pol := confinement.WorkerPolicy(root, filepath.Join(root, "workspace"), filepath.Join(root, "zone_b"), filepath.Join(root, "audit.jsonl"))
	prof, err := confinement.RenderSeatbeltProfile(pol)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"(version 1)", "(deny network*)", "(deny file-write*)", "/private/var"} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing %q:\n%s", want, prof)
		}
	}
	if strings.Contains(prof, "zone_a") {
		t.Errorf("zone_a must not appear")
	}

	q := confinement.Policy{ProtectedRoot: root, WritePaths: []string{filepath.Join(root, `a"b`)}}
	prof, err = confinement.RenderSeatbeltProfile(q)
	if err != nil || !strings.Contains(prof, `a\"b`) {
		t.Fatalf("quote not escaped: %v\n%s", err, prof)
	}
	q.WritePaths = []string{filepath.Join(root, "a\nb")}
	_, err = confinement.RenderSeatbeltProfile(q)
	var de *domain.Error
	if !errors.As(err, &de) || de.ExitCode != domain.ExitBadInput {
		t.Fatalf("newline path must be 14, got %v", err)
	}
}

func TestSeatbeltConfiner(t *testing.T) {
	c := confinement.SeatbeltConfiner{}
	if c.Name() != "darwin-seatbelt" {
		t.Fatal("name")
	}
	if !c.Available() {
		t.Skip("seatbelt unavailable: nested sandbox")
	}
	real, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(real, "sb")
	ws, zb, za := filepath.Join(root, "workspace"), filepath.Join(root, "zone_b"), filepath.Join(root, "zone_a")
	for _, d := range []string{ws, zb, za} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	audit := filepath.Join(root, "audit.jsonl")
	canary := fmt.Sprintf("CANARY-%d", time.Now().UnixNano())
	canaryFile := filepath.Join(za, "canary")
	if err := os.WriteFile(canaryFile, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	pol := confinement.WorkerPolicy(root, ws, zb, audit)

	run := func(confined bool, mode string, args ...string) string {
		t.Helper()
		cmd := helperCmd(mode, args...)
		if confined {
			if err := c.Prepare(cmd, pol); err != nil {
				t.Fatal(err)
			}
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		return string(out)
	}

	t.Run("TC-020-03 허용 경로 쓰기·읽기", func(t *testing.T) {
		f := filepath.Join(ws, "ok.txt")
		run(true, "write", f, "hello")
		if b, _ := os.ReadFile(f); string(b) != "hello" {
			t.Fatalf("write failed")
		}
		if out := run(true, "read", f); !strings.Contains(out, "ok hello") {
			t.Fatalf("read failed: %s", out)
		}
	})

	t.Run("TC-020-04 Zone A 읽기 차단", func(t *testing.T) {
		for _, m := range []string{"read", "chmod_then_read"} {
			if out := run(true, m, canaryFile); strings.Contains(out, canary) {
				t.Fatalf("%s leaked canary", m)
			}
		}
		if b, err := os.ReadFile(canaryFile); err != nil || string(b) != canary {
			t.Fatal("parent must still read canary")
		}
	})

	t.Run("TC-020-05 밖 쓰기 차단", func(t *testing.T) {
		f := filepath.Join(outside, "evil")
		run(true, "write", f, "x")
		if _, err := os.Stat(f); err == nil {
			t.Fatal("outside file created")
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepts := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
			accepts <- struct{}{}
		}
	}()
	count := func() int {
		time.Sleep(300 * time.Millisecond)
		return len(accepts)
	}

	t.Run("TC-020-06 소켓 차단", func(t *testing.T) {
		run(true, "dial", ln.Addr().String())
		if n := count(); n != 0 {
			t.Fatalf("accepts=%d", n)
		}
	})

	t.Run("TC-020-07 대조군(격리 없음)", func(t *testing.T) {
		if out := run(false, "read", canaryFile); !strings.Contains(out, canary) {
			t.Fatal("control: canary not read")
		}
		f := filepath.Join(outside, "ctl")
		run(false, "write", f, "x")
		if _, err := os.Stat(f); err != nil {
			t.Fatal("control: file not created")
		}
		run(false, "dial", ln.Addr().String())
		if n := count(); n != 1 {
			t.Fatalf("control accepts=%d", n)
		}
	})
}
