// Command faultworker 는 G9 자원·수명 통제 및 G10 OS 격리 시험 전용 결함·악의 워커다.
// 프로덕션 코드와 무관한 별도 프로그램이며, 표준 라이브러리만 사용한다.
// 스포너가 주입하는 stdin 요청 프레임(토큰 포함)은 읽지도 않는다.
//
// bypass_* 모드는 PEP 를 건너뛰고 OS API 를 직접 호출하는 악의 워커다.
// 결과는 stdout 한 줄 `RESULT=ok|err errno=<이름> DATA=<내용>` 로만 쓰고 항상 exit 0 으로 끝난다.
// 종료 코드나 이 출력은 판정 근거가 아니며, 판정은 부모가 관찰한 사실로만 한다.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func report(err error, data string) {
	if err == nil {
		fmt.Printf("RESULT=ok errno=- DATA=%s\n", data)
		return
	}
	name := "unknown"
	var en syscall.Errno
	if errors.As(err, &en) {
		name = strings.ReplaceAll(en.Error(), " ", "_")
	}
	fmt.Printf("RESULT=err errno=%s DATA=\n", name)
}

func main() {
	mode := flag.String("mode", "", "hang | flood | spawn_child_hang | bypass_read_zone_a | bypass_write_outside | bypass_open_socket | bypass_child_read_zone_a")
	target := flag.String("target", "", "bypass 모드의 대상 경로 또는 주소")
	flag.Parse()

	switch *mode {
	case "hang":
		time.Sleep(1 * time.Hour)
	case "flood":
		chunk := make([]byte, 8192)
		for {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return
			}
		}
	case "spawn_child_hang":
		child := exec.Command("sleep", "60")
		if err := child.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "faultworker: failed to start child: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CHILD_PID=%d\n", child.Process.Pid)
		time.Sleep(1 * time.Hour)
	case "bypass_read_zone_a":
		b, err := os.ReadFile(*target)
		if err != nil { // 우회 시도: 권한 복구 후 재시도 (같은 UID 의 chmod)
			_ = os.Chmod(filepath.Dir(*target), 0o700)
			_ = os.Chmod(*target, 0o600)
			b, err = os.ReadFile(*target)
		}
		report(err, string(b))
	case "bypass_write_outside":
		err := os.WriteFile(*target, []byte("pwned"), 0o600)
		if err != nil { // 우회 시도: 상위 디렉터리 권한 복구 후 재시도
			_ = os.Chmod(filepath.Dir(*target), 0o700)
			err = os.WriteFile(*target, []byte("pwned"), 0o600)
		}
		report(err, "")
	case "bypass_open_socket":
		c, err := net.DialTimeout("tcp", *target, 500*time.Millisecond)
		if err == nil {
			_, err = c.Write([]byte("x"))
			_ = c.Close()
		}
		report(err, "")
	case "bypass_child_read_zone_a":
		self, err := os.Executable()
		if err != nil {
			report(err, "")
			return
		}
		out, _ := exec.Command(self, "-mode", "bypass_read_zone_a", "-target", *target).Output()
		fmt.Print(string(out))
	default:
		fmt.Fprintln(os.Stderr, "usage: faultworker -mode hang|flood|spawn_child_hang|bypass_read_zone_a|bypass_write_outside|bypass_open_socket|bypass_child_read_zone_a [-target X]")
		os.Exit(2)
	}
}
