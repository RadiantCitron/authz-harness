// Command faultworker 는 G9 자원·수명 통제 시험 전용 결함 워커다.
// 프로덕션 코드와 무관한 별도 프로그램이며, 표준 라이브러리만 사용한다.
// 스포너가 주입하는 stdin 요청 프레임(토큰 포함)은 읽지도 않는다.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	mode := flag.String("mode", "", "hang | flood | spawn_child_hang")
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
	default:
		fmt.Fprintln(os.Stderr, "usage: faultworker -mode hang|flood|spawn_child_hang")
		os.Exit(2)
	}
}
