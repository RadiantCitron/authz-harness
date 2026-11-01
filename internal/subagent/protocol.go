package subagent

// SubagentRequest 는 부모 오케스트레이터가 stdin 파이프로 주입하는 단일 실행 요청 프레임이다.
type SubagentRequest struct {
	Version              string `json:"version"`                 // 프로토콜 버전 (기본 "1.0")
	TraceID              string `json:"trace_id"`                // 부모로부터 전파된 분산 추적 식별자
	Token                string `json:"token"`                   // 축소 위임된 Bearer Access Token
	Action               string `json:"action"`                  // "file:read" 또는 "file:write"
	FilePath             string `json:"file_path"`               // 대상 리소스 상대 경로
	Data                 string `json:"data,omitempty"`          // 쓰기 작업 시 기록할 내용
	InjectRevokeBeforeIO bool   `json:"inject_revoke_before_io"` // 결함 주입 스위치 (TOCTOU 검증용)
}

// SubagentResponse 는 자식 서브에이전트가 stdout 파이프로 반환하는 단일 실행 결과 프레임이다.
type SubagentResponse struct {
	TraceID      string `json:"trace_id"`                // 요청의 trace_id와 일치
	ExitCode     int    `json:"exit_code"`               // 표준 종료 코드 (0, 11~15)
	Action       string `json:"action"`                  // 실행된 액션
	FilePath     string `json:"file_path"`               // 대상 리소스 상대 경로
	BytesRead    int    `json:"bytes_read,omitempty"`    // 읽은 바이트 수
	BytesWritten int    `json:"bytes_written,omitempty"` // 기록된 바이트 수
	Output       string `json:"output,omitempty"`        // 파일 읽기 결과
	Error        string `json:"error,omitempty"`         // 에러 메시지
	Reason       string `json:"reason,omitempty"`        // 세부 인가/인증 사유 코드
}
