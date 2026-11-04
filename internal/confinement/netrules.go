package confinement

// netPortRule 은 Landlock NET_PORT 규칙 하나다(access 비트는 netConnectTCP 와 같은 값, 플랫폼 중립 상수 사용).
type netPortRule struct {
	port   int
	access uint64
}

const connectTCPAccess = uint64(1 << 1) // LANDLOCK_ACCESS_NET_CONNECT_TCP

// landlockNetRules 는 정책에서 Landlock 포트 규칙을 만든다. AllowNetwork 가 true 이면 규칙이 없다.
// 순수 함수라 Linux 가 아닌 호스트에서도 단위 시험할 수 있다.
func landlockNetRules(p Policy) []netPortRule {
	if p.AllowNetwork {
		return nil
	}
	var out []netPortRule
	for _, port := range uniquePorts(p.AllowConnectPorts) {
		out = append(out, netPortRule{port: port, access: connectTCPAccess})
	}
	return out
}
