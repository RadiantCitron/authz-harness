//go:build !darwin && !linux

package confinement

// Platform 은 현재 플랫폼의 기본 어댑터를 반환한다. 이 플랫폼에는 구현이 없어 NoopConfiner 다.
func Platform() Confiner { return NoopConfiner{} }
