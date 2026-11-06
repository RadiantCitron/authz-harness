//go:build !linux

package confinement

import "authz-harness/internal/domain"

// ApplySelf 는 Linux 가 아닌 플랫폼에서는 항상 16 으로 거부한다(침묵 폴백 금지).
func ApplySelf(_ Policy, _ ...string) error {
	return domain.NewError(domain.ReasonConfinementUnavailable, "landlock is only available on linux", nil)
}
