package domain

import (
	"crypto/sha256"
	"encoding/hex"
)

// DataDigest 는 도구 입력·결과 원문 대신 감사·승인 바인딩에 남기는 지문을 만든다.
// 빈 입력은 "" 이고, 그 외는 "sha256:" + 소문자 hex 다.
// 솔트가 없으므로 짧거나 추측 가능한 입력은 사전 대입으로 복원될 수 있다("원문 비노출" != "추측 불가").
func DataDigest(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
