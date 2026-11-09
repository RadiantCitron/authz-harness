// Package domain 은 도구 인자 및 결과 원문 대신 안전하게 남기는 SHA-256 지문(Digest) 생성 기능을 제공한다.
//
// [Zero Leakage 와 감사 바인딩]
// 1. 원문 비노출 원칙:
//    - 도구 실행 인자(예: 민감한 파일 내용, 패스워드 등)를 감사 로그(audit.jsonl)나 승인 티켓(ArgHash)에 원문 그대로 남기면
//      보안 노출 사고가 발생할 수 있다.
// 2. 단방향 SHA-256 해시 지문:
//    - 원문 대신 32바이트 SHA-256 해시를 64자리 소문자 hex 문자열("sha256:<hex>") 형태로 기록하여,
//      원문은 노출하지 않으면서도 나중에 "그 당시 실행된 인자가 정확히 이 내용이었는가?"를 증명(Attestation)할 수 있게 한다.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
)

// DataDigest 는 도구 입력·결과 원문 대신 감사 로그 및 승인 바인딩에 남기는 지문(Fingerprint)을 생성한다.
// 빈 입력(len == 0)은 "" 빈 문자열을 반환하고, 그 외에는 "sha256:" + 64자리 소문자 hex 를 반환한다.
//
// [주의사항]:
// 솔트(Salt)가 포함되지 않은 순수 해시이므로, 매우 짧거나 추측하기 쉬운 입력은 사전 대입 공격(Dictionary Attack)으로
// 원문이 복원될 수 있다 ("원문 직접 비노출" != "수학적 추측 불가").
func DataDigest(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
