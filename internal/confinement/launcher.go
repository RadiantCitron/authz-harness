package confinement

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"authz-harness/internal/domain"
)

// EncodePolicy 는 Policy 를 JSON → base64(URL-safe) 단일 인자로 직렬화한다(신뢰 런처 전달용).
func EncodePolicy(p Policy) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", domain.NewError(domain.ReasonInvalidArguments, stagePolicy, "cannot encode policy", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodePolicy 는 EncodePolicy 의 역변환이다. 깨진 입력이나 알 수 없는 필드는 14 로 거부한다.
func DecodePolicy(s string) (Policy, error) {
	var p Policy
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return p, domain.NewError(domain.ReasonInvalidArguments, stagePolicy, "policy is not valid base64", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, domain.NewError(domain.ReasonInvalidArguments, stagePolicy, "policy is not valid JSON", err)
	}
	return p, nil
}
