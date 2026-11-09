// Package keys 는 RFC 7517 규격 기반의 비대칭 전자서명 키(Ed25519) 수명주기 관리 및 Zone A/B 격리 저장소를 제공한다.
//
// [Zone A 와 Zone B 의 물리적 권한 격리 및 Zero Leakage]
// 1. Zone A (비밀키 특권 영역):
//    - 파일 경로: signing_keys.priv.json (권한: 0600, 부모 폴더: 0700).
//    - 내용: Ed25519 개인키 시드(PrivSeed) 및 활성 서명 키 정보.
//    - 오직 토큰 발급 권한을 가진 중앙 하네스/Issuer 만 접근할 수 있으며 서브에이전트/워커 프로세스는 접근이 차단된다.
// 2. Zone B (공개키 검증 영역):
//    - 파일 경로: jwks.pub.json (권한: 0644, 부모 폴더: 0755).
//    - 내용: RFC 7517 규격의 공개 JWKS (KID, Algorithm, Curve, Base64URL 공개키).
//    - 모든 검증 컴포넌트(PEP, 워커, 서브에이전트)에 자유롭게 배포되어 토큰의 서명을 로컬에서 검증한다.
//
// [RFC 7517 3단계 키 수명주기 전이 (KeyStatus)]
// - active (서명/검증) ➔ [RotateKey] ➔ verify-only (기존 토큰 검증 전용) ➔ [RevokeKey] ➔ retired (즉시 무효화)
package keys
