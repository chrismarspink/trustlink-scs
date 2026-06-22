package main

// oidc.go: Keycloak OIDC 액세스 토큰의 RS256 서명 + 표준 클레임(exp/nbf/iss/azp)을
// 검증한다. go.mod 무의존성(stdlib only)을 유지하기 위해 외부 JWT 라이브러리 없이
// crypto/rsa·crypto/sha256 으로 직접 검증한다.
//
// 검증 정책(fail-closed): 어느 한 단계라도 실패하면 토큰을 거부한다.
//   1) JWT 구조(header.payload.signature) + header.alg == RS256
//   2) JWKS 의 kid 공개키로 RSASSA-PKCS1-v1_5(SHA-256) 서명검증 (kid 미스 시 1회 갱신)
//   3) exp(만료) · nbf(아직 유효 전) — 60s leeway
//   4) iss == discovery 의 issuer
//   5) azp == clientID  또는  clientID ∈ aud  (Keycloak access token 은 aud="account" 라 azp 로 판정)

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const oidcLeeway = 60 // seconds

type oidcVerifier struct {
	kcInternal string
	realm      string
	clientID   string
	http       *http.Client

	mu      sync.RWMutex
	issuer  string
	jwksURL string
	keys    map[string]*rsa.PublicKey // kid -> public key
}

func newOIDCVerifier(cfg Config, hc *http.Client) *oidcVerifier {
	return &oidcVerifier{
		kcInternal: cfg.KCInternal,
		realm:      cfg.Realm,
		clientID:   cfg.ClientID,
		http:       hc,
		keys:       map[string]*rsa.PublicKey{},
	}
}

// ensureDiscovery: issuer/jwks_uri 를 OIDC discovery 로 1회 확보(lazy, 실패 시 재시도 허용).
// KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true 덕에 jwks_uri 는 백채널 도달가능 호스트로 반환된다.
func (v *oidcVerifier) ensureDiscovery() error {
	v.mu.RLock()
	ready := v.jwksURL != "" && v.issuer != ""
	v.mu.RUnlock()
	if ready {
		return nil
	}

	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", v.kcInternal, v.realm)
	resp, err := v.http.Get(url)
	if err != nil {
		return fmt.Errorf("discovery fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("discovery decode: %w", err)
	}
	if doc.Issuer == "" || doc.JWKSURI == "" {
		return errors.New("discovery missing issuer/jwks_uri")
	}
	v.mu.Lock()
	v.issuer = doc.Issuer
	v.jwksURL = doc.JWKSURI
	v.mu.Unlock()
	return nil
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// refreshKeys: JWKS 를 받아 kid->RSA 공개키 맵을 갱신한다(키 회전 대응).
func (v *oidcVerifier) refreshKeys() error {
	v.mu.RLock()
	jwksURL := v.jwksURL
	v.mu.RUnlock()
	if jwksURL == "" {
		return errors.New("jwks url not discovered")
	}
	resp, err := v.http.Get(jwksURL)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks decode: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pk, err := jwkToRSA(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pk
	}
	if len(keys) == 0 {
		return errors.New("jwks: no usable RSA keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}

func jwkToRSA(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

func (v *oidcVerifier) keyByKid(kid string) *rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys[kid]
}

// verify: 액세스 토큰을 검증하고 username/groups 를 반환한다. 실패 시 error(거부).
func (v *oidcVerifier) verify(raw string) (string, []string, error) {
	if err := v.ensureDiscovery(); err != nil {
		return "", nil, err
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", nil, errors.New("malformed jwt")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, fmt.Errorf("header decode: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return "", nil, fmt.Errorf("header parse: %w", err)
	}
	if hdr.Alg != "RS256" {
		return "", nil, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}

	key := v.keyByKid(hdr.Kid)
	if key == nil {
		// 키 회전: 캐시 미스 시 1회 갱신 후 재시도.
		if err := v.refreshKeys(); err != nil {
			return "", nil, fmt.Errorf("jwks refresh: %w", err)
		}
		key = v.keyByKid(hdr.Kid)
	}
	if key == nil {
		return "", nil, fmt.Errorf("no key for kid %q", hdr.Kid)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, fmt.Errorf("sig decode: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return "", nil, errors.New("signature invalid")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("payload decode: %w", err)
	}
	var c struct {
		Iss      string          `json:"iss"`
		Azp      string          `json:"azp"`
		Aud      json.RawMessage `json:"aud"`
		Exp      int64           `json:"exp"`
		Nbf      int64           `json:"nbf"`
		Username string          `json:"preferred_username"`
		Groups   []string        `json:"groups"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", nil, fmt.Errorf("claims parse: %w", err)
	}

	now := time.Now().Unix()
	if c.Exp == 0 || now > c.Exp+oidcLeeway {
		return "", nil, errors.New("token expired")
	}
	if c.Nbf != 0 && now+oidcLeeway < c.Nbf {
		return "", nil, errors.New("token not yet valid")
	}

	v.mu.RLock()
	issuer := v.issuer
	v.mu.RUnlock()
	if c.Iss != issuer {
		return "", nil, fmt.Errorf("issuer mismatch: %q != %q", c.Iss, issuer)
	}

	if !v.audienceOK(c.Azp, c.Aud) {
		return "", nil, errors.New("audience/azp mismatch")
	}

	return c.Username, c.Groups, nil
}

// audienceOK: azp==clientID 이거나 clientID 가 aud(문자열 또는 배열)에 포함되면 통과.
func (v *oidcVerifier) audienceOK(azp string, audRaw json.RawMessage) bool {
	if azp == v.clientID {
		return true
	}
	if len(audRaw) == 0 {
		return false
	}
	var single string
	if json.Unmarshal(audRaw, &single) == nil {
		return single == v.clientID
	}
	var list []string
	if json.Unmarshal(audRaw, &list) == nil {
		return contains(list, v.clientID)
	}
	return false
}
