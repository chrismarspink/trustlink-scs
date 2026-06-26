package main

// 신뢰된 외부 공유 워크플로 (§3, §11-5·6):
//   게이트 통과(현 단계는 관리자 액션) → CA 어댑터 발급 → CMS 서명(산출물+SBOM+VEX 묶음 매니페스트)
//   → Zot OCI Referrer 바인딩(.p7s) → SoR 기록.
// 서명 대상은 "묶음 매니페스트"(subject digest + SBOM/VEX referrer digest 열거) — 산출물 본문이 아닌
// 다이제스트 묶음을 서명해 효율·무결성을 동시에 만족(in-toto 식). 검증자는 루트(신뢰 앵커)만으로 검증.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"time"
)

const cmsArtifactType = "application/pkcs7-signature" // CMS .p7s referrer artifactType

// svcCaller: svc-bff 자격을 실은 더미 요청(pushBlob/subjectDescriptor 재사용용).
func (s *Server) svcCaller() *http.Request {
	r, _ := http.NewRequest("GET", s.cfg.ZotAPIURL+"/", nil)
	if s.cfg.ZotAdminUser != "" {
		r.SetBasicAuth(s.cfg.ZotAdminUser, s.cfg.ZotAdminPass)
	}
	return r
}

type bundleEntry struct {
	Kind         string `json:"kind"` // sbom | vex
	ArtifactType string `json:"artifactType"`
	Digest       string `json:"digest"`
}

type bundleManifest struct {
	Type      string        `json:"type"` // trustlink.bundle.v1
	Repo      string        `json:"repo"`
	Tag       string        `json:"tag"`
	Subject   string        `json:"subject"` // subject manifest digest
	Artifacts []bundleEntry `json:"artifacts"`
	SignedAt  string        `json:"signedAt"`
	Signer    string        `json:"signer"`
}

// collectBundle: subject 의 SBOM/VEX referrer 를 모아 묶음 매니페스트를 만든다.
func (s *Server) collectBundle(repo, tag, signer string) (*bundleManifest, string, error) {
	mr, err := s.zotGetSvc("/v2/"+repo+"/manifests/"+tag, acceptManifest)
	if err != nil || mr.StatusCode != 200 {
		if mr != nil {
			mr.Body.Close()
		}
		return nil, "", fmt.Errorf("subject 조회 실패")
	}
	dig := mr.Header.Get("Docker-Content-Digest")
	mr.Body.Close()
	if dig == "" {
		return nil, "", fmt.Errorf("subject digest 없음")
	}
	bm := &bundleManifest{Type: "trustlink.bundle.v1", Repo: repo, Tag: tag, Subject: dig,
		SignedAt: time.Now().UTC().Format(time.RFC3339), Signer: signer}
	rr, err := s.zotGetSvc("/v2/"+repo+"/referrers/"+dig, "")
	if err == nil && rr.StatusCode == 200 {
		var idx ociIndex
		_ = json.NewDecoder(rr.Body).Decode(&idx)
		rr.Body.Close()
		for _, ref := range idx.Manifests {
			k := kindDir(ref.ArtifactType, "")
			if k == "sbom" || k == "vex" {
				bm.Artifacts = append(bm.Artifacts, bundleEntry{Kind: k, ArtifactType: ref.ArtifactType, Digest: ref.Digest})
			}
		}
	} else if rr != nil {
		rr.Body.Close()
	}
	return bm, dig, nil
}

// bindCMSReferrer: .p7s 를 subject 다이제스트에 referrer 로 부착(svc 권한). 원본 불변·누적.
func (s *Server) bindCMSReferrer(repo, tag, subjectDigest string, p7s []byte, serial, signer string) (string, error) {
	caller := s.svcCaller()
	subj, err := s.subjectDescriptor(caller, repo, tag)
	if err != nil {
		return "", err
	}
	cfgDigest, err := s.pushBlob(caller, repo, []byte("{}"))
	if err != nil {
		return "", fmt.Errorf("config blob: %w", err)
	}
	sigDigest, err := s.pushBlob(caller, repo, p7s)
	if err != nil {
		return "", fmt.Errorf("p7s blob: %w", err)
	}
	created := time.Now().UTC().Format(time.RFC3339)
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     ociManifestType,
		"artifactType":  cmsArtifactType,
		"config":        map[string]any{"mediaType": ociEmptyType, "digest": cfgDigest, "size": 2, "data": "e30="},
		"layers": []any{map[string]any{
			"mediaType":   cmsArtifactType,
			"digest":      sigDigest,
			"size":        len(p7s),
			"annotations": map[string]string{"org.opencontainers.image.title": fmt.Sprintf("%s-%s.cms.p7s", path.Base(repo), tag)},
		}},
		"subject": map[string]any{"mediaType": subj.MediaType, "digest": subj.Digest, "size": subj.Size},
		"annotations": map[string]string{
			"org.opencontainers.image.created": created,
			"com.trustlink.cms.serial":         serial,
			"com.trustlink.cms.signer":         signer,
		},
	}
	mBytes, _ := json.Marshal(manifest)
	mDigest := "sha256:" + sha256hex(mBytes)
	putReq, _ := http.NewRequest("PUT", s.cfg.ZotAPIURL+"/v2/"+repo+"/manifests/"+mDigest, bytes.NewReader(mBytes))
	applyCaller(caller, putReq)
	putReq.Header.Set("Content-Type", ociManifestType)
	presp, err := s.http.Do(putReq)
	if err != nil {
		return "", err
	}
	presp.Body.Close()
	if presp.StatusCode != http.StatusCreated {
		return "", &zotStatusErr{presp.StatusCode}
	}
	return mDigest, nil
}

// POST /api/share/sign {repo, tag} — 발급→CMS 서명→referrer 바인딩→SoR.
func (s *Server) apiShareSign(w http.ResponseWriter, r *http.Request) {
	if !s.signingAvailable() {
		writeJSON(w, 503, map[string]string{"error": "서명 불가(CA/bigfoot 미구성)"})
		return
	}
	var in struct{ Repo, Tag string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Repo == "" || in.Tag == "" {
		writeJSON(w, 400, map[string]string{"error": "repo, tag 필수"})
		return
	}
	actor := w.Header().Get("X-User")

	// 1) 묶음 매니페스트(subject + SBOM/VEX 다이제스트)
	bm, subjectDigest, err := s.collectBundle(in.Repo, in.Tag, actor)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	manifestBytes, _ := json.Marshal(bm)

	// 2) CMS 서명 — bigfoot 위임 또는 내장 step-ca (3) 자체검증
	cn := fmt.Sprintf("trustlink-release/%s:%s", in.Repo, in.Tag)
	p7s, serial, err := s.signContent(actor, cn, manifestBytes)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "CMS 서명 실패: " + err.Error()})
		return
	}
	verified, vdetail := s.verifyCMS(p7s)
	fipsOn, fipsDetail := fipsStatus()

	// 4) Zot referrer 바인딩
	refDigest, err := s.bindCMSReferrer(in.Repo, in.Tag, subjectDigest, p7s, serial, actor)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "referrer 바인딩 실패: " + err.Error()})
		return
	}

	// 5) SoR
	_ = s.sor.append(SoREvent{Actor: actor, Action: "sign", Serial: serial, Subject: cn, Repo: in.Repo, Tag: in.Tag,
		Status: map[bool]string{true: "verified", false: "verify-failed"}[verified],
		Detail: map[string]any{"p7sSize": len(p7s), "fips": fipsOn, "artifacts": len(bm.Artifacts), "bigfoot": s.bigfootEnabled()}})
	_ = s.sor.append(SoREvent{Actor: actor, Action: "bind", Serial: serial, Repo: in.Repo, Tag: in.Tag,
		Detail: map[string]any{"referrer": refDigest, "subject": subjectDigest}})

	writeJSON(w, 200, map[string]any{
		"status":     "signed",
		"repo":       in.Repo,
		"tag":        in.Tag,
		"subject":    subjectDigest,
		"serial":     serial,
		"referrer":   refDigest,
		"p7sSize":    len(p7s),
		"artifacts":  bm.Artifacts,
		"verified":   verified,
		"verifyNote": vdetail,
		"fips":       map[string]any{"active": fipsOn, "detail": fipsDetail},
	})
}

// recipientByID: 수신자 레지스트리에서 지문(ID)으로 1건 조회.
func (s *Server) recipientByID(id string) (*Recipient, error) {
	rs, err := s.recips.list()
	if err != nil {
		return nil, err
	}
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i], nil
		}
	}
	return nil, fmt.Errorf("수신자 미존재")
}

// GET /api/share/package?repo=&tag=&sign=&recipientId=&password=
//   산출물 번들(zip) 에 대해 4가지 CMS 모드:
//     - 서명만           : sign=1            → .p7s (SignedData). 루트로 검증, 복호 불필요.
//     - 암호화(인증서)    : sign=0&recipientId → .p7m (EnvelopedData). 수신자만 복호.
//     - 서명+암호화(인증서): sign=1&recipientId → .p7m. 서명 후 수신자 인증서로 암호화.
//     - 서명+암호화(패스워드): sign=1&password   → .p7m (PWRI). 공유 비밀번호로 복호.
//   sign 기본=1. 서명도 암호화도 아니면 400.
func (s *Server) apiSharePackage(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	tag := r.URL.Query().Get("tag")
	recipID := r.URL.Query().Get("recipientId")
	password := r.URL.Query().Get("password")
	doSign := r.URL.Query().Get("sign") != "0" // 기본 서명
	if repo == "" || tag == "" {
		writeJSON(w, 400, map[string]string{"error": "repo, tag 필수"})
		return
	}
	if !doSign && recipID == "" && password == "" {
		writeJSON(w, 400, map[string]string{"error": "서명 또는 암호화 중 하나는 필요"})
		return
	}
	if doSign && !s.signingAvailable() {
		writeJSON(w, 503, map[string]string{"error": "서명 불가(CA/bigfoot 미구성)"})
		return
	}
	actor := w.Header().Get("X-User")

	// 1) 산출물 번들(zip) — svc 자격으로 수집
	caller := s.svcCaller()
	subj, subjDigest, err := s.fetchManifest(caller, repo, tag)
	if err != nil {
		writeJSON(w, httpStatus(err), map[string]string{"error": "산출물 조회 실패(권한 또는 미존재)"})
		return
	}
	var bundle bytes.Buffer
	s.writeBundleZip(caller, repo, tag, subj, subjDigest, &bundle)
	if bundle.Len() == 0 {
		writeJSON(w, 502, map[string]string{"error": "번들 수집 실패(빈 산출물)"})
		return
	}
	cn := fmt.Sprintf("trustlink-release/%s:%s", repo, tag)
	bundleBytes := bundle.Bytes()

	// 2) 서명/암호화 — bigfoot 위임(BIGFOOT_URL) 또는 내장 step-ca. 결과 .p7s/.p7m
	out, ext, ctype, mode, serial, recipName := bundleBytes, "p7s", "application/pkcs7-signature", "sign", "", ""
	switch {
	case recipID != "": // 인증서 암호화 → .p7m
		ext, ctype = "p7m", "application/pkcs7-mime"
		mode = map[bool]string{true: "sign+encrypt-cert", false: "encrypt-cert"}[doSign]
		if s.bigfootEnabled() {
			// bigfoot 가 (서명 후) 수신자 암호화. recipientId = bigfoot 수신자 레지스트리 ID.
			o, sn, e := s.bigfootEncrypt(bundleBytes, []string{recipID}, cn, doSign)
			if e != nil {
				writeJSON(w, 502, map[string]string{"error": "bigfoot 암호화 실패: " + e.Error()})
				return
			}
			out, serial, recipName = o, sn, recipID
		} else {
			recip, e := s.recipientByID(recipID)
			if e != nil {
				writeJSON(w, 404, map[string]string{"error": e.Error()})
				return
			}
			content := bundleBytes
			if doSign {
				if content, serial, e = s.signContent(actor, cn, content); e != nil {
					writeJSON(w, 502, map[string]string{"error": "CMS 서명 실패: " + e.Error()})
					return
				}
			}
			o, e := cmsEncrypt(content, [][]byte{[]byte(recip.CertPEM)}, s.cfg.CMSContentCipher, s.cfg.CMSRsaPadding)
			if e != nil {
				writeJSON(w, 500, map[string]string{"error": "인증서 암호화 실패: " + e.Error()})
				return
			}
			out, recipName = o, recip.Subject
		}
	case password != "": // 패스워드 암호화 → .p7m (PWRI 는 키 불필요 → 로컬). 서명은 bigfoot/로컬.
		ext, ctype = "p7m", "application/pkcs7-mime"
		mode = map[bool]string{true: "sign+encrypt-pw", false: "encrypt-pw"}[doSign]
		content := bundleBytes
		if doSign {
			c, sn, e := s.signContent(actor, cn, content)
			if e != nil {
				writeJSON(w, 502, map[string]string{"error": "CMS 서명 실패: " + e.Error()})
				return
			}
			content, serial = c, sn
		}
		o, e := cmsEncryptPassword(content, password)
		if e != nil {
			writeJSON(w, 500, map[string]string{"error": "패스워드 암호화 실패: " + e.Error()})
			return
		}
		out = o
	default: // 서명만 → .p7s
		o, sn, e := s.signContent(actor, cn, bundleBytes)
		if e != nil {
			writeJSON(w, 502, map[string]string{"error": "CMS 서명 실패: " + e.Error()})
			return
		}
		out, serial = o, sn
	}

	// 3) SoR
	fipsOn, _ := fipsStatus()
	_ = s.sor.append(SoREvent{Actor: actor, Action: "sign", Serial: serial, Repo: repo, Tag: tag,
		Status: "packaged", Detail: map[string]any{"mode": mode, "format": ext, "bundleSize": bundle.Len(),
			"outSize": len(out), "recipient": recipName, "fips": fipsOn, "bigfoot": s.bigfootEnabled()}})

	// 5) 다운로드 스트림
	base := nonName.ReplaceAllString(path.Base(repo)+"-"+tag, "_")
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-TrustLink-Fips", fmt.Sprintf("%v", fipsOn))
	if serial != "" {
		w.Header().Set("X-TrustLink-Serial", serial)
	}
	w.Header().Set("Content-Disposition", "attachment; filename="+base+"."+ext)
	w.Write(out)
}
