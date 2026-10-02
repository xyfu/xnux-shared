package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Release levels (spec v1.1 delta 12.1), most urgent first.
const (
	LevelSecurity    = "security"
	LevelRecommended = "recommended"
	LevelOptional    = "optional"
)

// LevelRank orders levels: higher is more urgent; 0 for an unknown level.
func LevelRank(level string) int {
	switch level {
	case LevelSecurity:
		return 3
	case LevelRecommended:
		return 2
	case LevelOptional:
		return 1
	}
	return 0
}

// Manifest is releases/manifest.json, attached to every agent release
// (C-AG-RELEASE-MANIFEST): every release up to that one, newest first.
type Manifest struct {
	Schema      int       `json:"schema"`
	Latest      string    `json:"latest"`
	GeneratedAt int64     `json:"generated_at"`
	Releases    []Release `json:"releases"`
}

// Release is one agent release in the manifest. Versions carry no "v".
type Release struct {
	Version       string              `json:"version"`
	Tag           string              `json:"tag"`
	Prerelease    bool                `json:"prerelease"`
	ReleasedAt    int64               `json:"released_at"`
	Level         string              `json:"level"`
	Highlights    map[string][]string `json:"highlights"`
	Artifacts     map[string]Artifact `json:"artifacts,omitempty"`
	InstallScript *Download           `json:"install_script,omitempty"`
}

// Artifact is a binary of one platform ("linux-amd64").
type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Sig    string `json:"sig,omitempty"`  // cosign signature
	Cert   string `json:"cert,omitempty"` // cosign certificate
}

// Download is a file and its checksum.
type Download struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Validate checks what clients rely on: versions that parse, known
// levels, both languages of highlights, and that the latest release can
// be installed.
func (m *Manifest) Validate() error {
	if m.Schema != 1 {
		return errors.New("manifest: unsupported schema")
	}
	if len(m.Releases) == 0 {
		return errors.New("manifest: no releases")
	}
	for i, r := range m.Releases {
		if _, ok := ParseVersion(r.Version); !ok {
			return errors.New("manifest: bad version " + r.Version)
		}
		if LevelRank(r.Level) == 0 {
			return errors.New("manifest: bad level for " + r.Version)
		}
		if len(r.Highlights["zh-Hans"]) == 0 || len(r.Highlights["en"]) == 0 {
			return errors.New("manifest: highlights missing for " + r.Version)
		}
		if i > 0 && CompareVersions(r.Version, m.Releases[i-1].Version) >= 0 {
			return errors.New("manifest: releases not newest first")
		}
	}
	if m.Latest != m.Releases[0].Version {
		return errors.New("manifest: latest is not the first release")
	}
	if l := m.Releases[0]; l.InstallScript == nil || l.InstallScript.SHA256 == "" || len(l.Artifacts) == 0 {
		return errors.New("manifest: the latest release has no downloads")
	}
	return nil
}

// VerifyManifest checks manifest.json.ed25519 (base64 of the signature of
// the file's bytes) against a base64 public key.
func VerifyManifest(body []byte, sigB64, pubB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("manifest: bad public key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), body, sig) {
		return errors.New("manifest: signature does not verify")
	}
	return nil
}

// Version is a parsed agent version: major.minor.patch with an optional
// pre-release ("pre3", "rc1").
type Version struct {
	Core [3]int
	Pre  string
}

// ParseVersion reads "v1.2.3", "1.2.3" or "1.2.3-pre4" (build metadata
// after "+" is ignored); false for anything else, such as "dev".
func ParseVersion(s string) (Version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	s, _, _ = strings.Cut(s, "+")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var v Version
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, false
		}
		v.Core[i] = n
	}
	v.Pre = pre
	return v, true
}

// CompareVersions orders two versions (-1, 0, 1): a pre-release comes
// before its release, and "pre10" after "pre9" (thread 0003 #16).
// Unparsable versions sort first.
func CompareVersions(a, b string) int {
	va, oka := ParseVersion(a)
	vb, okb := ParseVersion(b)
	switch {
	case !oka && !okb:
		return 0
	case !oka:
		return -1
	case !okb:
		return 1
	}
	for i := range va.Core {
		if va.Core[i] != vb.Core[i] {
			if va.Core[i] < vb.Core[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case va.Pre == vb.Pre:
		return 0
	case va.Pre == "":
		return 1
	case vb.Pre == "":
		return -1
	}
	return comparePre(va.Pre, vb.Pre)
}

// comparePre compares pre-release labels by their letters, then by the
// number at their end.
func comparePre(a, b string) int {
	split := func(s string) (string, int, bool) {
		i := len(s)
		for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
			i--
		}
		n, err := strconv.Atoi(s[i:])
		return s[:i], n, err == nil
	}
	pa, na, oka := split(a)
	pb, nb, okb := split(b)
	if pa != pb || !oka || !okb {
		return strings.Compare(a, b)
	}
	switch {
	case na < nb:
		return -1
	case na > nb:
		return 1
	}
	return 0
}
