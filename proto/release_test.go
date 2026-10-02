package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.9", 1},
		{"0.9.2-pre3", "0.9.2", -1},
		{"0.9.2-pre10", "0.9.2-pre9", 1},
		{"0.9.2-pre3", "0.9.2-rc1", -1},
		{"v0.9.2-pre3", "0.9.1", 1},
		{"dev", "0.9.1", -1},
		{"0.9.1", "dev", 1},
		{"1.2.3+abc", "1.2.3", 0},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestManifest(t *testing.T) {
	hl := map[string][]string{"zh-Hans": {"新增"}, "en": {"New"}}
	m := Manifest{Schema: 1, Latest: "0.9.3", Releases: []Release{
		{Version: "0.9.3", Level: LevelRecommended, Highlights: hl, InstallScript: &Download{URL: "u", SHA256: "s"},
			Artifacts: map[string]Artifact{"linux-amd64": {URL: "u", SHA256: "s"}}},
		{Version: "0.9.2-pre3", Level: LevelSecurity, Highlights: hl},
	}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Releases[1].Version = "0.9.4"
	if m.Validate() == nil {
		t.Fatal("unordered releases accepted")
	}
	m.Releases[1].Version = "0.9.2"
	m.Releases[1].Highlights = map[string][]string{"en": {"x"}}
	if m.Validate() == nil {
		t.Fatal("missing language accepted")
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(`{"schema":1}`)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body))
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := VerifyManifest(body, sig, pubB64); err != nil {
		t.Fatal(err)
	}
	if VerifyManifest([]byte(`{"schema":2}`), sig, pubB64) == nil {
		t.Fatal("tampered manifest verified")
	}
	if LevelRank(LevelSecurity) <= LevelRank(LevelRecommended) || LevelRank("x") != 0 {
		t.Fatal("level ranks")
	}
}
