package sanitize

import "testing"

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"example.com": "example.com", " Example.COM ": "example.com", "*.example.org": "example.org",
		".example.net.": "example.net", "shop.example.co.uk": "shop.example.co.uk", "my-site.io": "my-site.io",
	} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "com", "localhost", "exa mple.com", "example..com", "-bad.com", "bad-.com", "exa_mple.com", "例子.com"} {
		if got, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
	if _, err := New(Options{RedactDomains: []string{"example.com", "com"}}); err == nil {
		t.Error("a one-label entry must stop the barrier")
	}
}

func TestHostnameDomain(t *testing.T) {
	for in, want := range map[string]string{
		"web-01.example.com": "example.com", "a.b.example.com": "b.example.com", "WEB.Example.COM.": "example.com",
		"example.com": "", "web-01": "", "": "", "host": "",
	} {
		if got := HostnameDomain(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// The count goes into the payload's redactions; the list itself never does.
func TestDomainStats(t *testing.T) {
	b, err := New(Options{RedactDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	st := Stats{}
	if got := b.apply("a.example.com b.example.com", kindNormal, st); got != "a.[REDACTED:domain] b.[REDACTED:domain]" || st[RuleDomain] != 2 {
		t.Fatalf("%q %v", got, st)
	}
}
