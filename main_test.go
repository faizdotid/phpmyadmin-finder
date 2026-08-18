package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, scheme, host string
	}{
		{"example.com", "http", "example.com"},
		{"http://example.com", "http", "example.com"},
		{"https://example.com", "https", "example.com"},
		{"  https://example.com:8080  ", "https", "example.com:8080"},
		{"example.com/phpmyadmin", "http", "example.com"},
		{"https://example.com:443", "https", "example.com"}, // default port stripped
		{"http://example.com:80", "http", "example.com"},
	}
	for _, c := range cases {
		u := normalize(c.in)
		if u == nil {
			t.Fatalf("normalize(%q) = nil", c.in)
		}
		if u.Scheme != c.scheme || u.Host != c.host {
			t.Errorf("normalize(%q) = %q %q; want %q %q", c.in, u.Scheme, u.Host, c.scheme, c.host)
		}
	}
}

func TestNormalizeInvalid(t *testing.T) {
	for _, in := range []string{"", "://bad", "ftp://example.com", "file:///etc/passwd"} {
		if u := normalize(in); u != nil {
			t.Errorf("normalize(%q) = %v; want nil", in, u)
		}
	}
}

func TestBuildTargetsCount(t *testing.T) {
	s := newScanner(nil, 1, 0, "", false)
	targets := s.buildTargets("https://example.com")
	want := len(subdomains) + len(paths)
	if len(targets) != want {
		t.Errorf("got %d targets, want %d", len(targets), want)
	}
	seen := make(map[string]struct{}, len(targets))
	for _, tg := range targets {
		if _, ok := seen[tg]; ok {
			t.Errorf("duplicate target %q", tg)
		}
		seen[tg] = struct{}{}
	}
}

func TestBuildTargetsPreservesScheme(t *testing.T) {
	s := newScanner(nil, 1, 0, "", false)
	for _, tg := range s.buildTargets("https://example.com") {
		if !strings.HasPrefix(tg, "https://") {
			t.Errorf("target %q does not preserve https scheme", tg)
		}
	}
}

func TestBuildTargetsStructure(t *testing.T) {
	s := newScanner(nil, 1, 0, "", false)
	targets := s.buildTargets("http://example.com:8080")

	const (
		sub         = "http://adminer.example.com"
		subWithPort = "http://adminer.example.com:8080"
		path        = "http://example.com:8080/phpmyadmin/"
	)
	hasSub, hasSubPort, hasPath := false, false, false
	for _, tg := range targets {
		switch tg {
		case sub:
			hasSub = true
		case subWithPort:
			hasSubPort = true
		case path:
			hasPath = true
		}
	}
	if !hasSub {
		t.Errorf("missing subdomain target %q", sub)
	}
	if hasSubPort {
		t.Errorf("subdomain target should not include port: %q", subWithPort)
	}
	if !hasPath {
		t.Errorf("missing path target %q", path)
	}
}

func TestBuildTargetsInvalidURL(t *testing.T) {
	s := newScanner(nil, 1, 0, "", false)
	if got := s.buildTargets("ftp://example.com"); got != nil {
		t.Errorf("buildTargets(ftp://) = %v; want nil", got)
	}
	if got := s.buildTargets(""); got != nil {
		t.Errorf("buildTargets(\"\") = %v; want nil", got)
	}
}

func TestDedupeURLs(t *testing.T) {
	in := []string{
		"https://example.com",
		"example.com",
		"https://example.com/phpmyadmin",
		"https://other.com",
		"ftp://bad.com",           // invalid, dropped
		"https://example.com:443", // same as https://example.com after default-port strip
	}
	out := dedupeURLs(in)
	if len(out) != 3 {
		t.Errorf("got %d unique urls, want 3: %v", len(out), out)
	}
}

func TestMarkers(t *testing.T) {
	positive := []string{
		`<input name="pma_username">`,
		`<input name="pma_password">`,
		`<input name="auth[username]">`,
		`<input name="auth[password]">`,
		`phpMyAdmin`,
		`PHPMyAdmin`,
		`PMA_token`,
		`pma_servername`,
		`server_select`,
		`input_username`,
		`input_password`,
		`mysql-admin`,
		`adminer`,
		`MariaDB administration`,
	}
	for _, p := range positive {
		if !markersRe.MatchString(p) {
			t.Errorf("markersRe should match %q", p)
		}
	}
	negative := []string{
		`<html><body>hello</body></html>`,
		`<input type="password">`,
		`<form method="post">`,
		`<div>welcome to my site</div>`,
	}
	for _, n := range negative {
		if markersRe.MatchString(n) {
			t.Errorf("markersRe should NOT match %q", n)
		}
	}
}

func TestLoadURLs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "targets.txt")
	content := "# comment\n\n  https://example.com  \nhttp://other.com\n\n# another\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadURLs(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://example.com", "http://other.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadURLsMissing(t *testing.T) {
	if _, err := loadURLs(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Error("expected error for missing file")
	}
}
