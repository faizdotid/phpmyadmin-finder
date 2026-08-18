package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const loginBody = `<html><title>phpMyAdmin</title><body><form>` +
	`<input name="pma_username"><input name="pma_password"></form></body></html>`

func TestCheckPositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, loginBody)
	}))
	defer ts.Close()

	s := &Scanner{client: ts.Client()}
	if !s.check(ts.URL) {
		t.Fatal("expected true for phpMyAdmin login body")
	}
}

func TestCheckNegativeNoMarker(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body>hello</body></html>`)
	}))
	defer ts.Close()

	s := &Scanner{client: ts.Client()}
	if s.check(ts.URL) {
		t.Fatal("expected false for body without markers")
	}
}

func TestCheckNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := &Scanner{client: ts.Client()}
	if s.check(ts.URL) {
		t.Fatal("expected false for 404")
	}
}

func TestCheckSameHostRedirectFollowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, loginBody)
	}))
	defer ts.Close()

	s := newScanner([]string{ts.URL}, 1, 2*time.Second, "", false)
	if !s.check(ts.URL + "/redirect") {
		t.Fatal("expected same-host redirect to be followed and matched")
	}
}

func TestCheckCrossHostRedirectBlocked(t *testing.T) {
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, loginBody)
	}))
	defer srv2.Close()

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv2.URL, http.StatusFound)
	}))
	defer srv1.Close()

	s := newScanner([]string{srv1.URL}, 1, 2*time.Second, "", false)
	if s.check(srv1.URL) {
		t.Fatal("expected cross-host redirect to be blocked")
	}
}

func TestRunEndToEnd(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, loginBody)
	}))
	defer ts.Close()

	out := filepath.Join(t.TempDir(), "found.txt")

	// Route any host to the test server so all targets are reachable.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", ts.Listener.Addr().String())
		},
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}

	s := newScanner([]string{"http://example.com"}, 8, 2*time.Second, out, false)
	s.client = client

	found := s.Run()
	want := len(subdomains) + len(paths)
	if found != want {
		t.Fatalf("found = %d, want %d", found, want)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != found {
		t.Errorf("output file has %d lines, want %d", len(lines), found)
	}
}
