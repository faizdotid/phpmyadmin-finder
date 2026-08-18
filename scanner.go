package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	maxBody   = 1 << 20 // cap response body at 1 MiB
)

var (
	green = "\x1b[32m"
	blue  = "\x1b[34m"
	reset = "\x1b[0m"
)

func initColor() {
	if !isTerminal(os.Stdout) {
		green, blue, reset = "", "", ""
	}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

type Scanner struct {
	urls    []string
	threads int
	timeout time.Duration
	output  string
	debug   bool
	client  *http.Client
}

func newScanner(urls []string, threads int, timeout time.Duration, output string, debug bool) *Scanner {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}

	return &Scanner{
		urls:    urls,
		threads: threads,
		timeout: timeout,
		output:  output,
		debug:   debug,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
					return fmt.Errorf("cross-host redirect blocked")
				}
				return nil
			},
		},
	}
}

// normalize trims the URL, adds a scheme when missing, rejects unsupported
// schemes, and strips default ports. Returns nil for invalid input.
func normalize(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	switch {
	case strings.HasPrefix(raw, "http://"), strings.HasPrefix(raw, "https://"):
		// keep as-is
	default:
		if strings.Contains(raw, "://") {
			return nil // unsupported scheme (ftp://, file://, ...)
		}
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	stripDefaultPort(u)
	return u
}

// stripDefaultPort removes :80/:443 so equivalent hosts dedupe identically.
func stripDefaultPort(u *url.URL) {
	if strings.Contains(u.Hostname(), ":") {
		return // don't touch IPv6 literals
	}
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
	}
}

// buildTargets expands a URL into probe targets, preserving the input scheme.
func (s *Scanner) buildTargets(raw string) []string {
	u := normalize(raw)
	if u == nil {
		return nil
	}
	scheme, host, hostname := u.Scheme, u.Host, u.Hostname()
	targets := make([]string, 0, len(subdomains)+len(paths))
	for _, sub := range subdomains {
		targets = append(targets, fmt.Sprintf("%s://%s.%s", scheme, sub, hostname))
	}
	for _, p := range paths {
		targets = append(targets, fmt.Sprintf("%s://%s%s", scheme, host, p))
	}
	return targets
}

func (s *Scanner) check(target string) bool {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		if s.debug {
			log.Printf("[debug] %s — %v", target, err)
		}
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return false
	}
	return markersRe.Match(body)
}

func dedupeURLs(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		n := normalize(u)
		if n == nil {
			continue
		}
		key := n.Scheme + "://" + n.Host
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	return out
}

// Run scans all targets concurrently and returns the number of panels found.
func (s *Scanner) Run() int {
	urls := dedupeURLs(s.urls)
	targets := make([]string, 0, len(urls)*(len(subdomains)+len(paths)))
	for _, u := range urls {
		targets = append(targets, s.buildTargets(u)...)
	}

	fmt.Printf("%s[*]%s scanning %d url(s) → %d target(s), %d worker(s)\n",
		blue, reset, len(urls), len(targets), s.threads)

	out, err := s.openOutput()
	if err != nil {
		log.Printf("warning: cannot open output %q: %v", s.output, err)
	}
	if out != nil {
		defer out.Close()
	}

	jobCh := make(chan string)
	resultCh := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobCh {
				if s.check(t) {
					resultCh <- t
				}
			}
		}()
	}

	var (
		writeMu    sync.Mutex
		foundCount int
	)
	done := make(chan struct{})
	go func() {
		for r := range resultCh {
			writeMu.Lock()
			if out != nil {
				if _, err := out.WriteString(r + "\n"); err != nil {
					log.Printf("warning: write output: %v", err)
				}
			}
			fmt.Printf("%s[+]%s %s\n", green, reset, r)
			foundCount++
			writeMu.Unlock()
		}
		close(done)
	}()

	go func() {
		for _, t := range targets {
			jobCh <- t
		}
		close(jobCh)
	}()

	wg.Wait()
	close(resultCh)
	<-done

	return foundCount
}

func (s *Scanner) openOutput() (*os.File, error) {
	if s.output == "" {
		return nil, nil
	}
	return os.OpenFile(s.output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}
