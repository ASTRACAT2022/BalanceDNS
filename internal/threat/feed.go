package threat

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FeedFetcher downloads a single feed with security hardening: bounded body,
// timeout, TLS verification, controlled redirects, and SSRF protection (denies
// file://, localhost, metadata endpoints, and non-http(s) schemes).
type FeedFetcher struct {
	client *http.Client
}

// FetchResult is the raw body plus the HTTP status for sanity checking.
type FetchResult struct {
	Body       []byte
	StatusCode int
	ContentType string
}

// NewFeedFetcher builds a fetcher with a hardened transport.
func NewFeedFetcher(timeout time.Duration) *FeedFetcher {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: time.Second,
	}
	return &FeedFetcher{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// CheckRedirect enforces redirect limits and scheme safety.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				if err := validateFeedURL(req.URL); err != nil {
					return err
				}
				return nil
			},
		},
	}
}

// validateFeedURL rejects unsafe schemes and SSRF-prone targets.
func validateFeedURL(u *url.URL) error {
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("blocked feed URL scheme %q (only http/https allowed)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("feed URL has no host")
	}
	lower := strings.ToLower(host)
	if lower == "localhost" {
		return fmt.Errorf("feed URL host localhost is blocked")
	}
	if strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("feed URL host %q is blocked", host)
	}
	// Cloud metadata endpoints.
	if lower == "169.254.169.254" || strings.HasPrefix(lower, "169.254.169.") {
		return fmt.Errorf("feed URL cloud metadata endpoint blocked")
	}
	if strings.HasPrefix(lower, "metadata.") && strings.HasSuffix(lower, ".google") {
		return fmt.Errorf("feed URL gce metadata endpoint blocked")
	}
	// Reject literal IP loopback/private ranges to reduce SSRF blast radius.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("feed URL resolves to blocked address %s", host)
		}
	}
	return nil
}

// parseFeedURL validates a configured feed URL string.
func parseFeedURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid feed url: %w", err)
	}
	if err := validateFeedURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

// Fetch downloads a feed with the configured max size and auth header. It
// returns an error on network failure, non-2xx status, timeout, or oversized
// body, so the caller can reject a bad feed and keep the old snapshot.
func (f *FeedFetcher) Fetch(ctx context.Context, feed FeedConfig, maxBytes int64) (*FetchResult, error) {
	u, err := parseFeedURL(feed.URL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	// Sensible defaults: most threat feeds are plain text or JSON.
	req.Header.Set("User-Agent", "BalanceDNS-ThreatIntel/1.0 (+https://astracat.ru)")
	req.Header.Set("Accept", "*/*")
	if feed.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch feed %q: %w", feed.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		return nil, fmt.Errorf("feed %q returned HTTP %d", feed.Name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("read feed %q: %w", feed.Name, err)
	}
	if int64(len(body)) >= maxBytes {
		return nil, fmt.Errorf("feed %q exceeded max size %d bytes", feed.Name, maxBytes)
	}

	return &FetchResult{
		Body:        body,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}
