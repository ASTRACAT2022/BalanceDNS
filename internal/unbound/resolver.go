//go:build cgo && unbound
// +build cgo,unbound

package unbound

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	ub "github.com/miekg/unbound"
)

// Options controls Unbound recursion behavior.
type Options struct {
	RootAnchorPath string
	WorkerCount    int
	MsgCacheSize   string
	RRsetCacheSize string
	KeyCacheSize   string
	Prefetch       bool
	ServeExpired   bool
	DisableCache   bool
}

// Resolver wraps a pool of Unbound instances for parallel recursive resolution.
type Resolver struct {
	mu      sync.RWMutex
	workers []*resolverWorker
	opts    Options
	next    atomic.Uint64
}

type resolverWorker struct {
	u  *ub.Unbound
	mu sync.Mutex
}

// NewResolver creates a resolver with sane defaults.
func NewResolver(rootAnchorPath string) (*Resolver, error) {
	return NewResolverWithOptions(Options{
		RootAnchorPath: rootAnchorPath,
		Prefetch:       true,
		ServeExpired:   true,
	})
}

// NewResolverWithOptions creates a resolver and initializes worker pool.
func NewResolverWithOptions(opts Options) (*Resolver, error) {
	opts = withDefaultOptions(opts)
	if err := ensureRootAnchor(opts.RootAnchorPath); err != nil {
		return nil, err
	}

	workers := make([]*resolverWorker, 0, opts.WorkerCount)
	for i := 0; i < opts.WorkerCount; i++ {
		u := ub.New()
		if err := configureUnbound(u, opts); err != nil {
			u.Destroy()
			for _, w := range workers {
				w.u.Destroy()
			}
			return nil, err
		}
		workers = append(workers, &resolverWorker{u: u})
	}

	return &Resolver{workers: workers, opts: opts}, nil
}

// Resolve performs recursive DNS lookup.
func (r *Resolver) Resolve(question dns.Question) (*dns.Msg, error) {
	r.mu.RLock()
	if len(r.workers) == 0 {
		r.mu.RUnlock()
		return nil, fmt.Errorf("resolver is not initialized")
	}
	workerCount := len(r.workers)
	startIdx := selectWorkerIndex(r.next.Add(1), workerCount)
	worker := r.workers[startIdx]
	r.mu.RUnlock()

	result, err := resolveWithWorker(worker, question)
	if shouldRetryResolve(result, err) && workerCount > 1 {
		maxRetries := workerCount - 1
		if maxRetries > 2 {
			maxRetries = 2
		}
		for i := 1; i <= maxRetries; i++ {
			r.mu.RLock()
			alt := r.workers[(startIdx+i)%workerCount]
			r.mu.RUnlock()
			altResult, altErr := resolveWithWorker(alt, question)
			if !shouldRetryResolve(altResult, altErr) {
				if altErr == nil && altResult != nil && altResult.Rcode != dns.RcodeServerFailure {
					log.Printf("Unbound retry recovered query %s %s on worker %d", question.Name, dns.TypeToString[question.Qtype], (startIdx+i)%workerCount)
				}
				result, err = altResult, altErr
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("unbound resolution failed: %v", err)
	}

	resp, err := responseFromResult(question, result)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close closes all worker instances.
func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.workers {
		if w != nil && w.u != nil {
			w.mu.Lock()
			w.u.Destroy()
			w.u = nil
			w.mu.Unlock()
		}
	}
	r.workers = nil
}

// Reload recreates the resolver with existing options and new root anchor path.
func (r *Resolver) Reload(rootAnchorPath string) error {
	opts := r.opts
	if rootAnchorPath != "" {
		opts.RootAnchorPath = rootAnchorPath
	}
	fresh, err := NewResolverWithOptions(opts)
	if err != nil {
		return err
	}

	r.mu.Lock()
	oldWorkers := r.workers
	r.workers = fresh.workers
	r.opts = opts
	r.mu.Unlock()

	for _, w := range oldWorkers {
		if w != nil && w.u != nil {
			w.mu.Lock()
			w.u.Destroy()
			w.u = nil
			w.mu.Unlock()
		}
	}
	return nil
}

// ClearCache clears cache by full reload.
func (r *Resolver) ClearCache(rootAnchorPath string) error {
	return r.Reload(rootAnchorPath)
}

// WorkerCount returns active resolver workers.
func (r *Resolver) WorkerCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.workers)
}

func responseFromResult(question dns.Question, result *ub.Result) (*dns.Msg, error) {
	if result == nil {
		return nil, fmt.Errorf("unbound returned empty result")
	}
	if result.Bogus {
		msg := new(dns.Msg)
		msg.MsgHdr.Response = true
		msg.RecursionAvailable = true
		msg.Question = []dns.Question{question}
		msg.Rcode = dns.RcodeServerFailure
		msg.AuthenticatedData = false
		if result.WhyBogus != "" {
			log.Printf("Unbound bogus DNSSEC response for %s type=%s: %s", question.Name, dns.TypeToString[question.Qtype], result.WhyBogus)
		}
		return msg, nil
	}

	if result.AnswerPacket != nil {
		msg := result.AnswerPacket.Copy()
		msg.MsgHdr.Response = true
		msg.RecursionAvailable = true
		msg.Question = []dns.Question{question}
		if result.NxDomain {
			msg.Rcode = dns.RcodeNameError
		} else if msg.Rcode == dns.RcodeSuccess && result.Rcode != dns.RcodeSuccess {
			msg.Rcode = result.Rcode
		}
		if result.Secure && !result.Bogus {
			msg.AuthenticatedData = true
		} else {
			msg.AuthenticatedData = false
		}
		return msg, nil
	}

	// Return NOERROR/NODATA and NXDOMAIN correctly instead of converting to SERVFAIL.
	msg := new(dns.Msg)
	msg.MsgHdr.Response = true
	msg.RecursionAvailable = true
	msg.Question = []dns.Question{question}
	if result.NxDomain {
		msg.Rcode = dns.RcodeNameError
	} else {
		msg.Rcode = result.Rcode
	}
	msg.AuthenticatedData = result.Secure && !result.Bogus
	if len(result.Rr) > 0 {
		msg.Answer = append(msg.Answer, result.Rr...)
	}
	return msg, nil
}

func configureUnbound(u *ub.Unbound, opts Options) error {
	msgCacheSize := opts.MsgCacheSize
	rrsetCacheSize := opts.RRsetCacheSize
	keyCacheSize := opts.KeyCacheSize
	prefetch := opts.Prefetch
	serveExpired := opts.ServeExpired
	cacheMaxTTL := "86400"
	if opts.DisableCache {
		// Disable Unbound internal caches; AstracatDNS policy/cache layers remain active.
		msgCacheSize = "0"
		rrsetCacheSize = "0"
		keyCacheSize = "0"
		prefetch = false
		serveExpired = false
		cacheMaxTTL = "0"
	}

	entries := []struct {
		name     string
		value    string
		required bool
	}{
		{"module-config", "validator iterator", false},
		{"verbosity", "0", false},
		{"do-ip4", "yes", false},
		{"do-ip6", "yes", false},
		{"do-udp", "yes", false},
		{"do-tcp", "yes", false},
		{"prefer-ip6", "no", false},
		{"harden-glue", "yes", false},
		{"harden-dnssec-stripped", "yes", false},
		{"harden-algo-downgrade", "yes", false},
		{"val-permissive-mode", "no", false},
		{"use-caps-for-id", "yes", false},
		{"auto-trust-anchor-file", opts.RootAnchorPath, true},
		{"val-clean-additional", "yes", false},
		{"edns-buffer-size", "1232", false},
		{"so-rcvbuf", "4m", false},
		{"so-sndbuf", "4m", false},
		{"msg-cache-size", msgCacheSize, false},
		{"rrset-cache-size", rrsetCacheSize, false},
		{"key-cache-size", keyCacheSize, false},
		{"prefetch", boolToYesNo(prefetch), false},
		{"prefetch-key", boolToYesNo(prefetch), false},
		{"serve-expired", boolToYesNo(serveExpired), false},
		{"serve-expired-ttl", "86400", false},
		{"serve-expired-reply-ttl", "30", false},
		{"aggressive-nsec", "yes", false},
		{"minimal-responses", "yes", false},
		{"cache-min-ttl", "0", false},
		{"cache-max-ttl", cacheMaxTTL, false},
	}

	for _, e := range entries {
		if e.value == "" {
			continue
		}
		if err := u.SetOption(e.name, e.value); err != nil {
			if e.required {
				return fmt.Errorf("failed to set required unbound option %s=%s: %w", e.name, e.value, err)
			}
			log.Printf("Warning: unsupported/unset unbound option %s=%s: %v", e.name, e.value, err)
		}
	}

	privateAddrs := []string{
		"192.168.0.0/16", "169.254.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
		"fd00::/8", "fe80::/10",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
		"255.255.255.255/32", "2001:db8::/32",
	}
	for _, addr := range privateAddrs {
		if err := u.SetOption("private-address", addr); err != nil {
			log.Printf("Warning: failed to set private-address %s: %v", addr, err)
		}
	}

	return nil
}

func withDefaultOptions(opts Options) Options {
	if opts.RootAnchorPath == "" {
		opts.RootAnchorPath = "/var/lib/unbound/root.key"
	}
	if opts.WorkerCount <= 0 {
		workers := runtime.GOMAXPROCS(0)
		if workers < 2 {
			workers = 2
		}
		if workers > 16 {
			workers = 16
		}
		opts.WorkerCount = workers
	}
	if opts.MsgCacheSize == "" {
		opts.MsgCacheSize = "64m"
	}
	if opts.RRsetCacheSize == "" {
		opts.RRsetCacheSize = "128m"
	}
	if opts.KeyCacheSize == "" {
		opts.KeyCacheSize = "64m"
	}
	return opts
}

func selectWorkerIndex(next uint64, workerCount int) int {
	if workerCount == 1 {
		return 0
	}
	return int((next - 1) % uint64(workerCount))
}

func boolToYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func resolveWithWorker(worker *resolverWorker, question dns.Question) (*ub.Result, error) {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.u.Resolve(question.Name, question.Qtype, question.Qclass)
}

func shouldRetryResolve(result *ub.Result, err error) bool {
	if err != nil {
		return true
	}
	if result == nil {
		return true
	}
	return result.Rcode == dns.RcodeServerFailure
}

func ensureRootAnchor(rootAnchorPath string) error {
	info, err := os.Stat(rootAnchorPath)
	if err != nil {
		return fmt.Errorf("root anchor not found at %s: %w", rootAnchorPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("root anchor path %s is a directory", rootAnchorPath)
	}
	return nil
}
