package unbound

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

// Resolver wraps the Unbound instance.
type Resolver struct {
	u  *unbound.Unbound
	mu sync.Mutex
}

// NewResolver creates and initializes a new Unbound resolver.
func NewResolver() (*Resolver, error) {
	u := unbound.New()

	// Apply User Configuration
	opts := map[string]string{
		"verbosity":              "0",
		"do-ip4":                 "yes",
		"do-ip6":                 "yes",
		"do-udp":                 "yes",
		"do-tcp":                 "yes",
		"prefer-ip6":             "no",
		"harden-glue":            "yes",
		"harden-dnssec-stripped": "yes",
		"use-caps-for-id":        "no",
		"auto-trust-anchor-file": "/var/lib/unbound/root.key",
		"val-clean-additional":   "yes",
		"edns-buffer-size":       "1232",
		"so-rcvbuf":              "1m",
		"msg-cache-size":         "5k",
		"rrset-cache-size":       "5k",
		"prefetch":               "no",
		"prefetch-key":           "no",
		"serve-expired":          "no",
		"cache-min-ttl":          "0",
		"cache-max-ttl":          "86400",
	}

	for k, v := range opts {
		if err := u.SetOption(k, v); err != nil {
			return nil, fmt.Errorf("failed to set %s: %v", k, err)
		}
	}

	// Private Addresses (Privacy / RFC6303)
	privateAddrs := []string{
		"192.168.0.0/16", "169.254.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
		"fd00::/8", "fe80::/10",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
		"255.255.255.255/32", "2001:db8::/32",
	}
	for _, addr := range privateAddrs {
		if err := u.SetOption("private-address", addr); err != nil {
			return nil, fmt.Errorf("failed to set private-address %s: %v", addr, err)
		}
	}

	return &Resolver{u: u}, nil
}

// Resolve performs a DNS resolution for the given question.
func (r *Resolver) Resolve(question dns.Question) (*dns.Msg, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Convert dns.Question to Unbound expectation
	// Unbound Resolve() takes prompt, type, class
	// Note: miekg/unbound Resolve returns (*Result, error)
	// result.AnswerPacket is the raw wire bytes of the answer.

	result, err := r.u.Resolve(question.Name, question.Qtype, question.Qclass)
	if err != nil {
		return nil, fmt.Errorf("unbound resolution failed: %v", err)
	}

	if result.HaveData || result.NxDomain {
		// Parse the raw packet back into a dns.Msg
		// result.Packet is a []byte (if available in wrapper?)
		// Checking miekg/unbound docs (implied): result has fields like CanonName, Data...
		// But usually we want the full packet if possible for DNSSEC data.
		// Wait, miekg/unbound implementation details:
		// Resolve() calls ub_resolve().
		// Result struct has: Qname, Qtype, Qclass, Data [][]byte, CanonName, Rcode, Secure, WhyBogus...
		// It does NOT expose the full raw packet easily in the basic Resolve struct unless we use async or newer bindings.
		// However, for a proxy, we want to construct a dns.Msg response.

		m := new(dns.Msg)
		m.SetReply(&dns.Msg{Question: []dns.Question{question}})
		m.Rcode = result.Rcode
		m.AuthenticatedData = result.Secure

		// Reconstruct RR from Data
		// This is tedious. Let's see if there's a better way or if the wrapper provides the packet.
		// The wrapper *unbound.Unbound has a method implementation.
		// If we only get Data [][]byte, we have to rebuild RRs.

		// Alternative: Use `ResolveAsync` which might behave differently, or check if `AnswerPacket` is available.
		// Inspecting common Go unbound wrappers: often they just wrap ub_resolve.
		// If we can't get the full packet easily, we might just reconstruct the Answer section.

		// FOR MVP:
		// Since we cannot verify the exact API of the wrapper without reading it (and I entered Execution without reading the wrapper source code which I don't have access to),
		// I will assume for a moment that I need to build the response.
		// BUT, actually, standard `miekg/unbound` doesn't seem to expose raw packet in synchronous Resolve.
		// This might be why people use `github.com/miekg/dns` with `net.Resolver`.

		// RE-EVALUATION:
		// If I cannot easily get the whole packet, Unbound might just be acting as a cache/validator.
		// However, `libunbound` does have `ub_result` which has `answer_packet` and `answer_len`.
		// If `miekg/unbound` exposes `AnswerPacket []byte`, then we are good.
		// Most updated forks do. Let's assume `AnswerPacket` exists.
		// usage: if len(result.AnswerPacket) > 0 { msg.Unpack(result.AnswerPacket) }

		// result.AnswerPacket seems to be *dns.Msg according to linter.
		if result.AnswerPacket != nil {
			m := result.AnswerPacket
			m.SetReply(&dns.Msg{Question: []dns.Question{question}})
			// Restore AD bit if needed, though SetReply might reset some flags,
			// usually we want to keep the answer data.
			// Actually SetReply sets QR=1, copies ID/Opcode/Question.
			// We should ensure Rcode is correct.
			m.Rcode = result.Rcode
			// ID is handled by the caller (Proxy)

			return m, nil
		}

		// Fallback for empty packet with Rcode (e.g. simplified NXDOMAIN without SOA?)
		m = new(dns.Msg)
		m.SetReply(&dns.Msg{Question: []dns.Question{question}})
		m.Rcode = result.Rcode
		m.AuthenticatedData = result.Secure
		return m, nil
	}

	return nil, fmt.Errorf("resolution failed (Rcode: %d)", result.Rcode)
}

// Close closes the Unbound instance.
func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.u != nil {
		r.u.Destroy()
		r.u = nil
	}
}

// Reload re-initializes the Unbound resolver.
func (r *Resolver) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.u != nil {
		r.u.Destroy()
	}

	u := unbound.New()

	// Apply User Configuration
	opts := map[string]string{
		"verbosity":              "0",
		"do-ip4":                 "yes",
		"do-ip6":                 "yes",
		"do-udp":                 "yes",
		"do-tcp":                 "yes",
		"prefer-ip6":             "no",
		"harden-glue":            "yes",
		"harden-dnssec-stripped": "yes",
		"use-caps-for-id":        "no",
		"auto-trust-anchor-file": "/var/lib/unbound/root.key",
		"val-clean-additional":   "yes",
		"edns-buffer-size":       "1232",
		"so-rcvbuf":              "1m",
		"msg-cache-size":         "5k",
		"rrset-cache-size":       "5k",
		"prefetch":               "no",
		"prefetch-key":           "no",
		"serve-expired":          "no",
		"cache-min-ttl":          "0",
		"cache-max-ttl":          "86400",
	}

	for k, v := range opts {
		if err := u.SetOption(k, v); err != nil {
			return fmt.Errorf("failed to set %s: %v", k, err)
		}
	}

	// Private Addresses (Privacy / RFC6303)
	privateAddrs := []string{
		"192.168.0.0/16", "169.254.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
		"fd00::/8", "fe80::/10",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
		"255.255.255.255/32", "2001:db8::/32",
	}
	for _, addr := range privateAddrs {
		if err := u.SetOption("private-address", addr); err != nil {
			return fmt.Errorf("failed to set private-address %s: %v", addr, err)
		}
	}

	r.u = u
	return nil
}

// ClearCache clears the cache by recreating the instance (simplest method for embedded libunbound).
func (r *Resolver) ClearCache() error {
	return r.Reload()
}
