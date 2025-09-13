# resolver

A recursive DNS resolver with a Go-based API, designed to handle domain name resolution from the root nameservers.
It includes support for DNSSEC validation via the dnssec package, which ensures the authenticity 
and integrity of DNS responses. Please note that the dnssec package will eventually be moved to its own 
dedicated project.

> [!WARNING]
> This is an alpha release and remains a work in progress. Users should expect potential
> changes and improvements as development continues. It is not recommended to rely on this project for
> security-critical applications at this stage.

# Usage

```go
package main

import (
	"context"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

func main() {
	
	// Override the default logging hook on resolver.
	// Query to print each outgoing query to stdout.
	// (So you can see what's happening.)
	resolver.Query = func(s string) {
		fmt.Println("Query: " + s)
	}


	r := resolver.NewResolver()

	// Prepare a new DNS message struct.
	msg := new(dns.Msg)
	
	// Set it up as a question for the A record of “test.qazz.uk.” (Fqdn adds trailing dot).
	msg.SetQuestion(dns.Fqdn("test.qazz.uk"), dns.TypeA)

	// Add an OPT record to enable EDNS0 with a 4096‐byte UDP payload and DNSSEC OK bit.
	msg.SetEdns0(4096, true)

	// Perform the DNS query, using a background Context (no timeout/cancel).
	// Returns a resolver.Result, or error info embedded inside it.
	result := r.Exchange(context.Background(), msg)

	// Dump the full Result struct (including Response Msg, error, timings, etc.)
	// to stdout in a human-readable form.
	spew.Dump(result)
}
```

Outputs something along the lines of:

```shell
Query: 649949c-1: 12.616666ms taken querying [test.qazz.uk.] A in zone [.] on udp://a.root-servers.net. ([2001:503:ba3e::2:30]:53)
Query: 649949c-1: 5.895667ms taken querying [uk.] DNSKEY in zone [uk.] on udp://dns3.nic.uk. ([2a01:618:404::1]:53)
Query: 649949c-1: 6.14325ms taken querying [test.qazz.uk.] A in zone [uk.] on udp://dns1.nic.uk. ([2a01:618:400::1]:53)
Query: 649949c-1: 15.660209ms taken querying [qazz.uk.] DNSKEY in zone [qazz.uk.] on udp://ns2.qazz.uk. ([2600:9000:5300:7d00::1]:53)
Query: 649949c-1: 16.85725ms taken querying [test.qazz.uk.] A in zone [qazz.uk.] on udp://ns1.qazz.uk. ([2600:9000:5303:4800::1]:53)
Query: 649949c-1: 87.384083ms taken querying [.] DNSKEY in zone [.] on udp://c.root-servers.net. ([2001:500:2::c]:53)
Query: 649949c-1: 82.208416ms taken querying [.] DNSKEY in zone [.] on tcp://c.root-servers.net. ([2001:500:2::c]:53)

(*resolver.Response)(0x140000a82a0)({
 Msg: (*dns.Msg)(0x140000982d0)(;; opcode: QUERY, status: NOERROR, id: 44134
;; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags: do; udp: 4096

;; QUESTION SECTION:
;test.qazz.uk.  IN       A

;; ANSWER SECTION:
test.qazz.uk.   60      IN      A       192.0.2.53
test.qazz.uk.   60      IN      RRSIG   A 13 3 60 20250623072623 20250623052523 6938 qazz.uk. zMzm+gyHbQGc8D3pZYmcQ/r6UGoh2VZEjNHfqAHrHsupYvr2/hKzUC4XIA3H7JM4gTz0YnZDT6u25eSFKVsztw==
),
 Err: (error) <nil>,
 Duration: (time.Duration) 258.376875ms,
 Doe: (dnssec.DenialOfExistenceState) NotFound,
 Auth: (dnssec.AuthenticationResult) Secure
})
```

# Licence
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Also see:
- [github.com/miekg/dns license](https://github.com/miekg/dns/blob/master/LICENSE)
