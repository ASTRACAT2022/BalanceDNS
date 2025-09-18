package resolver

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

// rootHints - это список корневых DNS-серверов.
var rootHints = map[string]string{
	"a.root-servers.net.": "198.41.0.4",
	"b.root-servers.net.": "170.247.170.2",
	"c.root-servers.net.": "192.33.4.12",
	"d.root-servers.net.": "199.7.91.13",
	"e.root-servers.net.": "192.203.230.10",
	"f.root-servers.net.": "192.5.5.241",
	"g.root-servers.net.": "192.112.36.4",
	"h.root-servers.net.": "198.97.190.53",
	"i.root-servers.net.": "192.36.148.17",
	"j.root-servers.net.": "192.58.128.30",
	"k.root-servers.net.": "193.0.14.129",
	"l.root-servers.net.": "199.7.83.42",
	"m.root-servers.net.": "202.12.27.33",
}

// rootTrustAnchorDS - это DS-запись для корневого ключа KSK-2017.
const rootTrustAnchorDS = ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

var (
	// ErrBogus - DNSSEC-валидация не пройдена (BOGUS).
	ErrBogus = fmt.Errorf("bogus")
	// ErrInsecure - зона не подписана (INSECURE).
	ErrInsecure = fmt.Errorf("insecure")
)

// Result - это результат разрешения.
type Result struct {
	Msg *dns.Msg
	Err error
}

// Resolver - это рекурсивный DNS-резолвер.
type Resolver struct{}

// NewResolver создает новый резолвер.
func NewResolver() *Resolver {
	return &Resolver{}
}

// Exchange выполняет DNS-запрос и DNSSEC-валидацию.
func (r *Resolver) Exchange(ctx context.Context, msg *dns.Msg) *Result {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	finalMsg, err := r.resolve(ctx, msg.Question[0].Name, msg.Question[0].Qtype)
	if err != nil {
		servFail := new(dns.Msg)
		servFail.SetRcode(msg, dns.RcodeServerFailure)
		return &Result{Msg: servFail, Err: err}
	}

	finalMsg.Id = msg.Id

	err = r.validate(ctx, finalMsg)
	if err != nil {
		if errors.Is(err, ErrInsecure) {
			fmt.Println("DNSSEC status: Insecure")
			finalMsg.AuthenticatedData = false
			return &Result{Msg: finalMsg}
		}

		// All other validation errors are considered bogus
		fmt.Printf("DNSSEC validation failed: %v\n", err)
		servFail := new(dns.Msg)
		servFail.SetRcode(msg, dns.RcodeServerFailure)
		servFail.Id = msg.Id
		return &Result{Msg: servFail, Err: fmt.Errorf("DNSSEC validation failed: %w", err)}
	}

	fmt.Println("DNSSEC validation successful!")
	finalMsg.AuthenticatedData = true
	return &Result{Msg: finalMsg}
}

// resolve - основная логика рекурсивного разрешения.
func (r *Resolver) resolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	nsAddrs := getRootNSAddrs()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("resolution timed out for %s", qname)
		default:
		}

		req := new(dns.Msg)
		req.SetQuestion(qname, qtype)
		req.SetEdns0(4096, true)

		// fmt.Printf("Querying %s for %s, servers: %v\n", qname, dns.TypeToString[qtype], nsAddrs)
		resp, err := r.queryAny(ctx, nsAddrs, req)
		if err != nil {
			return nil, err
		}
		// fmt.Printf("Response from server: %s\n", resp.String())

		if len(resp.Answer) > 0 {
			for _, ans := range resp.Answer {
				if cname, ok := ans.(*dns.CNAME); ok {
					// fmt.Printf("Found CNAME for %s: %s. Restarting resolution.\n", qname, cname.Target)
					cnameResp, err := r.resolve(ctx, cname.Target, qtype)
					if err != nil {
						return nil, err
					}
					cnameResp.Answer = append([]dns.RR{ans}, cnameResp.Answer...)
					return cnameResp, nil
				}
			}
			return resp, nil
		}

		if len(resp.Ns) > 0 {
			_, nextAddrs, err := r.extractNS(ctx, resp)
			if err != nil {
				return nil, err
			}
			nsAddrs = nextAddrs
			continue
		}

		if resp.Rcode == dns.RcodeNameError || resp.Rcode == dns.RcodeSuccess {
			return resp, nil
		}
		return nil, fmt.Errorf("no answer or referral for %s, rcode: %s", qname, dns.RcodeToString[resp.Rcode])
	}
}

// validate - выполняет DNSSEC-валидацию ответа.
func (r *Resolver) validate(ctx context.Context, finalMsg *dns.Msg) error {
	if len(finalMsg.Answer) == 0 {
		// TODO: Validate non-existence with NSEC/NSEC3
		return ErrInsecure
	}

	rootDS, err := dns.NewRR(rootTrustAnchorDS)
	if err != nil {
		return fmt.Errorf("failed to parse root trust anchor: %w", err)
	}
	trustedDS := []*dns.DS{rootDS.(*dns.DS)}

	zones := getZoneChain(finalMsg.Question[0].Name)
	var trustedKeys []*dns.DNSKEY

	for i := len(zones) - 1; i >= 0; i-- {
		zone := zones[i]
		keys, err := r.validateZone(ctx, zone, trustedDS)
		if err != nil {
			return fmt.Errorf("failed to validate zone %s: %w", zone, err)
		}
		trustedKeys = keys

		if i > 0 {
			nextZone := zones[i-1]
			dsMsg, err := r.resolve(ctx, nextZone, dns.TypeDS)
			if err != nil {
				// If we can't get the DS record, we can't prove anything.
				return fmt.Errorf("could not get DS for %s: %w", nextZone, err)
			}

			// If the DS record query results in NXDOMAIN or NOERROR with no answer,
			// the child zone is unsigned.
			if dsMsg.Rcode == dns.RcodeNameError || (dsMsg.Rcode == dns.RcodeSuccess && len(dsMsg.Answer) == 0) {
				return ErrInsecure
			}

			if err := verifyRRSIGs(dsMsg.Answer, trustedKeys); err != nil {
				return fmt.Errorf("failed to verify DS RRset for %s: %w", nextZone, err)
			}

			trustedDS = extractDSs(dsMsg.Answer)
			if len(trustedDS) == 0 {
				// This should be caught by the check above, but as a fallback.
				return ErrInsecure
			}
		}
	}

	return verifyRRSIGs(finalMsg.Answer, trustedKeys)
}

func (r *Resolver) validateZone(ctx context.Context, zone string, parentDS []*dns.DS) ([]*dns.DNSKEY, error) {
	dnskeyMsg, err := r.resolve(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, fmt.Errorf("could not get DNSKEY for %s: %w", zone, err)
	}
	if dnskeyMsg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNSKEY query for %s failed with rcode %s: %w", zone, dns.RcodeToString[dnskeyMsg.Rcode], ErrBogus)
	}
	keys := extractDNSKEYs(dnskeyMsg.Answer)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no DNSKEY records found for %s: %w", zone, ErrBogus)
	}

	var trustedKSK *dns.DNSKEY
	for _, key := range keys {
		if (key.Flags&dns.ZONE) != 0 && (key.Flags&dns.SEP) != 0 {
			ds := key.ToDS(dns.SHA256)
			for _, anchor := range parentDS {
				if ds != nil && strings.ToUpper(ds.Digest) == strings.ToUpper(anchor.Digest) && ds.KeyTag == anchor.KeyTag {
					trustedKSK = key
					break
				}
			}
		}
		if trustedKSK != nil {
			break
		}
	}

	if trustedKSK == nil {
		return nil, fmt.Errorf("could not find a trusted KSK for zone %s: %w", zone, ErrBogus)
	}

	if err := verifyRRSIGs(dnskeyMsg.Answer, []*dns.DNSKEY{trustedKSK}); err != nil {
		return nil, fmt.Errorf("failed to verify DNSKEY RRset for %s: %w", zone, err)
	}

	return keys, nil
}

func getZoneChain(qname string) []string {
	labels := dns.SplitDomainName(qname)
	zones := make([]string, 0, len(labels))
	for i := 0; i < len(labels); i++ {
		if labels[i] == "" { // root label
			continue
		}
		zones = append(zones, joinDomainName(labels[i:]))
	}
	zones = append(zones, ".")
	return zones
}

func joinDomainName(labels []string) string {
	return strings.Join(labels, ".") + "."
}

func verifyRRSIGs(records []dns.RR, keys []*dns.DNSKEY) error {
	var sigs []*dns.RRSIG
	rrset := []dns.RR{}
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
		} else {
			rrset = append(rrset, rr)
		}
	}

	if len(sigs) == 0 {
		// It's ok if there are no signatures for DNSKEY RRset at the root
		if len(rrset) > 0 && rrset[0].Header().Rrtype == dns.TypeDNSKEY && rrset[0].Header().Name == "." {
			return nil
		}
		return fmt.Errorf("no RRSIGs found in the record set: %w", ErrBogus)
	}

	for _, sig := range sigs {
		if len(rrset) > 0 && sig.TypeCovered != rrset[0].Header().Rrtype {
			continue
		}
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag && key.Header().Name == sig.SignerName {
				if err := sig.Verify(key, rrset); err == nil {
					// fmt.Printf("RRSIG for %s validated with key %d.\n", dns.TypeToString[sig.TypeCovered], key.KeyTag())
					return nil
				}
			}
		}
	}
	return fmt.Errorf("failed to verify any RRSIG: %w", ErrBogus)
}

func extractDSs(records []dns.RR) []*dns.DS {
	var dsSet []*dns.DS
	for _, rr := range records {
		if ds, ok := rr.(*dns.DS); ok {
			dsSet = append(dsSet, ds)
		}
	}
	return dsSet
}

func extractDNSKEYs(records []dns.RR) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, rr := range records {
		if key, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func (r *Resolver) queryAny(ctx context.Context, servers []string, msg *dns.Msg) (*dns.Msg, error) {
	client := new(dns.Client)
	for _, server := range servers {
		addr := net.JoinHostPort(server, "53")
		resp, _, err := client.ExchangeContext(ctx, msg, addr)
		if err == nil && resp.Rcode != dns.RcodeServerFailure {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("all servers failed for query %s", msg.Question[0].Name)
}

func (r *Resolver) extractNS(ctx context.Context, resp *dns.Msg) ([]string, []string, error) {
	var nsNames []string
	var nsAddrs []string

	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}

	for _, rr := range resp.Extra {
		if a, ok := rr.(*dns.A); ok {
			for _, nsName := range nsNames {
				if a.Header().Name == nsName {
					nsAddrs = append(nsAddrs, a.A.String())
				}
			}
		}
	}

	if len(nsAddrs) < len(nsNames) {
		for _, nsName := range nsNames {
			isResolved := false
			for _, rr := range resp.Extra {
				if a, ok := rr.(*dns.A); ok && a.Header().Name == nsName {
					isResolved = true
					break
				}
			}
			if !isResolved {
				// fmt.Printf("Resolving NS %s\n", nsName)
				nsResp, err := r.resolve(ctx, nsName, dns.TypeA)
				if err == nil {
					for _, ans := range nsResp.Answer {
						if a, ok := ans.(*dns.A); ok {
							nsAddrs = append(nsAddrs, a.A.String())
						}
					}
				}
			}
		}
	}

	if len(nsAddrs) == 0 {
		return nil, nil, fmt.Errorf("could not find any IP for NS records")
	}

	return nsNames, nsAddrs, nil
}

func getRootNSAddrs() []string {
	addrs := make([]string, 0, len(rootHints))
	for _, addr := range rootHints {
		addrs = append(addrs, addr)
	}
	return addrs
}
