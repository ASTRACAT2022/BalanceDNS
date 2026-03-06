package recursor

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type dnssecStatus string

const (
	dnssecStatusUnknown  dnssecStatus = "unknown"
	dnssecStatusSecure   dnssecStatus = "secure"
	dnssecStatusBogus    dnssecStatus = "bogus"
	dnssecStatusInsecure dnssecStatus = "insecure"
)

var defaultRootTrustAnchorDS = []string{
	". 86400 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
}

type rrsetKey struct {
	name  string
	rtype uint16
}

type zoneValidationResult struct {
	keys   []*dns.DNSKEY
	secure bool
	err    error
}

type negativeProofSet struct {
	nsec  []*dns.NSEC
	nsec3 []*dns.NSEC3
}

var errNSEC3OptOutInsecure = errors.New("nsec3 opt-out insecure delegation")

func loadTrustAnchorDS(raw []string) ([]*dns.DS, error) {
	if len(raw) == 0 {
		raw = defaultRootTrustAnchorDS
	}
	anchors := make([]*dns.DS, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		rr, err := dns.NewRR(item)
		if err != nil {
			return nil, fmt.Errorf("invalid DNSSEC trust anchor %q: %w", item, err)
		}
		ds, ok := rr.(*dns.DS)
		if !ok {
			return nil, fmt.Errorf("trust anchor is not DS RR: %q", item)
		}
		ds.Hdr.Name = normalizeFQDN(ds.Hdr.Name)
		anchors = append(anchors, ds)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("no DNSSEC trust anchors configured")
	}
	return anchors, nil
}

func (r *Resolver) validateResponseDNSSEC(ctx context.Context, q dns.Question, resp *dns.Msg) (dnssecStatus, error) {
	if resp == nil {
		return dnssecStatusUnknown, fmt.Errorf("empty response")
	}
	if len(resp.Answer) == 0 {
		return r.validateNegativeResponseDNSSEC(ctx, q, resp)
	}

	rrsets, sigs := collectSignedRRsets(resp.Answer)
	memo := map[string]zoneValidationResult{}

	if len(sigs) == 0 {
		zone, err := r.findAuthoritativeZone(ctx, q.Name)
		if err != nil {
			return dnssecStatusInsecure, nil
		}
		_, secure, err := r.validateZoneKeys(ctx, zone, memo)
		if err != nil {
			return dnssecStatusBogus, err
		}
		if secure {
			return dnssecStatusBogus, fmt.Errorf("signed zone response has no RRSIG for %s", q.Name)
		}
		return dnssecStatusInsecure, nil
	}

	secureRRsets := 0
	for key, rrset := range rrsets {
		rrSigs := sigs[key]
		if len(rrSigs) == 0 {
			continue
		}

		validated := false
		hadSecureSigner := false
		for _, sig := range rrSigs {
			zone := normalizeFQDN(sig.SignerName)
			keys, secure, err := r.validateZoneKeys(ctx, zone, memo)
			if err != nil {
				return dnssecStatusBogus, err
			}
			if !secure {
				continue
			}
			hadSecureSigner = true
			if verifyRRSetWithKey(rrset, sig, keys) {
				validated = true
				break
			}
		}

		if hadSecureSigner && !validated {
			return dnssecStatusBogus, fmt.Errorf("dnssec verify failed for %s type=%d", key.name, key.rtype)
		}
		if validated {
			secureRRsets++
		}
	}

	if secureRRsets == 0 {
		return dnssecStatusInsecure, nil
	}
	return dnssecStatusSecure, nil
}

func (r *Resolver) validateNegativeResponseDNSSEC(ctx context.Context, q dns.Question, resp *dns.Msg) (dnssecStatus, error) {
	if resp == nil {
		return dnssecStatusUnknown, fmt.Errorf("empty response")
	}
	if !resp.Authoritative {
		return dnssecStatusInsecure, nil
	}

	memo := map[string]zoneValidationResult{}
	zone := zoneFromSOA(resp)
	if zone == "" {
		z, err := r.findAuthoritativeZone(ctx, q.Name)
		if err != nil {
			return dnssecStatusInsecure, nil
		}
		zone = z
	}

	keys, secure, err := r.validateZoneKeys(ctx, zone, memo)
	if err != nil {
		return dnssecStatusBogus, err
	}
	if !secure {
		return dnssecStatusInsecure, nil
	}

	authSection := append([]dns.RR{}, resp.Ns...)
	authSection = append(authSection, resp.Answer...)

	soaRR := extractRRSet(authSection, zone, dns.TypeSOA)
	soaSigs := extractRRSIGSet(authSection, zone, dns.TypeSOA)
	if len(soaRR) == 0 || len(soaSigs) == 0 {
		return dnssecStatusBogus, fmt.Errorf("signed negative response for %s missing SOA signature", zone)
	}
	if err := verifyRRSetWithAnySignature(soaRR, soaSigs, keys); err != nil {
		return dnssecStatusBogus, fmt.Errorf("invalid SOA signature for %s: %w", zone, err)
	}

	proofs, err := verifySignedDenialRRsets(authSection, keys)
	if err != nil {
		return dnssecStatusBogus, err
	}

	qname := normalizeFQDN(q.Name)
	if resp.Rcode == dns.RcodeNameError || isAuthoritativeNoData(resp) {
		switch resp.Rcode {
		case dns.RcodeNameError:
			if err := validateNXDOMAINProof(qname, zone, proofs); err != nil {
				if errors.Is(err, errNSEC3OptOutInsecure) {
					return dnssecStatusInsecure, nil
				}
				return dnssecStatusBogus, err
			}
			return dnssecStatusSecure, nil
		case dns.RcodeSuccess:
			if isAuthoritativeNoData(resp) {
				if err := validateNODATAProof(qname, q.Qtype, zone, proofs); err != nil {
					if errors.Is(err, errNSEC3OptOutInsecure) {
						return dnssecStatusInsecure, nil
					}
					return dnssecStatusBogus, err
				}
				return dnssecStatusSecure, nil
			}
		}
	}

	return dnssecStatusInsecure, nil
}

func (r *Resolver) findAuthoritativeZone(ctx context.Context, name string) (string, error) {
	q := dns.Question{Name: normalizeFQDN(name), Qtype: dns.TypeSOA, Qclass: dns.ClassINET}
	resp, err := r.resolveIterative(ctx, q, r.rootServers, 0, map[string]int{})
	if err != nil {
		return "", err
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return normalizeFQDN(soa.Hdr.Name), nil
		}
	}
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return normalizeFQDN(soa.Hdr.Name), nil
		}
	}
	return "", fmt.Errorf("no SOA found for %s", name)
}

func (r *Resolver) validateZoneKeys(ctx context.Context, zone string, memo map[string]zoneValidationResult) ([]*dns.DNSKEY, bool, error) {
	zone = normalizeFQDN(zone)
	if cached, ok := memo[zone]; ok {
		return cached.keys, cached.secure, cached.err
	}

	res := zoneValidationResult{}
	defer func() { memo[zone] = res }()

	if zone == "." {
		keys, err := r.validateRootDNSKEY(ctx)
		if err != nil {
			res.err = err
			return nil, false, err
		}
		res.keys = keys
		res.secure = true
		return keys, true, nil
	}

	parent := parentZone(zone)
	parentKeys, parentSecure, err := r.validateZoneKeys(ctx, parent, memo)
	if err != nil {
		res.err = err
		return nil, false, err
	}
	if !parentSecure {
		return nil, false, nil
	}

	dsRRset, dsSigs, err := r.fetchDSRRSet(ctx, zone)
	if err != nil {
		res.err = err
		return nil, false, err
	}
	if len(dsRRset) == 0 {
		return nil, false, nil
	}
	if len(dsSigs) == 0 {
		err := fmt.Errorf("missing RRSIG for DS %s", zone)
		res.err = err
		return nil, false, err
	}
	if err := verifyRRSetWithAnySignature(dsRRset, dsSigs, parentKeys); err != nil {
		err = fmt.Errorf("verify DS RRset %s: %w", zone, err)
		res.err = err
		return nil, false, err
	}

	dnskeyRRset, dnskeySigs, err := r.fetchDNSKEYRRSet(ctx, zone)
	if err != nil {
		res.err = err
		return nil, false, err
	}
	zoneKeys := toDNSKEYSlice(dnskeyRRset)
	if len(zoneKeys) == 0 {
		err := fmt.Errorf("empty DNSKEY RRset for %s", zone)
		res.err = err
		return nil, false, err
	}
	if len(dnskeySigs) == 0 {
		err := fmt.Errorf("missing DNSKEY RRSIG for %s", zone)
		res.err = err
		return nil, false, err
	}
	if err := verifyRRSetWithAnySignature(dnskeyRRset, dnskeySigs, zoneKeys); err != nil {
		err = fmt.Errorf("verify DNSKEY RRset %s: %w", zone, err)
		res.err = err
		return nil, false, err
	}

	dsSet := toDSSlice(dsRRset)
	if !hasDNSKEYMatchingDS(zoneKeys, dsSet) {
		err := fmt.Errorf("no DNSKEY matching DS for %s", zone)
		res.err = err
		return nil, false, err
	}

	res.keys = zoneKeys
	res.secure = true
	return zoneKeys, true, nil
}

func (r *Resolver) validateRootDNSKEY(ctx context.Context) ([]*dns.DNSKEY, error) {
	dnskeyRRset, dnskeySigs, err := r.fetchDNSKEYRRSet(ctx, ".")
	if err != nil {
		return nil, err
	}
	rootKeys := toDNSKEYSlice(dnskeyRRset)
	if len(rootKeys) == 0 {
		return nil, fmt.Errorf("root DNSKEY RRset is empty")
	}
	if len(dnskeySigs) == 0 {
		return nil, fmt.Errorf("root DNSKEY RRset has no RRSIG")
	}

	trustedKeys := make([]*dns.DNSKEY, 0)
	for _, k := range rootKeys {
		for _, ds := range r.trustedDS {
			if dnskeyMatchesDS(k, ds) {
				trustedKeys = append(trustedKeys, k)
				break
			}
		}
	}
	if len(trustedKeys) == 0 {
		return nil, fmt.Errorf("root DNSKEY does not match trust anchors")
	}
	if err := verifyRRSetWithAnySignature(dnskeyRRset, dnskeySigs, trustedKeys); err != nil {
		return nil, fmt.Errorf("verify root DNSKEY RRset: %w", err)
	}
	return rootKeys, nil
}

func (r *Resolver) fetchDNSKEYRRSet(ctx context.Context, zone string) ([]dns.RR, []*dns.RRSIG, error) {
	q := dns.Question{Name: normalizeFQDN(zone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	resp, err := r.resolveIterative(ctx, q, r.rootServers, 0, map[string]int{})
	if err != nil {
		return nil, nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("DNSKEY query for %s returned rcode=%s", zone, dns.RcodeToString[resp.Rcode])
	}
	rrset := extractRRSet(resp.Answer, zone, dns.TypeDNSKEY)
	sigs := extractRRSIGSet(resp.Answer, zone, dns.TypeDNSKEY)
	if len(rrset) == 0 {
		return nil, nil, fmt.Errorf("no DNSKEY RRset for %s", zone)
	}
	return rrset, sigs, nil
}

func (r *Resolver) fetchDSRRSet(ctx context.Context, zone string) ([]dns.RR, []*dns.RRSIG, error) {
	q := dns.Question{Name: normalizeFQDN(zone), Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	resp, err := r.resolveIterative(ctx, q, r.rootServers, 0, map[string]int{})
	if err != nil {
		return nil, nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, nil, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("DS query for %s returned rcode=%s", zone, dns.RcodeToString[resp.Rcode])
	}
	rrset := extractRRSet(resp.Answer, zone, dns.TypeDS)
	sigs := extractRRSIGSet(resp.Answer, zone, dns.TypeDS)
	return rrset, sigs, nil
}

func collectSignedRRsets(answer []dns.RR) (map[rrsetKey][]dns.RR, map[rrsetKey][]*dns.RRSIG) {
	rrsets := make(map[rrsetKey][]dns.RR)
	sigs := make(map[rrsetKey][]*dns.RRSIG)
	for _, rr := range answer {
		h := rr.Header()
		if h == nil {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			k := rrsetKey{name: normalizeFQDN(sig.Hdr.Name), rtype: sig.TypeCovered}
			sigs[k] = append(sigs[k], sig)
			continue
		}
		k := rrsetKey{name: normalizeFQDN(h.Name), rtype: h.Rrtype}
		rrsets[k] = append(rrsets[k], rr)
	}
	return rrsets, sigs
}

func verifySignedDenialRRsets(rrs []dns.RR, keys []*dns.DNSKEY) (*negativeProofSet, error) {
	rrsets, sigs := collectSignedRRsets(rrs)
	validated := false
	proofs := &negativeProofSet{
		nsec:  make([]*dns.NSEC, 0),
		nsec3: make([]*dns.NSEC3, 0),
	}
	for key, rrset := range rrsets {
		if key.rtype != dns.TypeNSEC && key.rtype != dns.TypeNSEC3 {
			continue
		}
		setSigs := sigs[key]
		if len(setSigs) == 0 {
			return nil, fmt.Errorf("missing RRSIG for denial RRset %s type=%d", key.name, key.rtype)
		}
		if err := verifyRRSetWithAnySignature(rrset, setSigs, keys); err != nil {
			return nil, fmt.Errorf("invalid denial RRset signature for %s type=%d: %w", key.name, key.rtype, err)
		}
		switch key.rtype {
		case dns.TypeNSEC:
			for _, rr := range rrset {
				n, ok := rr.(*dns.NSEC)
				if ok {
					proofs.nsec = append(proofs.nsec, n)
				}
			}
		case dns.TypeNSEC3:
			for _, rr := range rrset {
				n3, ok := rr.(*dns.NSEC3)
				if ok {
					proofs.nsec3 = append(proofs.nsec3, n3)
				}
			}
		}
		validated = true
	}
	if !validated {
		return nil, fmt.Errorf("signed negative response has no NSEC/NSEC3 proof RRsets")
	}
	return proofs, nil
}

func validateNXDOMAINProof(qname, zone string, proofs *negativeProofSet) error {
	if proofs == nil {
		return fmt.Errorf("missing denial proofs")
	}
	if len(proofs.nsec) > 0 {
		return validateNXDOMAINWithNSEC(qname, zone, proofs.nsec)
	}
	if len(proofs.nsec3) > 0 {
		return validateNXDOMAINWithNSEC3(qname, zone, proofs.nsec3)
	}
	return fmt.Errorf("no NSEC/NSEC3 records for NXDOMAIN proof")
}

func validateNODATAProof(qname string, qtype uint16, zone string, proofs *negativeProofSet) error {
	if proofs == nil {
		return fmt.Errorf("missing denial proofs")
	}
	if len(proofs.nsec) > 0 {
		return validateNODATAWithNSEC(qname, qtype, zone, proofs.nsec)
	}
	if len(proofs.nsec3) > 0 {
		return validateNODATAWithNSEC3(qname, qtype, zone, proofs.nsec3)
	}
	return fmt.Errorf("no NSEC/NSEC3 records for NODATA proof")
}

func validateNXDOMAINWithNSEC(qname, zone string, nsecs []*dns.NSEC) error {
	qname = normalizeFQDN(qname)
	zone = normalizeFQDN(zone)
	if nsecNameExists(qname, nsecs) {
		return fmt.Errorf("NXDOMAIN proof failed: name %s exists", qname)
	}
	if !anyNSECCoversName(qname, nsecs) {
		return fmt.Errorf("NXDOMAIN proof failed: no NSEC covers %s", qname)
	}

	ce := closestEncloserByNSEC(qname, zone, nsecs)
	if ce == "" {
		return fmt.Errorf("NXDOMAIN proof failed: cannot find closest encloser")
	}
	nextCloser, ok := nextCloserName(qname, ce)
	if !ok {
		return fmt.Errorf("NXDOMAIN proof failed: invalid next closer for %s", qname)
	}
	if !anyNSECCoversName(nextCloser, nsecs) {
		return fmt.Errorf("NXDOMAIN proof failed: no NSEC covers next-closer %s", nextCloser)
	}

	wc := wildcardName(ce)
	if nsecNameExists(wc, nsecs) {
		return fmt.Errorf("NXDOMAIN proof failed: wildcard %s exists", wc)
	}
	if !anyNSECCoversName(wc, nsecs) {
		return fmt.Errorf("NXDOMAIN proof failed: no wildcard denial proof for %s", wc)
	}
	return nil
}

func validateNODATAWithNSEC(qname string, qtype uint16, zone string, nsecs []*dns.NSEC) error {
	qname = normalizeFQDN(qname)
	zone = normalizeFQDN(zone)

	if n := findNSECByOwner(qname, nsecs); n != nil {
		if nsecTypePresent(n.TypeBitMap, dns.TypeCNAME) {
			return fmt.Errorf("NODATA proof failed: CNAME exists at %s", qname)
		}
		if qtype != dns.TypeCNAME && nsecTypePresent(n.TypeBitMap, qtype) {
			return fmt.Errorf("NODATA proof failed: type %d exists at %s", qtype, qname)
		}
		return nil
	}

	ce := closestEncloserByNSEC(qname, zone, nsecs)
	if ce == "" {
		return fmt.Errorf("NODATA proof failed: cannot find closest encloser")
	}
	nextCloser, ok := nextCloserName(qname, ce)
	if !ok {
		return fmt.Errorf("NODATA proof failed: invalid next closer for %s", qname)
	}
	if !anyNSECCoversName(nextCloser, nsecs) {
		return fmt.Errorf("NODATA proof failed: no NSEC covers next-closer %s", nextCloser)
	}

	wc := wildcardName(ce)
	wn := findNSECByOwner(wc, nsecs)
	if wn == nil {
		return fmt.Errorf("NODATA proof failed: wildcard owner %s not proven", wc)
	}
	if nsecTypePresent(wn.TypeBitMap, dns.TypeCNAME) {
		return fmt.Errorf("NODATA proof failed: wildcard CNAME exists at %s", wc)
	}
	if qtype != dns.TypeCNAME && nsecTypePresent(wn.TypeBitMap, qtype) {
		return fmt.Errorf("NODATA proof failed: wildcard type %d exists at %s", qtype, wc)
	}
	return nil
}

func validateNXDOMAINWithNSEC3(qname, zone string, nsec3 []*dns.NSEC3) error {
	qname = normalizeFQDN(qname)
	zone = normalizeFQDN(zone)

	ce := closestEncloserByNSEC3(qname, zone, nsec3)
	if ce == "" {
		if maybeOptOutInsecure(qname, "", "", nsec3) {
			return errNSEC3OptOutInsecure
		}
		return fmt.Errorf("NXDOMAIN proof failed: cannot find closest encloser (NSEC3)")
	}
	if normalizeFQDN(ce) == qname {
		return fmt.Errorf("NXDOMAIN proof failed: name %s exists (NSEC3 match)", qname)
	}

	nextCloser, ok := nextCloserName(qname, ce)
	if !ok {
		if maybeOptOutInsecure(qname, "", "", nsec3) {
			return errNSEC3OptOutInsecure
		}
		return fmt.Errorf("NXDOMAIN proof failed: invalid next closer for %s", qname)
	}
	if !anyNSEC3CoversName(nextCloser, nsec3) {
		if maybeOptOutInsecure(qname, nextCloser, "", nsec3) {
			return errNSEC3OptOutInsecure
		}
		return fmt.Errorf("NXDOMAIN proof failed: no NSEC3 covers next-closer %s", nextCloser)
	}

	wc := wildcardName(ce)
	if hasMatchingNSEC3(wc, nsec3) {
		return fmt.Errorf("NXDOMAIN proof failed: wildcard %s exists (NSEC3 match)", wc)
	}
	if !anyNSEC3CoversName(wc, nsec3) {
		if maybeOptOutInsecure(qname, nextCloser, wc, nsec3) {
			return errNSEC3OptOutInsecure
		}
		return fmt.Errorf("NXDOMAIN proof failed: no NSEC3 wildcard denial for %s", wc)
	}
	return nil
}

func validateNODATAWithNSEC3(qname string, qtype uint16, zone string, nsec3 []*dns.NSEC3) error {
	qname = normalizeFQDN(qname)
	zone = normalizeFQDN(zone)

	if n := findMatchingNSEC3(qname, nsec3); n != nil {
		if nsecTypePresent(n.TypeBitMap, dns.TypeCNAME) {
			return fmt.Errorf("NODATA proof failed: CNAME exists at %s (NSEC3)", qname)
		}
		if qtype != dns.TypeCNAME && nsecTypePresent(n.TypeBitMap, qtype) {
			return fmt.Errorf("NODATA proof failed: type %d exists at %s (NSEC3)", qtype, qname)
		}
		return nil
	}

	ce := closestEncloserByNSEC3(qname, zone, nsec3)
	if ce == "" {
		if maybeOptOutInsecure(qname, "", "", nsec3) {
			return errNSEC3OptOutInsecure
		}
		return fmt.Errorf("NODATA proof failed: cannot find closest encloser (NSEC3)")
	}
	nextCloser, ok := nextCloserName(qname, ce)
	if !ok {
		if maybeOptOutInsecure(qname, "", "", nsec3) {
			return errNSEC3OptOutInsecure
		}
		return fmt.Errorf("NODATA proof failed: invalid next closer for %s", qname)
	}
	if !anyNSEC3CoversName(nextCloser, nsec3) {
		if maybeOptOutInsecure(qname, nextCloser, "", nsec3) {
			return errNSEC3OptOutInsecure
		}
		return fmt.Errorf("NODATA proof failed: no NSEC3 covers next-closer %s", nextCloser)
	}

	wc := wildcardName(ce)
	wn := findMatchingNSEC3(wc, nsec3)
	if wn == nil {
		if maybeOptOutInsecure(qname, nextCloser, wc, nsec3) {
			return errNSEC3OptOutInsecure
		}
		return fmt.Errorf("NODATA proof failed: wildcard %s has no matching NSEC3", wc)
	}
	if nsecTypePresent(wn.TypeBitMap, dns.TypeCNAME) {
		return fmt.Errorf("NODATA proof failed: wildcard CNAME exists at %s (NSEC3)", wc)
	}
	if qtype != dns.TypeCNAME && nsecTypePresent(wn.TypeBitMap, qtype) {
		return fmt.Errorf("NODATA proof failed: wildcard type %d exists at %s (NSEC3)", qtype, wc)
	}
	return nil
}

func findNSECByOwner(name string, nsecs []*dns.NSEC) *dns.NSEC {
	name = normalizeFQDN(name)
	for _, n := range nsecs {
		if normalizeFQDN(n.Hdr.Name) == name {
			return n
		}
	}
	return nil
}

func nsecNameExists(name string, nsecs []*dns.NSEC) bool {
	return findNSECByOwner(name, nsecs) != nil
}

func anyNSECCoversName(name string, nsecs []*dns.NSEC) bool {
	for _, n := range nsecs {
		if nsecCoversName(n, name) {
			return true
		}
	}
	return false
}

func nsecCoversName(n *dns.NSEC, name string) bool {
	if n == nil {
		return false
	}
	owner := normalizeFQDN(n.Hdr.Name)
	next := normalizeFQDN(n.NextDomain)
	name = normalizeFQDN(name)
	if owner == name {
		return false
	}
	cmpOwnerNext := dnsNameCompare(owner, next)
	cmpOwnerName := dnsNameCompare(owner, name)
	cmpNameNext := dnsNameCompare(name, next)

	if cmpOwnerNext < 0 {
		return cmpOwnerName < 0 && cmpNameNext < 0
	}
	if cmpOwnerNext > 0 {
		return cmpOwnerName < 0 || cmpNameNext < 0
	}
	// owner == next means empty interval over full ring except owner itself.
	return owner != name
}

func closestEncloserByNSEC(qname, zone string, nsecs []*dns.NSEC) string {
	qname = normalizeFQDN(qname)
	zone = normalizeFQDN(zone)
	if !dns.IsSubDomain(zone, qname) {
		return ""
	}
	cur := qname
	for {
		if nsecNameExists(cur, nsecs) || cur == zone {
			return cur
		}
		if cur == "." {
			break
		}
		next := parentZone(cur)
		if next == cur {
			break
		}
		cur = next
	}
	return ""
}

func hasMatchingNSEC3(name string, nsec3 []*dns.NSEC3) bool {
	return findMatchingNSEC3(name, nsec3) != nil
}

func findMatchingNSEC3(name string, nsec3 []*dns.NSEC3) *dns.NSEC3 {
	name = normalizeFQDN(name)
	for _, n := range nsec3 {
		if n.Match(name) {
			return n
		}
	}
	return nil
}

func anyNSEC3CoversName(name string, nsec3 []*dns.NSEC3) bool {
	name = normalizeFQDN(name)
	for _, n := range nsec3 {
		if n.Cover(name) {
			return true
		}
	}
	return false
}

func maybeOptOutInsecure(qname, nextCloser, wildcard string, nsec3 []*dns.NSEC3) bool {
	targets := []string{qname, nextCloser, wildcard}
	for _, n := range nsec3 {
		if !nsec3IsOptOut(n) {
			continue
		}
		for _, t := range targets {
			if strings.TrimSpace(t) == "" {
				continue
			}
			name := normalizeFQDN(t)
			if n.Match(name) || n.Cover(name) {
				return true
			}
		}
	}
	return false
}

func nsec3IsOptOut(n *dns.NSEC3) bool {
	if n == nil {
		return false
	}
	return (n.Flags & 0x01) == 0x01
}

func closestEncloserByNSEC3(qname, zone string, nsec3 []*dns.NSEC3) string {
	qname = normalizeFQDN(qname)
	zone = normalizeFQDN(zone)
	if !dns.IsSubDomain(zone, qname) {
		return ""
	}
	cur := qname
	for {
		if hasMatchingNSEC3(cur, nsec3) || cur == zone {
			return cur
		}
		if cur == "." {
			break
		}
		next := parentZone(cur)
		if next == cur {
			break
		}
		cur = next
	}
	return ""
}

func nextCloserName(qname, closestEncloser string) (string, bool) {
	qname = normalizeFQDN(qname)
	closestEncloser = normalizeFQDN(closestEncloser)
	if qname == closestEncloser {
		return "", false
	}
	if !dns.IsSubDomain(closestEncloser, qname) {
		return "", false
	}

	qLabels := dns.SplitDomainName(qname)
	ceLabels := dns.SplitDomainName(closestEncloser)
	if len(qLabels) <= len(ceLabels) {
		return "", false
	}
	idx := len(qLabels) - len(ceLabels) - 1
	if idx < 0 || idx >= len(qLabels) {
		return "", false
	}
	return strings.Join(qLabels[idx:], ".") + ".", true
}

func wildcardName(closestEncloser string) string {
	closestEncloser = normalizeFQDN(closestEncloser)
	if closestEncloser == "." {
		return "*."
	}
	return "*." + closestEncloser
}

func nsecTypePresent(bitmap []uint16, t uint16) bool {
	for _, v := range bitmap {
		if v == t {
			return true
		}
	}
	return false
}

// dnsNameCompare compares FQDNs in canonical DNSSEC name order.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func dnsNameCompare(a, b string) int {
	al := dns.SplitDomainName(normalizeFQDN(a))
	bl := dns.SplitDomainName(normalizeFQDN(b))
	i := len(al) - 1
	j := len(bl) - 1
	for i >= 0 && j >= 0 {
		cmp := strings.Compare(al[i], bl[j])
		if cmp < 0 {
			return -1
		}
		if cmp > 0 {
			return 1
		}
		i--
		j--
	}
	if i < 0 && j < 0 {
		return 0
	}
	if i < 0 {
		return -1
	}
	return 1
}

func extractRRSet(rrs []dns.RR, name string, rrtype uint16) []dns.RR {
	name = normalizeFQDN(name)
	out := make([]dns.RR, 0)
	for _, rr := range rrs {
		h := rr.Header()
		if h == nil {
			continue
		}
		if normalizeFQDN(h.Name) != name || h.Rrtype != rrtype {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func extractRRSIGSet(rrs []dns.RR, name string, covered uint16) []*dns.RRSIG {
	name = normalizeFQDN(name)
	out := make([]*dns.RRSIG, 0)
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if normalizeFQDN(sig.Hdr.Name) != name || sig.TypeCovered != covered {
			continue
		}
		out = append(out, sig)
	}
	return out
}

func verifyRRSetWithAnySignature(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY) error {
	if len(rrset) == 0 {
		return fmt.Errorf("empty rrset")
	}
	if len(sigs) == 0 {
		return fmt.Errorf("missing rrsig")
	}
	for _, sig := range sigs {
		if verifyRRSetWithKey(rrset, sig, keys) {
			return nil
		}
	}
	return fmt.Errorf("no valid signature")
}

func verifyRRSetWithKey(rrset []dns.RR, sig *dns.RRSIG, keys []*dns.DNSKEY) bool {
	for _, key := range keys {
		if key.Algorithm != sig.Algorithm || key.KeyTag() != sig.KeyTag {
			continue
		}
		if err := sig.Verify(key, rrset); err == nil {
			return true
		}
	}
	return false
}

func hasDNSKEYMatchingDS(keys []*dns.DNSKEY, dsSet []*dns.DS) bool {
	for _, key := range keys {
		for _, ds := range dsSet {
			if dnskeyMatchesDS(key, ds) {
				return true
			}
		}
	}
	return false
}

func dnskeyMatchesDS(key *dns.DNSKEY, ds *dns.DS) bool {
	calc := key.ToDS(ds.DigestType)
	if calc == nil {
		return false
	}
	if calc.KeyTag != ds.KeyTag {
		return false
	}
	if calc.Algorithm != ds.Algorithm {
		return false
	}
	if calc.DigestType != ds.DigestType {
		return false
	}
	return strings.EqualFold(calc.Digest, ds.Digest)
}

func toDNSKEYSlice(rrs []dns.RR) []*dns.DNSKEY {
	out := make([]*dns.DNSKEY, 0, len(rrs))
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, k)
		}
	}
	return out
}

func toDSSlice(rrs []dns.RR) []*dns.DS {
	out := make([]*dns.DS, 0, len(rrs))
	for _, rr := range rrs {
		if ds, ok := rr.(*dns.DS); ok {
			out = append(out, ds)
		}
	}
	return out
}

func normalizeFQDN(name string) string {
	return dns.Fqdn(strings.ToLower(strings.TrimSpace(name)))
}

func zoneFromSOA(resp *dns.Msg) string {
	if resp == nil {
		return ""
	}
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return normalizeFQDN(soa.Hdr.Name)
		}
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return normalizeFQDN(soa.Hdr.Name)
		}
	}
	return ""
}

func parentZone(zone string) string {
	zone = normalizeFQDN(zone)
	if zone == "." {
		return "."
	}
	labels := dns.SplitDomainName(zone)
	if len(labels) <= 1 {
		return "."
	}
	return strings.Join(labels[1:], ".") + "."
}
