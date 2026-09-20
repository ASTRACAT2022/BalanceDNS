package threat

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

// ParseStats accumulates parser-level sanity statistics for a feed.
type ParseStats struct {
	TotalLines     int
	ParsedEntries  int
	DroppedInvalid int // lines that looked like domains but failed validation
	DuplicateRate  float64
	ParserErrors   int
}

// FeedParseResult is a parsed, validated, deduplicated set of IOCs from a
// single feed fetch.
type FeedParseResult struct {
	IOCs  []*IOC
	Stats ParseStats
}

// ParseFeedEntry parses raw feed bytes according to the configured format and
// produces validated IOCs. It never panics on malformed input: bad lines are
// counted and skipped. Confidence and category come from the feed config.
func ParseFeedEntry(feed FeedConfig, r io.Reader, now int64) (*FeedParseResult, error) {
	switch strings.ToLower(strings.TrimSpace(feed.Format)) {
	case "", "domains":
		return parsePlain(r, feed, now)
	case "hosts":
		return parseHosts(r, feed, now)
	case "rpz":
		return parseRPZ(r, feed, now)
	case "json":
		return parseJSON(r, feed, now)
	default:
		return nil, &ParseError{Msg: "unsupported feed format: " + feed.Format}
	}
}

// ParseError is a structured parser/feed error.
type ParseError struct{ Msg string }

func (e *ParseError) Error() string { return e.Msg }

// parsePlain parses a plain domain list: one domain per line, optional "#"
// comments and blank lines ignored. "*." and leading "." become suffix rules.
func parsePlain(r io.Reader, feed FeedConfig, now int64) (*FeedParseResult, error) {
	res := &FeedParseResult{}
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	conf := parseConfidence(feed.Confidence)
	cat := parseCategory(feed.Category)

	for sc.Scan() {
		res.Stats.TotalLines++
		line := sc.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if c := strings.IndexByte(line, '#'); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		base := stripWildcard(line)
		if !isValidDomain(base) {
			res.Stats.DroppedInvalid++
			continue
		}
		if _, dup := seen[base]; dup {
			continue
		}
		seen[base] = struct{}{}
		res.IOCs = append(res.IOCs, &IOC{
			Domain:       base,
			SourcesCount: 1,
			Sources:      []string{feed.Name},
			Category:     cat,
			Confidence:   conf,
			FirstSeen:    now,
			LastSeen:     now,
		})
		res.Stats.ParsedEntries++
	}
	if err := sc.Err(); err != nil {
		res.Stats.ParserErrors++
		return res, &ParseError{Msg: "scan feed: " + err.Error()}
	}
	if res.Stats.ParsedEntries > 0 {
		res.Stats.DuplicateRate = float64(res.Stats.TotalLines-res.Stats.ParsedEntries) / float64(res.Stats.TotalLines)
	}
	return res, nil
}

// parseHosts parses a /etc/hosts-style file. Lines with an IP followed by one
// or more hostnames. Comment lines and blank lines ignored. Only the hostname
// portion is used (IPv4/IPv6 addresses are skipped, not treated as domains).
func parseHosts(r io.Reader, feed FeedConfig, now int64) (*FeedParseResult, error) {
	res := &FeedParseResult{}
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	conf := parseConfidence(feed.Confidence)
	cat := parseCategory(feed.Category)

	for sc.Scan() {
		res.Stats.TotalLines++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if c := strings.IndexByte(line, '#'); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			res.Stats.DroppedInvalid++
			continue
		}
		// First field is the IP; remaining fields are hostnames.
		for _, host := range fields[1:] {
			base := normalizeQuery(host)
			if !isValidDomain(base) {
				res.Stats.DroppedInvalid++
				continue
			}
			if _, dup := seen[base]; dup {
				continue
			}
			seen[base] = struct{}{}
			res.IOCs = append(res.IOCs, &IOC{
				Domain:       base,
				SourcesCount: 1,
				Sources:      []string{feed.Name},
				Category:     cat,
				Confidence:   conf,
				FirstSeen:    now,
				LastSeen:     now,
			})
			res.Stats.ParsedEntries++
		}
	}
	if err := sc.Err(); err != nil {
		res.Stats.ParserErrors++
		return res, &ParseError{Msg: "scan hosts feed: " + err.Error()}
	}
	if res.Stats.ParsedEntries > 0 {
		res.Stats.DuplicateRate = float64(res.Stats.TotalLines-res.Stats.ParsedEntries) / float64(res.Stats.TotalLines)
	}
	return res, nil
}

// parseRPZ parses an RPZ-style zone list. It accepts lines of the form
//   example.com CNAME .
//   example.com .  ; comment
//   example.com
// and ignores the second field (the RPZ rcode/CNAME target). Comment lines
// beginning with ';', '#', '//' and blank lines are skipped.
func parseRPZ(r io.Reader, feed FeedConfig, now int64) (*FeedParseResult, error) {
	res := &FeedParseResult{}
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	conf := parseConfidence(feed.Confidence)
	cat := parseCategory(feed.Category)

	for sc.Scan() {
		res.Stats.TotalLines++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Cut inline comment (RPZ uses ';').
		if c := strings.IndexByte(line, ';'); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		domain := strings.TrimSuffix(fields[0], ".")
		domain = strings.TrimPrefix(domain, "*.")
		if !isValidDomain(normalizeQuery(domain)) {
			res.Stats.DroppedInvalid++
			continue
		}
		base := normalizeQuery(domain)
		if _, dup := seen[base]; dup {
			continue
		}
		seen[base] = struct{}{}
		res.IOCs = append(res.IOCs, &IOC{
			Domain:       base,
			SourcesCount: 1,
			Sources:      []string{feed.Name},
			Category:     cat,
			Confidence:   conf,
			FirstSeen:    now,
			LastSeen:     now,
		})
		res.Stats.ParsedEntries++
	}
	if err := sc.Err(); err != nil {
		res.Stats.ParserErrors++
		return res, &ParseError{Msg: "scan rpz feed: " + err.Error()}
	}
	if res.Stats.ParsedEntries > 0 {
		res.Stats.DuplicateRate = float64(res.Stats.TotalLines-res.Stats.ParsedEntries) / float64(res.Stats.TotalLines)
	}
	return res, nil
}

// parseJSON parses common JSON threat-feed shapes. It accepts either an array
// of objects with "domain"/"host"/"value" fields, or an object mapping keys
// "domains"/"hosts"/"blocklist" to arrays of strings. Confidence/category are
// taken from the feed config; optional per-entry "category"/"confidence" may
// override. Unknown fields are ignored.
func parseJSON(r io.Reader, feed FeedConfig, now int64) (*FeedParseResult, error) {
	res := &FeedParseResult{}
	seen := make(map[string]struct{})
	var raw any
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		res.Stats.ParserErrors++
		return res, &ParseError{Msg: "json decode: " + err.Error()}
	}
	conf := parseConfidence(feed.Confidence)
	cat := parseCategory(feed.Category)

	var domains []string
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			if obj, ok := item.(map[string]any); ok {
				if d := firstStringField(obj, "domain", "host", "hostname", "value", "ioc", "name"); d != "" {
					domains = append(domains, d)
					continue
				}
				// Nested object: { "ioc": { "domain": "..." } }
				if nested, ok := obj["ioc"].(map[string]any); ok {
					if d := firstStringField(nested, "domain", "host", "value"); d != "" {
						domains = append(domains, d)
					}
				}
			}
		}
	case map[string]any:
		for _, key := range []string{"domains", "hosts", "blocklist", "values"} {
			if arr, ok := v[key].([]any); ok {
				for _, item := range arr {
					if s, ok := item.(string); ok {
						domains = append(domains, s)
					}
				}
			}
		}
	}

	for _, d := range domains {
		base := normalizeQuery(d)
		if !isValidDomain(base) {
			res.Stats.DroppedInvalid++
			continue
		}
		if _, dup := seen[base]; dup {
			continue
		}
		seen[base] = struct{}{}
		res.IOCs = append(res.IOCs, &IOC{
			Domain:       base,
			SourcesCount: 1,
			Sources:      []string{feed.Name},
			Category:     cat,
			Confidence:   conf,
			FirstSeen:    now,
			LastSeen:     now,
		})
		res.Stats.ParsedEntries++
	}
	res.Stats.TotalLines = res.Stats.ParsedEntries + res.Stats.DroppedInvalid
	if res.Stats.ParsedEntries > 0 {
		res.Stats.DuplicateRate = float64(res.Stats.TotalLines-res.Stats.ParsedEntries) / float64(res.Stats.TotalLines)
	}
	return res, nil
}

// firstStringField returns the first non-empty string field from a map, given
// a priority list of keys.
func firstStringField(obj map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := obj[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
