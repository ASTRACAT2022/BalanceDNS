package threat

import "sort"

// ReputationEngine merges per-feed parse results into a single set of IOCs and
// computes, for each domain, whether it should be blocked based on the
// configured thresholds (custom/high confidence, minimum sources). Domains that
// fail the thresholds are kept in the snapshot for observability but marked
// observe-only.
type ReputationEngine struct {
	cfg ReputationConfig
}

// NewReputationEngine builds a reputation engine from config.
func NewReputationEngine(cfg ReputationConfig) *ReputationEngine {
	return &ReputationEngine{cfg: cfg}
}

// BlockDecision carries the per-domain enforcement flags so the policy can act
// at query time without re-deriving the reputation logic.
type BlockDecision struct {
	IOC         *IOC
	Reason      string // "custom" | "high_confidence" | "min_sources" | "observe"
	ShouldBlock bool
}

// Evaluate applies reputation thresholds to a single merged IOC and returns
// whether it should block, plus a stable reason string.
//
// Policy (all configurable):
//   - custom-confidence IOC (ASTRACAT custom list) -> block
//   - high-confidence trusted feed IOC -> block
//   - medium-confidence IOC && medium confidence blocking enabled -> block
//   - domain found in >= minimum_sources (normal feeds) -> block
//   - otherwise -> observe only
func (r *ReputationEngine) Evaluate(ioc *IOC) BlockDecision {
	if ioc == nil {
		return BlockDecision{ShouldBlock: false, Reason: "observe"}
	}
	switch ioc.Confidence {
	case ConfidenceCustom:
		return BlockDecision{IOC: ioc, ShouldBlock: true, Reason: "custom"}
	case ConfidenceHigh:
		if r.cfg.BlockHighConfidence {
			return BlockDecision{IOC: ioc, ShouldBlock: true, Reason: "high_confidence"}
		}
		if ioc.SourcesCount >= r.cfg.MinimumSources {
			return BlockDecision{IOC: ioc, ShouldBlock: true, Reason: "min_sources"}
		}
		return BlockDecision{IOC: ioc, ShouldBlock: false, Reason: "observe"}
	case ConfidenceMedium:
		if r.cfg.BlockMediumConfidence && ioc.SourcesCount >= r.cfg.MinimumSources {
			return BlockDecision{IOC: ioc, ShouldBlock: true, Reason: "min_sources"}
		}
		if ioc.SourcesCount >= r.cfg.MinimumSources {
			return BlockDecision{IOC: ioc, ShouldBlock: true, Reason: "min_sources"}
		}
		return BlockDecision{IOC: ioc, ShouldBlock: false, Reason: "observe"}
	default: // low
		if ioc.SourcesCount >= r.cfg.MinimumSources {
			return BlockDecision{IOC: ioc, ShouldBlock: true, Reason: "min_sources"}
		}
		return BlockDecision{IOC: ioc, ShouldBlock: false, Reason: "observe"}
	}
}

// merge aggregates IOCs across feeds by normalized domain, accumulating source
// counts, deduplicated source names, first/last seen, and resolving the
// dominant category and confidence.
func merge(iocs []*IOC) map[string]*IOC {
	byDomain := make(map[string]*IOC, len(iocs))
	for _, i := range iocs {
		if i == nil || i.Domain == "" {
			continue
		}
		existing, ok := byDomain[i.Domain]
		if !ok {
			cp := *i
			cp.Sources = append([]string(nil), i.Sources...)
			byDomain[i.Domain] = &cp
			continue
		}
		existing.Sources = append(existing.Sources, i.Sources...)
		existing.SourcesCount++
		if i.FirstSeen > 0 && (existing.FirstSeen == 0 || i.FirstSeen < existing.FirstSeen) {
			existing.FirstSeen = i.FirstSeen
		}
		if i.LastSeen > i.LastSeen {
			existing.LastSeen = i.LastSeen
		}
		if i.Category.weight() > existing.Category.weight() {
			existing.Category = i.Category
		}
		if confidenceWeight(i.Confidence) > confidenceWeight(existing.Confidence) {
			existing.Confidence = i.Confidence
		}
	}
	for _, ioc := range byDomain {
		seen := make(map[string]struct{}, len(ioc.Sources))
		uniq := ioc.Sources[:0]
		for _, s := range ioc.Sources {
			if s == "" {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			uniq = append(uniq, s)
		}
		sort.Strings(uniq)
		ioc.Sources = uniq
		ioc.SourcesCount = len(uniq)
	}
	return byDomain
}

// BuildSnapshot compiles a snapshot from all feed results, applying reputation
// thresholds. The snapshot stores the full IOC set; a companion BlockMap keeps
// the per-domain ShouldBlock decisions so the O(1) lookup path knows the
// enforcement without scanning thresholds again.
func (r *ReputationEngine) BuildSnapshot(results []*FeedParseResult) (*Snapshot, map[string]BlockDecision) {
	var all []*IOC
	for _, res := range results {
		if res == nil {
			continue
		}
		all = append(all, res.IOCs...)
	}
	merged := merge(all)

	out := make([]*IOC, 0, len(merged))
	blockMap := make(map[string]BlockDecision, len(merged))
	for _, ioc := range merged {
		cp := *ioc
		out = append(out, &cp)
		blockMap[ioc.Domain] = r.Evaluate(&cp)
	}
	return BuildSnapshot(out), blockMap
}
