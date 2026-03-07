package dnsproxy

import "testing"

func TestSecurityManagerGlobalInflightLimit(t *testing.T) {
	sm := newSecurityManager(ProxyOptions{
		EnableAttackProtection: true,
		MaxGlobalInflight:      1,
	})
	if sm == nil {
		t.Fatal("expected security manager")
	}

	release, reason := sm.admit("203.0.113.10")
	if reason != "" || release == nil {
		t.Fatalf("unexpected first admit result: release_nil=%v reason=%q", release == nil, reason)
	}

	secondRelease, secondReason := sm.admit("198.51.100.20")
	if secondReason != "global_inflight_limit" {
		t.Fatalf("expected global limit reason, got %q", secondReason)
	}
	if secondRelease != nil {
		t.Fatal("expected nil release callback for denied request")
	}

	release()
}

func TestSecurityManagerPerIPRateLimit(t *testing.T) {
	sm := newSecurityManager(ProxyOptions{
		EnableAttackProtection: true,
		MaxQPSPerIP:            1,
		RateLimitBurstPerIP:    1,
	})
	if sm == nil {
		t.Fatal("expected security manager")
	}

	release1, reason1 := sm.admit("192.0.2.5")
	if reason1 != "" || release1 == nil {
		t.Fatalf("unexpected first admit result: release_nil=%v reason=%q", release1 == nil, reason1)
	}
	release1()

	release2, reason2 := sm.admit("192.0.2.5")
	if reason2 != "per_ip_rate_limit" {
		t.Fatalf("expected per_ip_rate_limit, got %q", reason2)
	}
	if release2 != nil {
		t.Fatal("expected nil release callback for denied request")
	}
}

func TestShardIndexStableRange(t *testing.T) {
	const ip = "203.0.113.77"
	a := shardIndex(ip)
	b := shardIndex(ip)
	if a != b {
		t.Fatalf("shard index should be deterministic: %d vs %d", a, b)
	}
	if a >= uint32(securityShardCount) {
		t.Fatalf("shard index out of range: %d", a)
	}
}
