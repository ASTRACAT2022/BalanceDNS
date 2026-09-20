package app

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestTenantIsolation проверяет, что per-tenant правила изолированы:
// config_id A не влияет на config_id B, и наоборот.
func TestTenantIsolation(t *testing.T) {
	dir := t.TempDir()

	// Tenant A: блокирует example.com, hosts для chatgpt.com
	writeFile(t, filepath.Join(dir, "aaa.blacklist"), "example.com\n")
	writeFile(t, filepath.Join(dir, "aaa.hosts"), "87.58.204.29 chatgpt.com\n")
	writeFile(t, filepath.Join(dir, "aaa.allowlist"), "\n")
	writeFile(t, filepath.Join(dir, "aaa.security"), "1\n")

	// Tenant B: блокирует ads.com, hosts для instagram.com
	writeFile(t, filepath.Join(dir, "bbb.blacklist"), "ads.com\n")
	writeFile(t, filepath.Join(dir, "bbb.hosts"), "87.58.204.29 instagram.com\n")
	writeFile(t, filepath.Join(dir, "bbb.allowlist"), "\n")
	writeFile(t, filepath.Join(dir, "bbb.security"), "0\n")

	store, err := loadTenants(dir)
	if err != nil {
		t.Fatalf("loadTenants: %v", err)
	}

	// Tenant A.
	ta := store.get("aaa")
	if ta == nil {
		t.Fatal("tenant aaa not loaded")
	}
	if !ta.blacklist.contains("example.com") {
		t.Error("aaa should block example.com")
	}
	if ta.blacklist.contains("ads.com") {
		t.Error("aaa should NOT block ads.com (isolation)")
	}
	if ips, ok := ta.lookupHost("chatgpt.com", 1); !ok || len(ips) == 0 {
		t.Error("aaa should have host for chatgpt.com")
	}
	if _, ok := ta.lookupHost("instagram.com", 1); ok {
		t.Error("aaa should NOT have host for instagram.com (isolation)")
	}

	// Tenant B.
	tb := store.get("bbb")
	if tb == nil {
		t.Fatal("tenant bbb not loaded")
	}
	if !tb.blacklist.contains("ads.com") {
		t.Error("bbb should block ads.com")
	}
	if tb.blacklist.contains("example.com") {
		t.Error("bbb should NOT block example.com (isolation)")
	}
	if ips, ok := tb.lookupHost("instagram.com", 1); !ok || len(ips) == 0 {
		t.Error("bbb should have host for instagram.com")
	}
	if _, ok := tb.lookupHost("chatgpt.com", 1); ok {
		t.Error("bbb should NOT have host for chatgpt.com (isolation)")
	}

	// Неизвестный config_id → nil (default).
	if store.get("zzz") != nil {
		t.Error("unknown config_id should return nil")
	}
}

// TestTenantReload проверяет атомарную перезагрузку.
func TestTenantReload(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "aaa.blacklist"), "example.com\n")

	store, err := loadTenants(dir)
	if err != nil {
		t.Fatalf("loadTenants: %v", err)
	}
	if !store.get("aaa").blacklist.contains("example.com") {
		t.Fatal("initial load failed")
	}

	// Обновляем файл и перезагружаем.
	writeFile(t, filepath.Join(dir, "aaa.blacklist"), "newdomain.com\n")
	if err := store.reload(dir); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if store.get("aaa").blacklist.contains("example.com") {
		t.Error("old rule should be gone after reload")
	}
	if !store.get("aaa").blacklist.contains("newdomain.com") {
		t.Error("new rule should be loaded after reload")
	}
}

// TestTenantHostsQType проверяет фильтрацию по qtype.
func TestTenantHostsQType(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "aaa.hosts"), "87.58.204.29 v4.example.com\n2001:db8::1 v6.example.com\n")

	store, err := loadTenants(dir)
	if err != nil {
		t.Fatalf("loadTenants: %v", err)
	}
	ta := store.get("aaa")

	// A-запрос для v4.
	ips, ok := ta.lookupHost("v4.example.com", 1) // TypeA
	if !ok || len(ips) != 1 || ips[0].To4() == nil {
		t.Errorf("v4 host A lookup failed: %v %v", ips, ok)
	}
	// AAAA-запрос для v4 → пусто.
	if _, ok := ta.lookupHost("v4.example.com", 28); ok { // TypeAAAA
		t.Error("v4 host should not match AAAA")
	}
	// AAAA-запрос для v6.
	ips6, ok := ta.lookupHost("v6.example.com", 28)
	if !ok || len(ips6) != 1 || ips6[0].To4() != nil {
		t.Errorf("v6 host AAAA lookup failed: %v %v", ips6, ok)
	}
	_ = net.IPv4zero
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
