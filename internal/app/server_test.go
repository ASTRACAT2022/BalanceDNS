package app

import (
	"os"
	"path/filepath"
	"testing"

	"balancedns/internal/config"
)

// TestIsBlockedSuffixBoundary проверяет, что суффиксное совпадение
// срабатывает только на границе метки (sub.ads.com), а не на
// подстроке (notads.com). Это регрессионный тест для бага, когда
// strings.HasSuffix("notexample.com", "example.com") == true.
func TestIsBlockedSuffixBoundary(t *testing.T) {
	s := &Server{
		blacklist: parseBlacklist([]string{"example.com", "*.ads.com", ".tracker.net"}),
	}

	cases := []struct {
		name string
		want bool
	}{
		// example.com без префикса — ТОЧНОЕ правило: блокирует только сам домен.
		{"example.com", true},
		{"sub.example.com", false},
		{"deep.sub.example.com", false},
		// НЕ поддомен, но содержит домен как подстроку — НЕ должен блокироваться.
		{"notexample.com", false},
		{"myexample.com", false},
		{"example.com.evil.com", false},
		{"www.example.com.attacker.com", false},
		// *.ads.com — суффиксное правило: блокирует домен и поддомены.
		{"ads.com", true},
		{"sub.ads.com", true},
		{"deep.sub.ads.com", true},
		{"notads.com", false},
		// .tracker.net — суффиксное правило.
		{"tracker.net", true},
		{"x.tracker.net", true},
		{"nottracker.net", false},
		// Не связанные домены.
		{"google.com", false},
		{"", false},
	}

	for _, tc := range cases {
		got := s.isBlocked(tc.name)
		if got != tc.want {
			t.Errorf("isBlocked(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestLoadBlacklistFile проверяет загрузку чёрного списка из файла
// (blacklist.file), который генерирует Node Agent.
func TestLoadBlacklistFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.txt")

	content := `# ASTRACAT DNS — чёрный список
example.com
*.ads.com
.tracker.net

# inline comment
blocked.org # trailing comment
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.BlacklistConfig{
		Domains: []string{"inline.com"},
		File:    path,
	}

	idx, err := loadBlacklist(cfg)
	if err != nil {
		t.Fatalf("loadBlacklist: %v", err)
	}

	s := &Server{blacklist: idx}
	// Из файла.
	if !s.isBlocked("example.com") {
		t.Error("example.com should be blocked from file")
	}
	if !s.isBlocked("sub.ads.com") {
		t.Error("sub.ads.com should be blocked (suffix from file)")
	}
	if !s.isBlocked("blocked.org") {
		t.Error("blocked.org should be blocked (trailing comment stripped)")
	}
	// Из inline domains.
	if !s.isBlocked("inline.com") {
		t.Error("inline.com should be blocked from inline domains")
	}
	// Граница метки.
	if s.isBlocked("notexample.com") {
		t.Error("notexample.com should NOT be blocked")
	}
}

// TestLoadBlacklistFileMissing проверяет поведение при отсутствующем файле.
func TestLoadBlacklistFileMissing(t *testing.T) {
	cfg := config.BlacklistConfig{
		File: "/nonexistent/blacklist.txt",
	}
	if _, err := loadBlacklist(cfg); err == nil {
		t.Error("expected error for missing blacklist file")
	}
}

// TestLoadBlacklistEmptyFile проверяет, что пустой файл не ломает.
func TestLoadBlacklistEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.BlacklistConfig{File: path}
	idx, err := loadBlacklist(cfg)
	if err != nil {
		t.Fatalf("loadBlacklist: %v", err)
	}
	if idx == nil {
		t.Error("expected non-nil index for empty file")
	}
	s := &Server{blacklist: idx}
	if s.isBlocked("anything.com") {
		t.Error("empty blacklist should not block anything")
	}
}

// BenchmarkIsBlockedLargeList проверяет производительность lookup
// на большом списке (аналог 5MB production blacklist).
func BenchmarkIsBlockedLargeList(b *testing.B) {
	// 250K точных + 10K суффиксных правил.
	domains := make([]string, 0, 260000)
	for i := 0; i < 250000; i++ {
		domains = append(domains, "domain"+itoa(i)+".com")
	}
	for i := 0; i < 10000; i++ {
		domains = append(domains, "*.suffix"+itoa(i)+".net")
	}
	s := &Server{blacklist: parseBlacklist(domains)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Смесь: точное попадание, суффиксное попадание, промах.
		switch i % 3 {
		case 0:
			_ = s.isBlocked("domain12345.com")
		case 1:
			_ = s.isBlocked("sub.suffix9999.net")
		default:
			_ = s.isBlocked("legit.example.org")
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
