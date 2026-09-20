package app

import "testing"

// TestTenantForSNI verifies per-tenant SNI selection (personal DoT):
// {config_id}.dns.astracat.network → config_id, resolved against the tenant store.
func TestTenantForSNI(t *testing.T) {
	store := newTenantStore()
	for _, cid := range []string{"ed2x", "baa5aa", "de1906"} {
		store.tenants[cid] = &tenantRules{configID: cid}
	}
	s := &Server{tenants: store}

	cases := []struct {
		sni  string
		want string // ожидаемый config_id, "" = нет tenant
	}{
		{"ed2x.dns.astracat.network", "ed2x"},
		{"baa5aa.dns.astracat.network", "baa5aa"},
		{"de1906.dns.astracat.network", "de1906"},
		{"dns.astracat.network", ""},          // без поддомена → nil
		{"ed2x.dns.astracat.network.", "ed2x"}, // с trailing dot
		{"unknown.dns.astracat.network", ""},   // неизвестный конфиг → nil
		{"", ""},                               // пустой SNI → nil
	}

	for _, c := range cases {
		got := s.tenantForSNI(c.sni)
		if got != c.want {
			t.Errorf("tenantForSNI(%q): expected %q, got %q", c.sni, c.want, got)
		}
	}
}
