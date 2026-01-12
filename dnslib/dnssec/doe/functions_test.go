package doe

import (
	"slices"
	"testing"
)

func TestFunctions_CanonicalCmp(t *testing.T) {

	// Example domains to sort
	domains := []string{
		"z.example",
		"z.example",
		`xxx.qazz.uk`,
		"yljkjljk.a.example",
		"Z.a.example",
		`\200.z.example`,
		"zABC.a.EXAMPLE",
		`t\100.example`,
		`\001.z.example`,
		"*.z.example",
		`\000.xxx.qazz.uk`,
		"*.Z.a.example",
		"example",
	}

	slices.SortFunc(domains, canonicalCmp)

	expected := []string{
		"example",
		"yljkjljk.a.example",
		"Z.a.example",
		"*.Z.a.example",
		"zABC.a.EXAMPLE",
		`t\100.example`,
		"z.example",
		"z.example",
		`\001.z.example`,
		"*.z.example",
		`\200.z.example`,
		`xxx.qazz.uk`,
		`\000.xxx.qazz.uk`,
	}

	if !slices.Equal(expected, domains) {
		t.Error("domain ordering does not match")
	}
}

func TestFunctions_WildcardName(t *testing.T) {

	if s := wildcardName("text.example.com"); s != "*.example.com" {
		t.Errorf("we expected '*.example.com' but got '%s'", s)
	}

	if s := wildcardName("a.b.c.d.e.example.com."); s != "*.b.c.d.e.example.com." {
		t.Errorf("we expected '*.b.c.d.e.example.com' but got '%s'", s)
	}

	if s := wildcardName("com."); s != "*." {
		t.Errorf("we expected '*.' but got '%s'", s)
	}

}
