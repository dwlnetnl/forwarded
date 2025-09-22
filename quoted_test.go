package forwarded

import (
	"strconv"
	"testing"
)

var escapeTests = []struct {
	in   string
	want string
}{
	{"_gazonk", `_gazonk`},
	{"192.0.2.43", `192.0.2.43`},
	{"192.0.2.43:47011", `"192.0.2.43:47011"`},
	{"[2001:db8:cafe::17]", `"[2001:db8:cafe::17]"`},
	{"[2001:db8:cafe::17]:47011", `"[2001:db8:cafe::17]:47011"`},
	{"unknown", `unknown`},

	{``, ""},
	{`"`, `"\""`},
}

func TestEscape(t *testing.T) {
	for _, c := range escapeTests {
		got := escape(c.in)
		if got != c.want {
			t.Errorf("escape(%q) = %q, want: %q", c.in, got, c.want)
		}
	}
}

func BenchmarkEscape(b *testing.B) {
	tokens := []string{
		"_gazonk",
		"192.0.2.43",
		"[2001:db8:cafe::17]",
		"unknown",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, token := range tokens {
			escape(token)
		}
	}
}

var unescapeTests = []struct {
	in   string
	want string
	err  string
}{
	// token
	{`192.0.2.43`, "192.0.2.43", ""},
	{`unknown`, "unknown", ""},

	// unquote path
	{`"_gazonk"`, "_gazonk", ""},
	{`"192.0.2.43:47011"`, "192.0.2.43:47011", ""},
	{`"[2001:db8:cafe::17]"`, "[2001:db8:cafe::17]", ""},
	{`"[2001:db8:cafe::17]:47011"`, "[2001:db8:cafe::17]:47011", ""},

	{"", ``, "first DQUOTE missing"},
	{`"""`, ``, "unescaped DQUOTE found"},
	{"\"\x00\"", ``, "invalid character found"},
	{`"`, ``, "last DQUOTE missing"},
	{`"u`, ``, "last DQUOTE missing"},

	// unescape path
	{`"\""`, `"`, ""},
	{`"\"unknown"`, "\"unknown", ""},
	{`""\"`, "", "unescaped DQUOTE found"},
	{"\"\x00\\\"", "", "invalid character found"},
	{`"\`, "", "last DQUOTE missing"},
	{`"\"`, "", "escaped DQUOTE found"},
}

func TestUnescape(t *testing.T) {
	for _, c := range unescapeTests {
		got, err := unescape(c.in)

		if got != c.want || err == nil && c.err != "" || err != nil && err.Error() != c.err {
			t.Errorf("unescape(%s) = (%q, %v), want: (%q, %v)", c.in, got, err, c.want, c.err)
		}
	}
}

func BenchmarkUnescape(b *testing.B) {
	tokens := []string{
		`"_gazonk"`,
		"192.0.2.43",
		`"[2001:db8:cafe::17]"`,
		"unknown",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, token := range tokens {
			unescape(token)
		}
	}
}

func BenchmarkStrconvUnquote(b *testing.B) {
	tokens := []string{
		`"_gazonk"`,
		"192.0.2.43",
		`"[2001:db8:cafe::17]"`,
		"unknown",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, token := range tokens {
			strconv.Unquote(token)
		}
	}
}

func BenchmarkValidElementToken(b *testing.B) {
	names := []string{
		"",
		"by",
		"for",
		"proto",
		"host",
		"résumé",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, name := range names {
			validElementToken(name)
		}
	}
}
