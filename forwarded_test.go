package forwarded

import (
	"iter"
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

type parseTest struct {
	name string
	in   string
	want []*Element
}

var parseTests = []parseTest{
	{
		name: "rfc7239/4/1",
		in:   `for="_gazonk"`,
		want: []*Element{
			{For: "_gazonk"},
		},
	},
	{
		name: "rfc7239/4/2",
		in:   `For="[2001:db8:cafe::17]:4711"`,
		want: []*Element{
			{For: "[2001:db8:cafe::17]:4711"},
		},
	},
	{
		name: "rfc7239/4/3",
		in:   `for=192.0.2.60;proto=http;by=203.0.113.43`,
		want: []*Element{{
			For:   "192.0.2.60",
			Proto: "http",
			By:    "203.0.113.43",
		}},
	},
	{
		name: "rfc7239/4/4",
		in:   `for=192.0.2.43, for=198.51.100.17`,
		want: []*Element{
			{For: "192.0.2.43"},
			{For: "198.51.100.17"},
		},
	},
	{
		name: "rfc7239/6.3",
		in:   `for=_hidden, for=_SEVKISEK`,
		want: []*Element{
			{For: "_hidden"},
			{For: "_SEVKISEK"},
		},
	},
	{
		name: "rfc7239/7.1/1",
		in:   `for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown`,
		want: []*Element{
			{For: "192.0.2.43"},
			{For: "[2001:db8:cafe::17]"},
			{For: "unknown"},
		},
	},
	{
		name: "rfc7239/7.1/2",
		in:   `for=192.0.2.43, for="[2001:db8:cafe::17]", for=unknown`,
		want: []*Element{
			{For: "192.0.2.43"},
			{For: "[2001:db8:cafe::17]"},
			{For: "unknown"},
		},
	},
	{
		name: "rfc7239/7.5",
		in:   `for=192.0.2.43, for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com`,
		want: []*Element{
			{
				For: "192.0.2.43",
			},
			{
				For:   "198.51.100.17",
				By:    "203.0.113.60",
				Proto: "http",
				Host:  "example.com",
			},
		},
	},

	{
		name: "rfc7239/5.5",
		in:   `key=value;token="\"quoted-string\""`,
		want: []*Element{{
			Extra: []Paramater{
				{"key", "value"},
				{"token", `"quoted-string"`},
			},
		}},
	},
}

func TestParse(t *testing.T) {
	for _, c := range parseTests {
		t.Run(c.name, func(t *testing.T) {
			t.Run("forward", testParse(c, false))
			t.Run("reverse", testParse(c, true))
		})
	}
}

func testParse(c parseTest, reverse bool) func(t *testing.T) {
	return func(t *testing.T) {
		var got []*Element
		for elem, err := range Parse(c.in, reverse) {
			if err != nil {
				t.Fatalf("got error: %v\nelems: %v", err, got)
			}
			got = append(got, elem)
		}

		want := c.want
		if reverse {
			want = slices.Clone(want)
			slices.Reverse(want)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("\ngot:  %v\nwant: %v", got, want)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	collect := func(b *testing.B, elems iter.Seq2[*Element, error]) {
		for _, err := range elems {
			if err != nil {
				b.Fatal(err)
			}
		}
	}

	for _, c := range parseTests {
		b.Run(c.name, func(b *testing.B) {
			b.Run("forward", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					collect(b, Parse(c.in, false))
				}
			})

			b.Run("reverse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					collect(b, Parse(c.in, true))
				}
			})
		})
	}
}

func TestNode(t *testing.T) {
	t.Run("AddrPort", func(t *testing.T) {
		cases := []struct {
			node Node
			addr netip.Addr
			port NodePort
			ok   bool
		}{
			{"192.0.2.43", netip.MustParseAddr("192.0.2.43"), "", true},
			{"192.0.2.43:47011", netip.MustParseAddr("192.0.2.43"), "47011", true},
			{"192.0.2.43:_gazonk", netip.MustParseAddr("192.0.2.43"), "_gazonk", true},
			{"[2001:db8:cafe::17]", netip.MustParseAddr("2001:db8:cafe::17"), "", true},
			{"[2001:db8:cafe::17]:47011", netip.MustParseAddr("2001:db8:cafe::17"), "47011", true},
			{"[2001:db8:cafe::17]:_gazonk", netip.MustParseAddr("2001:db8:cafe::17"), "_gazonk", true},
			{"_SEVKISEK", netip.Addr{}, "", false},
			{"_SEVKISEK:47011", netip.Addr{}, "47011", true},
			{"_SEVKISEK:_gazonk", netip.Addr{}, "_gazonk", true},
			{"unknown", netip.Addr{}, "", false},
			{"unknown:47011", netip.Addr{}, "47011", true},
			{"unknown:_gazonk", netip.Addr{}, "_gazonk", true},
		}

		for _, c := range cases {
			addr, port, ok := c.node.AddrPort()
			if addr != c.addr || c.port != port || ok != c.ok {
				t.Errorf("Node(%q).AddrPort() = (%v, %v, %v), want: (%v, %v, %v)",
					c.node, addr, port, ok, c.addr, c.port, c.ok)
			}
		}
	})

	t.Run("IsObfuscated", func(t *testing.T) {
		obf := Node("_gazonk").IsObfuscated()
		if !obf {
			t.Error(`Node("_gazonk").IsObfuscated() returned false`)
		}
		obf = Node("gazonk").IsObfuscated()
		if obf {
			t.Error(`Node("gazonk").IsObfuscated() returned true`)
		}
	})

	t.Run("IsUnknown", func(t *testing.T) {
		unk := Node("unknown").IsUnknown()
		if !unk {
			t.Error(`Node("unknown").IsUnknown() returned false`)
		}
		unk = Node("_unknown").IsUnknown()
		if unk {
			t.Error(`Node("_unknown").IsUnknown() returned true`)
		}
	})
}

func TestNodePort(t *testing.T) {
	t.Run("Uint16", func(t *testing.T) {
		port, ok := NodePort("47011").Uint16()
		if port != 47011 || !ok {
			t.Errorf(`NodePort("47011").Uint16() = (%d, %v), want: (47011, true)`, port, ok)
		}
		port, ok = NodePort("_gazonk").Uint16()
		if port != 0 || ok {
			t.Errorf(`NodePort("_gazonk").Uint16() = (%d, %v), want: (0, false)`, port, ok)
		}
	})

	t.Run("IsObfuscated", func(t *testing.T) {
		obf := NodePort("_gazonk").IsObfuscated()
		if !obf {
			t.Error(`NodePort("_gazonk").IsObfuscated() returned false`)
		}
		obf = NodePort("gazonk").IsObfuscated()
		if obf {
			t.Error(`NodePort("gazonk").IsObfuscated() returned true`)
		}
	})
}
