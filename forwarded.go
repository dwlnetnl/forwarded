// Package forwarded implements a RFC 7239 (Forwarded HTTP Extension) parser.
package forwarded

import (
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// Parse parses elements in the given line. If reverse
// is true, the elements are parsed in reverse.
// The error returned is of type [*ParseError].
func Parse(line string, reverse bool) iter.Seq2[*Element, error] {
	splitSeq := strings.SplitSeq
	if reverse {
		splitSeq = reverseSplitSeq
	}

	return func(yield func(*Element, error) bool) {
		for elem := range splitSeq(line, ",") {
			var e Element

			for i := strings.IndexByte(elem, ';'); i != -1; i = strings.IndexByte(elem, ';') {
				err := parsePair(&e, trimOWS(elem[:i]))
				if err != nil {
					yield(nil, err)
					return
				}
				elem = elem[i+1:]
			}
			if err := parsePair(&e, trimOWS(elem)); err != nil {
				yield(nil, err)
				return
			}

			if !yield(&e, nil) {
				return
			}
		}
	}
}

func parsePair(e *Element, pair string) error {
	token, value, found := strings.Cut(pair, "=")
	if !found {
		return &ParseError{`no "=" found in`, pair}
	}

	if !validElementToken(token) {
		return &ParseError{`invalid token`, token}
	}
	value, err := unescape(value)
	if err != nil {
		return &ParseError{`invalid value`, value}
	}

	switch strings.ToLower(token) {
	case "by":
		e.By = Node(value)
	case "for":
		e.For = Node(value)
	case "proto":
		e.Proto = value
	case "host":
		e.Host = value
	default:
		e.Extra = append(e.Extra, Paramater{
			Key:   token,
			Value: value,
		})
	}

	return nil
}

func reverseSplitSeq(s, sep string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for {
			start := 0
			i := strings.LastIndex(s, sep)
			if i != -1 {
				start = i + 1
			}

			if !yield(s[start:]) || i == -1 {
				return
			}

			s = s[:i]
		}
	}
}

// ParseError is returned if a line cannot be parsed.
type ParseError struct {
	Msg  string
	Text string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("forwarded: %s %q", e.Msg, e.Text)
}

// Last returns the last element in the given line.
// The error returned is of type [*ParseError].
func Last(line string) (*Element, error) {
	for elem, err := range Parse(line, true) {
		return elem, err
	}
	return nil, nil
}

// Element contains information about a proxy.
type Element struct {
	By    Node
	For   Node
	Proto string
	Host  string
	Extra []Paramater
}

// Pair represents a key-value pair making up a element
// parameter.
type Paramater struct {
	Key, Value string
}

// String returns the string equivalent of element e.
// It assumes that element e is valid.
func (e Element) String() string {
	var pairs []string
	if e.By != "" {
		pairs = append(pairs, "by="+escape(string(e.By)))
	}
	if e.For != "" {
		pairs = append(pairs, "for="+escape(string(e.For)))
	}
	if e.Proto != "" {
		pairs = append(pairs, "proto="+escape(e.Proto))
	}
	if e.Host != "" {
		pairs = append(pairs, "host="+escape(e.Host))
	}
	for _, p := range e.Extra {
		pairs = append(pairs, p.Key+"="+escape(p.Value))
	}
	return strings.Join(pairs, ";")
}

// A Node identifier is one of the following:
//   - The client's IP address, with an optional port number.
//   - A token indicating that the IP address of the client
//     is not known to the proxy server.
//   - A generated token, allowing for tracing and debugging,
//     while allowing the internal structure or sensitive
//     information to be hidden.
type Node string

// AddrPort attempts to parse node n as a IP address and port.
// Either addr or node port returned may be invalid.
func (n Node) AddrPort() (netip.Addr, NodePort, bool) {
	host, port, err := net.SplitHostPort(string(n))
	if err != nil {
		host = string(n)
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	a, err := netip.ParseAddr(host)
	np := NodePort(port)
	return a, np, err == nil || np.IsValid()
}

// IsObfuscated returns true if node n is a generated token.
func (n Node) IsObfuscated() bool {
	return strings.HasPrefix(string(n), "_")
}

// IsUnknown returns true if node n is the unknown token.
func (n Node) IsUnknown() bool {
	return n == "unknown"
}

// NodePort represents the port of a node, either a uint16 value
// or obfuscated.
type NodePort string

// IsValid returns true if node port np is not empty.
func (np NodePort) IsValid() bool {
	return np != ""
}

// Uint16 attempts to parse the port as a uint16 value.
func (np NodePort) Uint16() (uint16, bool) {
	u, err := strconv.ParseUint(string(np), 10, 16)
	return uint16(u), err == nil
}

// IsObfuscated returns true if node port np is obfuscated.
func (np NodePort) IsObfuscated() bool {
	return strings.HasPrefix(string(np), "_")
}

const header = "Forwarded"

// ParseRequests parses elements in the Forwarded header
// in request r. If reverse is true, the elements are
// parsed in reverse.
// The error returned is of type [*ParseError].
func ParseRequest(r *http.Request, reverse bool) iter.Seq2[*Element, error] {
	return Parse(r.Header.Get(header), reverse)
}

// LastRequest returns the last element in the Forwarded
// header in request r.
// The error returned is of type [*ParseError].
func LastRequest(r *http.Request) (*Element, error) {
	return Last(r.Header.Get(header))
}
