package forwarded

import (
	"errors"
	"strings"
)

// escape returns string s as token or quoted-string per
// RFC 7230, section 3.2.6.
func escape(s string) string {
	if !strings.ContainsAny(s, `"(),/:;<=>?@[\]{}`) {
		return s
	}

	buf := make([]byte, 0, 3*len(s)/2)
	buf = append(buf, '"')

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			buf = append(buf, '\\', c)
		default:
			buf = append(buf, c)
		}
	}

	buf = append(buf, '"')
	return string(buf)
}

// unescape unescapes value s per RFC 7329, section 4.
func unescape(s string) (string, error) {
	if validElementToken(s) {
		return s, nil
	}

	if !strings.HasPrefix(s, `"`) {
		return "", errors.New("first DQUOTE missing")
	}

	// only remove quotes at begin and end if string
	// is just quoted and contains valid characters
	if strings.IndexByte(s, '\\') == -1 {
		if !strings.HasSuffix(s, `"`) || len(s) == 1 {
			return "", errors.New("last DQUOTE missing")
		}
		u := s[1 : len(s)-1]
		for i := 0; i < len(u); i++ {
			c := u[i]
			switch {
			case c == '"':
				return "", errors.New("unescaped DQUOTE found")
			case isCTL(c) && !isLWS(c):
				return "", errors.New("invalid character found")
			}
		}
		return u, nil
	}

	// string needs to be unescaped
	buf := make([]byte, 0, 3*len(s)/2)
	backslash := false
	for i := 1; i < len(s)-1; i++ {
		c := s[i]
		switch {
		case !backslash && c == '"':
			return "", errors.New("unescaped DQUOTE found")
		case !backslash && c == '\\':
			backslash = true
		case c == '\t', c >= 0x20 && c <= 0x7e, c >= 0x80:
			buf = append(buf, c)
			backslash = false
		default:
			return "", errors.New("invalid character found")
		}
	}
	if !strings.HasSuffix(s, `"`) {
		return "", errors.New("last DQUOTE missing")
	}
	if backslash {
		return "", errors.New("escaped DQUOTE found")
	}

	return string(buf), nil
}
