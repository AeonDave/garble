// Package cmdquoted provides string manipulation utilities compatible with
// cmd/dist's quoting semantics. The implementation mirrors Go's internal
// tooling so that garble can safely sanitize command-line arguments.
package cmdquoted

import (
	"flag"
	"fmt"
	"strings"
	"unicode"
)

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// Split splits s into a list of fields, allowing single or double quotes
// around elements. There is no unescaping or other processing within quoted
// fields.
func Split(s string) ([]string, error) {
	var f []string
	for len(s) > 0 {
		for len(s) > 0 && isSpaceByte(s[0]) {
			s = s[1:]
		}
		if len(s) == 0 {
			break
		}
		if s[0] == '"' || s[0] == '\'' {
			quote := s[0]
			s = s[1:]
			i := 0
			for i < len(s) && s[i] != quote {
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated %c string", quote)
			}
			f = append(f, s[:i])
			s = s[i+1:]
			continue
		}
		i := 0
		for i < len(s) && !isSpaceByte(s[i]) {
			i++
		}
		f = append(f, s[:i])
		s = s[i:]
	}
	return f, nil
}

// Join joins a list of arguments into a string that can be parsed with Split.
// Arguments are quoted only if necessary; arguments without spaces or quotes
// are kept as-is.
func Join(args []string) (string, error) {
	var buf []byte
	for i, arg := range args {
		if i > 0 {
			buf = append(buf, ' ')
		}
		var sawSpace, sawSingleQuote, sawDoubleQuote bool
		for _, c := range arg {
			switch {
			case c > unicode.MaxASCII:
				continue
			case isSpaceByte(byte(c)):
				sawSpace = true
			case c == '\'':
				sawSingleQuote = true
			case c == '"':
				sawDoubleQuote = true
			}
		}
		switch {
		case !sawSpace && !sawSingleQuote && !sawDoubleQuote:
			buf = append(buf, arg...)
		case !sawSingleQuote:
			buf = append(buf, '\'')
			buf = append(buf, arg...)
			buf = append(buf, '\'')
		case !sawDoubleQuote:
			buf = append(buf, '"')
			buf = append(buf, arg...)
			buf = append(buf, '"')
		default:
			return "", fmt.Errorf("argument %q contains both single and double quotes and cannot be quoted", arg)
		}
	}
	return string(buf), nil
}

// Flag parses a list of string arguments encoded with Join.
type Flag []string

var _ flag.Value = (*Flag)(nil)

// Set implements flag.Value.
func (f *Flag) Set(v string) error {
	fs, err := Split(v)
	if err != nil {
		return err
	}
	*f = fs[:len(fs):len(fs)]
	return nil
}

// String implements flag.Value.
func (f *Flag) String() string {
	if f == nil {
		return ""
	}
	s, err := Join(*f)
	if err != nil {
		return strings.Join(*f, " ")
	}
	return s
}
