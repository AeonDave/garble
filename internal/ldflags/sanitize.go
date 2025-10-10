package ldflags

import (
	"strings"

	"github.com/AeonDave/garble/internal/cmdquoted"
)

type entry struct {
	fullName string
	value    string
}

// Sanitize extracts plaintext -X assignments and replaces them with empty
// assignments so that the Go linker never observes the original values. The
// returned slice is a sanitized copy of the provided flags, and the map
// contains the intercepted assignments keyed by fully-qualified variable name.
func Sanitize(flags []string) ([]string, map[string]string, error) {
	sanitized := append([]string(nil), flags...)
	captured := make(map[string]string)

	recordEntries := func(entries []entry) {
		for _, e := range entries {
			captured[e.fullName] = e.value
		}
	}

	for i := 0; i < len(sanitized); i++ {
		arg := sanitized[i]
		switch {
		case strings.HasPrefix(arg, "-ldflags="):
			value := strings.TrimPrefix(arg, "-ldflags=")
			rewritten, entries, err := sanitizeValue(value)
			if err != nil {
				return nil, nil, err
			}
			recordEntries(entries)
			sanitized[i] = "-ldflags=" + rewritten

		case arg == "-ldflags":
			if i+1 >= len(sanitized) {
				continue
			}
			rewritten, entries, err := sanitizeValue(sanitized[i+1])
			if err != nil {
				return nil, nil, err
			}
			recordEntries(entries)
			sanitized[i+1] = rewritten
		}
	}

	return sanitized, captured, nil
}

func sanitizeValue(value string) (string, []entry, error) {
	if strings.TrimSpace(value) == "" {
		return value, nil, nil
	}

	parts, err := cmdquoted.Split(value)
	if err != nil {
		return "", nil, err
	}

	records := make([]entry, 0, len(parts))

	record := func(fullName, plain string) {
		records = append(records, entry{fullName: fullName, value: plain})
	}

	for i := 0; i < len(parts); i++ {
		part := parts[i]
		if strings.HasPrefix(part, "-X=") {
			payload := strings.TrimPrefix(part, "-X=")
			fullName, plain, ok := strings.Cut(payload, "=")
			if !ok {
				continue
			}
			record(fullName, plain)
			parts[i] = "-X=" + fullName + "="
			continue
		}
		if part == "-X" && i+1 < len(parts) {
			payload := parts[i+1]
			fullName, plain, ok := strings.Cut(payload, "=")
			if !ok {
				continue
			}
			record(fullName, plain)
			parts[i+1] = fullName + "="
		}
	}

	joined, err := cmdquoted.Join(parts)
	if err != nil {
		return "", nil, err
	}

	return joined, records, nil
}
