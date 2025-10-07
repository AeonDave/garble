package ctrlflow

import (
	"fmt"
	"strings"
)

// Mode controls how control-flow obfuscation is applied across a package.
type Mode int

const (
	ModeOff Mode = iota
	// ModeAnnotated obfuscates only functions decorated with //garble:controlflow.
	ModeAnnotated
	// ModeAuto obfuscates all eligible functions unless explicitly skipped.
	ModeAuto
	// ModeAll obfuscates every function, including trivial ones.
	ModeAll
)

// Enabled reports whether the mode enables any control-flow obfuscation.
func (m Mode) Enabled() bool {
	return m != ModeOff
}

func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeAnnotated:
		return "directives"
	case ModeAuto:
		return "auto"
	case ModeAll:
		return "all"
	default:
		return "unknown"
	}
}

// ParseMode converts a string value into a Mode.
func ParseMode(value string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto", "1", "true", "on":
		return ModeAuto, nil
	case "off", "0", "false", "none":
		return ModeOff, nil
	case "directives", "annotated":
		return ModeAnnotated, nil
	case "all":
		return ModeAll, nil
	default:
		return ModeOff, fmt.Errorf("invalid controlflow mode %q", value)
	}
}
