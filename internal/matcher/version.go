package matcher

import (
	"strconv"
	"strings"
	"unicode"
)

// IsVulnerableVersion returns true when installed is older than fixedVersion.
func IsVulnerableVersion(installed, fixedVersion string) bool {
	return compareAPKVersions(installed, fixedVersion) < 0
}

// compareAPKVersions performs an APK-oriented version comparison.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareAPKVersions(a, b string) int {
	aMain, aRev := splitRevision(a)
	bMain, bRev := splitRevision(b)

	if cmp := compareVersionCore(aMain, bMain); cmp != 0 {
		return cmp
	}

	switch {
	case aRev < bRev:
		return -1
	case aRev > bRev:
		return 1
	default:
		return 0
	}
}

func splitRevision(v string) (string, int) {
	parts := strings.SplitN(v, "-r", 2)
	if len(parts) != 2 {
		return v, 0
	}

	rev, err := strconv.Atoi(parts[1])
	if err != nil {
		return parts[0], 0
	}

	return parts[0], rev
}

func compareVersionCore(a, b string) int {
	aTokens := tokenize(a)
	bTokens := tokenize(b)

	maxLen := len(aTokens)
	if len(bTokens) > maxLen {
		maxLen = len(bTokens)
	}

	for i := 0; i < maxLen; i++ {
		aTok := ""
		bTok := ""
		if i < len(aTokens) {
			aTok = aTokens[i]
		}
		if i < len(bTokens) {
			bTok = bTokens[i]
		}

		if aTok == bTok {
			continue
		}

		aNum := isNumeric(aTok)
		bNum := isNumeric(bTok)

		if aNum && bNum {
			aVal, _ := strconv.Atoi(aTok)
			bVal, _ := strconv.Atoi(bTok)
			switch {
			case aVal < bVal:
				return -1
			case aVal > bVal:
				return 1
			default:
				continue
			}
		}

		if aNum && !bNum {
			return 1
		}
		if !aNum && bNum {
			return -1
		}

		if aTok < bTok {
			return -1
		}
		return 1
	}

	return 0
}

func tokenize(v string) []string {
	var tokens []string
	var current strings.Builder
	currentNumeric := false
	hasCurrent := false

	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
		hasCurrent = false
	}

	for _, r := range v {
		if r == '.' || r == '_' || r == '-' || r == '+' {
			flush()
			continue
		}

		isNum := unicode.IsDigit(r)
		if !hasCurrent {
			currentNumeric = isNum
			hasCurrent = true
		} else if currentNumeric != isNum {
			flush()
			currentNumeric = isNum
			hasCurrent = true
		}

		current.WriteRune(r)
	}
	flush()

	return tokens
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
