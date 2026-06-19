package matcher

import (
	"strconv"
	"strings"
)

// IsVulnerableVersion reports whether the installed package version is older
// than fixedVersion using apk's version ordering. A package is vulnerable when
// its installed version sorts strictly below the version carrying the fix.
func IsVulnerableVersion(installed, fixedVersion string) bool {
	return compareAPKVersions(installed, fixedVersion) < 0
}

// compareAPKVersions compares two apk package versions, returning -1 if a < b,
// 0 if a == b, and 1 if a > b.
//
// The ordering follows apk-tools (apk_version.c): a version is a sequence of
// dot-separated numeric components, an optional trailing letter, zero or more
// pre/post-release suffixes (e.g. _alpha, _pre, _git, _p), and an optional
// "-rN" build revision. Pre-release suffixes sort below the bare release while
// post-release suffixes sort above it, so 1.2_pre1 < 1.2 < 1.2_p1.
//
// Known limitation: numeric components are compared as integers, so apk's
// leading-zero fractional comparison (e.g. 1.07 vs 1.1) is not reproduced.
// SecDB package versions do not rely on that behaviour.
func compareAPKVersions(a, b string) int {
	aMain, aRev := splitRevision(a)
	bMain, bRev := splitRevision(b)

	if cmp := compareTokens(tokenize(aMain), tokenize(bMain)); cmp != 0 {
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

// splitRevision separates the trailing apk build revision ("-rN") from the main
// version. A missing or malformed revision is treated as r0.
func splitRevision(v string) (string, int) {
	idx := strings.LastIndex(v, "-r")
	if idx < 0 {
		return v, 0
	}

	rev, err := strconv.Atoi(v[idx+2:])
	if err != nil {
		return v, 0
	}

	return v[:idx], rev
}

// tokenKind orders the categories of token that can appear in a version. The
// values matter: when two tokens carry equal numeric values, the smaller kind
// sorts first, and kindEnd is deliberately the largest so that a bare release
// outranks a trailing pre-release suffix (whose value is negative).
type tokenKind int

const (
	kindNumber tokenKind = iota
	kindLetter
	kindSuffix
	kindSuffixNum
	kindEnd
)

type token struct {
	kind  tokenKind
	value int
}

// suffixRanks orders apk's known release suffixes. Pre-release suffixes are
// negative so they sort below the bare release; post-release suffixes are
// positive so they sort above it.
var suffixRanks = map[string]int{
	"alpha": -4,
	"beta":  -3,
	"pre":   -2,
	"rc":    -1,
	"cvs":   1,
	"svn":   2,
	"git":   3,
	"hg":    4,
	"p":     5,
}

// unknownSuffixRank sorts unrecognised suffixes after every known one rather
// than failing the comparison outright.
const unknownSuffixRank = 100

// tokenize breaks an apk main version (without the -rN revision) into ordered
// comparison tokens.
func tokenize(v string) []token {
	var tokens []token
	i, n := 0, len(v)

	for i < n {
		c := v[i]
		switch {
		case c == '.':
			// Component separator; emits nothing.
			i++
		case c >= '0' && c <= '9':
			j := i
			for j < n && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			num, _ := strconv.Atoi(v[i:j])
			tokens = append(tokens, token{kind: kindNumber, value: num})
			i = j
		case c == '_':
			i++ // consume '_'
			j := i
			for j < n && isLetter(v[j]) {
				j++
			}
			rank, ok := suffixRanks[v[i:j]]
			if !ok {
				rank = unknownSuffixRank
			}
			tokens = append(tokens, token{kind: kindSuffix, value: rank})
			i = j

			// An optional number follows the suffix (e.g. _pre2); a bare
			// suffix is treated as _suffix0.
			k := i
			for k < n && v[k] >= '0' && v[k] <= '9' {
				k++
			}
			num := 0
			if k > i {
				num, _ = strconv.Atoi(v[i:k])
			}
			tokens = append(tokens, token{kind: kindSuffixNum, value: num})
			i = k
		case isLetter(c):
			// A bare trailing letter, e.g. the "a" in 1.0a.
			tokens = append(tokens, token{kind: kindLetter, value: int(c)})
			i++
		default:
			// '~' commit markers and any other separator are skipped.
			i++
		}
	}

	return tokens
}

// compareTokens compares two token streams position by position, padding the
// shorter stream with kindEnd. Values are compared first; equal values fall
// back to kind order, which is what lets a bare release outrank a trailing
// pre-release suffix.
func compareTokens(a, b []token) int {
	end := token{kind: kindEnd}
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	for i := 0; i < maxLen; i++ {
		at, bt := end, end
		if i < len(a) {
			at = a[i]
		}
		if i < len(b) {
			bt = b[i]
		}

		if at.value != bt.value {
			if at.value < bt.value {
				return -1
			}
			return 1
		}
		if at.kind != bt.kind {
			if at.kind < bt.kind {
				return -1
			}
			return 1
		}
	}

	return 0
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
