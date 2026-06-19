package matcher

import "testing"

func TestIsVulnerableVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		installed string
		fixed     string
		want      bool
	}{
		{
			name:      "installed older numeric patch",
			installed: "1.2.2-r4",
			fixed:     "1.2.3-r0",
			want:      true,
		},
		{
			name:      "installed newer numeric patch",
			installed: "1.2.3-r0",
			fixed:     "1.2.2-r4",
			want:      false,
		},
		{
			name:      "same main different revision older",
			installed: "1.2.2-r4",
			fixed:     "1.2.2-r5",
			want:      true,
		},
		{
			name:      "same main different revision newer",
			installed: "1.2.2-r6",
			fixed:     "1.2.2-r5",
			want:      false,
		},
		{
			// The release 1.2.2 is newer than its own pre-release 1.2.2_pre2,
			// so an installed release is not vulnerable to a pre-release fix.
			name:      "installed release newer than prerelease fix",
			installed: "1.2.2-r4",
			fixed:     "1.2.2_pre2-r0",
			want:      false,
		},
		{
			name:      "git style token compared correctly",
			installed: "1.2.2-r4",
			fixed:     "1.2.4_git20230717-r5",
			want:      true,
		},
		{
			name:      "equal versions not vulnerable",
			installed: "3.5.1-r0",
			fixed:     "3.5.1-r0",
			want:      false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := IsVulnerableVersion(tc.installed, tc.fixed)
			if got != tc.want {
				t.Fatalf("IsVulnerableVersion(%q, %q) = %v, want %v", tc.installed, tc.fixed, got, tc.want)
			}
		})
	}
}

// TestCompareAPKVersions_Ordering pins the canonical apk ordering of pre- and
// post-release suffixes. Every version in the chain must sort strictly below
// every version after it, so each adjacent and non-adjacent pair is checked in
// both directions.
func TestCompareAPKVersions_Ordering(t *testing.T) {
	t.Parallel()

	// Ascending order: pre-releases, the bare release, post-releases, then a
	// trailing letter, then the next patch.
	ordered := []string{
		"1.2.2_alpha",
		"1.2.2_alpha1",
		"1.2.2_beta",
		"1.2.2_pre",
		"1.2.2_pre1",
		"1.2.2_pre2",
		"1.2.2_rc",
		"1.2.2_rc1",
		"1.2.2",
		"1.2.2_cvs",
		"1.2.2_svn",
		"1.2.2_git",
		"1.2.2_hg",
		"1.2.2_p",
		"1.2.2_p1",
		"1.2.2a",
		"1.2.3",
	}

	for i := 0; i < len(ordered); i++ {
		for j := 0; j < len(ordered); j++ {
			a, b := ordered[i], ordered[j]
			got := compareAPKVersions(a, b)

			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}

			if got != want {
				t.Errorf("compareAPKVersions(%q, %q) = %d, want %d", a, b, got, want)
			}
		}
	}
}

// TestCompareAPKVersions_Cases covers comparison details outside the suffix
// chain: numeric components, trailing zeros, letters, the build revision
// tiebreak, and unknown suffixes.
func TestCompareAPKVersions_Cases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "equal", a: "1.2.3-r0", b: "1.2.3-r0", want: 0},
		{name: "numeric component", a: "1.2.9", b: "1.2.10", want: -1},
		{name: "trailing zero is less than shorter", a: "1.0.0", b: "1.0", want: -1},
		{name: "extra nonzero component is greater", a: "1.0.1", b: "1.0", want: 1},
		{name: "letter release outranks bare release", a: "1.0a", b: "1.0", want: 1},
		{name: "letters compared in order", a: "1.0a", b: "1.0b", want: -1},
		{name: "revision breaks tie when main equal", a: "1.2.3-r1", b: "1.2.3-r2", want: -1},
		{name: "missing revision treated as r0", a: "1.2.3", b: "1.2.3-r1", want: -1},
		{name: "main version wins over revision", a: "1.2.4-r0", b: "1.2.3-r9", want: 1},
		{name: "unknown suffix sorts after release", a: "1.0", b: "1.0_zzz", want: -1},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := compareAPKVersions(tc.a, tc.b); got != tc.want {
				t.Fatalf("compareAPKVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
