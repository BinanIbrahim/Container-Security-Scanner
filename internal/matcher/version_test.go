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
