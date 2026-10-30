//go:build amd64

package main

// The sidecar runs on whatever CPU a user has, and some of what Go does
// depends on it. go-re2 v1.6.0 ran RE2 on wazero, whose compiled code called
// Go's own memmove and, before wazero v1.9.0, counted on it leaving DX alone.
// Go 1.24's amd64 memmove does not on Intel CPUs with both ERMS and FSRM, Ice
// Lake and newer: it copies 2 KiB and more with REP MOVSQ and writes DX on the
// way (runtime/memmove_amd64.s, fwdBy8). On those machines the sidecar crashed
// while loading CRS, "wasm error: invalid table access" in go-re2's cre2New,
// and on no other, the computer the RE2 change was measured on included.
//
// So the first case takes that path whatever the CPU, by setting the bit the
// runtime sets for such a CPU, and the second copies the way this CPU does.
// CI runs both again with GODEBUG=cpu.all=off, where the second is a CPU with
// no optional features at all. Reaching runtime.memmoveBits needs
// `go test -ldflags=-checklinkname=0`; see README.md.

import (
	"testing"
	_ "unsafe" // for go:linkname
)

//go:linkname memmoveBits runtime.memmoveBits
var memmoveBits uint8

// repmovsPreferred is runtime/cpuflags_amd64.go's "REP MOVSx is faster here".
const repmovsPreferred = 1 << 1

func TestCRSLoadsAndMatchesOnEveryMemmovePath(t *testing.T) {
	cases := []struct {
		name  string
		force bool
	}{
		{"REP MOVS, as on Intel from Ice Lake on", true},
		{"as this CPU copies", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			saved := memmoveBits
			if c.force {
				memmoveBits |= repmovsPreferred
			}
			t.Cleanup(func() { memmoveBits = saved })

			waf, err := buildWAF("../vendor/coreruleset", ".", 2)
			if err != nil {
				t.Fatalf("loading CRS: %v (fetch it with `zodiarc setup-crs`)", err)
			}

			// 942100 is libinjection; 930110 is @rx, so RE2 has to match as
			// well as compile.
			method := "GET"
			for _, want := range []struct {
				target string
				rule   int
			}{
				{"/?id=1%27%20OR%20%271%27%3D%271", 942100},
				{"/?file=../../../../etc/passwd", 930110},
			} {
				found := evaluate(waf, record{
					LineNo:    1,
					ClientIP:  "203.0.113.5",
					Method:    &method,
					RawTarget: want.target,
				}, "localhost")
				if !fired(found, want.rule) {
					t.Errorf("%d did not fire on %s; got %v", want.rule, want.target, ruleIDs(found))
				}
			}
		})
	}
}

func fired(found []evidence, rule int) bool {
	for _, e := range found {
		if e.RuleID == rule {
			return true
		}
	}
	return false
}

func ruleIDs(found []evidence) []int {
	ids := make([]int, 0, len(found))
	for _, e := range found {
		ids = append(ids, e.RuleID)
	}
	return ids
}
