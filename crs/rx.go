// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
//
// Adapted for logarc from rx.go in github.com/corazawaf/coraza-wasilibs
// v0.2.0. Changed: registered from this package's init rather than by a call,
// and compiled patterns are not memoised, since a sidecar builds one WAF.

package main

import (
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/wasilibs/go-re2"
	"github.com/wasilibs/go-re2/experimental"
)

// The @rx operator on RE2 compiled to WebAssembly instead of Go's regexp, which
// was half of a sidecar's time. Measured 2026-10-14 on the three 2026-10-06
// tiers, six sidecars, the middle of three runs: 10.1 s becomes 8.8 s, 28.6 s
// becomes 21.3 s and 69.1 s becomes 49.0 s, with the same detections on every
// tier and on CRS's regression corpus. A sidecar starts in 0.7 s rather than
// 0.1 s, wazero compiling RE2, which is why the sidecars live for a whole run.
//
// Written here rather than taken from coraza-wasilibs, whose package also
// carries pm, detectSQLi and detectXSS on two more WebAssembly modules. Each
// of those compiles its module when the package loads, so importing it for
// @rx alone made every sidecar pay at start for two libraries it never calls.
func init() {
	plugins.RegisterOperator("rx", newRX)
}

type rx struct {
	re *re2.Regexp
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	// (?sm) is what Coraza's own @rx prefixes, and 942522-7 needs the m.
	data := fmt.Sprintf("(?sm)%s", options.Arguments)

	var re *re2.Regexp
	var err error
	if matchesArbitraryBytes(data) {
		re, err = experimental.CompileLatin1(data)
	} else {
		re, err = re2.Compile(data)
	}
	if err != nil {
		return nil, err
	}
	return &rx{re: re}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if !tx.Capturing() {
		return o.re.MatchString(value)
	}
	match := o.re.FindStringSubmatch(value)
	if len(match) == 0 {
		return false
	}
	for i, c := range match {
		if i == 9 {
			return true
		}
		tx.CaptureField(i, c)
	}
	return true
}

// matchesArbitraryBytes reports whether the expression's \xNN escapes spell
// something other than UTF-8, which RE2 can only match in Latin-1 mode.
func matchesArbitraryBytes(expr string) bool {
	decoded := make([]byte, 0, len(expr))
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c != '\\' {
			decoded = append(decoded, c)
			continue
		}
		if i+3 >= len(expr) {
			decoded = append(decoded, expr[i:]...)
			break
		}
		if expr[i+1] != 'x' {
			decoded = append(decoded, expr[i])
			continue
		}

		v, mb, _, err := strconv.UnquoteChar(expr[i:], 0)
		if err != nil || mb {
			decoded = append(decoded, expr[i])
			continue
		}

		decoded = append(decoded, byte(v))
		i += 3
	}

	return !utf8.Valid(decoded)
}
