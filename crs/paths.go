package main

import (
	"path"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
)

// CRS's file lists — lfi-os-files.data, restricted-files.data, unix-shell.data
// — are written with forward slashes, and the rules that read them clean the
// path first with t:normalizePath or t:normalizePathWin. Coraza v3.7.0 cleans
// it with path/filepath, whose Clean on Windows turns every / into \, so on a
// Windows build /etc/passwd was compared as \etc\passwd and never matched.
// Measured 2026-10-14 on CRS's regression corpus: the Windows sidecar made 104
// fewer detections than the Linux one, all in 930120, 930121, 930130, 930140,
// 932160 and 932161, and a request for /.git/config passed as harmless.
//
// These replace Coraza's four names for the two transformations with the same
// steps on package path, which is what path/filepath already is on Linux. So
// the Linux sidecar reports exactly what it did, and the Windows one now
// reports the same.
func init() {
	plugins.RegisterTransformation("normalisePath", normalisePath)
	plugins.RegisterTransformation("normalizePath", normalisePath)
	plugins.RegisterTransformation("normalisePathWin", normalisePathWin)
	plugins.RegisterTransformation("normalizePathWin", normalisePathWin)
}

func normalisePath(data string) (string, bool, error) {
	if len(data) < 1 {
		return data, false, nil
	}
	clean := path.Clean(data)
	if clean == "." {
		return "", true, nil
	}
	if data[len(data)-1] == '/' {
		return clean + "/", true, nil
	}
	return clean, data != clean, nil
}

func normalisePathWin(data string) (string, bool, error) {
	if len(data) < 1 {
		return data, false, nil
	}
	return normalisePath(strings.ReplaceAll(data, "\\", "/"))
}
