// Command crs-sidecar replays parsed access-log records through OWASP Core Rule
// Set via Coraza and emits the matched rules as JSONL evidence.
//
// It contains no attack knowledge of its own: CRS supplies every detection, and
// this program is transport plus configuration. Input is pre-parsed JSON rather
// than raw log lines, so logarc's parsers stay the single source of truth for
// reading a log — this program never sees a log format and does not need to
// know there are fourteen of them.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// presenceTestRules fire on 100% of replayed records regardless of content:
// each is a &REQUEST_HEADERS:X presence test on a header Apache never logs, so
// "absent from the log" is indistinguishable from "absent from the request".
// That is constant signal, not weak signal, so it is removed rather than
// down-weighted. 920280 (Host) is included because we synthesize a Host header.
var presenceTestRules = []int{
	920171, 920180, 920181, 920300, 920340, 920490,
	920510, 920620, 920640, 920660, 921230, 920280,
}

// controlRanges are rule-ID thousands blocks that carry engine plumbing rather
// than attack evidence: 900 setup variables, 901 initialization, 949 blocking
// evaluation, 980 correlation. They are loaded (later rules depend on them) but
// never reported. These need an explicit list because, unlike the plumbing
// caught by isEvidence below, 949110 and 980170 do carry messages.
var controlRanges = map[int]bool{900: true, 901: true, 949: true, 980: true}

// isEvidence separates CRS detections from CRS machinery.
//
// A large majority of "matches" in a replay are control flow, not findings:
// paranoia-level gates (9xx017/9xx018) testing TX:detection_paranoia_level,
// performance shortcuts like 941010 that call ctl:ruleRemoveTargetByTag, and
// counting rules like 921170 that only setvar for a later reporting rule. On the
// SQLi sample these accounted for 3,237 of 3,439 raw matches.
//
// The distinguishing feature is CRS's own nolog convention: rules meant to be
// reported carry a msg, machinery does not. Filtering on the message rather than
// on ID patterns means new CRS versions do not silently reintroduce noise.
func isEvidence(rule types.MatchedRule) bool {
	if controlRanges[rule.Rule().ID()/1000] {
		return false
	}
	return rule.Message() != ""
}

type record struct {
	LineNo    int     `json:"line_no"`
	ClientIP  string  `json:"client_ip"`
	Method    *string `json:"method"`
	RawTarget string  `json:"raw_target"`
	Protocol  *string `json:"protocol"`
	Status    *int    `json:"status"`
	Referer   *string `json:"referer"`
	UserAgent *string `json:"user_agent"`
}

type evidence struct {
	LineNo           int      `json:"line_no"`
	RuleID           int      `json:"rule_id"`
	Severity         string   `json:"severity"`
	Msg              string   `json:"msg"`
	AttackFamily     *string  `json:"attack_family"`
	ParanoiaLevel    *int     `json:"paranoia_level"`
	Tags             []string `json:"tags"`
	Capec            []string `json:"capec"`
	MatchedVar       string   `json:"matched_var"`
	TransformedValue string   `json:"transformed_value"`
}

func buildWAF(rulesDir, confDir string, paranoia int) (coraza.WAF, error) {
	var err error
	requestRules, err := filepath.Glob(filepath.Join(rulesDir, "rules", "REQUEST-*.conf"))
	if err != nil {
		return nil, err
	}
	if len(requestRules) == 0 {
		return nil, fmt.Errorf("no REQUEST-*.conf found under %s/rules", rulesDir)
	}

	// Paths are made absolute: CRS rule files reference sibling .data files, and
	// Coraza resolves those relative to the including file.
	if rulesDir, err = filepath.Abs(rulesDir); err != nil {
		return nil, err
	}
	if confDir, err = filepath.Abs(confDir); err != nil {
		return nil, err
	}

	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile(filepath.Join(confDir, "coraza.conf"))

	// Paranoia level is set before CRS setup so the setup file's defaults do not
	// override it. Chosen by measurement rather than by instinct: see the flag
	// default in main for the numbers. False positives are not cheap here — a
	// detection can name an activity, and naming one starts a new episode — but
	// no control produced any, and the recall difference between levels is
	// large.
	cfg = cfg.WithDirectives(fmt.Sprintf(
		"SecAction \"id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d\"\n"+
			"SecAction \"id:900001,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=%d\"\n",
		paranoia, paranoia))

	setup := filepath.Join(confDir, "crs-setup.conf")
	if _, err := os.Stat(setup); err == nil {
		cfg = cfg.WithDirectivesFromFile(setup)
	}

	// RESPONSE-*.conf is never loaded: all 173 of those rules are dead when the
	// only evidence is an access log.
	for _, path := range requestRules {
		cfg = cfg.WithDirectivesFromFile(path)
	}

	ids := make([]string, len(presenceTestRules))
	for i, id := range presenceTestRules {
		ids[i] = strconv.Itoa(id)
	}
	cfg = cfg.WithDirectives("SecRuleRemoveById " + strings.Join(ids, " ") + "\n")

	return coraza.NewWAF(cfg)
}

func tagInfo(tags []string) (family *string, paranoia *int, capec []string) {
	for _, tag := range tags {
		switch {
		case strings.HasPrefix(tag, "attack-") && family == nil:
			value := tag
			family = &value
		case strings.HasPrefix(tag, "capec/"):
			capec = append(capec, tag)
		case strings.HasPrefix(tag, "paranoia-level/"):
			if level, err := strconv.Atoi(strings.TrimPrefix(tag, "paranoia-level/")); err == nil {
				paranoia = &level
			}
		}
	}
	return family, paranoia, capec
}

func matchedVar(data types.MatchData) string {
	name := data.Variable().Name()
	if key := data.Key(); key != "" {
		return name + ":" + key
	}
	return name
}

// evaluate replays one record and returns every reported match.
func evaluate(waf coraza.WAF, rec record, host string) []evidence {
	// Apache writes "-" for aborted connections and 408 timeouts. There is no
	// request line to evaluate, so there is nothing for CRS to say.
	if rec.Method == nil || rec.RawTarget == "" || rec.RawTarget == "-" {
		return nil
	}
	proto := "HTTP/1.1"
	if rec.Protocol != nil && *rec.Protocol != "" {
		proto = *rec.Protocol
	}

	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	tx.ProcessConnection(rec.ClientIP, 0, "", 0)
	// Synthesized: Apache does not log Host. Without it every request looks like
	// a missing-Host anomaly.
	tx.AddRequestHeader("Host", host)
	if rec.UserAgent != nil && *rec.UserAgent != "" {
		tx.AddRequestHeader("User-Agent", *rec.UserAgent)
	}
	if rec.Referer != nil && *rec.Referer != "" {
		tx.AddRequestHeader("Referer", *rec.Referer)
	}
	tx.ProcessURI(rec.RawTarget, *rec.Method, proto)
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		fmt.Fprintf(os.Stderr, "line %d: request body phase: %v\n", rec.LineNo, err)
	}
	if rec.Status != nil {
		tx.ProcessResponseHeaders(*rec.Status, proto)
	}

	var out []evidence
	for _, rule := range tx.MatchedRules() {
		if !isEvidence(rule) {
			continue
		}
		meta := rule.Rule()
		id := meta.ID()
		family, paranoia, capec := tagInfo(meta.Tags())
		if capec == nil {
			capec = []string{}
		}
		tags := meta.Tags()
		if tags == nil {
			tags = []string{}
		}

		// One evidence line per matched datum, not per rule: a rule that matched
		// in two parameters produces two lines sharing a rule_id. Collapsing
		// them would discard the anchor for transformed_value.
		datas := rule.MatchedDatas()
		if len(datas) == 0 {
			out = append(out, evidence{
				LineNo: rec.LineNo, RuleID: id, Severity: meta.Severity().String(),
				Msg: rule.Message(), AttackFamily: family, ParanoiaLevel: paranoia,
				Tags: tags, Capec: capec,
			})
			continue
		}
		for _, data := range datas {
			out = append(out, evidence{
				LineNo: rec.LineNo, RuleID: id, Severity: meta.Severity().String(),
				Msg: rule.Message(), AttackFamily: family, ParanoiaLevel: paranoia,
				Tags: tags, Capec: capec,
				MatchedVar: matchedVar(data),
				// Post-transformation value: Coraza sets MatchData.Value from the
				// transformed argument (internal/corazawaf/rule.go, "args
				// represents the transformed variables"), so this reflects
				// t:urlDecodeUni, t:replaceComments, t:compressWhitespace etc.
				TransformedValue: data.Value(),
			})
		}
	}
	return out
}

func main() {
	host := flag.String("host", "localhost", "Host header to synthesize (Apache does not log it)")
	rules := flag.String("rules", "../vendor/coreruleset", "path to a coreruleset checkout")
	confDir := flag.String("conf", ".", "directory holding coraza.conf and crs-setup.conf")
	// PL2, not the PL3 this sidecar was first written with, and not the PL1 it
	// was first set to here. A false positive matters more in this tool than in
	// the one this came from — a CRS detection can name a request's
	// ActivityCategory, and a category change starts a new episode — so the
	// instinct was to be conservative. Measurement did not support it: across
	// CRS's own 1,194 access-log-visible regression payloads, PL1 reached 67%
	// and PL2 reached 90%, while every negative control produced the same
	// number of hostile episodes at every level from 1 to 4.
	paranoia := flag.Int("paranoia", 2, "CRS paranoia level")
	flag.Parse()

	waf, err := buildWAF(*rules, *confDir, *paranoia)
	if err != nil {
		fmt.Fprintf(os.Stderr, "crs-sidecar: %v\n", err)
		os.Exit(1)
	}

	started := time.Now()
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	encoder := json.NewEncoder(out)

	var processed, skipped, matchedRecords, totalMatches, malformed int
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var rec record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			malformed++
			fmt.Fprintf(os.Stderr, "crs-sidecar: malformed input: %v\n", err)
			continue
		}
		if rec.Method == nil {
			skipped++
			continue
		}
		processed++
		matches := evaluate(waf, rec, *host)
		if len(matches) > 0 {
			matchedRecords++
			totalMatches += len(matches)
		}
		for _, item := range matches {
			if err := encoder.Encode(item); err != nil {
				fmt.Fprintf(os.Stderr, "crs-sidecar: encode: %v\n", err)
				os.Exit(1)
			}
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "crs-sidecar: read: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr,
		"crs-sidecar: processed=%d skipped_no_request_line=%d malformed=%d "+
			"records_with_matches=%d total_matches=%d elapsed=%s\n",
		processed, skipped, malformed, matchedRecords, totalMatches,
		time.Since(started).Round(time.Millisecond))
}
