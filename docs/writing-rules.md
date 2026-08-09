# Writing detection rules

Detection is data, not code. A rule is a YAML entry; adding one means editing a
file, not touching the engine. That is deliberate — an investigator who knows
what an attack looks like should not have to know Python to say so, and a rule
pack can be reviewed, diffed and versioned by someone who will never read
`engine.py`.

The packs that ship are in `src/logarc/detect/rulepacks/`. They are ordinary
input to the loader: yours work the same way.

```bash
logarc analyze  --case ./case-001 --ip 203.0.113.45 --rules ./my-rules.yaml
logarc evidence --case ./case-001 --ip 203.0.113.45 --rules ./my-rules.yaml
logarc export   --case ./case-001 --ip 203.0.113.45 --rules ./my-rules.yaml -o report.html
```

`--rules` takes a file or a directory, and repeats. Rules apply at *analysis*
time, not at ingest — a case stores events, and the same events can be re-read
against a better ruleset tomorrow without re-ingesting a gigabyte. Extra packs
add to the bundled ones rather than replacing them, so writing one rule about
your own application does not silently drop OWASP coverage.

## The shape of a pack

```yaml
version: 1
rules:
  - id: sqli_union_probe
    name: SQL injection probe (UNION)
    category: injection
    severity: high
    owasp: "A03:2021"
    confidence: 0.9
    references: ["CAPEC-66"]
    match:
      any:
        - {field: query_decoded, regex: "union[\\s/*]+select"}
        - {field: path_decoded, regex: "union[\\s/*]+select"}
```

`id` must be unique across every loaded pack. The loader refuses a duplicate
rather than letting the later one win, because which pack was loaded first is
not something a report should depend on.

`category` decides which episode a request joins, so it is the field that shapes
the graph. `severity` decides the colour and, on a tie, which label wins.
`confidence` is recorded but does not currently affect ranking.

## Two kinds of rule

### Signature rules — one request is enough

Use a signature rule when a single line is damning on its own. `match` takes
`any` (or) or `all` (and), never both.

```yaml
  - id: shellshock_probe
    name: Shellshock probe
    category: injection
    severity: critical
    owasp: "A03:2021"
    match:
      all:
        - {field: user_agent, contains: "() {"}
        - {field: user_agent, regex: "(curl|wget|bash|/bin/)"}
```

A condition takes **exactly one** predicate: `regex`, `contains`, `equals`,
`any_of`, `min` or `max`. Two in one condition is a load error rather than a
silent choice between them.

Fields available to `field`:

| Raw | Normalised | Numeric |
|---|---|---|
| `method`, `path`, `query`, `target`, `referer`, `user_agent`, `protocol`, `host`, `extension` | `path_decoded`, `query_decoded`, `target_decoded`, `referer_decoded`, `user_agent_decoded` | `status`, `bytes_sent`, `decode_depth` |

**Match the decoded field unless you mean not to.** `%2553ELECT` is `%53ELECT`
after one decode pass and `SELECT` after two; a rule against the raw `query`
sees none of that. The raw forms are kept so a rule can deliberately target what
was literally sent — `decode_depth` above 1 is itself worth a rule, since
double-encoding is not something a browser does by accident.

Regexes are compiled case-insensitively, once at load time.

### Window rules — one request tells you nothing

Twenty 404s in a minute is enumeration. Any one of them is a missing page. That
distinction cannot be drawn from a single line, so it needs a window.

```yaml
  - id: directory_enumeration
    name: Directory enumeration
    category: recon
    severity: medium
    owasp: "A01:2021"
    member:
      all:
        - {field: status, min: 404}
        - {field: status, max: 410}
    window:
      span_seconds: 60
      min_requests: 20
      conditions:
        - {metric: distinct_paths, op: ">=", value: 15}
        - {metric: not_found_ratio, op: ">=", value: 0.7}
```

Metrics: `request_count`, `distinct_paths`, `not_found_ratio`,
`client_error_ratio`, `server_error_ratio`, `success_ratio`,
`distinct_statuses`, `requests_per_second`. Operators: `>=`, `>`, `<=`, `<`,
`==`, `!=`.

**`member` is the part that is easy to get wrong.** Without it a window is just
a span of time, so a burst of 404s next to a stretch of ordinary browsing
produces a window straddling both — and labels the browsing as enumeration. With
it, the metrics are computed over matching requests only and only those are
labelled. The window then describes a behaviour rather than a period.

Getting `member` wrong is not hypothetical. `directory_enumeration` originally
matched `status 400–499`, which swept up the 401s and 403s that are an access
control failure being *refused*. Recall for access control was 0.000 over 2,097
requests while lenient recall was 1.000 — the rule was firing every time and
being outranked every time. Narrowing the members to 404–410 moved overall
accuracy from 0.919 to 0.973. See [evaluation.md](evaluation.md).

## Write the test first

Every rule is a claim about traffic, and an untested claim is a guess. The packs
are covered by `tests/detect/test_rulepacks.py`, which supplies an `engine`
fixture and a `request()` helper:

```python
def test_my_probe_is_detected(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events([request("/x?id=1'%20OR%20'1'='1")])

    assert "house_sqli_probe" in [label.rule_id for label in labelled.all_labels]
```

Then the half people skip, which is the half that matters:

```python
def test_an_ordinary_search_is_not_flagged(engine: RuleEngine) -> None:
    (labelled,) = engine.label_events([request("/search?q=or+1+products")])

    assert not [
        label for label in labelled.all_labels
        if label.category is ActivityCategory.INJECTION
    ]
```

A rule that fires on real traffic is worse than a rule that misses. A missed
attack leaves the investigator where they started; a false positive sends them
to write up something that never happened, and enough of them make the whole
report untrustworthy. The measured results report **zero false positives across
240,000 requests** — that number is the thing a new rule most easily breaks.

Run the rule pack tests, then check nothing else moved:

```bash
pytest tests/detect -q
logarc generate -s mixed -n 40000 -o sample.log -t sample.truth.jsonl
logarc ingest sample.log --case ./case-check
logarc evaluate --case ./case-check --truth sample.truth.jsonl
```

## How a request gets its label

When several rules match one request, the highest severity becomes the primary
label and the rest are kept. They are not discarded: `AnalysisResult.assignments`
carries every match, so a rule that fired and lost is distinguishable from a
rule that never fired at all. That distinction is what `recall_any` measures in
the evaluation, and it is the difference between "the rule is wrong" and "the
ranking is wrong" — two problems with different fixes.

A request matching nothing falls to a benign classification from its extension,
status and method. Benign is a real answer here, not an absence of one: an
episode of ordinary browsing between two attack episodes is what the noise
absorption rule needs in order to decide whether they are one act or two.

## Which ruleset produced a finding

Every reconstruction carries a `ruleset_fingerprint`, derived from the rules
that were loaded, and the HTML report prints it under Provenance. Add a rule and
re-run, and the fingerprint moves — so two reports about the same client cannot
silently claim the same provenance while disagreeing about what happened.

That is the property to preserve when extending detection. A finding that cannot
be tied back to the rules that produced it is not reproducible, and a
reconstruction is only worth as much as its ability to be checked.
