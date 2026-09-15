# Changelog

Notable changes to logarc. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **PHP detection goes from 15% to 68% against the OWASP CRS corpus, with no new false alarms.**
  Thirteen rules covering the shapes that were getting through: the open tag in all its forms
  (`<?php`, `<?=`, `<?`, `[php]`, `{php}`), superglobals and `${}` interpolation, function calls
  with every separator the corpus evades through, stream wrappers, configuration directives and
  serialised objects.

  Every family rises with it, because a PHP pattern in a parameter is a PHP pattern whatever the
  server runs — RFI 21% to 45%, XSS 18% to 35%, generic 15% to 17%, RCE 8% to 9%. Across all nine
  families, matches on the 134 requests CRS certifies as harmless go from **1 to 0**; on 3,825
  lines of real shopfront traffic, nothing moves at all.

  The rules were written against the corpus's false-positive tests as much as its attacks. PHP
  named its functions after ordinary words, so `executor()` is not `exec`, `ecosystem()` is not
  `system`, `exec (` is a truncated string while `pi()` is a real call, and `<?xml` is not a short
  tag.

- **Rule packs now describe ordinary use, not only attacks.** A new `action/` tree names what a
  client *did*: Checkout, Modify Cart, Payment, Sign In, Password Reset, Order History, Search,
  File Upload. `POST /checkout` was previously reported as "Non-idempotent Request", which names
  the HTTP verb and tells a reader nothing.

  "Which of these addresses was a customer?" is the question a person actually asks of a log with
  fifty thousand clients in it, and no attack rule can answer it. On the labelled shopfront
  excerpt this *improves* classification — accuracy 0.9307 to 0.9310, macro F1 0.8404 to 0.8436,
  authentication F1 0.96 to **1.00** — while attack detection is untouched.

  Action rules are `severity: info`, and a hostile label now outranks a benign one at equal
  severity whatever its confidence: a `curl` request to `/cart` is still reported as a scripted
  client rather than as a cart view.

- **`logarc score-crs` scores this project's rules against a corpus somebody else wrote.** Until
  now every number the detection layer produced came from payloads its own author chose — rules
  marking their own homework. This runs them against the OWASP CRS regression suite: a question
  paper written for a different tool, years before this project existed.

  **The corpus was never missing.** It has been in the repository the whole time at
  `vendor/coreruleset/tests/regression/`, carried in with the ruleset clone. What was missing was
  anything that could read it, and ADR-0008 — which retired the old `score-crs` — is amended rather
  than contradicted: that one scored *CRS's* rules with *CRS's* corpus, which is the objection, and
  reversing the direction reverses the objection.

  Counting a case as caught when *any* hostile rule fires:

  | Family | Cases | Should match | Caught | Recall | Should not | Fired wrongly |
  |---|---:|---:|---:|---:|---:|---:|
  | 933 PHP | 429 | 184 | 28 | **15%** | 38 | 0 |
  | 932 RCE | 1,006 | 406 | 33 | **8%** | 64 | 0 |
  | 941 XSS | 263 | 72 | 13 | **18%** | 4 | 0 |
  | 942 SQLi | 1,033 | 135 | 31 | **23%** | 12 | 0 |

  SQLi and XSS have had rules for months and sit beside PHP, whose rules are days old — so this
  measures the pack, not one afternoon's work.

  **The corpus asks three questions and only two of them are ours.** `expect_ids` is an attack, and
  it is the recall denominator. A `no_expect_ids` case CRS describes as a false positive is traffic
  it certifies as harmless — `firstname.dockery@host.tld`, `a timeless cinematic icon` — and that is
  the second denominator, the one that stops a pack scoring well by matching everything. But
  `no_expect_ids` on its own names *CRS rule IDs*, not traffic: one such case is
  `system('echo cd /tmp;wget …;rm -rf')`, an attack marked so that rule 932230 stays out of another
  rule's way. logarc has no mapping onto CRS rule numbers, so 469 cases like it are counted, named
  and scored in neither column.

  Across every family, **one** false alarm in 134 certified-benign cases: `template_injection` on a
  bare ERB output tag, which CRS holds is legitimate unless the tag evaluates something.

  **Recall is over what a log can see, never over everything.** 2,650 cases put their payload in a
  body or a header a combined log never writes, and those are counted apart: scoring them would
  measure the log format and publish it as a score for the rules. The command prints that number
  too, and prints the requests that got through, because a bare percentage says a pack is weak
  while the misses say how.

  **These figures replace a first run that was wrong.** It read every case as an attack, so the
  quarter of the corpus that must *not* match was counted as misses — publishing 11%, 8%, 13% and
  17% for the four families above. The tool's own standard is that a number which looks like a
  result and is not one is the worst thing it can emit, and that applies to its own scoreboard.

- **The evaluation's own numbers are now committed and checked on every run.**
  `tests/data/apache-shopfront/excerpt.scores.json` holds the complete scoring output for the
  committed 3,825-line excerpt, beside the log and the truth it came from, and a test re-runs the
  whole chain — ingest, evaluate, compare — against it.

  The comparison is exact and covers the whole file. Every rule change moves a number, so every
  rule change now fails that test and has to update the fixture out loud. That is the gate that
  was missing: the episode builder changed on 25 August, nobody re-ran the evaluation, and a
  boundary recall of 0.98 stayed published for weeks while the tool scored 0.27. Proved armed by
  moving one rule threshold, which fails it with the regeneration command in the message.

  Only this corpus, and it is the one a fresh clone already has. The two pinned dataset builds are
  22 MB and 80 MB and stay out of the repository, so their tables remain re-derivable only with the
  download.

- **Ingest uses the machine's cores without being asked.** `--workers` has existed for a while and
  defaulted to one, so almost nobody used it. It now defaults to the cores available, capped at
  four. On the 84 MB log below that is 2.6x faster out of the box.

  **The cap is the measurement, not a guess.** Taken on an 84 MB log, four physical cores behind
  eight logical, polling RSS across the whole process tree:

  | workers | speed-up | peak RSS | memory vs 1 |
  |---:|---:|---:|---:|
  | 1 | 1.00x | 326 MB | 1.00x |
  | 2 | 1.86x | 603 MB | 1.85x |
  | 3 | 2.35x | 815 MB | 2.50x |
  | **4** | **2.61x** | **969 MB** | **2.98x** |
  | 6 | 2.75x | 1,339 MB | 4.11x |
  | 8 | 2.68x | 1,448 MB | 4.45x |

  Throughput peaks at six and **falls at eight**, so one worker per logical core is slower as well
  as hungrier — hyperthreading does not help work already saturating the arithmetic units. And
  memory grows faster than speed at every step: four buys 2.61x for 2.98x the memory, and going on
  to six buys 5% more speed for 38% more memory.

  Four is where the curve flattens — 95% of the best speed measured, for under a gigabyte. It is a
  **cap rather than a ratio** because the memory is the user's to spend and has to stay
  predictable: a sixty-four-core server must not start sixty-four workers and ask for twenty
  gigabytes to read a log one process could have read. `--workers 1` returns to a single process,
  and a log under 32 MB or a compressed one is still read sequentially whatever is asked for.

### Detection

- **PHP has rules of its own for the first time.** Every `php` in either pack was a filename
  pattern; nothing looked at the language. Against the CRS regression corpus family 933 scored
  **0.012 over 173 cases**, and the two that matched did so through a reconnaissance rule catching
  a path — `docs/evaluation.md` calls that "a hole, not a framing artefact".

  Four rules, covering what an access log can actually see in a parameter: `php_stream_wrapper`
  (`php://filter`, `php://input`, `data:`, `phar:` — reading a file the application never meant to
  serve, or feeding it code outright), `remote_file_inclusion` (a URL on a parameter named like it
  will be included), `php_code_execution` (`system`, `shell_exec`, `passthru`, `eval` and the rest)
  and `php_object_injection` (a serialised object reaching `unserialize`). Nine payload shapes that
  reached the pack as **nothing at all** are now caught.

  `command_injection` also gained two shapes it was missing: a newline before a command, and brace
  expansion (`{cat,/etc/passwd}`, which needs no space and so slips a filter looking for one). Both
  were previously caught only when the payload happened to name a well-known file — the filename
  was doing the work, not the injection. The newline one matches the **raw** target, because
  `normalize` collapses every run of whitespace to a single space and the evidence that it was a
  newline survives only in the encoding.

  **Measured cost on the committed excerpt: none at all.** The scores gate reports exactly one
  change across the whole evaluation — the ruleset fingerprint. Every category, count and ratio is
  identical, so none of these fires on any of its 3,825 real requests. What the corpus cannot say
  is what they are worth, and the honest answer is that it will not say until there is a corpus
  that can score them. They are committed for the logs this one does not contain.

- **Template injection past the arithmetic probe.** `template_injection` matched `{{7*7}}` and
  `${7*7}` and nothing else — which is how an attacker *finds* the hole, not what they send once
  they have it. Four of the seven standard payload shapes were passing every signature, including
  `{{''.__class__.__mro__[1].__subclasses__()}}`, the most-used server-side template RCE payload
  there is. Now covered: Python's object graph, Jinja2's globals, any call inside `{{ }}`, ERB and
  JSP scriptlets, `#{ }`, and the Java runtime a Freemarker or Spring EL payload reaches for.

  **This buys almost nothing on the corpus and is worth having anyway** — accuracy 0.930 → 0.931,
  because the one such request in the excerpt was already being caught under a different label.
  The gain is coverage for logs this corpus does not contain.

  **The first draft of it was a denial of service.** Written as `\{\{[^}]{0,200}(…)`, it cost
  **53 ms on a single 8 KB request line** of repeated `{{` — linear, but a 1,500x per-line tax that
  a crafted log could apply to every line it holds, which `SECURITY.md` names as in scope. Two
  changes fixed it: the distinctive literals are matched bare, so the engine can use a fast literal
  search instead of scanning from every brace, and the remaining bounded scans are 64 rather than
  200. Worst case is now 1.2 ms, and `runtime.` and `getclass` were dropped rather than anchored —
  bare, `runtime.` matches the `runtime.js` half the bundlers on earth emit. Measured cost on
  ordinary traffic: labelling went 232.9 to 239.8 µs per request, **+2.9%**, median of seven runs
  of 500.

- **A credential attack the server locks out is still a credential attack.** `credential_attack`
  wanted ten failed logins inside five minutes. The excerpt's server rate-limits a login after
  six, so the attacker stops at six and comes back hours later — and a rule counting to ten could
  never fire against a server that defends itself sooner than the rule counts. 13 requests reached
  the report as a scripted client rather than as part of the attack they belonged to.

  The floor is now five, which is the count almost every authentication system already uses to lock
  an account: the point at which failures stop looking like a forgotten password. Measured on the
  excerpt, no client other than the attacker has more than *one* failed login in any window, so
  nothing was paid for it — but the number is chosen for being defensible in general, not for what
  this log happens to contain, and a test pins that two fumbled passwords are still not an attack.

  `credential_attack` recall 0.667 → **0.974**, precision unchanged at **1.000**. Macro F1 0.825 →
  0.840, accuracy 0.927 → 0.930.

- **sqlmap's default boolean-blind series is no longer invisible.** Four of the five payload shapes
  a default `sqlmap` run sends were reaching the rules as *nothing at all*, while the `UNION ALL
  SELECT` payloads from the same scan were caught — so a case showed an attack's conclusion and
  none of its working.

  `sqli_tautology` required the comparison to end at a comment or at the end of the string, which
  is the right guard and was the only part worth keeping strict. Everything before it was too
  narrow: sqlmap wraps the comparison in parentheses (`oak')) AND 5481=5481 AND (('SUiH'='SUiH`),
  compares with `LIKE` rather than `=`, and leaves a `%` inside the quoted operand
  (`'ZxzJ%'='ZxzJ`). All three now match. New rule `sqli_column_count` covers `ORDER BY n--`, the
  step between finding an injection point and building a UNION to fit it. `sqli_time_based` gained
  `randomblob(`, which is what sqlmap falls back to when `sleep()` is unavailable — a timing oracle
  built from expensive work, and a small denial of service in its own right.

  Measured on the committed excerpt: `injection` recall 0.684 → **0.877** with precision unchanged
  at **1.000**, and `reconnaissance` precision rose 0.822 → 0.836 as those requests moved to where
  they belonged. Accuracy 0.924 → 0.927, macro F1 0.815 → 0.825, false alarms unchanged at 0.765%.
  Every broadened pattern was timed against adversarial input first and is linear.

- **A probe for software the site does not run is now enumeration.** New rule
  `known_software_probe`: a path naming software by that software's own convention —
  `/wp-admin/`, `/phpmyadmin/`, `/administrator/`, `/xmlrpc.php`, `/vendor/phpunit/...` — answered
  404 or 410, from a client that sent a User-Agent. One request is enough, which is why it is a
  signature rule and not another window: the scanner in the committed excerpt asks for four to six
  of these, waits hours, and asks again, so `directory_enumeration_low_slow` — which wants eight —
  never fired. 92 requests the truth calls enumeration were reaching the report as ordinary
  browsing.

  Measured on the committed excerpt: `enumeration` recall 0.629 → **0.843** with precision rising
  0.975 → **0.981**, `browsing` precision 0.394 → **0.535**, accuracy 0.900 → **0.924**, and 92
  fewer attacks missed (179 → 87) with false alarms unchanged at 0.765%. Reconnaissance is
  untouched at precision 0.822 and recall 0.866.

  **The cost, recorded rather than restated: boundary F1 fell 0.642 → 0.619.** More hostile labels
  cut more episodes — 567 became 595, against 297 activities in the truth. Boundary recall held at
  0.996, so nothing was lost; the cuts are finer than the truth draws them.

  Two conditions carry the whole rule and both are tested. The status condition is what makes it
  defensible at all: `/wp-admin/` answered 200 is a WordPress site's own administrator, and only a
  404 means the software is not there. The User-Agent condition keeps it from outranking
  `absent_user_agent`: the same paths appear in the excerpt from a client sending no User-Agent at
  all, which the truth calls reconnaissance, and which was already being read correctly. `.env` and
  `.git/` are deliberately excluded for the same reason — `config_file_exposure` has them, and the
  truth agrees.

### Documentation

- **The enumeration/reconnaissance confusion is partly structural, and the document now says so.**
  It had been recorded as "a rule question". Measured on the committed excerpt, the truth labels a
  request by which campaign sent it rather than by what the request is, and the campaigns' path
  sets overlap: 70 of 444 distinct `(path, status)` pairs carry more than one truth category,
  covering 37.5% of scored requests. `GET /backup.zip` answered 404 is enumeration from a client
  forging a User-Agent and reconnaissance from one sending none — the same request line. No rule
  reading only the request line can be right on both sides. Most of it is already resolved by the
  User-Agent, which is why `crawling` scores precision 1.000; the residual is deliberately not
  chased, because closing it would mean encoding the dataset's own convention as a security rule.
- **The 100,000 lines/s ingest target is retired**, and `docs/evaluation.md` says so where the
  measurement is. It named a rate without naming the hardware, so it could be cited but never
  passed or failed; and lines per second moved on its own when the corpus changed to real logs
  with longer lines, while megabytes per second held. What is kept in its place is throughput
  reported with its hardware in both units, and one claim that does have a pass and a fail in
  it — reconstruction cost per request staying flat as the corpus grows, 214.5 µs against
  209.3 µs over a 2.4x corpus, which is the O(k) claim the two-pass architecture makes.
- **`docs/adr/` has an index**, carrying each record's status: which decisions still hold, that
  0005's corpus decision was superseded by 0011, and that 0007's scoring tooling was removed
  after the measurement was taken. A filename cannot say any of that, and these records are never
  renamed.

### Security

- **A line is now bounded before it is parsed** (`--max-line-bytes`, default 1 MB). Parsing one
  costs about **327 times its own length in memory** — measured 5.5 GB for a 16 MB line and 20.9 GB
  for a 64 MB one. The parse is linear; the multiplier is simply very large. Nothing bounded the
  line, and nothing bounds the gzip ratio that delivers it either: 31.9 KB of gzip expanded to a
  32 MB line in the same audit, a factor of 1,028.

  Composed, that was a denial of service from a file small enough to email. Measured end to end: a
  **63.9 KB archive** holding one 67 MB line went from **20.9 GB and 168 s** to **201 MB and
  0.44 s**. The remaining 201 MB is reading the line, which is still unbounded and roughly 3x its
  length; the 327x multiplier was the part worth closing.

  The over-long line is **quarantined with its length**, not dropped, so the case still accounts
  for every line. The bound is applied in two places — the sequential loop and the worker loop,
  which does not call `ingest_file` — and in the detection sample, which is scored against every
  registered parser before the log's real format is even chosen. A test pins each.

  A megabyte is about 120 times the longest line Apache will write, so no real log reaches it.

### Changed

- **Detection no longer raises a false alarm on the measured log, and catches more than before.**
  Attack-or-not precision **0.982 → 1.000**, recall **0.928 → 0.943**, false alarms **20 → 0**
  (0.765% of ordinary traffic → nothing). Classification accuracy 0.9310 → 0.9378 and
  reconnaissance F1 0.859 → 0.895 with it.

  Every one of the twenty was `Scripted Client`: the rule matched `python-requests` and filed it
  under `reconnaissance` while its own `severity: info` said it was not calling this an attack.
  Those contradict, because whether a finding counts as hostile is read from the category. The
  traffic underneath was one script fetching `/c/garden`, `/search?q=socket` and `/cart` — a
  shopper, not a scanner. A User-Agent is the cheapest field in a request to forge, so it can
  support "a program, not a person" and nothing further. It now says `crawling`.

  That cost sixteen catches, and they came back with eighteen more. Printed side by side the lost
  requests were one shape — `/`, `HEAD /`, `/LICENSE`, `/.gitignore`,
  `/.well-known/security.txt`, `/CHANGELOG.md`, mostly 404, inside a minute — which is a tool
  fingerprinting the stack before it picks an exploit. The new `project_metadata_probe` names that
  behaviour, so the same run is now caught from a browser User-Agent too, which it never was.

  `/robots.txt` and `/sitemap.xml` are deliberately not in that rule. They sit in the same place
  and look like they belong; they are fetched 47 times each in the corpus and are crawling in
  every one.

- **Rule packs are grouped by what they are about.** Two files of 32 and 9 rules become ten, in
  folders: `attack/global/` holds what presumes no technology, `attack/php.yaml` and its
  neighbours hold what only means something to one runtime, and `action/` holds ordinary use.
  `src/logarc/detect/rulepacks/README.md` explains the two axes — what a rule is about is the
  directory, what stack it presumes is the file name, and the OWASP category is neither because it
  already sits on every rule's `category:` line.

  Everything still loads at once. A PHP payload aimed at a Python backend is a PHP payload, and
  the folders are for the person editing them rather than for the engine.

- **`logarc evaluate -o` writes sorted JSON with a closing newline.** One of those files is
  committed as the drift gate and regenerated whenever a rule changes; the old writer reshuffled
  261 lines of unchanged values and buried the line that had actually moved.

### Fixed

- **Rule packs inside a folder were silently not loaded.** `load_rules` globbed one level deep,
  so a pack in a subdirectory contributed no rules and raised nothing: the engine started, the
  case analysed, and the report came out looking complete with a hole where that file's detection
  should have been. Anyone pointing `--rules` at a directory with packs organised inside it has
  been hitting this. A directory holding no packs at all is now refused for the same reason.

  **The packaging spec had the same one-level assumption**, so the first build after the packs
  were grouped would have shipped an executable with no rules in it.

- **A crafted line no longer ends a whole ingest.** A log line nested deeper than Python will
  decode — twenty thousand `[` characters will do it — raised `RecursionError` out of the JSON
  parser. That is not a `ValueError`, so it travelled untouched out through `score_parser`,
  `detect_format` and `ingest_file`, and the ingest stopped.

  It happened during **format detection**, which scores every registered parser against the sample,
  so it did not matter what kind of log the file actually was: one such line in the first 200 lines
  stopped a case being made at all. The quarantine record — which exists precisely so a line too
  damaged to read is counted rather than fatal — never saw it.

  A line this tool cannot decode is a line that is not of that format, so it is now refused like
  any other. The crafted line is quarantined and counted, and the rest of the log is read. Found by
  auditing logarc as a target rather than as an examiner; **not reachable through an ordinary
  request**, which was tested rather than assumed — a User-Agent of 8,000 `[` characters ingests
  cleanly, because an Apache line begins with the client address and `json.loads` fails at the
  first character without recursing.

- **The throughput tables said Python 3.13 and were measured on 3.12.** No 3.13 exists on the
  machine that produced them — the venv is 3.12.10, `py -0p` lists nothing else, and CI tests
  3.11 and 3.12. The version was changed in `a3743df` alongside a genuine re-measurement on the
  new corpus; the corpus changed and the interpreter did not. A later note then reasoned from the
  wrong figure, calling the older memory table "the previous interpreter" when both tables are on
  the same one. Both corrected, and what actually separates those two tables — the date, and rows
  pushed into the store rather than log lines parsed — is now what the note says.
- **The path cache's retention is recorded.** `canonical_path` memoises 8,192 entries capped by
  count rather than by bytes, and nothing clears it, so it outlives the case that filled it: 0.05
  MB on the committed excerpt, 132 MB if every path is distinct and at Apache's 8 KB request-line
  limit. Bounded, measured, and accepted at that size — but invisible to a memory table that
  measures each size in a fresh process, which is why it is now written beside one.
- **The packaged application no longer tells its reader to run `go build`.** CRS enrichment is
  unavailable in a frozen build, and the error said to build the sidecar from a `crs/` directory
  the bundle does not carry, with a toolchain it does not include. It now says what is missing,
  the two ways to get it, and that nothing else depends on it.

## [0.2.0] — 2026-09-14

### Evaluation

- **The evaluation corpus is a real server's log, and the generator is gone.** `logarc generate`
  and its scenario scripts have been removed. The headline figures are now measured on the
  BlackHat-Dataset `apache-shopfront` medium build (243,908 lines over seven days, a real Apache
  serving a real PHP shop, driven by real security tools and six reactive attack campaigns)
  with the small build as a fast check and a committed 3,825-line excerpt of it as the test
  fixture. What forced this: the generator wrote a shopper's page view, the assets it pulled in
  and its cart call as three activities, while the episode builder has drawn them as one since
  25 August. Nobody re-ran the evaluation across that change, and `docs/evaluation.md` went on
  publishing a boundary recall of 0.98 that the tool scored at 0.27. Regraining the generator
  fixed the figure but left it grading the tool against the tool's own model of an activity,
  which is the circularity ADR-0005 warned about. See ADR-0011.
- **`logarc benchmark` measures a log it is given** (`--log`, with `--lines` for prefixes)
  rather than generating one, and refuses a size the log cannot supply instead of quietly
  measuring a shorter run.
- **`docs/evaluation.md` re-measured**, every table, on the pinned dataset builds with CRS
  enrichment at paranoia level 2 as the notes require, and the CRS revision recorded beside the
  figures. The headline numbers are lower than the generated ones; that is the first honest
  measurement, not a regression. The dataset's truth cuts episodes at a finer grain than the
  tool draws: of the 2,738 cuts it makes between ordinary requests, 152 fall inside the episode
  gap, and the tool misses 114 of those, 89% of every boundary the headline run misses. Recorded
  rather than adjusted for.
- **The builds are pinned by SHA-256, not versioned.** They are 22 MB and 80 MB and are not in
  the repository; `samples/README.md` says how to get or rebuild one. A rebuild at the same seed
  reproduces the plan of requests but not the bytes, because the campaigns react to a live
  server, so a rebuilt corpus scores close rather than identically.

### Log formats

- **Write your own log format, and keep it.** logarc read three Apache presets and had no way to
  add a fourth: the extension point existed in `parsers/registry.py` from the beginning and nothing
  could reach it. The window passed no format at all, so every ingest from the interface was
  auto-detected; the CLI's `--format` took a name and the only names were the three built-ins; and
  `logarc formats` printed that a custom directive "is supported by passing its directive string",
  which nothing accepted. A site running its own `LogFormat` could not use the tool.

  A format is now a definition rather than a name, and it travels with the work — into the ingest
  workers, and into the case. `logarc formats add`, `remove`, `show` and `check` write and try one
  from the command line; **Case → Log formats…** does the same in the window, reading a pasted log
  line back field by field as the directive is typed. Saved formats live in a plain JSON file you
  own, are offered wherever the built-ins are, and take part in auto-detection — a log in a format
  you wrote is now recognised without `--format` at all.

  `logarc formats check` exists because a wrong directive does not announce itself: it quarantines
  every line and presents as an empty case, which the quarantine notice already calls this tool's
  worst failure mode. Point it at the log and read the fields before saving anything.
- **A case outlives the format that read it.** `case.json` recorded a format's *name*, and
  `evidence._parser_for` had always returned `None` when a name no longer resolved — a docstring
  anticipating the day a case outlived the thing that read it. Letting readers edit and delete
  formats is that day, so each source now records the definition it was ingested with. Editing or
  deleting a saved format cannot make an existing case unreadable, and a case whose format has
  since changed says so on a strip that shows both definitions. A `case.json` written before this
  field existed still loads, unchanged.
  See [ADR-0010](docs/adr/0010-a-log-format-is-data-that-travels-with-the-work.md).
- **Fourteen formats ship, where three did.** Apache's three, plus `apache-combined-io`,
  `apache-vhost-common` and `nginx-combined-forwarded`; `nginx-json`, `caddy-json`,
  `traefik-json`, `cloudflare-json`, `gcp-http-json` and `ecs-http`; `iis-w3c` and `cloudfront`.
  Each has a real line of the log it is named for in `tests/parsers/test_builtins.py`, and a test
  that reading that line yields the right client, path and status — a built-in that does not read
  the logs it is named for is worse than an absent one, because absent the reader writes their own
  and wrong they get a case that looks complete.

  A second test asks more: that each is the format **auto-detection picks** for its own log.
  Reading it is not enough with fourteen candidates; one that reads its log and loses to another
  is one nobody will ever see used. That test found three real defects. Caddy writes
  `"User-Agent": ["curl/8.4.0"]` and the value reached the evidence table as `['curl/8.4.0']`,
  brackets and all, so a one-element list is now unwrapped. Scoring counted a W3C log's four
  header directives as lines the parser failed to read, which put `iis-w3c` far below the
  threshold on its own logs — scoring now skips what a format calls its own bookkeeping, as ingest
  already did. And an nginx forwarded line satisfies `apache-combined-io` as well, because io's
  two trailing counts are bare fields that match a quoted address and a duration, so the order was
  wrong.

  `logarc formats` now lists what each format *reads* rather than its definition. With three the
  definitions fitted; with fourteen they are a wall of mappings nine lines deep, and a list exists
  to help someone pick. `logarc formats show <name>` prints the definition.

  Not included, deliberately: AWS ALB, Envoy and HAProxy, which write the client as
  `address:port`. Stripping the port is not safe without deciding what to do about IPv6, where the
  colons are part of the address, and a wrong answer turns every connection from one client into a
  client of its own.
- **A log nothing else can read is readable by a regular expression you write.** The fourth and
    last kind, for a syslog-wrapped line, an appliance with a syntax of its own, a load balancer
    that agrees with nobody. Also the simplest: **the named groups are the mapping**, so
    `(?P<client_ip>\S+)` is the client address and there is nothing else to configure. A group
    logarc does not recognise is kept beside the event as evidence.

  ```bash
  logarc formats check-pattern '^(?P<timestamp>\S+) (?P<client_ip>\S+) …' --log proxy.log
  logarc formats add-pattern gw-proxy '…' --time-format '%Y %b %d %H:%M:%S'
  ```

  **Anchored at the start of the line**, after measuring what happens otherwise:
  `(?P<timestamp>\d+) (?P<client_ip>\S+)` searched anywhere found `1 09:00:45` inside
  `May  1 09:00:45 gw01 proxy…`, read the `1` as one second past the epoch, and produced events
  dated 1970 that nothing downstream would have questioned. A pattern describes the line; a reader
  who means to skip a prefix says so with `.*`.
- **Two things a timestamp cannot be.** A time format naming no year is refused when it is
  written — `%b %d %H:%M:%S` has `strptime` supply 1900, so every event of the log lands there
  together and a report reads "the attack occurred on 1 May 1900". And a number below 1e8 seconds
  (March 1973, before any web server) is not read as an epoch at all: below that it is a field
  somebody misidentified as the time. Both were found by looking at a screen showing the answer,
  not by a test.
- **A log laid out as a table is readable: IIS W3C, and CSV.** The third kind, and the one that
  brought a problem the first two did not have — **the file declares its own columns**. A W3C log
  opens with `#Fields: date time c-ip …`, and a CSV often names its columns in the first row, so
  the definition a reader saves is not the whole answer.

  It is settled by resolving the format against the file's opening lines before anything reads it,
  in the process that opened the file. What travels to an ingest worker and into the case is the
  resolved definition, with the columns it actually found written down: a worker handed a byte
  range has never seen the header, and a case recording "the columns are in the file" would depend
  a year later on a file nobody kept. The saved format keeps no columns at all, because IIS writes
  different fields on different servers and one that froze a server's columns would read only that
  server's logs.

  ```bash
  logarc formats check-columns --log u_ex240501.log      # its own header, and what it reads
  logarc formats add-columns iis --log u_ex240501.log
  logarc formats add-columns edge --log edge.csv --separator comma
  ```

  W3C's habit of writing the date and the time in separate columns is spelled `date+time`, and
  guessed. The log's own bookkeeping — the four directives that open every IIS file, a CSV header
  row — is neither parsed nor quarantined, which needed a new question in the `LogParser`
  contract: quarantining them would have put a "lines could not be parsed" strip over every such
  case, and that notice exists to mean something went wrong.

  A row whose column count does not match is refused rather than read. That is also what a log
  which redeclares its fields part-way through does — W3C permits it and this cannot follow — so
  such a log quarantines from that point rather than being misread from it: read by position
  against the wrong count, every field after the missing one is somebody else's value.
- **A log that writes one JSON object per line is readable.** The second kind of format, and
  the one that says whether the record shape was general enough — it works the other way round
  from a `LogFormat` directive, matching names rather than positions.

  A JSON log does not say which of its keys is the client address, so a format of this kind is a
  mapping. `logarc formats check-json --log gateway.jsonl` proposes one from the first line and
  shows what it reads; `logarc formats add-json` saves it, and `--map ours=theirs` corrects any
  field without writing out the rest. In the window, **New JSON format…** shows the mapping beside
  what it read, so the rule and its result are one glance apart.

  Guessing is worth doing here and is not worth doing for a positional format: JSON keys are
  self-describing where `%h` and `%v` are not. Nested paths are read (`client.ip`), and a path
  whose leaf names a shape rather than a field — `user_agent.original`, as ECS and everything
  copying it writes — is matched on its parent. A key nothing recognises is left out rather than
  guessed at, and the proposal is always shown before it is saved: a wrong guess is worse than
  none, because the reader accepts it and finds out at ingest.

  ISO timestamps, epoch seconds, milliseconds and microseconds are told apart without being
  configured — read as seconds, a millisecond stamp lands in the year 56,000 and sorts last for
  ever without anything downstream questioning it.
- **A log with a timestamp of its own is readable at last.** `%{%Y-%m-%dT%H:%M:%S%z}t` was
  refused as an unsupported directive. The compiler had carried a branch for it from the
  beginning — with a comment giving `%{%Y-%m-%d}t` as its example, and a timestamp fallback written
  for ISO-8601 input that could not arrive — and the branch was unreachable: `t` was missing from
  the table the directive was looked up in, so every `%{...}t` was refused two lines earlier.

  Found by using the format library on a log from an appliance that writes ISO timestamps, which is
  a large class of logs and was entirely shut out. The pattern the field is matched against is now
  built from the strftime format and parsed back with the same one, so the two cannot disagree, and
  a format containing a space (`%{%d/%b/%Y %H:%M:%S}t`) works — matching it as one non-blank run
  would stop at the space and hand the rest of the line to the next field. Apache's own named time
  tokens (`%{sec}t`, `%{begin:...}t`) are refused by name rather than misread as strftime. The
  plain `%t` keeps its hand-sliced CLF fast path.
- **Corrected: nginx `log_format` definitions were never supported.** The compiler's docstring
  claimed it handled "most nginx `log_format` definitions too". Measured: one is rejected outright
  with `no directives found`. What is true is that nginx's default *output* is byte-identical to
  Apache's `combined` and is read by `apache-combined` at confidence 1.0 — reading an nginx log
  works, pasting an nginx format definition does not. A custom nginx format has to be rewritten as
  the equivalent Apache directive.

### Interface

- **Type an address to find one client among tens of thousands.** A filter box above the client
  list, always visible rather than behind a keystroke — a control nobody can find is a control that
  is not there. A complete address matches exactly, because substring matching answered
  `203.0.3.9` with eleven rows: `203.0.3.90` through `.99` all contain it, and an investigator
  copying an address out of a ticket could open the wrong one. Anything shorter stays a search, so
  `203.0.3.` isolates a /24 and `113.66` finds a remembered tail. Every filtered caption names the
  total — a narrowed list reading `9 clients` describes a case with nine clients in it — and an
  empty result says which filter emptied it rather than leaving a blank table.
- **A case you have opened before is one click away.** Opening the window puts
  the list in front of you — **View → Reopen the last case on start** skips it
  and goes straight to the case you were in — and **Case → Recently opened…**
  (Ctrl+Shift+O) brings it back at any time.
  Right-click a row to **pin** it, **rename it in this list**, show its folder,
  or drop just that one. A pinned case holds the top and is exempt from the
  ten-entry cap, so a busy week cannot push it off the end. A rename is a name
  for *this list*: `case.json` is untouched, because the case id is printed in
  the provenance table of every exported report and renaming the case itself
  would leave a report written yesterday and one written today disagreeing about
  what the same case is called. The folder column still shows what it really is.
  Reopening a case keeps whatever pin and name the list already held for it —
  the snapshot read off disk knows about neither. Reopening yesterday's work
  meant navigating a folder dialog to a path you had to remember. The last case
  now reopens with the window — **View → Reopen the last case on start** turns
  that off — and **Case → Recently opened…** (Ctrl+Shift+O) offers the rest as a
  table: when each was opened, how many events it holds, which log it was built
  from, and which folder it is. A submenu was drawn first and rejected against
  it: two cases named `case-001` and `case-002` are not told apart by a name.
  A case whose folder has moved stays listed, says so, and cannot be chosen —
  offering it would send the reader into a failure the list already knew about.
  A case is recorded only once it has opened, so the list never fills with
  entries that lead nowhere.
  **This is the first thing logarc stores that records what was investigated**
  rather than how the window looked doing it: the folders, and when they were
  opened, under `HKCU\Software\logarc`. The chooser carries **Forget these**,
  and the README says what is kept.
- **A long trace wraps instead of running off the canvas.** Laid out on one row
  it was as wide as it was long and barely taller than a node, so fitting it
  shrank the scene to 0.64 on seven episodes and 0.15 on thirty — correct, and
  no longer legible. Rows now wrap and alternate direction; seven episodes fit
  at 1.16 and thirty at 0.75. Short traces keep their straight line.
  See [ADR-0009](docs/adr/0009-parallel-ingest-rather-than-a-native-parser.md)'s
  neighbour, and the numbers in the commit.
- **The side panels could not be resized at all.** The key added below the
  canvas was one unbroken row and reported a minimum width of **1,729px** —
  wider than the window it sat in. A minimum is a demand, so the centre column
  inherited it and both side panels were pinned at their own minimums to pay for
  it; with no slack anywhere, a splitter handle had nothing to give. Measured on
  the client panel: **one** reachable width, or zero if collapsed. Dragging it
  therefore did nothing until it jumped the whole way.
  The key now wraps onto as many rows as it needs (107px minimum, 23 reachable
  widths on the same panel), extra width goes to the graph rather than being
  shared out, and panels no longer collapse to an invisible handle against the
  window edge. The 430px floor put on the client table to stop its columns
  hiding is gone — it was the wrong tool, and it was half of what wedged this.
- **The evidence is a sortable table.** One row per request — source, time,
  the request, status, size — with the selected row shown in full beneath it.
  Twenty-five pieces of evidence were 175 rows of wrapped text readable only in
  the order they arrived; they are twenty-five rows now, and can be **sorted by
  size to find the request that got data out** or by status to find what was
  served rather than refused. Those are the two questions a blue team asks of an
  episode and neither could be answered before without reading every line.
  The detail pane carries the whole payload, the agent at full length, and the
  source line **exactly as the log holds it** — so nothing is summarised away,
  only moved to where there is room for it. `View → Show raw log lines` is
  retired: the pane shows the original for the selected row always, which is
  strictly more than a global on-or-off could give.
- **Both tables were showing raw numbers in place of their formatted values.**
  Qt keeps `DisplayRole` and `EditRole` in one slot on a table item, so a sort
  key written to `EditRole` replaces the text. The client list has shown
  `0.8888888888888888` where it formats `89%` since it was written — in the
  column an investigator sorts by when looking for something worth opening. The
  key now lives in a role of its own, in one shared item both tables use.
- **The evidence panel showed everything except the evidence.** It printed the
  raw source line and nothing else. A Combined line is 293 characters, of which
  **53% is the user agent** and 15% is the client address and timestamp already
  printed in the heading above — leaving **15% carrying the whole finding**, and
  that 15% written as `%27+OR+%271%27%3D%271`. Unwrapped in a ~330px panel every
  line ended at `"GET` with the payload off the right-hand edge; six pieces of
  proof on screen and not one of them showed any.
  Each piece of evidence is now laid out as the request it was — target, status,
  size, referer, agent — **parsed by the same parser that ingested the file**,
  so what is shown is what the detection actually ran against rather than a
  second reading that could disagree with it. nginx, IIS and JSON cases get this
  for nothing. A line the parser cannot read falls back to its raw text, because
  a request that will not parse is itself worth seeing.
  Targets are URL-decoded, so `' OR '1'='1` reads as the tautology it is.
  **Every decoded string is neutralised first**: an attacker controls the URL,
  and `%0A` would otherwise let them compose what looks like a second log entry
  inside the panel, while `%E2%80%AE` would let them reverse how a hostile path
  is drawn. Control and format characters are printed as `<U+000A>` instead.
  Decoding is one pass, so a doubly-encoded payload keeps the percent signs that
  give the evasion away.
  Response sizes read as sizes (`1.3 MB`), a served status stands out while a
  refused one recedes — a 2xx on an injection is the alarm, not the reassurance
  — and an agent identical to the one above is stated once, which turns a field
  that filled twelve of twenty-six rows into a signal that a client changed tool
  mid-episode. Measured on six requests: **489 characters in place of 1,170**.
  Two menu items, both remembered: **View → Decode URL escapes** for when the
  encoding itself is the finding, and **View → Show raw log lines** (Ctrl+R),
  which prints the whole source line verbatim beneath each entry. The
  `file:line` reference is printed whatever either is set to.
- **The evidence panel said "1 requests"** while the node caption beside it said
  "1 request", because each formatted the count itself. One shared helper now.
- **The wrap can be turned off** — **View → Wrap long traces**, Alt+Z, as an
  editor spells it, because it is the same choice about the same trade: fold the
  long line and read it, or keep it straight and scroll. Folding stays the
  default. An unwrapped trace no longer opens half way along itself: once the
  fit clamps at the legibility floor the view starts at the first activity,
  which is the only place to begin reading a chronology. The setting is
  remembered between launches, which means the desktop application now writes
  one key to `HKCU\Software\logarc`; nothing else about it leaves the machine.
  It is greyed out on the behaviour map, where a circle has no rows to fold.
- **A key to the drawing**, under the canvas and in the HTML report. Colour is
  severity, the outline is outcome, size is volume — none of which was written
  anywhere a reader could see it. Built from the tables the renderers draw from,
  so it cannot describe a colour no longer in use.
- **The activity being read is ringed on the canvas.** Clicking a node filled
  the evidence panel and left nothing saying which node it belonged to.
- **The behaviour map says how often a transition was seen** (`x3`), rather than
  carrying it in line thickness alone — which cannot be read as a number or
  compared between two clients' maps, and which is the finding on that view.
- **All six client-table columns fit.** Three of them sat behind a scrollbar,
  including the 4xx ratio the table is sorted by when looking for something
  worth opening.

### Performance

- **Ingest can parse a log across worker processes** — `logarc ingest --workers N`. Measured on
  400,000 lines, ingest only: 27,265 lines/s sequential against **69,655 at eight workers, 2.55×**.
  Profiling drove the choice: parsing is 96% of ingest and the regex is only a quarter of *that*,
  so a faster pattern engine had little to give while the work parallelises cleanly.
  See [ADR-0009](docs/adr/0009-parallel-ingest-rather-than-a-native-parser.md).
- **The parse path reads fields by group index rather than through a dictionary.** `parse_line`
  called `groupdict()` and read the result back through sixteen `dict.get` calls per line; the
  indices are fixed once a format is compiled, so they are resolved there. The timestamp is built
  in UTC and shifted rather than built in the log's zone and converted, which drops an `astimezone`
  and two allocations a line. Measured, best of three runs of 300,000 lines: **51,268 → 58,508
  lines/s parsing, +14.1%**, and **28,772 → 33,435 lines/s ingesting a million lines end to end,
  +16.2%** — both versions run on one machine minutes apart rather than compared against a figure
  from another day.
- **The 100,000 lines/s target is still not met**, and the estimate that was going to close it was
  wrong. The remedy named in 0.1.0 — parallel ingest — closes about two thirds of the gap; the
  prediction of 124,000 assumed throughput scales with the worker count, and it does not, because
  the test machine has four physical cores behind eight logical ones. The remaining "40% of parse
  time in field marshalling" recorded here was `cProfile` self-time, which inflates exactly the
  per-call overhead that removing it takes away: the real rate moved by a seventh, not a third.
  What is left is the regex at 30% of the parse and constructing the event at 10%, and no
  rearrangement of Python reaches the target from there.
- Parallel ingest is opt-in and defaults to off, because **each worker holds its own batch and
  memory rises roughly in step with the count.** Bounded memory is one of the design's stronger
  claims and is not spent without being asked. Compressed logs (no random access) and logs under
  32 MB (spawning costs more than parsing saves) fall back to sequential rather than failing.
  Cancellation is not offered on the parallel path — a stop that only sometimes reaches every
  process is worse than none — so the sequential path, which the desktop application uses, keeps it.
- `logarc enrich` no longer reads the whole case into memory. `EventStore.all_events()` streams, and
  both of its consumers were undoing that: the CLI wrapped it in `list()` and the sidecar collected
  it again into a dict of lists. On a twelve-million-line case that was several gigabytes, against a
  design whose central claim is that memory follows the batch size.

### Fixed

- **Every command that reads a case crashed on one whose ingest never finished** —
  `list-ips`, `analyze`, `evidence`, `export`, `enrich`, all with an unhandled
  exception and no message at all. That state is not a corner case: cancelling an
  ingest leaves one deliberately so the part already read is not thrown away, and
  the window says as much. Someone told a case "cannot be analysed" and then
  trying a command against the folder got a stack trace. It now says which case
  was never finalised.
- **Paths printed to the terminal could not be copied.** Rich wraps to the console
  width and a path offers no spaces to break at, so a long one was cut mid-word —
  and the case folder, which every later command takes as `--case`, was in a table
  title, where it arrived as three centred fragments padded with spaces. It now
  sits under the table as `Case: <path>`, on one line. The same applied to the
  error naming a file that could not be parsed, which was breaking that filename
  across five lines.
- **The behaviour map drew one arrow where there were two.** A map folds a trace by activity type,
  so a client alternating between two of them produces an edge each way between the same circles —
  and drawn straight, both are the same line. Measured, the two midpoints were `0.0` apart, so the
  second label was written exactly over the first and which transition survived was the order the
  edges happened to be listed in. Only a reciprocal pair now bows, so the curve means *there are
  two arrows here* and the map stays straight everywhere else. The HTML report had the identical
  fault — its cubic is symmetric under reversal — and is separated the same way.
- **An arrow and the report disagreed about the same gap.** `report/html.py` had grown its own
  duration formatter beside `gui.style`'s, and the two had drifted: nine of eleven sample gaps
  differed. One transition read `1h 0m` in the window and `60m` in the report, `5h 33m` against
  `5.6h`, and half a second was reported as `0s` — a gap presented as no gap. The report now uses
  the window's own label, which is what the severity colours already do.
- **Captions collided when the graph was zoomed out.** Text was pinned to screen size so `fit()`
  could not shrink it into a smudge, which meant the geometry shrank while the words did not: on a
  52-activity trace, overlapping caption pairs went from 7 at full zoom to **117 at 0.35** and 228
  at 0.25. The whole drawing scales together again — so two captions that clear each other at one
  zoom clear each other at every zoom — and the smudge is answered by sizing captions against the
  fit floor instead, where they come out at the size they always were. Layout spacing widened to
  suit, and is stretched further at draw time when the platform's font is wider than it assumes.
- **The numbers on an arrow were three times dimmer than the captions beside them** — 5.5:1 against
  a caption's 16.5:1, at half a point smaller. Legal by the 4.5:1 floor and unreadable in practice,
  because the eye is calibrated by the brighter text next to it.

- **The desktop application ignored CRS entirely.** `analyse_ip` has taken a detection index since
  CRS was added and the CLI passed one, but the window never did — so the same enriched case
  reported different findings depending on which front end asked. `CrsEvidence` and
  `Case.crs_evidence()` are now the one way to obtain it, so the two cannot disagree again.
- **Staged Parquet files were numbered per store instance.** Harmless with one writer and silent
  data loss with several: every worker would have written `part-000000.parquet` and all but the
  last would have been replaced.
- **CI never built the CRS sidecar**, so the four tests covering the Python/Go boundary skipped
  themselves on every run — the newest and least-proven component was the one nothing verified. CI
  now builds it on both runners and sets `LOGARC_REQUIRE_CRS=1`, which turns the skip into a
  failure so a broken build cannot go back to being quiet.

### Detection

- **OWASP CRS runs beside the bundled rules**, through Coraza in a Go sidecar. `logarc enrich`
  replays a case's requests past CRS once and stores the result; `analyze`, `evidence`, `export`
  and `evaluate` read it. This is the real CRS, not a copy of its patterns: the transformation
  chains, per-`ARGS` targeting, rule chaining and libinjection are what a regex port would lose.
  Optional, and a case without it analyses natively and says so on every run. See
  [ADR-0008](docs/adr/0008-crs-as-a-signature-layer-beside-the-rule-packs.md); build instructions
  are in `crs/README.md`.
- **Every native rule is kept.** CRS does one of the four jobs the detection layer performs — the
  signature matching — and cannot do the others: it is stateless per request, so it expresses none
  of the five window rules; it emits rule ids and tags rather than an `ActivityCategory`; and it
  says nothing at all about the traffic no rule matched.
- A CRS detection names a request **only where the rule packs reached INFO** — nothing matched, or
  the only match was an observation like `Scripted Client`. Anything LOW or above is a real claim
  and keeps precedence. CRS is attached as evidence either way, with `crs:942100`-style rule ids.
- **Paranoia level 2 by default**, chosen by measurement. Across CRS's own 1,194 access-log-visible
  regression payloads, PL1 classifies 67% as hostile and PL2 reaches 90%. PL2 is also the ceiling:
  20,000 requests of generated benign traffic yield zero detections at every level, and on 365
  lines of real 2010 WordPress traffic PL1 and PL2 leave the hostile-episode count untouched while
  PL3 flags a plain `GET /` as "Unix Shell Code Found in Request".
- The CRS revision, configuration fingerprint and paranoia level are written into the case
  manifest, and reported beside the ruleset fingerprint.
- **HTML entity, JavaScript escape and null-byte normalisation.** `&#60;script&#62;` and
  `/etc/passwd%00.jpg` now reach the rules in the form the server acts on. The three decoders run
  in one loop with percent-decoding rather than in sequence, because they nest in both directions —
  `%26lt%3B` is percent-then-entity and `&#x25;3C` is entity-then-percent. Entity decoding is
  deliberately stricter than `html.unescape`, which resolves unterminated named entities and would
  invent payloads in ordinary query strings.
- A null byte is now stripped from the matched text but recorded on the result as `had_null`, and
  exposed as a `had_null` match field. This reverses an earlier decision to keep the null in the
  text: the reasoning behind it — that sending one is never accidental — was right, but keeping it
  in the text meant `sensitive_file_access` never saw the path the server actually opens. Both are
  satisfiable at once.

### Added

- `EventStore.all_events()`, a streamed whole-case read. Enrichment needs one pass over everything
  rather than a lookup per client.

### Fixed

- **`distinct_paths` counted `/a/b`, `/a//b` and `/a/./b` as three paths.** That metric is a
  threshold in three of the five bundled window rules, so how a path happened to be written decided
  whether a behaviour was detected — eight requests across two resources were labelled directory
  enumeration. Paths are now counted canonically while `top_targets` still reports what was
  actually requested. Note this changes window-rule firing, not only accuracy: episodes whose
  detection depended on the inflated count will no longer be labelled.

### Evaluation

- **The bundled rules were measured against the OWASP CRS regression corpus at 12.3%** — 140 of the
  1,138 payloads an access log can carry, against a ceiling of 27% because three cases in five ride
  in a request body. Reported because a changelog quoting only favourable numbers is worse than
  none, and because it is the evidence for adopting CRS rather than writing more signatures.
- **That gap is expressiveness, not decoding**, and it was measured rather than assumed. Adding the
  three transforms above moved the rate by three cases. Of the 1,001 missed payloads, five carry an
  HTML entity, one a JavaScript escape and none a null byte; the rest arrive in plain text with no
  rule expressing them — `for %variable in (set) do`, `while(!false)`, Postgres `::jsonb`
  operators. See [ADR-0007](docs/adr/0007-scoring-detection-against-the-crs-regression-corpus.md).
- The `logarc score-crs` command that produced those figures was added and then removed within this
  same unreleased cycle, so it never shipped: once CRS supplies detection, scoring against CRS's own
  corpus grades the rules with the suite their project maintains. ADR-0007's postscript names the
  commits, and reverting the removal restores it.

## [0.1.0] — 2026-08-09

First release. Reconstructs what an IP did on a web server, from its access logs,
and draws it as an activity graph.

### Parsing

- Canonical `NormalizedEvent` schema, so a new log format changes nothing past ingest.
- Apache `LogFormat` directives are **compiled**, not hardcoded, so a site's own directive
  string is supported without code. Presets for `common`, `combined` and `vhost_combined`.
- Format auto-detection by scoring a sample; ambiguity is reported rather than guessed at,
  because silently choosing the wrong parser quarantines an entire log and looks like an
  empty result.
- Open parser registry: `register_format` / `register_logformat` make a format written
  elsewhere available to `--format`, to auto-detection and to `logarc formats`.

### Ingest and storage

- Streaming ingest with memory bounded by batch size rather than file size. `.gz` and `.bz2`
  read transparently.
- Parquet partitioned by `hash(client_ip) % 64` and sorted within partition, queried through
  embedded DuckDB. Two-pass finalize — stream into buckets, then sort each — so memory follows
  the bucket count, not the corpus.
- `ip_index` summary table, so choosing a client is instant and needs no rescan.
- Malformed lines are quarantined with a reason, never dropped silently.
- Long ingests can be cancelled. A stopped run leaves the case un-finalised, and the store
  refuses to be read until it is, so a truncated log cannot be analysed as a complete one.

### Detection and segmentation

- Three-level deterministic segmentation: sessionize on idle gap, user-agent change and maximum
  duration; label each request; merge labelled runs into episodes, absorbing short benign
  interludes so one `favicon.ico` does not split an attack into three.
- Declarative YAML rule engine — signature rules for a single request, window rules for what only
  several requests reveal. Extra packs load with `--rules` and add to the bundled ones.
- Evasion-aware normalisation before matching: bounded recursive percent-decoding, NFKC,
  case folding, SQL comment stripping. Raw and decoded forms are both exposed to rules.
- OWASP mapping as an attribute rather than as the structure, with coverage stated honestly:
  six of ten categories are observable from an access log.
- `outcome` derived from status histogram and response size, so *attempted* and *succeeded* are
  different findings on the graph.

### Output

- Session trace and behaviour map, built from the same episodes, with layout computed in pure
  Python outside the GUI.
- Self-contained HTML report, JSON graph, and PNG export. Attacker-controlled strings are escaped:
  opening the report of an attack must not run the attacker's script.
- `EvidenceRef(source_file_id, line_no)` on every event, episode and node, and `logarc evidence`
  to read the original lines back.

### Desktop application

- PyQt6 window: client table, activity canvas, evidence panel, trace ⇄ behaviour toggle, export.
- All engine work on a `QThreadPool` worker; the window never calls a blocking engine function.
- Presentation rules — colour is severity, border is outcome, size is volume — kept Qt-free in
  `logarc.gui.style` and tested without a display.
- PyInstaller one-folder Windows bundle (~250 MB), carrying the rule packs and package metadata
  that a freezer otherwise drops silently.

### Evaluation

- Synthetic generator with ground truth written from behaviour, never from rule output.
- `logarc evaluate` for per-category precision/recall/F1 and boundary-level segmentation scoring;
  `logarc benchmark` for throughput, peak RSS and reconstruction latency; CSIC 2010 adapter.
- Measured results, and what they do and do not establish, in [docs/evaluation.md](docs/evaluation.md).

### Known limitations

- **Ingest throughput is 28,532 lines/s against a 100,000 target**, and the target is not
  reachable on this class of hardware. Cost per line does not grow with the corpus — that part of
  the design holds — but the constant misses the goal.

  The named remedy *was* parallel ingest over byte-range splits, and that shipped: `--workers`
  and [ADR-0009](docs/adr/0009-parallel-ingest-rather-than-a-native-parser.md). It reaches 69,655
  lines/s with eight workers, 2.55x the sequential rate on the same log. That is close to what the
  hardware has to give: four physical cores behind eight logical ones, and adding workers past
  four moves 2.42x to 2.55x.

  So the gap is no longer a missing feature. 100,000 lines/s needs either more cores than a
  laptop has or a parser that costs less per line, and the second is what ADR-0009 decided
  against rewriting in another language. The figure stands as measured rather than as a target
  about to be met.
- No plugin discovery for parsers — registering one means importing a module that calls
  `register_format`.
- Four OWASP categories are not observable from an access log and are not claimed.
- Recall on CSIC 2010 is capped below 100%, because a substantial share of its attacks carry the
  payload in a POST body and an access log records the request line only.

<!-- Reference links for the version headings above. `0.1.0` was never tagged,
     so it points at the history rather than at a release that does not exist. -->
[Unreleased]: https://github.com/FRTX045/logarc/compare/v0.2.0...main
[0.2.0]: https://github.com/FRTX045/logarc/releases/tag/v0.2.0
[0.1.0]: https://github.com/FRTX045/logarc/commits/main
