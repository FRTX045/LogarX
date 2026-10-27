# What LogarX detects

Eight hostile categories and five kinds of ordinary use, because **a graph of
attacks alone loses the thread between them** — it cannot tell a scanner that
only probed from an attacker who probed, succeeded, and then used what they had
opened.

| Ordinary use | Attack behaviour |
|---|---|
| `browsing` · `static_asset` · `api_call` · `authentication` · `crawling` | `reconnaissance` · `enumeration` · `injection` · `path_traversal` · `access_control` · `credential_attack` · `ssrf` · `exploitation` |

Two rule families do the labelling. **Signature** rules test one request against
a pattern. **Window** rules test a run of requests against aggregate thresholds,
catching what no single request reveals — twenty 404s in a minute across fifteen
distinct paths is enumeration, while any one of them is a missing page.

Matching runs against **normalised** text, because signatures match text and
attackers know it: `%2553ELECT`, `UNI/**/ON`, fullwidth `ＳＥＬＥＣＴ` and
`SeLeCt` are one request to the server and four strings to a naive rule. Decoding
is bounded to three iterations and the depth is kept, because ordinary traffic is
encoded once and anything beyond that is a deliberate act.

Adding a detection needs no Python — the rules are YAML. See
[writing-rules.md](writing-rules.md).

## About OWASP Top 10 coverage

Bundled rules use [OWASP Top 10:2025](https://top10.owasp.org/2025/).
OWASP classifies vulnerability risks; LogarX classifies behaviour visible in
access logs and attaches an optional OWASP annotation. These six categories
are represented, but representation does not mean complete detection coverage:

| OWASP Top 10:2025 annotation | What the bundled rules can indicate |
|---|---|
| A01:2025 Broken Access Control | Access refusals, traversal, forced browsing and SSRF-shaped parameters. These do not prove a successful access-control bypass. |
| A02:2025 Security Misconfiguration | Requests for exposed configuration files, debug endpoints and project metadata. |
| A03:2025 Software Supply Chain Failures | Component paths, dependency manifests, Log4Shell and Shellshock payloads. These four rules concern component risk, not the wider build, distribution or dependency supply chain. |
| A05:2025 Injection | SQL, script, command, template and PHP payload patterns. |
| A07:2025 Authentication Failures | Repeated failed authentication requests and session-fixation indicators where the required fields are logged. |
| A08:2025 Software or Data Integrity Failures | PHP serialised-object payloads that suggest object injection, not proof of unsafe deserialisation. |

No bundled annotations claim A04 Cryptographic Failures, A06 Insecure Design,
A09 Security Logging and Alerting Failures, or A10 Mishandling of Exceptional
Conditions. Repeated server errors alone do not establish A10.

Internal activity categories, including `ssrf`, remain independent of OWASP
numbers. Custom rules may retain older edition-qualified annotations such as
`A03:2021`; findings and exports preserve those values.
