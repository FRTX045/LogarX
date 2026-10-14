"""A stand-in for crs-sidecar that talks a lot, over real pipes.

Run by `test_replay_once.py` in place of the Go binary, to check what the
in-memory fake cannot: that a share whose records and answers both overflow an
operating-system pipe, sent to a sidecar that also fills its stderr before each
answer, is answered rather than deadlocked. It speaks the sidecar's protocol,
reports 942100 for every record, and ignores its arguments.
"""

import json
import sys

#: More than a pipe holds on Windows or Linux, which is 64 KiB on both.
SAID_PER_SHARE = 256 * 1024


def main() -> None:
    for line in sys.stdin:
        if line.startswith('{"flush":'):
            sys.stderr.write("x" * (SAID_PER_SHARE - 1) + "\n")
            sys.stderr.flush()
            sys.stdout.write(json.dumps({"flushed": json.loads(line)["flush"]}) + "\n")
            sys.stdout.flush()
            continue
        record = json.loads(line)
        answer = {
            "line_no": record["line_no"],
            "rule_id": 942100,
            "severity": "CRITICAL",
            "msg": "SQL Injection Attack Detected via libinjection",
            "matched_var": "ARGS:q",
            "transformed_value": record["raw_target"],
            "attack_family": "attack-sqli",
            "paranoia_level": 1,
            "tags": ["attack-sqli"],
            "capec": [],
        }
        sys.stdout.write(json.dumps(answer) + "\n")
    sys.stderr.write("crs-sidecar: done\n")


if __name__ == "__main__":
    main()
