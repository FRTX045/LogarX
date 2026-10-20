## What and why

<!-- What this changes, and the problem it solves. Link the issue if there is one. -->

## How it was checked

<!--
The tests that cover it, and how you know they can fail: written before the code
and seen failing for the reason expected.
A detection change: both numbers, before and after — what it catches of the
corpus, and how often it fires on harmless traffic.
A change to the window: a screenshot.
-->

## Checklist

- [ ] Tests added or changed, and seen to fail without the change
- [ ] `ruff check .`, `ruff format --check .`, `mypy src/logarc` and `mypy --platform linux src/logarc` pass
- [ ] CHANGELOG and docs updated where a user would notice the change
- [ ] Measurements reported as they came out, including any target that was missed
