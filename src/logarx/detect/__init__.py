"""Detection: turning requests into labelled activity.

Rules are declarative YAML, not Python. Adding a detection is editing a data
file, which means the ruleset can be reviewed, versioned and hashed into the
fingerprint every analysis export records, independently of the code that runs
it.
"""
