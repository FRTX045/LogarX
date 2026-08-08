"""Log format adapters.

Every parser turns lines of one log format into `NormalizedEvent`. This is the
extension point for supporting new web servers: implement `LogParser`, register
it, and nothing else in the system changes.
"""
