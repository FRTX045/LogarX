"""Reading logs off disk and turning them into stored events.

Everything here is streaming: memory use is bounded by batch size, never by
file size, so a log larger than RAM ingests without special handling.
"""
