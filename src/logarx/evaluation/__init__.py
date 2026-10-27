"""Measuring whether the reconstruction is any good.

Three things live here, and they exist because a forensic tool that cannot be
checked is a tool nobody should rely on:

* a **truth** reader and writer for the ground-truth sidecar that says, for
  every line of a log, which activity produced it. The BlackHat-Dataset
  shopfront builds write this format; `convert-csic` writes it too;
* **scoring**, which reruns the reconstruction over that log and reports where
  it agreed and where it did not, per activity category and at each boundary;
* a **benchmark**, which measures throughput and peak memory on a log large
  enough for the scalability claim to mean something.

Nothing here is imported by the analysis path. Evaluation depends on the engine;
the engine never depends on evaluation.
"""

from __future__ import annotations
