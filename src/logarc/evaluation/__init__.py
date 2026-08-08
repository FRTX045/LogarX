"""Measuring whether the reconstruction is any good.

Three things live here, and they exist because a forensic tool that cannot be
checked is a tool nobody should rely on:

* a **generator** that writes synthetic access logs together with a record of
  exactly what it wrote, so there is a known answer to compare against;
* **scoring**, which reruns the reconstruction over that log and reports where
  it agreed and where it did not, per activity category;
* a **benchmark**, which measures throughput and peak memory on inputs large
  enough for the scalability claim to mean something.

Nothing here is imported by the analysis path. Evaluation depends on the engine;
the engine never depends on evaluation.
"""

from __future__ import annotations
