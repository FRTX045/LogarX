"""Peak resident memory of the current process.

The scalability claim is that ingest runs in memory bounded by the batch size
rather than by the length of the file, so the number that has to be true is the
peak, not the reading at the end.

Measured through the operating system rather than with `tracemalloc`, which
only sees Python allocations. Most of the memory an ingest touches belongs to
Arrow and DuckDB, and a figure that left those out would be flattering and
wrong. Doing it this way also avoids a dependency on `psutil` for two dozen
lines of platform code.
"""

from __future__ import annotations

import sys

__all__ = ["peak_rss_bytes"]


def peak_rss_bytes() -> int:
    """The high-water mark of resident memory, in bytes.

    Returns 0 when the platform will not say, so a caller can report the figure
    as unavailable rather than print a zero as if it were a measurement.
    """
    if sys.platform == "win32":
        return _windows_peak()
    return _posix_peak()


def _windows_peak() -> int:
    import ctypes
    from ctypes import wintypes

    class _MemoryCounters(ctypes.Structure):
        _fields_ = (
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        )

    counters = _MemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)

        # Without these the pseudo-handle -1 is marshalled as a 32-bit int and
        # the call fails on 64-bit Windows, silently reporting no memory used.
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetCurrentProcess.argtypes = ()
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        psapi.GetProcessMemoryInfo.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_MemoryCounters),
            wintypes.DWORD,
        )

        ok = psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        )
    except (OSError, AttributeError):
        return 0
    return int(counters.PeakWorkingSetSize) if ok else 0


def _posix_peak() -> int:
    # The guard is for the type checker as much as for the runtime: `resource`
    # does not exist on Windows, and without it every check run on a Windows
    # machine reports this function as broken.
    if sys.platform == "win32":  # pragma: no cover - unreachable via peak_rss_bytes
        return 0

    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kilobytes; macOS and the BSDs report bytes.
    return int(peak) if sys.platform == "darwin" else int(peak) * 1024
