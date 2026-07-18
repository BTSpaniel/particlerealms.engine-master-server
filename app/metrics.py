# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""Small in-process metrics registry with Prometheus text export.

The service deliberately has no database and no telemetry dependency. These
aggregates contain no IPs, route tags, session IDs, payloads, or credentials.
"""

from __future__ import annotations

import asyncio
import math
import os
import time
import threading
from collections import defaultdict
from pathlib import Path


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = defaultdict(float)
        self._samples: dict[str, list[float]] = defaultdict(list)

    def increment(self, name: str, amount: float = 1.0) -> None:
        with self._lock:
            self._counters[name] += amount

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe(self, name: str, value: float) -> None:
        if not math.isfinite(value):
            return
        with self._lock:
            samples = self._samples[name]
            samples.append(value)
            if len(samples) > 4096:
                del samples[: len(samples) - 4096]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "samples": {key: list(value) for key, value in self._samples.items()},
            }

    def quantile(self, name: str, value: float) -> float:
        with self._lock:
            samples = list(self._samples.get(name, ()))
        return _quantile(samples, value)

    def gauge_value(self, name: str) -> float:
        with self._lock:
            return float(self._gauges.get(name, 0.0))

    def render_prometheus(self) -> str:
        snapshot = self.snapshot()
        lines: list[str] = []
        for name, value in sorted(snapshot["counters"].items()):
            lines.append(f"particle_{_metric_name(name)}_total {value:g}")
        for name, value in sorted(snapshot["gauges"].items()):
            lines.append(f"particle_{_metric_name(name)} {value:g}")
        for name, values in sorted(snapshot["samples"].items()):
            metric = f"particle_{_metric_name(name)}"
            for boundary in _histogram_boundaries(name):
                count = sum(value <= boundary for value in values)
                lines.append(f'{metric}_bucket{{le="{boundary:g}"}} {count}')
            lines.append(f'{metric}_bucket{{le="+Inf"}} {len(values)}')
            lines.append(f"{metric}_count {len(values)}")
            lines.append(f"{metric}_sum {sum(values):g}")
        return "\n".join(lines) + "\n"


def _metric_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in name.lower())


def _quantile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return ordered[index]


def _histogram_boundaries(name: str) -> tuple[float, ...]:
    if "cpu_percent" in name:
        return (5, 10, 25, 50, 80, 100, 200)
    if name.endswith("_seconds"):
        return (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
    return (1, 5, 10, 25, 50, 100, 250, 500, 1000)


async def runtime_metrics_loop(metrics: Metrics, interval_seconds: float = 1.0) -> None:
    """Measure event-loop lag and process resources without external telemetry."""
    interval = max(0.1, interval_seconds)
    previous_wall = time.monotonic()
    previous_cpu = time.process_time()
    deadline = previous_wall + interval
    while True:
        await asyncio.sleep(max(0.0, deadline - time.monotonic()))
        current_wall = time.monotonic()
        current_cpu = time.process_time()
        metrics.observe("event_loop_lag_seconds", max(0.0, current_wall - deadline))
        wall_delta = current_wall - previous_wall
        if wall_delta > 0:
            one_core = max(0.0, (current_cpu - previous_cpu) / wall_delta * 100.0)
            metrics.observe("process_cpu_percent_one_core", one_core)
            metrics.observe("process_cpu_percent", one_core / max(1, os.cpu_count() or 1))
        rss = _resident_set_bytes()
        if rss > 0:
            metrics.gauge("process_rss_bytes", rss)
            metrics.gauge("process_rss_peak_bytes", max(metrics.gauge_value("process_rss_peak_bytes"), rss))
        open_fds = _open_file_descriptor_count()
        if open_fds >= 0:
            metrics.gauge("process_open_file_descriptors", open_fds)
        previous_wall = current_wall
        previous_cpu = current_cpu
        deadline += interval
        if deadline <= current_wall:
            deadline = current_wall + interval


def _resident_set_bytes() -> int:
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
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
                ]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            get_current_process = ctypes.windll.kernel32.GetCurrentProcess
            get_current_process.restype = wintypes.HANDLE
            get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
            get_process_memory_info.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(ProcessMemoryCounters),
                wintypes.DWORD,
            ]
            get_process_memory_info.restype = wintypes.BOOL
            process = get_current_process()
            if get_process_memory_info(process, ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize)
        except (AttributeError, OSError, ValueError):
            pass
    try:
        statm = Path("/proc/self/statm").read_text(encoding="ascii").split()
        return int(statm[1]) * os.sysconf("SC_PAGE_SIZE")
    except (FileNotFoundError, OSError, ValueError, IndexError, AttributeError):
        pass
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return value if os.name == "darwin" else value * 1024
    except (ImportError, OSError, ValueError):
        return 0


def _open_file_descriptor_count() -> int:
    try:
        return len(list(Path("/proc/self/fd").iterdir()))
    except (FileNotFoundError, OSError):
        return -1


metrics = Metrics()
