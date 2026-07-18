# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

import asyncio

from app.metrics import Metrics, _resident_set_bytes, runtime_metrics_loop


def test_prometheus_samples_use_aggregatable_histograms():
    metrics = Metrics()
    for value in (0.01, 0.02, 0.03, 0.5):
        metrics.observe("event_loop_lag_seconds", value)
    rendered = metrics.render_prometheus()
    assert 'particle_event_loop_lag_seconds_bucket{le="0.1"} 3' in rendered
    assert 'particle_event_loop_lag_seconds_bucket{le="+Inf"} 4' in rendered
    assert "particle_event_loop_lag_seconds_count 4" in rendered
    assert metrics.quantile("event_loop_lag_seconds", 0.99) == 0.5


def test_runtime_metrics_sampler_records_lag_cpu_and_rss():
    async def run():
        metrics = Metrics()
        task = asyncio.create_task(runtime_metrics_loop(metrics, 0.01))
        await asyncio.sleep(0.13)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return metrics.snapshot()

    snapshot = asyncio.run(run())
    assert snapshot["samples"]["event_loop_lag_seconds"]
    assert snapshot["samples"]["process_cpu_percent"]
    assert _resident_set_bytes() > 0
