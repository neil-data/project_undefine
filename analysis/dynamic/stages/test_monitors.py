"""
test_monitors.py — Health and resource monitoring for a sandbox guest.

These two monitors answer questions the pipeline itself cannot: is the guest
still in a state where its findings mean anything, and is the sample trying to
exhaust the host it is running on. Both are read by an operator deciding
whether to trust a run, so the interesting cases are the unhealthy ones.

Coverage here replaces the monitor exercises from the old root-level
`test_sandbox_manager.py`, which drove the monitors through real `asyncio.sleep`
calls and asserted on whichever values the simulator happened to produce. That
made it slow and non-deterministic, and it only ever tested the healthy path.
These tests drive the collection step directly instead, so the thresholds,
the precedence rules and the empty-state behaviour are all pinned.

Run:
    pytest dynamic-sandbox/stages/test_monitors.py -v
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from stages.health_monitor import (
    ComponentType,
    HealthMonitor,
    HealthStatus,
)
from stages.resource_monitor import (
    ResourceMonitor,
    ResourceStatus,
    ResourceType,
)


@pytest.fixture
def health():
    return HealthMonitor(uuid4(), "windows", check_interval_sec=1)


@pytest.fixture
def resources():
    return ResourceMonitor(uuid4(), "windows", sample_interval_sec=1)


async def check(monitor: HealthMonitor) -> None:
    """Run one health-check pass without starting the background loop."""
    await monitor._check_all_components()


async def collect(monitor: ResourceMonitor, samples: int = 1) -> None:
    """Collect metrics directly, rather than waiting on the sample interval."""
    for _ in range(samples):
        await monitor._collect_metrics()


async def collect_at(monitor: ResourceMonitor, *, cpu=None, memory=None, disk=None) -> None:
    """
    Take one sample at chosen usage levels.

    The monitor's built-in simulator randomizes every reading, which is right
    for a demo and useless for a test: an exhaustion assertion would pass or
    fail on the draw. Pinning the simulator lets the threshold and alerting
    logic be exercised for real.
    """
    if cpu is not None:
        monitor._cpu_usage = cpu
    if memory is not None:
        monitor._memory_usage = memory
    if disk is not None:
        monitor._disk_usage = disk

    original = monitor._simulate_resource_usage
    monitor._simulate_resource_usage = lambda: None
    try:
        await monitor._collect_metrics()
    finally:
        monitor._simulate_resource_usage = original


def set_all(monitor: HealthMonitor, value: bool) -> None:
    monitor.set_vm_running(value)
    monitor.set_agent_connected(value)
    monitor.set_network_available(value)
    monitor.set_storage_available(value)


# ============================================================================
# Health — component state
# ============================================================================

class TestHealthComponents:

    @pytest.mark.asyncio
    async def test_all_four_components_are_tracked(self, health):
        set_all(health, True)
        await check(health)

        snapshot = health.get_health_snapshot()
        tracked = {component.component_type for component in snapshot.components}
        assert tracked == {ComponentType.VM, ComponentType.AGENT,
                           ComponentType.NETWORK, ComponentType.STORAGE}

    @pytest.mark.asyncio
    async def test_everything_up_is_healthy(self, health):
        set_all(health, True)
        await check(health)

        snapshot = health.get_health_snapshot()
        assert snapshot.overall_status is HealthStatus.HEALTHY
        assert snapshot.is_healthy
        assert health.is_healthy()
        assert snapshot.degraded_components == []

    @pytest.mark.asyncio
    async def test_stopped_vm_makes_the_guest_unhealthy(self, health):
        """A run whose guest is not running has no findings worth reading."""
        set_all(health, True)
        health.set_vm_running(False)
        await check(health)

        assert health.get_component_health(ComponentType.VM).status is HealthStatus.UNHEALTHY
        assert health.get_health_snapshot().overall_status is HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_disconnected_agent_makes_the_guest_unhealthy(self, health):
        """No agent means no events — silence that is the harness, not the sample."""
        set_all(health, True)
        health.set_agent_connected(False)
        await check(health)

        assert health.get_component_health(ComponentType.AGENT).status is HealthStatus.UNHEALTHY
        assert not health.is_healthy()

    @pytest.mark.asyncio
    async def test_missing_network_is_degraded_not_unhealthy(self, health):
        """
        Deliberate: network containment is a *configuration*, not a fault. An
        air-gapped run with INetSim off is still a valid run, so this must not
        be reported at the same level as a dead guest.
        """
        set_all(health, True)
        health.set_network_available(False)
        await check(health)

        assert health.get_component_health(ComponentType.NETWORK).status is HealthStatus.DEGRADED
        assert health.get_health_snapshot().overall_status is HealthStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_unavailable_storage_makes_the_guest_unhealthy(self, health):
        """Without storage the artifacts a run exists to produce cannot be written."""
        set_all(health, True)
        health.set_storage_available(False)
        await check(health)

        assert health.get_component_health(ComponentType.STORAGE).status is HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_unhealthy_outranks_degraded(self, health):
        set_all(health, True)
        health.set_network_available(False)     # degraded
        health.set_vm_running(False)            # unhealthy
        await check(health)

        assert health.get_health_snapshot().overall_status is HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_degraded_components_are_listed(self, health):
        set_all(health, True)
        health.set_network_available(False)
        health.set_storage_available(False)
        await check(health)

        failing = {c.component_type for c in health.get_health_snapshot().degraded_components}
        assert failing == {ComponentType.NETWORK, ComponentType.STORAGE}


# ============================================================================
# Health — reporting
# ============================================================================

class TestHealthReporting:

    def test_unchecked_monitor_reports_unknown_not_healthy(self, health):
        """
        "Not yet checked" and "checked and fine" must never be the same answer.
        """
        snapshot = health.get_health_snapshot()
        assert snapshot.overall_status is HealthStatus.UNKNOWN
        assert not snapshot.is_healthy
        assert snapshot.components == []

    def test_component_query_returns_none_before_any_check(self, health):
        assert health.get_component_health(ComponentType.VM) is None

    @pytest.mark.asyncio
    async def test_snapshot_carries_identity_and_uptime(self, health):
        set_all(health, True)
        await check(health)

        snapshot = health.get_health_snapshot()
        assert snapshot.analysis_id == health.analysis_id
        assert snapshot.platform == "windows"
        assert snapshot.uptime_seconds >= 0.0

    @pytest.mark.asyncio
    async def test_component_detail_explains_the_status(self, health):
        """The message is what an operator reads; it has to say what is wrong."""
        set_all(health, True)
        health.set_vm_running(False)
        await check(health)

        vm = health.get_component_health(ComponentType.VM)
        assert "not running" in vm.message
        assert isinstance(vm.last_check, datetime)

    @pytest.mark.asyncio
    async def test_recovery_is_reflected_on_the_next_check(self, health):
        set_all(health, True)
        health.set_agent_connected(False)
        await check(health)
        assert not health.is_healthy()

        health.set_agent_connected(True)
        await check(health)
        assert health.is_healthy()

    @pytest.mark.asyncio
    async def test_overall_status_is_derived_not_cached(self, health):
        """
        Regression guard. A previous `_update_overall_status()` computed the
        overall status into a local and discarded it, so it read as though it
        maintained state while doing nothing at all. Recomputing on demand is
        what keeps the snapshot honest when a component changes between
        checks, and this pins that: no check pass runs between the two reads.
        """
        set_all(health, True)
        await check(health)
        assert health.get_health_snapshot().overall_status is HealthStatus.HEALTHY

        # Corrupt a component directly, with no intervening check.
        health._components[f"{health.platform}_vm"].status = HealthStatus.UNHEALTHY

        assert health.get_health_snapshot().overall_status is HealthStatus.UNHEALTHY
        assert not health.is_healthy()

    def test_no_stale_overall_status_is_stored(self, health):
        """The class must not carry a cached copy that can drift."""
        assert not any(
            "overall" in name and not callable(getattr(health, name))
            for name in vars(health)
        )


# ============================================================================
# Health — lifecycle
# ============================================================================

class TestHealthLifecycle:

    @pytest.mark.asyncio
    async def test_loop_runs_a_check_and_stops_cleanly(self, health):
        set_all(health, True)
        await health.start()
        await asyncio.sleep(0.05)
        await health.stop()

        assert health.get_health_snapshot().components
        assert health._monitoring_task.cancelled() or health._monitoring_task.done()

    @pytest.mark.asyncio
    async def test_stop_without_start_does_not_raise(self, health):
        await health.stop()


# ============================================================================
# Resources — thresholds
# ============================================================================

class TestResourceThresholds:

    @pytest.mark.parametrize("usage,expected", [
        (10.0, ResourceStatus.NORMAL),
        (49.9, ResourceStatus.NORMAL),
        (50.0, ResourceStatus.ELEVATED),
        (74.9, ResourceStatus.ELEVATED),
        (75.0, ResourceStatus.HIGH),
        (89.9, ResourceStatus.HIGH),
        (90.0, ResourceStatus.CRITICAL),
        (100.0, ResourceStatus.CRITICAL),
    ])
    def test_cpu_bands(self, resources, usage, expected):
        assert resources._evaluate_cpu_status(usage) is expected

    @pytest.mark.parametrize("usage,expected", [
        (30.0, ResourceStatus.NORMAL),
        (60.0, ResourceStatus.ELEVATED),
        (80.0, ResourceStatus.HIGH),
        (95.0, ResourceStatus.CRITICAL),
    ])
    def test_memory_bands(self, resources, usage, expected):
        assert resources._evaluate_memory_status(usage) is expected

    @pytest.mark.parametrize("usage,expected", [
        (40.0, ResourceStatus.NORMAL),
        (70.0, ResourceStatus.ELEVATED),
        (85.0, ResourceStatus.HIGH),
        (95.0, ResourceStatus.CRITICAL),
    ])
    def test_disk_bands(self, resources, usage, expected):
        assert resources._evaluate_disk_status(usage) is expected

    @pytest.mark.parametrize("statuses,expected", [
        ([ResourceStatus.NORMAL] * 3, ResourceStatus.NORMAL),
        ([ResourceStatus.NORMAL, ResourceStatus.ELEVATED], ResourceStatus.ELEVATED),
        ([ResourceStatus.ELEVATED, ResourceStatus.HIGH], ResourceStatus.HIGH),
        ([ResourceStatus.NORMAL, ResourceStatus.CRITICAL], ResourceStatus.CRITICAL),
        ([], ResourceStatus.NORMAL),
    ])
    def test_worst_resource_decides_the_overall_status(self, resources, statuses, expected):
        assert resources._calculate_overall_status(statuses) is expected


# ============================================================================
# Resources — collection
# ============================================================================

class TestResourceCollection:

    @pytest.mark.asyncio
    async def test_a_sample_records_all_three_resources(self, resources):
        await collect(resources)

        recorded = {metric.resource_type for metric in resources.get_metrics_history()}
        assert recorded == {ResourceType.CPU, ResourceType.MEMORY, ResourceType.DISK}

    @pytest.mark.asyncio
    async def test_snapshot_reports_the_latest_sample(self, resources):
        await collect(resources, samples=3)

        snapshot = resources.get_current_snapshot()
        latest_cpu = resources.get_metrics_history(ResourceType.CPU)[-1]
        assert snapshot.cpu_percent == latest_cpu.value
        assert snapshot.memory_used_mb > 0

    def test_snapshot_before_collection_is_zeroed_and_normal(self, resources):
        """No data is not an emergency, and it is not a reading either."""
        snapshot = resources.get_current_snapshot()
        assert snapshot.cpu_percent == 0.0
        assert snapshot.memory_percent == 0.0
        assert snapshot.overall_status is ResourceStatus.NORMAL

    @pytest.mark.asyncio
    async def test_history_is_filtered_by_resource_type(self, resources):
        await collect(resources, samples=4)

        cpu = resources.get_metrics_history(ResourceType.CPU)
        assert len(cpu) == 4
        assert all(metric.resource_type is ResourceType.CPU for metric in cpu)

    @pytest.mark.asyncio
    async def test_history_is_filtered_by_time(self, resources):
        await collect(resources, samples=2)
        cutoff = datetime.utcnow() + timedelta(seconds=1)
        assert resources.get_metrics_history(since=cutoff) == []

    @pytest.mark.asyncio
    async def test_history_is_bounded(self, resources):
        """A long run must not accumulate metrics until the host runs out."""
        monitor = ResourceMonitor(uuid4(), "windows", history_size=5)
        await collect(monitor, samples=20)

        assert len(monitor.get_metrics_history()) <= 5 * 3

    @pytest.mark.asyncio
    async def test_network_counters_accumulate(self, resources):
        await collect(resources, samples=2)
        first = resources.get_current_snapshot()
        await collect(resources, samples=2)
        second = resources.get_current_snapshot()

        assert second.network_sent_kb >= first.network_sent_kb
        assert second.network_recv_kb >= first.network_recv_kb


# ============================================================================
# Resources — exhaustion
# ============================================================================

class TestResourceExhaustion:

    @pytest.mark.asyncio
    async def test_ordinary_load_is_not_exhaustion(self, resources):
        await collect_at(resources, cpu=15.0, memory=35.0, disk=45.0)

        assert not resources.is_resource_exhaustion_detected()
        assert resources.get_resource_alerts() == []

    @pytest.mark.asyncio
    async def test_pegged_cpu_is_reported_as_exhaustion(self, resources):
        """
        A sample that pins the host is doing it deliberately — either to burn
        the analysis window or to make the sandbox unusable for the next case.
        """
        await collect_at(resources, cpu=97.0)

        assert resources.is_resource_exhaustion_detected()
        assert any("CRITICAL" in alert and "CPU" in alert
                   for alert in resources.get_resource_alerts())

    @pytest.mark.asyncio
    async def test_high_usage_alerts_without_declaring_exhaustion(self, resources):
        """High is worth saying out loud; only critical stops a run."""
        await collect_at(resources, cpu=20.0, memory=82.0, disk=40.0)

        alerts = resources.get_resource_alerts()
        assert any("HIGH" in alert and "Memory" in alert for alert in alerts)
        assert not resources.is_resource_exhaustion_detected()

    @pytest.mark.asyncio
    async def test_elevated_usage_is_not_worth_an_alert(self, resources):
        await collect_at(resources, cpu=55.0, memory=65.0, disk=72.0)
        assert resources.get_resource_alerts() == []
        assert resources.get_current_snapshot().overall_status is ResourceStatus.ELEVATED

    @pytest.mark.asyncio
    async def test_every_exhausted_resource_is_named(self, resources):
        await collect_at(resources, cpu=96.0, memory=97.0, disk=96.0)

        alerts = resources.get_resource_alerts()
        assert len(alerts) == 3
        assert {alert.split()[1] for alert in alerts} == {"CPU", "Memory", "Disk"}


# ============================================================================
# Resources — lifecycle
# ============================================================================

class TestResourceLifecycle:

    @pytest.mark.asyncio
    async def test_loop_collects_and_stops_cleanly(self, resources):
        await resources.start()
        await asyncio.sleep(0.05)
        await resources.stop()

        assert resources.get_metrics_history()
        assert resources._monitoring_task.cancelled() or resources._monitoring_task.done()

    @pytest.mark.asyncio
    async def test_stop_without_start_does_not_raise(self, resources):
        await resources.stop()
