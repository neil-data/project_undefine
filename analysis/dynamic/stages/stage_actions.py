"""
stage_actions.py — Concrete guest operations for each pipeline stage.

Each StageAction owns the "what actually happens inside the VM" for one stage.
The orchestrator handles timing, event correlation, and reporting; actions
handle sandbox control.

Every action implements the same three-method contract:

    setup()    — prepare the guest (bring up INetSim, arm hooks, ...)
    execute()  — run for the stage duration, return findings
    teardown() — clean up, capture artifacts

Actions talk to the guest through a SandboxController abstraction, so the same
stage logic drives CAPE/KVM (Windows) and Android-x86/Frida (Android). The
controller is injected, which also makes every action unit-testable against
MockSandboxController with no VM present.
"""

from __future__ import annotations

import asyncio
import logging
import random
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol
from uuid import UUID, uuid4

from .stage_definitions import (
    EvasionClass,
    StageArtifact,
    StageConfig,
    StageFinding,
    StageId,
)

_LOGGER = logging.getLogger(__name__)


# ============================================================================
# Sandbox Controller Interface
# ============================================================================

class SandboxController(Protocol):
    """
    Platform-agnostic guest control surface.

    Implemented by CapeSandboxController (Windows/KVM) and
    AndroidSandboxController (Android-x86/Frida). Kept deliberately narrow —
    if a stage needs something exotic it goes through send_command().
    """

    async def restore_snapshot(self, snapshot: str = "golden") -> bool: ...
    async def start_guest(self) -> bool: ...
    async def stop_guest(self) -> bool: ...
    async def reboot_guest(self, graceful: bool = True, preserve_disk: bool = True) -> bool: ...
    async def await_agent(self, timeout_sec: int) -> bool: ...

    async def drop_sample(self, sample_path: str) -> str: ...
    async def execute_sample(self, guest_path: str) -> int: ...

    async def send_input(self, action: str, params: Dict[str, Any]) -> bool: ...
    async def screenshot(self) -> Optional[bytes]: ...
    async def dump_memory(self, pid: Optional[int] = None) -> Optional[str]: ...

    async def list_processes(self) -> List[Dict[str, Any]]: ...
    async def snapshot_state(self, targets: List[str]) -> Dict[str, Any]: ...
    async def diff_state(self, baseline: Dict[str, Any], targets: List[str]) -> Dict[str, Any]: ...

    async def configure_network(self, profile: str, params: Dict[str, Any]) -> bool: ...
    async def send_command(self, command: str, params: Dict[str, Any]) -> Dict[str, Any]: ...


# ============================================================================
# Execution Context
# ============================================================================

class StageContext:
    """
    Mutable state threaded through the whole pipeline.

    Stages both read and write this: Stage 1 writes the baseline, Stage 5 reads
    it to diff, Stage 6 reads Stage 5's persistence list to verify what fired.
    """

    def __init__(
        self,
        analysis_id: UUID,
        platform: str,
        sample_path: str,
        controller: SandboxController,
        time_scale: float = 1.0,
    ):
        self.analysis_id = analysis_id
        self.platform = platform
        self.sample_path = sample_path
        self.controller = controller

        # Wall-clock compression factor. 1.0 is real time (production).
        # Tests and demos raise this to run a 60-minute pipeline in seconds
        # without changing any stage logic or timing *ratios*.
        #
        # Practical ceiling is around 60x. Sleeps compress, but the fixed cost
        # of each controller round-trip does not, so past roughly 60x the
        # per-call overhead no longer fits inside the scaled stage timeout and
        # stages begin reporting TIMED_OUT for reasons that have nothing to do
        # with sample behavior. Verified clean at 60x.
        self.time_scale = max(1.0, time_scale)

        # Populated by Stage 1
        self.guest_sample_path: Optional[str] = None
        self.sample_pid: Optional[int] = None
        self.baseline_state: Dict[str, Any] = {}

        # Populated by Stage 5, consumed by Stage 6
        self.persistence_entries: List[Dict[str, Any]] = []

        # Populated by Stage 4
        self.observed_c2_candidates: List[str] = []

        # Cross-stage scratch space
        self.shared: Dict[str, Any] = {}

        # Set by the orchestrator when an investigator kills the run
        self.abort_requested: bool = False


# ============================================================================
# Base Action
# ============================================================================

class StageAction(ABC):
    """Base class for all stage actions."""

    stage_id: StageId

    def __init__(self, config: StageConfig):
        self.config = config
        self.artifacts: List[StageArtifact] = []
        self.findings: List[StageFinding] = []

        # Set True by an action when it directly observes sample behavior.
        #
        # This exists because the orchestrator's other activity signal — a
        # count of events in the DB — is unavailable when no DB is attached and
        # can lag when the event-ingest pipeline is backed up. Relying on that
        # alone means a stage silently reports "no activity", which propagates
        # into the report as "sample appeared inert". That is the one direction
        # this system must never fail in, so actions report what they saw
        # first-hand and the orchestrator takes either signal.
        self.activity_observed: bool = False

    async def setup(self, ctx: StageContext) -> None:
        """Prepare the guest. Default: nothing."""
        return None

    @abstractmethod
    async def execute(self, ctx: StageContext) -> None:
        """Run the stage body for its duration budget."""
        ...

    async def teardown(self, ctx: StageContext) -> None:
        """Capture end-of-stage artifacts."""
        if self.config.capture_screenshot:
            await self._capture_screenshot(ctx, label="stage_end")

    # --- helpers ------------------------------------------------------

    def _finding(
        self,
        title: str,
        detail: str,
        severity: str = "info",
        mitre: Optional[List[str]] = None,
    ) -> StageFinding:
        finding = StageFinding(
            stage_id=self.stage_id,
            title=title,
            detail=detail,
            severity=severity,
            mitre_techniques=mitre or [],
            observed_at=datetime.utcnow(),
        )
        self.findings.append(finding)
        return finding

    async def _capture_screenshot(self, ctx: StageContext, label: str) -> None:
        try:
            data = await ctx.controller.screenshot()
            if not data:
                return
            path = f"artifacts/{ctx.analysis_id}/{self.stage_id.value}_{label}.png"
            self.artifacts.append(
                StageArtifact(
                    artifact_type="screenshot",
                    path=path,
                    size_bytes=len(data),
                    captured_at=datetime.utcnow(),
                )
            )
        except Exception as exc:
            _LOGGER.warning("Screenshot failed in %s: %s", self.stage_id.value, exc)

    async def _sleep_interruptible(self, ctx: StageContext, seconds: float) -> bool:
        """
        Sleep in slices so an investigator's kill lands within about a second
        instead of at the end of a 30-minute stage. Returns False if aborted.

        Honors ctx.time_scale so the whole pipeline can be run compressed.
        """
        remaining = max(0.0, seconds) / ctx.time_scale
        slice_sec = min(1.0, max(0.01, remaining))
        while remaining > 0:
            if ctx.abort_requested:
                return False
            await asyncio.sleep(min(slice_sec, remaining))
            remaining -= slice_sec
        return True

    @staticmethod
    def _tick(preferred: float, budget: float) -> float:
        """
        Choose a sampling interval that fits inside the stage budget.

        A fixed 30s poll inside a stage configured for 10s would overshoot the
        budget by 3x and trip the orchestrator's timeout, so short budgets get
        proportionally shorter ticks.
        """
        if budget <= 0:
            return preferred
        return max(0.05, min(preferred, budget / 4.0))


# ============================================================================
# Stage 1 — Boot
# ============================================================================

class BootAction(StageAction):
    """Restore snapshot, boot guest, baseline the system, detonate the sample."""

    stage_id = StageId.BOOT

    async def setup(self, ctx: StageContext) -> None:
        _LOGGER.info("[%s] Restoring golden snapshot", ctx.analysis_id)
        await ctx.controller.restore_snapshot("golden")
        await ctx.controller.start_guest()

        if self.config.params.get("await_agent_checkin", True):
            timeout = self.config.params.get("agent_checkin_timeout_sec", 60)
            ready = await ctx.controller.await_agent(timeout_sec=timeout)
            if not ready:
                # Not fatal on its own, but the whole run is suspect without
                # the in-guest agent, so make it loud.
                self._finding(
                    "Guest agent did not check in",
                    f"No agent check-in within {timeout}s. Behavioral capture "
                    f"may be incomplete for this run.",
                    severity="critical",
                )

    async def execute(self, ctx: StageContext) -> None:
        # Baseline before detonation — everything Stage 5 diffs against.
        if self.config.params.get("snapshot_baseline", True):
            targets = self.config.params.get("baseline_targets", [])
            ctx.baseline_state = await ctx.controller.snapshot_state(targets)
            _LOGGER.info(
                "[%s] Baseline captured: %s", ctx.analysis_id, list(ctx.baseline_state)
            )

        # Drop and run
        # Snapshot the process list so we can tell "the sample merely started"
        # from "the sample actually did something".
        pre_procs = await ctx.controller.list_processes()
        pre_pids = {p.get("pid") for p in pre_procs}

        ctx.guest_sample_path = await ctx.controller.drop_sample(ctx.sample_path)
        ctx.sample_pid = await ctx.controller.execute_sample(ctx.guest_sample_path)

        self._finding(
            "Sample executed",
            f"Sample detonated at {ctx.guest_sample_path} (pid={ctx.sample_pid}).",
            severity="info",
        )

        await self._capture_screenshot(ctx, label="post_detonation")

        # Observe first-contact behavior for the rest of the budget
        await self._sleep_interruptible(
            ctx, max(0.0, self.config.duration_sec - 20)
        )

        procs = await ctx.controller.list_processes()
        alive = any(p.get("pid") == ctx.sample_pid for p in procs)

        # Launching is not behavior — every sample launches. Activity at this
        # stage means the sample did something beyond starting: spawned a
        # child, injected, or dropped a new running process. A sample that
        # only sits there is dormant, and must stay dormant in the report so
        # later stages get correct credit for waking it.
        new_pids = {p.get("pid") for p in procs} - pre_pids - {ctx.sample_pid}
        self.activity_observed = bool(new_pids)

        if new_pids:
            self._finding(
                "Child processes spawned during boot",
                f"The sample spawned {len(new_pids)} additional process(es) "
                f"immediately on execution, indicating it acts without "
                f"requiring any further trigger.",
                severity="warning",
                mitre=["T1106"],
            )

        if not alive:
            self._finding(
                "Sample process exited during boot stage",
                "The initial process is no longer running. This is consistent "
                "with either a crash, a successful hand-off to a child process, "
                "or an environment check causing early exit.",
                severity="warning",
                mitre=["T1497"],
            )
            ctx.shared["boot_process_exited"] = True


# ============================================================================
# Stage 2 — Idle
# ============================================================================

class IdleAction(StageAction):
    """
    Do nothing on purpose. Isolates autonomous behavior from provoked behavior.
    """

    stage_id = StageId.IDLE

    async def execute(self, ctx: StageContext) -> None:
        _LOGGER.info(
            "[%s] Idle observation for %ss", ctx.analysis_id, self.config.duration_sec
        )

        measure_beacon = self.config.params.get("measure_beacon_interval", True)
        connection_times: List[float] = []

        elapsed = 0.0
        sample_interval = self._tick(10.0, self.config.duration_sec)

        while elapsed < self.config.duration_sec:
            if not await self._sleep_interruptible(ctx, sample_interval):
                return
            elapsed += sample_interval

            if measure_beacon:
                result = await ctx.controller.send_command(
                    "query_recent_connections", {"window_sec": sample_interval}
                )
                for conn in result.get("connections", []):
                    connection_times.append(conn.get("timestamp", elapsed))

        # A tight standard deviation across outbound connections is a strong
        # beaconing signal — human/benign traffic is far more irregular.
        if len(connection_times) >= 3:
            deltas = [
                connection_times[i + 1] - connection_times[i]
                for i in range(len(connection_times) - 1)
            ]
            mean = sum(deltas) / len(deltas)
            variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            stddev = variance ** 0.5

            if mean > 0 and (stddev / mean) < 0.25:
                self.activity_observed = True
                self._finding(
                    "Regular beaconing detected during idle",
                    f"Outbound connections at a consistent ~{mean:.1f}s interval "
                    f"(stddev {stddev:.1f}s) with no user activity. Regular "
                    f"timing with low jitter is characteristic of C2 check-in "
                    f"rather than normal application traffic.",
                    severity="critical",
                    mitre=["T1071", "T1029"],
                )
                ctx.shared["beacon_interval_sec"] = mean

        if connection_times:
            self.activity_observed = True
        else:
            self._finding(
                "No autonomous activity during idle",
                "The sample produced no outbound traffic while unattended. This "
                "does not indicate benign behavior — it is consistent with "
                "interaction-gated or network-gated activation, tested in the "
                "following stages.",
                severity="info",
            )


# ============================================================================
# Stage 3 — User Interaction
# ============================================================================

class UserInteractionAction(StageAction):
    """
    Synthesize human activity. Defeats malware that fingerprints idle cursors
    and empty user profiles to detect sandboxes.
    """

    stage_id = StageId.USER_INTERACTION

    async def setup(self, ctx: StageContext) -> None:
        # A convincing user profile matters as much as the input itself — a
        # desktop with zero documents and no browser history is its own tell.
        if self.config.params.get("decoy_documents_present", True):
            await ctx.controller.send_command("populate_decoy_documents", {"count": 12})
        if self.config.params.get("decoy_browser_history", True):
            await ctx.controller.send_command("populate_browser_history", {"entries": 40})

    async def execute(self, ctx: StageContext) -> None:
        actions: List[str] = self.config.params.get("actions", [])
        jitter_lo, jitter_hi = self.config.params.get("jitter_ms", [80, 600])

        deadline = self.config.duration_sec
        elapsed = 0.0
        performed: Dict[str, int] = {}

        while elapsed < deadline:
            if ctx.abort_requested:
                return

            action = random.choice(actions)
            params = self._params_for(action)

            try:
                await ctx.controller.send_input(action, params)
                performed[action] = performed.get(action, 0) + 1
            except Exception as exc:
                _LOGGER.warning("Input action %s failed: %s", action, exc)

            # Human-plausible pacing. Uniform robotic delays are detectable.
            delay = random.uniform(jitter_lo / 1000.0, jitter_hi / 1000.0)
            if not await self._sleep_interruptible(ctx, delay):
                return
            elapsed += delay

        # Did the sample respond to the input we generated? This is the
        # signal that distinguishes an interaction-gated sample from an
        # inert one, so it is queried explicitly rather than inferred.
        summary = await ctx.controller.send_command(
            "query_activity_summary", {"window_sec": deadline}
        )
        if summary.get("event_count", 0) > 0:
            self.activity_observed = True
            self._finding(
                "Sample became active following user interaction",
                "The sample produced no behavior while the machine was "
                "unattended but began acting once synthetic user input was "
                "introduced. This indicates activation deliberately gated on "
                "human presence, which defeats sandboxes that leave the "
                "cursor motionless.",
                severity="critical",
                mitre=["T1497.002"],
            )

        self._finding(
            "Simulated user interaction completed",
            f"Performed {sum(performed.values())} synthetic input events across "
            f"{len(performed)} action types: "
            + ", ".join(f"{k}×{v}" for k, v in sorted(performed.items()))
            + ".",
            severity="info",
        )

        # Correlating the activity spike to this stage is the orchestrator's
        # job; here we just record what we did.
        ctx.shared["interaction_actions_performed"] = performed

    def _params_for(self, action: str) -> Dict[str, Any]:
        if action == "mouse_move_bezier":
            return {
                "start": (random.randint(0, 1280), random.randint(0, 720)),
                "end": (random.randint(0, 1280), random.randint(0, 720)),
                "steps": random.randint(20, 60),
                "curve": True,
            }
        if action == "mouse_scroll":
            return {"delta": random.choice([-5, -3, 3, 5]), "smooth": True}
        if action == "mouse_click":
            return {
                "button": random.choice(["left", "left", "left", "right"]),
                "x": random.randint(0, 1280),
                "y": random.randint(0, 720),
            }
        if action == "keyboard_type":
            return {
                "text": random.choice(
                    ["meeting notes", "invoice", "report draft", "budget q3"]
                ),
                "wpm": random.randint(35, 75),
            }
        if action == "open_document":
            return {"path": "decoy", "linger_sec": random.randint(5, 20)}
        if action == "open_browser":
            return {"url": "http://intranet.local/", "linger_sec": random.randint(5, 25)}
        if action == "lock_unlock":
            return {"lock_duration_sec": random.randint(10, 30)}
        if action == "switch_windows":
            return {"count": random.randint(2, 5)}
        return {}


# ============================================================================
# Stage 4 — Internet Simulation
# ============================================================================

class InternetSimulationAction(StageAction):
    """
    Make the network look real and reachable so network-gated payloads arm.
    All traffic remains contained inside the detonation plane.
    """

    stage_id = StageId.INTERNET_SIMULATION

    async def setup(self, ctx: StageContext) -> None:
        profile = self.config.params.get("inetsim_profile", "full_response")
        await ctx.controller.configure_network(
            profile,
            {
                "dns_wildcard": self.config.params.get("dns_wildcard", True),
                "tls_metadata_only": self.config.params.get(
                    "tls_intercept_metadata_only", True
                ),
                "capture_ja3": self.config.params.get("capture_ja3", True),
                "capture_sni": self.config.params.get("capture_sni", True),
            },
        )
        _LOGGER.info("[%s] INetSim profile '%s' active", ctx.analysis_id, profile)

    async def execute(self, ctx: StageContext) -> None:
        half = self.config.duration_sec / 2

        if not await self._sleep_interruptible(ctx, half):
            return

        result = await ctx.controller.send_command("query_network_summary", {})
        dns_queries = result.get("dns_queries", [])
        connections = result.get("connections", [])

        # Adaptive escalation: if the sample is still silent halfway through,
        # serve more convincing C2-shaped responses before giving up on it.
        if not connections and self.config.params.get("adaptive_response", True):
            _LOGGER.info("[%s] No traffic yet — escalating responses", ctx.analysis_id)
            await ctx.controller.configure_network(
                "aggressive_c2_emulation",
                {"respond_to_all": True, "generic_c2_payload": True},
            )
            self._finding(
                "Escalated network emulation",
                "No outbound traffic observed at the halfway point; switched to "
                "aggressive C2 emulation to test whether the sample requires a "
                "responsive controller before activating.",
                severity="info",
            )

        if not await self._sleep_interruptible(ctx, half):
            return

        final = await ctx.controller.send_command("query_network_summary", {})
        dns_queries = final.get("dns_queries", [])
        connections = final.get("connections", [])
        ja3_fingerprints = final.get("ja3", [])

        if dns_queries or connections:
            self.activity_observed = True

        if dns_queries:
            domains = sorted({q.get("domain", "") for q in dns_queries if q.get("domain")})
            ctx.observed_c2_candidates.extend(domains)
            self._finding(
                "DNS resolution attempts observed",
                f"Sample resolved {len(domains)} distinct domain(s): "
                + ", ".join(domains[:10])
                + ("…" if len(domains) > 10 else "")
                + ". Domains resolved only after full network simulation was "
                  "enabled indicate network-gated activation.",
                severity="warning",
                mitre=["T1071.004"],
            )

        if connections:
            self._finding(
                "Outbound connections established",
                f"{len(connections)} outbound connection(s) once the network "
                f"appeared reachable. The sample was dormant under a black-holed "
                f"network, confirming network-gated behavior.",
                severity="critical",
                mitre=["T1071.001"],
            )
            ctx.shared["network_gated"] = True

        if ja3_fingerprints:
            self._finding(
                "TLS client fingerprints captured",
                f"Captured {len(ja3_fingerprints)} JA3 fingerprint(s) from TLS "
                f"handshakes. Metadata only — no traffic was decrypted. "
                f"Fingerprints: {', '.join(ja3_fingerprints[:3])}",
                severity="info",
                mitre=["T1573"],
            )


# ============================================================================
# Stage 5 — Persistence Check
# ============================================================================

class PersistenceCheckAction(StageAction):
    """
    Diff live system state against the Stage 1 baseline to enumerate every
    persistence foothold installed so far.
    """

    stage_id = StageId.PERSISTENCE_CHECK

    async def execute(self, ctx: StageContext) -> None:
        targets = (
            self.config.params.get("windows_targets", [])
            if ctx.platform == "windows"
            else self.config.params.get("android_targets", [])
        )

        if not ctx.baseline_state:
            # Without a baseline we can only report absolute state, which is
            # noisy. Say so rather than pretending the diff is meaningful.
            self._finding(
                "No baseline available for persistence diff",
                "Stage 1 baseline was not captured, so persistence findings are "
                "based on absolute state and may include benign system entries.",
                severity="warning",
            )

        diff = await ctx.controller.diff_state(ctx.baseline_state, targets)

        total = 0
        for target, entries in diff.items():
            if not entries:
                continue
            total += len(entries)
            self.activity_observed = True

            for entry in entries:
                ctx.persistence_entries.append({"target": target, **entry})

            self._finding(
                f"Persistence: {target.replace('_', ' ')}",
                f"{len(entries)} new entr{'y' if len(entries) == 1 else 'ies'} "
                f"since baseline: "
                + "; ".join(
                    str(e.get("name") or e.get("path") or e.get("key", "?"))
                    for e in entries[:5]
                )
                + ("…" if len(entries) > 5 else ""),
                severity="critical",
                mitre=self._mitre_for(target),
            )

        if total == 0:
            self._finding(
                "No persistence mechanisms detected",
                "No new autostart entries relative to baseline. The sample may "
                "be memory-resident only, may persist later in the run, or may "
                "rely on a mechanism outside the enumerated targets.",
                severity="info",
            )
        else:
            ctx.shared["persistence_count"] = total

    @staticmethod
    def _mitre_for(target: str) -> List[str]:
        mapping = {
            "registry_run_keys": ["T1547.001"],
            "registry_runonce": ["T1547.001"],
            "scheduled_tasks": ["T1053.005"],
            "services": ["T1543.003"],
            "wmi_subscriptions": ["T1546.003"],
            "startup_folder": ["T1547.001"],
            "winlogon_shell": ["T1547.004"],
            "image_file_execution_options": ["T1546.012"],
            "com_hijack": ["T1546.015"],
            "boot_completed_receivers": ["T1398"],
            "device_admin_apps": ["T1626.001"],
            "accessibility_services": ["T1416"],
            "foreground_services": ["T1541"],
        }
        return mapping.get(target, [])


# ============================================================================
# Stage 6 — Reboot
# ============================================================================

class RebootAction(StageAction):
    """
    Restart the guest with disk state preserved and observe the second boot.
    Verifies that Stage 5's persistence entries actually fire.
    """

    stage_id = StageId.REBOOT

    async def execute(self, ctx: StageContext) -> None:
        graceful = self.config.params.get("reboot_method", "graceful") == "graceful"
        preserve = self.config.params.get("preserve_disk_state", True)

        pre_reboot_procs = await ctx.controller.list_processes()
        pre_names = {p.get("name", "") for p in pre_reboot_procs}

        _LOGGER.info("[%s] Rebooting guest (graceful=%s)", ctx.analysis_id, graceful)
        ok = await ctx.controller.reboot_guest(graceful=graceful, preserve_disk=preserve)

        if not ok and graceful:
            # A sample that blocks clean shutdown is itself worth reporting.
            self._finding(
                "Graceful reboot failed; forced reset",
                "The guest did not shut down cleanly within the allotted window. "
                "This can indicate a process actively resisting termination.",
                severity="warning",
                mitre=["T1489"],
            )
            await ctx.controller.reboot_guest(graceful=False, preserve_disk=preserve)

        timeout = self.config.params.get("agent_checkin_timeout_sec", 120)
        back = await ctx.controller.await_agent(timeout_sec=timeout)

        if not back:
            self._finding(
                "Guest did not return after reboot",
                f"No agent check-in within {timeout}s post-reboot. The system may "
                f"be unbootable — consistent with destructive payloads or a "
                f"corrupted boot path.",
                severity="critical",
                mitre=["T1561"],
            )
            return

        await self._capture_screenshot(ctx, label="post_reboot")

        # Let post-boot payloads run before we evaluate
        settle = min(90, self.config.duration_sec // 3)
        if not await self._sleep_interruptible(ctx, settle):
            return

        post_reboot_procs = await ctx.controller.list_processes()
        post_names = {p.get("name", "") for p in post_reboot_procs}

        # Did the persistence we catalogued in Stage 5 actually execute?
        if self.config.params.get("verify_persistence_fired", True) and ctx.persistence_entries:
            fired = [
                e for e in ctx.persistence_entries
                if any(
                    str(e.get("name", "")).lower() in n.lower()
                    or str(e.get("path", "")).lower() in n.lower()
                    for n in post_names
                    if n
                )
            ]
            if fired:
                self.activity_observed = True
                self._finding(
                    "Persistence confirmed active after reboot",
                    f"{len(fired)} of {len(ctx.persistence_entries)} catalogued "
                    f"persistence entries produced running processes after reboot. "
                    f"The infection survives restart.",
                    severity="critical",
                    mitre=["T1547"],
                )
                ctx.shared["persistence_survives_reboot"] = True

        # New processes that only exist post-reboot are the reboot-gated payload
        new_procs = post_names - pre_names
        if new_procs:
            self.activity_observed = True
            self._finding(
                "New processes appeared only after reboot",
                f"{len(new_procs)} process(es) present after reboot that were not "
                f"running before: {', '.join(sorted(new_procs)[:8])}. Payload "
                f"activation gated on reboot would be invisible to a "
                f"single-execution sandbox.",
                severity="critical",
                mitre=["T1547"],
            )
            ctx.shared["reboot_gated"] = True

        remaining = self.config.duration_sec - settle
        if remaining > 0:
            await self._sleep_interruptible(ctx, remaining)


# ============================================================================
# Stage 7 — Long Execution
# ============================================================================

class LongExecutionAction(StageAction):
    """
    Extended observation window to outlast sleep-based evasion, with light
    periodic interaction so interaction-gated logic stays satisfied.
    """

    stage_id = StageId.LONG_EXECUTION

    async def setup(self, ctx: StageContext) -> None:
        if self.config.params.get("sleep_patching_enabled", False):
            threshold = self.config.params.get("sleep_patch_threshold_ms", 60_000)
            factor = self.config.params.get("sleep_patch_factor", 10)
            await ctx.controller.send_command(
                "enable_sleep_patching",
                {"threshold_ms": threshold, "factor": factor},
            )
            # This is an intervention on the evidence. Record it explicitly so
            # the report never implies an unmodified timeline.
            self._finding(
                "Sleep patching enabled",
                f"Sleep calls exceeding {threshold}ms were accelerated {factor}×. "
                f"Observed timings in this stage do not reflect wall-clock "
                f"behavior on a real host.",
                severity="info",
            )

    async def execute(self, ctx: StageContext) -> None:
        total = self.config.duration_sec
        interact_every = self.config.params.get("periodic_interaction_interval_sec", 180)
        checkpoint_every = self.config.params.get("checkpoint_interval_sec", 300)
        early_exit = self.config.params.get("early_exit_on_process_death", True)
        early_grace = self.config.params.get("early_exit_grace_sec", 120)

        elapsed = 0.0
        tick = self._tick(30.0, total)
        last_interact = 0.0
        last_checkpoint = 0.0
        dead_since: Optional[float] = None

        activity_timeline: List[Dict[str, Any]] = []

        while elapsed < total:
            if not await self._sleep_interruptible(ctx, tick):
                return
            elapsed += tick

            summary = await ctx.controller.send_command(
                "query_activity_summary", {"window_sec": tick}
            )
            event_count = summary.get("event_count", 0)

            activity_timeline.append({"t": elapsed, "events": event_count})

            # A sample that was quiet for a long stretch and then bursts is the
            # exact pattern this stage exists to catch.
            if event_count > 0 and dead_since is not None:
                self._finding(
                    "Delayed activation detected",
                    f"Activity resumed at T+{int(elapsed // 60)}m after "
                    f"{int((elapsed - dead_since) // 60)} minute(s) of silence. "
                    f"Sleep-gated activation of this length defeats sandboxes "
                    f"that terminate after a few minutes.",
                    severity="critical",
                    mitre=["T1497.003"],
                )
                ctx.shared["delayed_activation_at_sec"] = elapsed
                dead_since = None

            if event_count == 0 and dead_since is None:
                dead_since = elapsed

            if elapsed - last_interact >= interact_every:
                last_interact = elapsed
                await ctx.controller.send_input(
                    "mouse_move_bezier",
                    {
                        "start": (random.randint(0, 1280), random.randint(0, 720)),
                        "end": (random.randint(0, 1280), random.randint(0, 720)),
                        "steps": 30,
                        "curve": True,
                    },
                )

            if elapsed - last_checkpoint >= checkpoint_every:
                last_checkpoint = elapsed
                await self._capture_screenshot(ctx, label=f"t{int(elapsed)}s")
                await ctx.controller.send_command("checkpoint", {"elapsed_sec": elapsed})

            if early_exit and dead_since is not None:
                procs = await ctx.controller.list_processes()
                sample_alive = any(p.get("pid") == ctx.sample_pid for p in procs)
                if not sample_alive and (elapsed - dead_since) > early_grace:
                    self._finding(
                        "Sample process terminated; ending long execution early",
                        f"No sample process and no activity for "
                        f"{int((elapsed - dead_since) // 60)} minute(s). Ending "
                        f"the stage early; memory capture still proceeds.",
                        severity="info",
                    )
                    break

        ctx.shared["long_execution_timeline"] = activity_timeline

        peak = max((a["events"] for a in activity_timeline), default=0)
        if peak > 0:
            self.activity_observed = True
        if peak == 0:
            self._finding(
                "No activity during long execution",
                "The sample produced no observable behavior across the extended "
                "window. Combined with earlier stages, this may indicate the "
                "sample requires conditions not reproduced in this environment, "
                "or is genuinely inert.",
                severity="info",
            )


# ============================================================================
# Stage 8 — Memory Dump
# ============================================================================

class MemoryDumpAction(StageAction):
    """
    Freeze the guest, capture memory, and extract what never touched disk:
    unpacked payloads, C2 config, keys, staged exfil buffers.
    """

    stage_id = StageId.MEMORY_DUMP

    # Extractions that return data on any healthy system. Their mere presence
    # is inventory, not behavior — only the anomalies inside them count as
    # activity, otherwise an inert sample would look active.
    INVENTORY_EXTRACTIONS = {"loaded_dlls", "handles"}

    # Reset per run in execute(); declared here so the helpers are safe to
    # call directly in tests.
    _dlls_reported = False
    _handles_reported = False

    # Directories a legitimate system DLL is never loaded from.
    _SUSPECT_DLL_DIRS = (
        r"\temp", r"\tmp", r"\appdata\local\temp", r"\users\public",
        r"\programdata", r"\downloads", r"\recycle",
    )

    # Access rights on a handle to *another* process that only make sense if
    # the holder intends to write code into it and run it.
    _INJECTION_RIGHTS = (
        "PROCESS_VM_WRITE", "PROCESS_VM_OPERATION", "PROCESS_CREATE_THREAD",
        "THREAD_SET_CONTEXT", "PROCESS_ALL_ACCESS", "THREAD_ALL_ACCESS",
    )

    async def execute(self, ctx: StageContext) -> None:
        params = self.config.params

        # The dedicated extractions and the volatility plugins can both cover
        # modules and handles. Whichever runs first owns the reporting; the
        # other only contributes inventory, so findings aren't emitted twice.
        self._dlls_reported = False
        self._handles_reported = False

        # Full physical memory first — the authoritative artifact
        if params.get("dump_full_physical_memory", True):
            path = await ctx.controller.dump_memory(pid=None)
            if path:
                self.artifacts.append(
                    StageArtifact(
                        artifact_type="memdump",
                        path=path,
                        captured_at=datetime.utcnow(),
                    )
                )
                self._finding(
                    "Full memory dump captured",
                    f"Physical memory image written to {path}"
                    + (
                        " and hashed for chain of custody."
                        if params.get("hash_dump_for_custody", True)
                        else "."
                    ),
                    severity="info",
                )

        # Per-process dumps for anything suspicious
        if params.get("dump_per_process", True):
            procs = await ctx.controller.list_processes()
            targets = (
                [p for p in procs if p.get("suspicious")]
                if params.get("target_suspicious_processes_only", False)
                else procs
            )
            for proc in targets[:25]:  # Bound the work
                pid = proc.get("pid")
                if pid is None:
                    continue
                path = await ctx.controller.dump_memory(pid=pid)
                if path:
                    self.artifacts.append(
                        StageArtifact(
                            artifact_type="process_memdump",
                            path=path,
                            captured_at=datetime.utcnow(),
                        )
                    )

        # Structured extraction
        for extraction in params.get("extractions", []):
            result = await ctx.controller.send_command(
                "extract_from_memory", {"extraction": extraction}
            )
            items = result.get("items", [])
            if not items:
                continue

            if extraction not in self.INVENTORY_EXTRACTIONS:
                self.activity_observed = True
            self._finding(
                *self._describe_extraction(extraction, items)
            )

            if extraction == "config_blocks":
                for item in items:
                    for host in item.get("c2_hosts", []):
                        if host not in ctx.observed_c2_candidates:
                            ctx.observed_c2_candidates.append(host)
            elif extraction == "loaded_dlls":
                await self._process_loaded_dlls(ctx, items, params)
            elif extraction == "handles":
                self._process_handles(ctx, items, params)

        # Volatility structural analysis
        for plugin in params.get("volatility_plugins", []):
            result = await ctx.controller.send_command(
                "volatility", {"plugin": plugin}
            )
            if plugin == "malfind" and result.get("regions"):
                self.activity_observed = True
                self._finding(
                    "Injected code regions found in memory",
                    f"malfind identified {len(result['regions'])} memory region(s) "
                    f"with executable permissions and no backing file — the "
                    f"signature of code injection or in-memory unpacking.",
                    severity="critical",
                    mitre=["T1055"],
                )
            elif plugin == "ldrmodules" and result.get("unlinked"):
                self.activity_observed = True
                self._finding(
                    "Unlinked modules detected",
                    f"{len(result['unlinked'])} loaded module(s) missing from the "
                    f"PEB loader lists, indicating deliberate hiding from module "
                    f"enumeration.",
                    severity="critical",
                    mitre=["T1055.001"],
                )
            elif plugin == "dlllist" and result.get("modules"):
                self._report_dlllist(ctx, result["modules"])
            elif plugin == "handles" and result.get("handles"):
                self._report_handle_table(ctx, result["handles"], params)

        if params.get("yara_scan_memory", True):
            result = await ctx.controller.send_command("yara_scan_memory", {})
            matches = result.get("matches", [])
            if matches:
                self.activity_observed = True
                names = [m.get("rule", "?") for m in matches]
                self._finding(
                    "YARA rules matched in memory",
                    f"{len(matches)} rule match(es) against the memory image: "
                    + ", ".join(names[:8])
                    + ". Memory-only matches indicate payloads that never existed "
                      "unpacked on disk.",
                    severity="critical",
                )

    # --- DLL extraction -------------------------------------------------

    async def _process_loaded_dlls(
        self, ctx: StageContext, items: List[Dict[str, Any]], params: Dict[str, Any]
    ) -> None:
        """
        Turn the recovered module list into artifacts and findings.

        The inventory itself is unremarkable — every process loads DLLs. What
        matters is the modules that shouldn't be there: images with no file
        backing them (reflectively loaded), modules whose in-memory path
        disagrees with the file they claim to be, and system-named DLLs loaded
        out of a user-writable directory.
        """
        ctx.shared["memory_loaded_dlls"] = items
        self._dlls_reported = True

        suspicious = [d for d in items if self._dll_is_suspicious(d)]
        ctx.shared["memory_suspicious_dlls"] = suspicious

        # Dump module images out of the memory image
        if params.get("dump_extracted_dlls", True):
            unbacked_only = params.get("dll_dump_unbacked_only", True)
            to_dump = suspicious if unbacked_only else items
            limit = int(params.get("max_dumped_dlls", 50))
            for module in to_dump[:limit]:
                result = await ctx.controller.send_command(
                    "dump_module",
                    {
                        "pid": module.get("pid"),
                        "base": module.get("base"),
                        "name": module.get("name") or module.get("path"),
                    },
                )
                path = result.get("path")
                if path:
                    self.artifacts.append(
                        StageArtifact(
                            artifact_type="dll_dump",
                            path=path,
                            size_bytes=int(result.get("size_bytes", 0) or 0),
                            sha256=result.get("sha256"),
                            captured_at=datetime.utcnow(),
                        )
                    )

        if not suspicious:
            return

        self.activity_observed = True

        unbacked = [d for d in suspicious if not d.get("disk_backed", True)]
        if unbacked:
            self._finding(
                "Memory-only modules recovered",
                f"{len(unbacked)} loaded module(s) have no file backing them on "
                f"disk: "
                + ", ".join(self._dll_label(d) for d in unbacked[:6])
                + ". Modules that exist only in memory were mapped manually "
                  "rather than loaded by the OS — the standard shape of a "
                  "reflectively loaded payload. The images have been dumped "
                  "for static analysis.",
                severity="critical",
                mitre=["T1620", "T1055.001"],
            )

        mismatched = [
            d for d in suspicious
            if d.get("disk_backed", True) and d.get("path_mismatch")
        ]
        if mismatched:
            self._finding(
                "Module path mismatch in memory",
                f"{len(mismatched)} module(s) report a different path in memory "
                f"than the file they were mapped from: "
                + ", ".join(self._dll_label(d) for d in mismatched[:6])
                + ". This is how a hollowed or overwritten module presents "
                  "itself to module enumeration.",
                severity="critical",
                mitre=["T1055.012"],
            )

        sideloaded = [
            d for d in suspicious
            if d.get("disk_backed", True)
            and not d.get("path_mismatch")
            and self._dll_from_suspect_dir(d)
        ]
        if sideloaded:
            self._finding(
                "Modules loaded from user-writable directories",
                f"{len(sideloaded)} module(s) were loaded from a location no "
                f"legitimate system DLL lives in: "
                + ", ".join(self._dll_label(d) for d in sideloaded[:6])
                + ". Consistent with DLL search-order hijacking or side-loading "
                  "a malicious module next to a trusted executable.",
                severity="warning",
                mitre=["T1574.001", "T1574.002"],
            )

        unsigned = [
            d for d in suspicious
            if d.get("disk_backed", True) and d.get("signed") is False
        ]
        if unsigned and not (mismatched or sideloaded):
            self._finding(
                "Unsigned modules loaded into memory",
                f"{len(unsigned)} loaded module(s) carry no valid signature: "
                + ", ".join(self._dll_label(d) for d in unsigned[:6])
                + ".",
                severity="warning",
                mitre=[],
            )

    def _report_dlllist(
        self, ctx: StageContext, modules: List[Dict[str, Any]]
    ) -> None:
        """Summarize the volatility dlllist inventory (structural view)."""
        ctx.shared["memory_dlllist"] = modules
        if self._dlls_reported:
            # The loaded_dlls extraction already analysed these modules.
            return
        pids = {m.get("pid") for m in modules if m.get("pid") is not None}
        anomalous = [m for m in modules if self._dll_is_suspicious(m)]

        self._finding(
            "Loaded module inventory captured",
            f"dlllist enumerated {len(modules)} module load(s) across "
            f"{len(pids)} process(es)"
            + (
                f", {len(anomalous)} of which are anomalous."
                if anomalous
                else ", all consistent with their on-disk images."
            ),
            severity="warning" if anomalous else "info",
            mitre=[],
        )

    @classmethod
    def _dll_is_suspicious(cls, module: Dict[str, Any]) -> bool:
        if not module.get("disk_backed", True):
            return True
        if module.get("path_mismatch"):
            return True
        if module.get("in_load_order") is False:
            return True
        if module.get("signed") is False:
            return True
        return cls._dll_from_suspect_dir(module)

    @classmethod
    def _dll_from_suspect_dir(cls, module: Dict[str, Any]) -> bool:
        path = (module.get("path") or "").lower().replace("/", "\\")
        return any(part in path for part in cls._SUSPECT_DLL_DIRS)

    @staticmethod
    def _dll_label(module: Dict[str, Any]) -> str:
        name = (
            module.get("name")
            or (module.get("path") or "").replace("/", "\\").rsplit("\\", 1)[-1]
            or "<unnamed>"
        )
        pid = module.get("pid")
        return f"{name} (pid {pid})" if pid is not None else name

    # --- Handle extraction ----------------------------------------------

    def _process_handles(
        self, ctx: StageContext, items: List[Dict[str, Any]], params: Dict[str, Any]
    ) -> None:
        """
        Reduce the extracted handle table to the objects that carry meaning.

        Handles say what the sample had *open* at freeze time, which is often
        the only surviving evidence of a resource it touched: the mutex naming
        its campaign, the process it opened for injection, the token it stole,
        the file it was mid-write to.
        """
        wanted = set(params.get("handle_types_of_interest") or [])
        relevant = [
            h for h in items
            if not wanted or (h.get("type") or "") in wanted
        ]
        ctx.shared["memory_handles"] = relevant
        self._report_handle_table(ctx, relevant, params, already_filtered=True)

    def _report_handle_table(
        self,
        ctx: StageContext,
        handles: List[Dict[str, Any]],
        params: Dict[str, Any],
        already_filtered: bool = False,
    ) -> None:
        if not already_filtered:
            wanted = set(params.get("handle_types_of_interest") or [])
            handles = [
                h for h in handles
                if not wanted or (h.get("type") or "") in wanted
            ]
            ctx.shared.setdefault("memory_handles", handles)
            if self._handles_reported:
                # The handles extraction already reported on this table.
                return
        if not handles:
            return
        self._handles_reported = True

        by_type: Dict[str, int] = {}
        for h in handles:
            by_type[h.get("type") or "Unknown"] = (
                by_type.get(h.get("type") or "Unknown", 0) + 1
            )

        # Mutexes are the highest-value IOC in a handle table: named, stable
        # across infections, and usually unique to a family.
        mutexes = [
            h.get("name") for h in handles
            if (h.get("type") == "Mutant") and h.get("name")
        ]
        if mutexes:
            ctx.shared["memory_mutexes"] = mutexes
            self._finding(
                "Named mutexes recovered from memory",
                f"{len(mutexes)} named mutant object(s) held at capture time: "
                + ", ".join(str(m) for m in mutexes[:6])
                + ". Family-specific mutex names are durable host indicators "
                  "and can be used to detect this sample without a hash.",
                severity="warning",
                mitre=["T1057"],
            )

        # Cross-process handles with write/execute rights
        cross = [h for h in handles if self._handle_is_injection_capable(h)]
        if cross:
            self.activity_observed = True
            targets = ", ".join(
                f"{h.get('target_name') or h.get('target_pid')}"
                for h in cross[:6]
            )
            self._finding(
                "Cross-process handles with injection rights",
                f"{len(cross)} open handle(s) to other process(es) carry memory "
                f"write or thread-creation rights: {targets}. These are the "
                f"handles a sample needs to write and execute code inside "
                f"another process, and they were still open when memory was "
                f"frozen.",
                severity="critical",
                mitre=["T1055"],
            )

        tokens = [h for h in handles if h.get("type") == "Token"]
        if tokens:
            self.activity_observed = True
            self._finding(
                "Access token handles held",
                f"{len(tokens)} token handle(s) open, indicating the sample "
                f"obtained token objects it can duplicate or impersonate to "
                f"run under another security context.",
                severity="critical",
                mitre=["T1134", "T1134.001"],
            )

        sections = [
            h for h in handles
            if h.get("type") == "Section" and h.get("name")
        ]
        if sections:
            self._finding(
                "Shared memory sections open",
                f"{len(sections)} named section object(s) mapped: "
                + ", ".join(str(h.get("name")) for h in sections[:6])
                + ". Named sections are used both for legitimate IPC and to "
                  "stage code into another process.",
                severity="info",
                mitre=["T1055.003"],
            )

        summary = ", ".join(f"{n} {t}" for t, n in sorted(by_type.items()))
        self._finding(
            "Open handle table captured",
            f"Recovered {len(handles)} handle(s) of interest from memory "
            f"({summary}). The handle table records the files, keys, and "
            f"synchronization objects the sample had open at capture time, "
            f"including resources it never left on disk.",
            severity="info",
            mitre=[],
        )

    @classmethod
    def _handle_is_injection_capable(cls, handle: Dict[str, Any]) -> bool:
        if (handle.get("type") or "") not in ("Process", "Thread"):
            return False
        target = handle.get("target_pid")
        # A handle to itself is normal; a handle to someone else is the signal.
        if target is not None and target == handle.get("pid"):
            return False
        access = handle.get("access") or ""
        if isinstance(access, (list, tuple, set)):
            granted = {str(a).upper() for a in access}
        else:
            granted = {a.strip().upper() for a in str(access).split("|") if a.strip()}
        return any(right in granted for right in cls._INJECTION_RIGHTS)

    @staticmethod
    def _describe_extraction(extraction: str, items: List[Any]) -> tuple:
        n = len(items)
        table = {
            "unpacked_pe_images": (
                "Unpacked executables recovered from memory",
                f"Reconstructed {n} PE image(s) that existed only in memory. "
                f"These represent the sample's true payload after unpacking.",
                "critical",
                ["T1027.002"],
            ),
            "injected_code_regions": (
                "Injected code regions extracted",
                f"Extracted {n} region(s) of injected code from other processes.",
                "critical",
                ["T1055"],
            ),
            "loaded_dlls": (
                "Loaded modules extracted from memory",
                f"Recovered {n} loaded module(s) from process address spaces. "
                f"Module images are reconstructed from memory, so DLLs that were "
                f"mapped manually or overwritten after load are captured as they "
                f"actually ran rather than as they appear on disk.",
                "info",
                [],
            ),
            "handles": (
                "Open handles extracted from memory",
                f"Enumerated {n} open handle(s) from process handle tables — the "
                f"files, registry keys, mutexes, sections, tokens, and processes "
                f"held open at the moment memory was frozen.",
                "info",
                [],
            ),
            "config_blocks": (
                "Malware configuration recovered",
                f"Decoded {n} configuration block(s) containing operational "
                f"parameters such as C2 endpoints and campaign identifiers.",
                "critical",
                ["T1027"],
            ),
            "strings_urls_ips": (
                "Network indicators recovered from memory",
                f"Extracted {n} URL/IP indicator(s) present only in memory.",
                "warning",
                [],
            ),
            "crypto_keys": (
                "Cryptographic key material recovered",
                f"Recovered {n} key artifact(s) from memory. These may permit "
                f"decryption of captured traffic or encrypted files.",
                "critical",
                ["T1027"],
            ),
            "credential_artifacts": (
                "Credential artifacts found in memory",
                f"Located {n} credential-shaped artifact(s), indicating "
                f"credential harvesting.",
                "critical",
                ["T1003"],
            ),
            "clipboard_contents": (
                "Clipboard contents captured",
                f"Recovered {n} clipboard item(s) — relevant where the sample "
                f"monitors the clipboard for banking or wallet data.",
                "warning",
                ["T1115"],
            ),
            "staged_exfil_buffers": (
                "Staged exfiltration data found",
                f"Found {n} buffer(s) holding collected data prepared for "
                f"exfiltration. Contents indicate exactly what was targeted.",
                "critical",
                ["T1074.001"],
            ),
        }
        title, detail, severity, mitre = table.get(
            extraction,
            (
                f"Memory extraction: {extraction}",
                f"Recovered {n} item(s).",
                "info",
                [],
            ),
        )
        return title, detail, severity, mitre


# ============================================================================
# Registry
# ============================================================================

STAGE_ACTIONS: Dict[StageId, type[StageAction]] = {
    StageId.BOOT: BootAction,
    StageId.IDLE: IdleAction,
    StageId.USER_INTERACTION: UserInteractionAction,
    StageId.INTERNET_SIMULATION: InternetSimulationAction,
    StageId.PERSISTENCE_CHECK: PersistenceCheckAction,
    StageId.REBOOT: RebootAction,
    StageId.LONG_EXECUTION: LongExecutionAction,
    StageId.MEMORY_DUMP: MemoryDumpAction,
}


def build_action(config: StageConfig) -> StageAction:
    """Instantiate the action class for a stage config."""
    cls = STAGE_ACTIONS[config.stage_id]
    return cls(config)
