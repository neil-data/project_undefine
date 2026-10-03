"""
stage_definitions.py — Multi-stage dynamic analysis pipeline definitions.

WHY THIS EXISTS
---------------
A single-shot detonation ("run the sample for 2 minutes, dump the log") misses
most modern malware. Real samples are evasion-aware:

  • Time-delayed activation — sleeps 10-30 min to outlive typical sandbox TTL
  • Reboot-gated payloads   — only the persistence stub runs pre-reboot; the
                              real payload activates on the second boot
  • Interaction-gated       — waits for mouse movement, a click, a keystroke,
                              or an unlock event before deobfuscating
  • Network-gated           — dormant until it can reach its C2; no internet,
                              no behavior
  • Environment checks      — bails out if no user documents, no browser
                              history, uptime too low, CPU count too low

Each stage below exists to defeat one of those specific evasion classes. The
stage boundaries are also the reporting boundaries: knowing that a sample was
silent through Boot/Idle and only woke at Stage 7 (Long Execution) is itself
evidence, and it's the difference between "clean" and "patient".

STAGE CONTRACT
--------------
Every stage:
  1. Declares its duration budget and the evasion class it defeats
  2. Emits stage_start / stage_end markers into the live event stream
     (so the Phase 1-8 live dashboard can render a stage timeline)
  3. Can be skipped by config, but skips are recorded in the report — an
     un-run stage is never silently treated as "nothing found"
  4. Produces a StageResult that carries forward into the final report
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ============================================================================
# Stage Identity
# ============================================================================

class StageId(str, Enum):
    """
    The eight stages, in execution order. Values are stable identifiers —
    they appear in the DB, the API, and the report, so do not rename them
    without a migration.
    """
    BOOT = "boot"                              # Stage 1
    IDLE = "idle"                              # Stage 2
    USER_INTERACTION = "user_interaction"      # Stage 3
    INTERNET_SIMULATION = "internet_simulation"  # Stage 4
    PERSISTENCE_CHECK = "persistence_check"    # Stage 5
    REBOOT = "reboot"                          # Stage 6
    LONG_EXECUTION = "long_execution"          # Stage 7
    MEMORY_DUMP = "memory_dump"                # Stage 8


# Canonical execution order. The orchestrator walks this list; nothing else
# should hardcode stage sequencing.
STAGE_ORDER: List[StageId] = [
    StageId.BOOT,
    StageId.IDLE,
    StageId.USER_INTERACTION,
    StageId.INTERNET_SIMULATION,
    StageId.PERSISTENCE_CHECK,
    StageId.REBOOT,
    StageId.LONG_EXECUTION,
    StageId.MEMORY_DUMP,
]


class StageStatus(str, Enum):
    """Lifecycle state of a single stage."""
    PENDING = "pending"        # Not yet reached
    RUNNING = "running"        # Currently executing
    COMPLETED = "completed"    # Finished normally
    SKIPPED = "skipped"        # Deliberately not run (config or platform)
    FAILED = "failed"          # Errored; pipeline may continue or abort
    TIMED_OUT = "timed_out"    # Exceeded its duration budget
    ABORTED = "aborted"        # Investigator killed the run mid-stage


class EvasionClass(str, Enum):
    """
    The specific evasion technique each stage is designed to defeat.
    Surfaced in the report so an investigator can explain *why* the
    analysis took 45 minutes.
    """
    NONE = "none"
    TIME_DELAY = "time_delay"                  # Sleep/stall loops
    REBOOT_GATE = "reboot_gate"                # Payload arms on next boot
    INTERACTION_GATE = "interaction_gate"      # Needs mouse/keyboard/unlock
    NETWORK_GATE = "network_gate"              # Needs C2 reachability
    ENVIRONMENT_CHECK = "environment_check"    # Sandbox/VM fingerprinting
    IN_MEMORY_ONLY = "in_memory_only"          # Never touches disk unpacked


# ============================================================================
# Per-Stage Configuration
# ============================================================================

@dataclass
class StageConfig:
    """
    Declarative config for one stage.

    duration_sec is a *budget*, not a fixed sleep: a stage may exit early if
    its completion predicate fires (e.g. persistence artifact detected), and
    is force-terminated if it overruns.
    """
    stage_id: StageId
    display_name: str
    description: str
    defeats: List[EvasionClass]

    # Timing
    duration_sec: int
    min_duration_sec: int = 0        # Never exit before this, even on early-complete
    timeout_grace_sec: int = 30      # Extra time before hard-kill

    # Behavior
    required: bool = True            # If False, a failure does not abort the run
    capture_screenshot: bool = True
    capture_network: bool = True
    capture_memory: bool = False     # Expensive; only Stage 8 by default

    # Platform applicability — a stage that doesn't apply is SKIPPED, not failed
    platforms: List[str] = field(default_factory=lambda: ["windows", "android"])

    # Extra knobs consumed by the stage action implementations
    params: Dict[str, Any] = field(default_factory=dict)

    def applies_to(self, platform: str) -> bool:
        return platform in self.platforms

    @property
    def hard_timeout_sec(self) -> int:
        return self.duration_sec + self.timeout_grace_sec


# ============================================================================
# The Eight Stages
# ============================================================================

STAGE_CONFIGS: Dict[StageId, StageConfig] = {

    # ------------------------------------------------------------------
    # Stage 1 — BOOT
    # ------------------------------------------------------------------
    StageId.BOOT: StageConfig(
        stage_id=StageId.BOOT,
        display_name="Boot",
        description=(
            "Restore the golden snapshot, bring the guest to a clean logged-in "
            "desktop, verify the monitoring agent and network capture are live, "
            "then drop and execute the sample. Everything captured here is "
            "first-contact behavior: unpacking, initial file drops, first "
            "process spawns."
        ),
        defeats=[EvasionClass.NONE],
        duration_sec=120,
        min_duration_sec=30,
        required=True,
        capture_screenshot=True,
        capture_network=True,
        params={
            # Wait for the guest agent to check in before considering boot done
            "await_agent_checkin": True,
            "agent_checkin_timeout_sec": 60,
            # Baseline the system so later stages can diff against it
            "snapshot_baseline": True,
            "baseline_targets": ["filesystem", "registry", "processes", "services"],
        },
    ),

    # ------------------------------------------------------------------
    # Stage 2 — IDLE
    # ------------------------------------------------------------------
    StageId.IDLE: StageConfig(
        stage_id=StageId.IDLE,
        display_name="Idle Observation",
        description=(
            "Deliberately do nothing. No synthetic input, no network changes. "
            "This isolates autonomous behavior — beaconing intervals, scheduled "
            "wakeups, background scanning — from behavior we provoke in later "
            "stages. A sample that is completely silent here but loud in Stage 3 "
            "is interaction-gated, which is a strong report signal."
        ),
        defeats=[EvasionClass.TIME_DELAY],
        duration_sec=300,          # 5 min
        min_duration_sec=120,
        required=True,
        params={
            # Suppress all synthetic activity so idle really means idle
            "suppress_synthetic_input": True,
            # Record inter-packet timing to fingerprint beacon cadence
            "measure_beacon_interval": True,
        },
    ),

    # ------------------------------------------------------------------
    # Stage 3 — USER INTERACTION
    # ------------------------------------------------------------------
    StageId.USER_INTERACTION: StageConfig(
        stage_id=StageId.USER_INTERACTION,
        display_name="Simulated User Interaction",
        description=(
            "Drive synthetic human activity: mouse movement along non-linear "
            "paths, scrolling, clicks, typing, opening a document and a browser, "
            "and a lock/unlock cycle. Many droppers refuse to deobfuscate until "
            "they observe genuine input, specifically to defeat automated "
            "sandboxes that leave the cursor motionless."
        ),
        defeats=[EvasionClass.INTERACTION_GATE, EvasionClass.ENVIRONMENT_CHECK],
        duration_sec=240,
        min_duration_sec=90,
        required=True,
        params={
            "actions": [
                "mouse_move_bezier",     # Curved, human-like cursor paths
                "mouse_scroll",
                "mouse_click",
                "keyboard_type",
                "open_document",         # Populated decoy .docx
                "open_browser",          # Visits a local INetSim-served page
                "lock_unlock",           # Some payloads arm on session unlock
                "switch_windows",
            ],
            # Human-plausible pacing; robotic timing is itself a sandbox tell
            "jitter_ms": [80, 600],
            "decoy_documents_present": True,
            "decoy_browser_history": True,
        },
    ),

    # ------------------------------------------------------------------
    # Stage 4 — INTERNET SIMULATION
    # ------------------------------------------------------------------
    StageId.INTERNET_SIMULATION: StageConfig(
        stage_id=StageId.INTERNET_SIMULATION,
        display_name="Internet Simulation",
        description=(
            "Bring up full INetSim/FakeNet responses so every DNS lookup "
            "resolves and every HTTP/HTTPS request gets a plausible reply. "
            "Network-gated malware stays dormant against a black-holed network "
            "but activates the moment its C2 appears reachable. All traffic is "
            "still contained — no packet leaves the detonation plane."
        ),
        defeats=[EvasionClass.NETWORK_GATE],
        duration_sec=300,
        min_duration_sec=120,
        required=True,
        capture_network=True,
        params={
            "inetsim_profile": "full_response",
            # Answer every DNS query rather than NXDOMAIN, so the sample
            # believes its C2 resolves
            "dns_wildcard": True,
            # Present a TLS cert so HTTPS handshakes complete; we read
            # metadata (JA3, SNI, cert chain) but never decrypt content
            "tls_intercept_metadata_only": True,
            "capture_ja3": True,
            "capture_sni": True,
            # Escalating realism: if silent, try serving a generic C2-ish reply
            "adaptive_response": True,
        },
    ),

    # ------------------------------------------------------------------
    # Stage 5 — PERSISTENCE CHECK
    # ------------------------------------------------------------------
    StageId.PERSISTENCE_CHECK: StageConfig(
        stage_id=StageId.PERSISTENCE_CHECK,
        display_name="Persistence Check",
        description=(
            "Diff the live system against the Stage 1 baseline to enumerate "
            "every persistence foothold installed so far: Run/RunOnce keys, "
            "scheduled tasks, services, WMI event subscriptions, startup folder "
            "entries, and on Android, BOOT_COMPLETED receivers and device-admin "
            "escalation. This is a measurement stage — findings here determine "
            "what we expect to fire in Stage 6."
        ),
        defeats=[EvasionClass.REBOOT_GATE],
        duration_sec=120,
        min_duration_sec=30,
        required=True,
        params={
            "windows_targets": [
                "registry_run_keys",
                "registry_runonce",
                "scheduled_tasks",
                "services",
                "wmi_subscriptions",
                "startup_folder",
                "winlogon_shell",
                "image_file_execution_options",
                "com_hijack",
            ],
            "android_targets": [
                "boot_completed_receivers",
                "device_admin_apps",
                "accessibility_services",
                "foreground_services",
                "work_manager_jobs",
                "alarm_manager_schedules",
            ],
            # Compare against Stage 1 baseline rather than a static allowlist,
            # so we catch novel persistence rather than only known-bad
            "diff_against_baseline": True,
        },
    ),

    # ------------------------------------------------------------------
    # Stage 6 — REBOOT
    # ------------------------------------------------------------------
    StageId.REBOOT: StageConfig(
        stage_id=StageId.REBOOT,
        display_name="Reboot",
        description=(
            "Cleanly restart the guest while preserving disk state, then watch "
            "the second boot. A large class of malware installs only a small "
            "stub on first run and arms the real payload on the following boot — "
            "against a single-shot sandbox that payload is never observed at all. "
            "Post-reboot behavior is compared directly against Stage 5's "
            "predicted persistence entries."
        ),
        defeats=[EvasionClass.REBOOT_GATE, EvasionClass.TIME_DELAY],
        duration_sec=300,
        min_duration_sec=90,
        required=True,
        params={
            "reboot_method": "graceful",       # Fall back to hard reset on hang
            "hard_reset_after_sec": 90,
            "preserve_disk_state": True,       # Critical: never revert to snapshot
            "await_agent_checkin": True,
            "agent_checkin_timeout_sec": 120,
            # Verify each Stage 5 finding actually executed
            "verify_persistence_fired": True,
            # Auto-login so interaction-gated post-boot payloads can proceed
            "auto_login": True,
        },
    ),

    # ------------------------------------------------------------------
    # Stage 7 — LONG EXECUTION
    # ------------------------------------------------------------------
    StageId.LONG_EXECUTION: StageConfig(
        stage_id=StageId.LONG_EXECUTION,
        display_name="Long Execution",
        description=(
            "Run for an extended window with light periodic interaction to "
            "outlast sleep-based evasion. Samples commonly stall 10-30 minutes "
            "specifically because most automated sandboxes give up around the "
            "2-5 minute mark. Optional sleep-patching accelerates observed time "
            "without changing logic, and where it is applied the report says so "
            "explicitly, since it alters the evidentiary picture."
        ),
        defeats=[EvasionClass.TIME_DELAY, EvasionClass.ENVIRONMENT_CHECK],
        duration_sec=1800,         # 30 min — covers the common stall window
        min_duration_sec=600,
        timeout_grace_sec=120,
        required=True,
        params={
            # Hook Sleep/NtDelayExecution and compress long sleeps. Disabled by
            # default: it is an intervention, and evidence-grade runs may want
            # the unmodified timeline.
            "sleep_patching_enabled": False,
            "sleep_patch_threshold_ms": 60_000,
            "sleep_patch_factor": 10,
            # Periodic nudges keep interaction-gated logic satisfied without
            # dominating the behavioral record
            "periodic_interaction_interval_sec": 180,
            # Checkpoint so a crash late in the window doesn't lose the run
            "checkpoint_interval_sec": 300,
            # Exit early if the sample is confirmed dead
            "early_exit_on_process_death": True,
            "early_exit_grace_sec": 120,
        },
    ),

    # ------------------------------------------------------------------
    # Stage 8 — MEMORY DUMP
    # ------------------------------------------------------------------
    StageId.MEMORY_DUMP: StageConfig(
        stage_id=StageId.MEMORY_DUMP,
        display_name="Memory Dump & Extraction",
        description=(
            "Freeze the guest and capture full physical memory plus per-process "
            "address spaces, then run structured extraction. Packed samples are "
            "unpacked in memory and never written to disk in cleartext, so this "
            "is frequently the only place the real C2 addresses, encryption "
            "keys, stolen-data staging buffers, and injected code live."
        ),
        defeats=[EvasionClass.IN_MEMORY_ONLY],
        duration_sec=600,
        min_duration_sec=60,
        required=True,
        capture_memory=True,
        capture_screenshot=True,
        params={
            "dump_full_physical_memory": True,
            "dump_per_process": True,
            "target_suspicious_processes_only": False,
            "extractions": [
                "unpacked_pe_images",       # Reconstruct in-memory PEs
                "injected_code_regions",    # RWX / private-commit anomalies
                "loaded_dlls",              # Dump module images out of memory
                "handles",                  # Open handle table per process
                "config_blocks",            # Decoded C2 config structs
                "strings_urls_ips",
                "crypto_keys",              # AES/RSA material in memory
                "credential_artifacts",
                "clipboard_contents",
                "staged_exfil_buffers",
            ],
            # Volatility-family plugins for structural analysis
            "volatility_plugins": [
                "pslist", "psscan", "pstree",
                "malfind",          # Injected/hidden code
                "ldrmodules",       # Unlinked DLLs
                "dlllist",          # Loaded module inventory per process
                "handles",
                "netscan",
                "cmdline",
                "svcscan",
            ],
            # DLL extraction tuning
            "dump_extracted_dlls": True,     # Write recovered modules to disk
            "max_dumped_dlls": 50,           # Bound the artifact count
            "dll_dump_unbacked_only": True,  # Skip clean, disk-backed system DLLs
            # Handle types worth reporting on; anything else is noise
            "handle_types_of_interest": [
                "Mutant",           # Campaign markers / single-instance locks
                "Event",
                "File",
                "Key",
                "Process",         # Cross-process access → injection
                "Thread",
                "Token",           # Impersonation / privilege theft
                "Section",         # Shared memory used for injection
            ],
            "yara_scan_memory": True,
            "compress_dump": True,
            "hash_dump_for_custody": True,   # Chain-of-custody integrity
        },
    ),
}


# ============================================================================
# Results
# ============================================================================

class StageArtifact(BaseModel):
    """A file produced by a stage (screenshot, pcap, memory dump, ...)."""
    artifact_type: str                 # 'screenshot' | 'pcap' | 'memdump' | 'log'
    path: str
    size_bytes: int = 0
    sha256: Optional[str] = None       # Chain-of-custody
    captured_at: datetime


class StageFinding(BaseModel):
    """
    A discrete, reportable observation from a stage.

    Findings are the unit the narrative agent and the final report consume —
    deliberately coarser than raw events.
    """
    finding_id: UUID = Field(default_factory=uuid4)
    stage_id: StageId
    title: str
    detail: str
    severity: str = "info"             # info | warning | critical
    mitre_techniques: List[str] = Field(default_factory=list)
    evidence_event_ids: List[UUID] = Field(default_factory=list)
    observed_at: datetime


class StageResult(BaseModel):
    """Outcome of one stage. Carried forward into the final report."""
    analysis_id: UUID
    stage_id: StageId
    status: StageStatus

    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    duration_sec: float = 0.0

    # Volume of behavior seen during this stage specifically. The per-stage
    # split is the point: it shows *when* the sample woke up.
    event_count: int = 0
    event_counts_by_type: Dict[str, int] = Field(default_factory=dict)

    # Risk delta attributable to this stage
    risk_score_at_start: int = 0
    risk_score_at_end: int = 0

    findings: List[StageFinding] = Field(default_factory=list)
    artifacts: List[StageArtifact] = Field(default_factory=list)

    # Did the sample do anything at all here?
    activity_detected: bool = False
    # Evasion classes this stage actually provoked (not just targeted)
    evasion_defeated: List[EvasionClass] = Field(default_factory=list)

    error: Optional[str] = None
    skip_reason: Optional[str] = None

    @property
    def risk_delta(self) -> int:
        return self.risk_score_at_end - self.risk_score_at_start


class PipelineResult(BaseModel):
    """Aggregate result across all eight stages."""
    analysis_id: UUID
    platform: str

    started_at: datetime
    ended_at: Optional[datetime] = None
    total_duration_sec: float = 0.0

    stage_results: List[StageResult] = Field(default_factory=list)

    final_risk_score: int = 0
    completed: bool = False
    aborted: bool = False
    abort_reason: Optional[str] = None

    # --- Derived reporting helpers -------------------------------------

    @property
    def activation_stage(self) -> Optional[StageId]:
        """
        First stage where the sample showed meaningful activity.

        This single value answers the question the whole pipeline exists for:
        a sample that first activates at LONG_EXECUTION or REBOOT was
        deliberately hiding from short sandbox runs.
        """
        for result in self.stage_results:
            if result.activity_detected:
                return result.stage_id
        return None

    @property
    def dormant_stages(self) -> List[StageId]:
        """Stages the sample stayed completely silent through."""
        return [
            r.stage_id for r in self.stage_results
            if r.status == StageStatus.COMPLETED and not r.activity_detected
        ]

    @property
    def evasion_profile(self) -> List[EvasionClass]:
        """Every evasion class actually observed across the run."""
        seen: List[EvasionClass] = []
        for result in self.stage_results:
            for ev in result.evasion_defeated:
                if ev not in seen and ev != EvasionClass.NONE:
                    seen.append(ev)
        return seen

    @property
    def all_findings(self) -> List[StageFinding]:
        return [f for r in self.stage_results for f in r.findings]

    def stage(self, stage_id: StageId) -> Optional[StageResult]:
        for r in self.stage_results:
            if r.stage_id == stage_id:
                return r
        return None


# ============================================================================
# Profiles
# ============================================================================

@dataclass
class PipelineProfile:
    """
    A named set of stage overrides.

    QUICK exists because a 45-minute pipeline is wrong for triaging a queue of
    200 samples; DEEP exists because 45 minutes is not nearly enough for a
    sample that is clearly stalling. Investigators pick per case.
    """
    name: str
    description: str
    enabled_stages: List[StageId]
    duration_overrides: Dict[StageId, int] = field(default_factory=dict)
    param_overrides: Dict[StageId, Dict[str, Any]] = field(default_factory=dict)

    def config_for(self, stage_id: StageId) -> Optional[StageConfig]:
        """Materialize the effective config for a stage under this profile."""
        if stage_id not in self.enabled_stages:
            return None

        base = STAGE_CONFIGS[stage_id]

        # Shallow copy with overrides applied — never mutate STAGE_CONFIGS
        cfg = StageConfig(
            stage_id=base.stage_id,
            display_name=base.display_name,
            description=base.description,
            defeats=list(base.defeats),
            duration_sec=self.duration_overrides.get(stage_id, base.duration_sec),
            min_duration_sec=base.min_duration_sec,
            timeout_grace_sec=base.timeout_grace_sec,
            required=base.required,
            capture_screenshot=base.capture_screenshot,
            capture_network=base.capture_network,
            capture_memory=base.capture_memory,
            platforms=list(base.platforms),
            params={**base.params, **self.param_overrides.get(stage_id, {})},
        )

        # A shortened stage must not keep a min_duration longer than its budget
        if cfg.min_duration_sec > cfg.duration_sec:
            cfg.min_duration_sec = max(0, cfg.duration_sec // 2)

        return cfg

    @property
    def estimated_duration_sec(self) -> int:
        return sum(
            self.duration_overrides.get(s, STAGE_CONFIGS[s].duration_sec)
            for s in self.enabled_stages
        )


PROFILE_QUICK = PipelineProfile(
    name="quick",
    description=(
        "~8 minute triage pass. Skips reboot and long execution, so it will "
        "miss reboot-gated and sleep-gated payloads — appropriate for bulk "
        "triage, not for a sample already suspected of stalling."
    ),
    enabled_stages=[
        StageId.BOOT,
        StageId.IDLE,
        StageId.USER_INTERACTION,
        StageId.INTERNET_SIMULATION,
        StageId.PERSISTENCE_CHECK,
        StageId.MEMORY_DUMP,
    ],
    duration_overrides={
        StageId.BOOT: 60,
        StageId.IDLE: 60,
        StageId.USER_INTERACTION: 90,
        StageId.INTERNET_SIMULATION: 90,
        StageId.PERSISTENCE_CHECK: 60,
        StageId.MEMORY_DUMP: 180,
    },
)

PROFILE_STANDARD = PipelineProfile(
    name="standard",
    description=(
        "All eight stages at default budgets (~64 min). The default for "
        "casework — covers time-delay, reboot-gate, interaction-gate and "
        "network-gate evasion."
    ),
    enabled_stages=list(STAGE_ORDER),
)

PROFILE_DEEP = PipelineProfile(
    name="deep",
    description=(
        "Extended run (~2.5 hr) with a 90-minute execution window and a second "
        "reboot cycle's worth of observation. For samples that stayed dormant "
        "through a standard run or that show explicit long-sleep behavior."
    ),
    enabled_stages=list(STAGE_ORDER),
    duration_overrides={
        StageId.IDLE: 600,
        StageId.USER_INTERACTION: 420,
        StageId.INTERNET_SIMULATION: 600,
        StageId.REBOOT: 600,
        StageId.LONG_EXECUTION: 5400,   # 90 min
        StageId.MEMORY_DUMP: 900,
    },
    param_overrides={
        StageId.LONG_EXECUTION: {
            "periodic_interaction_interval_sec": 120,
        },
    },
)

PROFILE_EVIDENCE = PipelineProfile(
    name="evidence",
    description=(
        "Standard timings with every intervention disabled — no sleep patching, "
        "no adaptive network responses. Produces an unmodified behavioral "
        "timeline for court-facing reports, at the cost of possibly missing "
        "long-stall payloads."
    ),
    enabled_stages=list(STAGE_ORDER),
    param_overrides={
        StageId.LONG_EXECUTION: {"sleep_patching_enabled": False},
        StageId.INTERNET_SIMULATION: {"adaptive_response": False},
    },
)

PROFILES: Dict[str, PipelineProfile] = {
    p.name: p for p in (PROFILE_QUICK, PROFILE_STANDARD, PROFILE_DEEP, PROFILE_EVIDENCE)
}

DEFAULT_PROFILE = PROFILE_STANDARD


def get_profile(name: str) -> PipelineProfile:
    """Look up a profile by name, falling back to the standard profile."""
    return PROFILES.get(name, DEFAULT_PROFILE)
