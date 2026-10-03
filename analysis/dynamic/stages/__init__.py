"""
Multi-stage dynamic analysis pipeline.

Eight sequenced stages designed to defeat evasion-aware malware that hides from
single-shot sandbox detonation:

    1. Boot                 — clean start, baseline, detonate
    2. Idle                 — observe autonomous behavior only
    3. User Interaction     — defeat interaction-gated activation
    4. Internet Simulation  — defeat network-gated activation
    5. Persistence Check    — enumerate footholds vs. baseline
    6. Reboot               — defeat reboot-gated payloads
    7. Long Execution       — outlast sleep/stall evasion
    8. Memory Dump          — recover what never touched disk

Usage
-----
    from stages import run_pipeline, MockSandboxController, render_markdown

    result = await run_pipeline(
        analysis_id=uuid4(),
        platform="windows",
        sample_path="/samples/suspect.exe",
        controller=MockSandboxController(),
        profile_name="standard",
    )

    print(result.activation_stage)   # StageId.LONG_EXECUTION
    print(result.evasion_profile)    # [EvasionClass.TIME_DELAY, ...]
    print(render_markdown(result))
"""

from .stage_definitions import (
    DEFAULT_PROFILE,
    PROFILE_DEEP,
    PROFILE_EVIDENCE,
    PROFILE_QUICK,
    PROFILE_STANDARD,
    PROFILES,
    STAGE_CONFIGS,
    STAGE_ORDER,
    EvasionClass,
    PipelineProfile,
    PipelineResult,
    StageArtifact,
    StageConfig,
    StageFinding,
    StageId,
    StageResult,
    StageStatus,
    get_profile,
)
from .stage_actions import (
    STAGE_ACTIONS,
    BootAction,
    IdleAction,
    InternetSimulationAction,
    LongExecutionAction,
    MemoryDumpAction,
    PersistenceCheckAction,
    RebootAction,
    SandboxController,
    StageAction,
    StageContext,
    UserInteractionAction,
    build_action,
)
from .stage_orchestrator import StageOrchestrator, run_pipeline
from .controllers import (
    AndroidSandboxController,
    CapeSandboxController,
    MockBehaviorScript,
    MockSandboxController,
)
from .stage_report import (
    build_report,
    render_markdown,
    to_narrative_input,
)

__all__ = [
    # Definitions
    "StageId", "StageStatus", "EvasionClass",
    "StageConfig", "StageResult", "StageFinding", "StageArtifact",
    "PipelineResult", "PipelineProfile",
    "STAGE_ORDER", "STAGE_CONFIGS",
    "PROFILES", "PROFILE_QUICK", "PROFILE_STANDARD", "PROFILE_DEEP",
    "PROFILE_EVIDENCE", "DEFAULT_PROFILE", "get_profile",
    # Actions
    "StageAction", "StageContext", "SandboxController",
    "BootAction", "IdleAction", "UserInteractionAction",
    "InternetSimulationAction", "PersistenceCheckAction", "RebootAction",
    "LongExecutionAction", "MemoryDumpAction",
    "STAGE_ACTIONS", "build_action",
    # Orchestration
    "StageOrchestrator", "run_pipeline",
    # Controllers
    "CapeSandboxController", "AndroidSandboxController",
    "MockSandboxController", "MockBehaviorScript",
    # Reporting
    "build_report", "render_markdown", "to_narrative_input",
]
