"""
stage_orchestrator.py — Drives the eight-stage dynamic analysis pipeline.

RESPONSIBILITIES
----------------
  • Walk STAGE_ORDER, running each stage's action within its time budget
  • Emit stage_start / stage_end markers into the live event stream so the
    Phase 1-8 dashboard can render a stage timeline alongside raw events
  • Attribute events and risk-score movement to the stage that produced them —
    this per-stage split is what turns "the sample was malicious" into
    "the sample was silent for 40 minutes, then activated after reboot"
  • Enforce timeouts, honor investigator abort, and degrade gracefully when a
    non-required stage fails
  • Produce a PipelineResult that feeds the narrative agent and final report

The orchestrator deliberately owns *no* sandbox logic. Anything that touches
the guest lives in stage_actions.py behind the SandboxController interface.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

import redis.asyncio as redis
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from .stage_definitions import (
    DEFAULT_PROFILE,
    STAGE_ORDER,
    EvasionClass,
    PipelineProfile,
    PipelineResult,
    StageConfig,
    StageId,
    StageResult,
    StageStatus,
    get_profile,
)
from .stage_actions import SandboxController, StageContext, build_action

_LOGGER = logging.getLogger(__name__)


# Minimum events within a stage before we call it "activity". A couple of
# stray events are noise from the OS, not the sample waking up.
ACTIVITY_THRESHOLD = 5

# Floor on a stage's wall-clock timeout, however hard the run is compressed.
# See StageOrchestrator._stage_timeout.
MIN_STAGE_TIMEOUT_SEC = 30.0


class StageOrchestrator:
    """Executes the multi-stage pipeline for one analysis."""

    def __init__(
        self,
        analysis_id: UUID,
        platform: str,
        sample_path: str,
        controller: SandboxController,
        redis_client: Optional[redis.Redis] = None,
        db_session: Optional[Session] = None,
        profile: Optional[PipelineProfile] = None,
        time_scale: float = 1.0,
    ):
        self.analysis_id = analysis_id
        self.platform = platform
        self.sample_path = sample_path
        self.controller = controller
        self.redis = redis_client
        self.db = db_session
        self.profile = profile or DEFAULT_PROFILE
        self.time_scale = max(1.0, time_scale)

        self.ctx = StageContext(
            analysis_id=analysis_id,
            platform=platform,
            sample_path=sample_path,
            controller=controller,
            time_scale=self.time_scale,
        )

        self.result = PipelineResult(
            analysis_id=analysis_id,
            platform=platform,
            started_at=datetime.utcnow(),
        )

        self._current_stage: Optional[StageId] = None
        self._task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> PipelineResult:
        """Execute the full pipeline. Returns the aggregate result."""
        _LOGGER.info(
            "[%s] Starting %s pipeline (%s), est. %d min",
            self.analysis_id,
            self.profile.name,
            self.platform,
            self.profile.estimated_duration_sec // 60,
        )

        await self._publish_pipeline_event(
            "pipeline_start",
            {
                "profile": self.profile.name,
                "platform": self.platform,
                "stages": [s.value for s in self.profile.enabled_stages],
                "estimated_duration_sec": self.profile.estimated_duration_sec,
            },
        )

        try:
            for stage_id in STAGE_ORDER:
                if self.ctx.abort_requested:
                    self.result.aborted = True
                    # Never overwrite a reason the caller already supplied.
                    # request_abort() records why the run was stopped, and that
                    # specific reason ("sandbox unreachable", who terminated it
                    # and when) is what belongs in an evidence-grade report —
                    # clobbering it with a generic string loses the only record
                    # of why the analysis is incomplete.
                    if not self.result.abort_reason:
                        self.result.abort_reason = "Investigator terminated the run"
                    break

                config = self.profile.config_for(stage_id)

                # Stage disabled by profile
                if config is None:
                    self.result.stage_results.append(
                        self._skipped(
                            stage_id, f"Not enabled in '{self.profile.name}' profile"
                        )
                    )
                    continue

                # Stage doesn't apply to this platform
                if not config.applies_to(self.platform):
                    self.result.stage_results.append(
                        self._skipped(
                            stage_id, f"Not applicable to platform '{self.platform}'"
                        )
                    )
                    continue

                stage_result = await self._run_stage(config)
                self.result.stage_results.append(stage_result)

                # A failed required stage aborts the run — continuing past a
                # failed boot or reboot would produce misleading results.
                if stage_result.status == StageStatus.FAILED and config.required:
                    self.result.aborted = True
                    self.result.abort_reason = (
                        f"Required stage '{stage_id.value}' failed: "
                        f"{stage_result.error}"
                    )
                    _LOGGER.error("[%s] %s", self.analysis_id, self.result.abort_reason)
                    break

            self.result.completed = not self.result.aborted

        except Exception as exc:
            _LOGGER.exception("[%s] Pipeline error", self.analysis_id)
            self.result.aborted = True
            self.result.abort_reason = f"Unhandled pipeline error: {exc}"

        finally:
            self.result.ended_at = datetime.utcnow()
            self.result.total_duration_sec = (
                self.result.ended_at - self.result.started_at
            ).total_seconds()
            self.result.final_risk_score = await self._current_risk_score()

            await self._publish_pipeline_event(
                "pipeline_end",
                {
                    "completed": self.result.completed,
                    "aborted": self.result.aborted,
                    "abort_reason": self.result.abort_reason,
                    "duration_sec": self.result.total_duration_sec,
                    "final_risk_score": self.result.final_risk_score,
                    "activation_stage": (
                        self.result.activation_stage.value
                        if self.result.activation_stage
                        else None
                    ),
                    "evasion_profile": [e.value for e in self.result.evasion_profile],
                },
            )

        return self.result

    def request_abort(self, reason: str = "Investigator terminated the run") -> None:
        """
        Signal the pipeline to stop. Stages sleep in 1-second slices, so this
        lands within about a second rather than at the end of a 30-minute stage.
        """
        _LOGGER.info("[%s] Abort requested: %s", self.analysis_id, reason)
        self.ctx.abort_requested = True
        self.result.abort_reason = reason

    @property
    def current_stage(self) -> Optional[StageId]:
        return self._current_stage

    def progress(self) -> Dict[str, Any]:
        """Snapshot for the live dashboard's stage timeline widget."""
        done = len([r for r in self.result.stage_results if r.status != StageStatus.PENDING])
        total = len(self.profile.enabled_stages)
        return {
            "analysis_id": str(self.analysis_id),
            "profile": self.profile.name,
            "current_stage": self._current_stage.value if self._current_stage else None,
            "stages_completed": done,
            "stages_total": total,
            "percent": round(100.0 * done / total, 1) if total else 0.0,
            "elapsed_sec": (datetime.utcnow() - self.result.started_at).total_seconds(),
            "estimated_total_sec": self.profile.estimated_duration_sec,
            "stage_results": [
                {
                    "stage_id": r.stage_id.value,
                    "status": r.status.value,
                    "duration_sec": r.duration_sec,
                    "event_count": r.event_count,
                    "activity_detected": r.activity_detected,
                    "risk_delta": r.risk_delta,
                    "finding_count": len(r.findings),
                }
                for r in self.result.stage_results
            ],
        }

    # ------------------------------------------------------------------
    # Stage execution
    # ------------------------------------------------------------------

    async def _run_stage(self, config: StageConfig) -> StageResult:
        stage_id = config.stage_id
        self._current_stage = stage_id

        result = StageResult(
            analysis_id=self.analysis_id,
            stage_id=stage_id,
            status=StageStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        result.risk_score_at_start = await self._current_risk_score()

        _LOGGER.info(
            "[%s] ── Stage %d/%d: %s (budget %ds)",
            self.analysis_id,
            STAGE_ORDER.index(stage_id) + 1,
            len(STAGE_ORDER),
            config.display_name,
            config.duration_sec,
        )

        await self._publish_pipeline_event(
            "stage_start",
            {
                "stage_id": stage_id.value,
                "display_name": config.display_name,
                "description": config.description,
                "defeats": [e.value for e in config.defeats],
                "duration_budget_sec": config.duration_sec,
                "stage_index": STAGE_ORDER.index(stage_id) + 1,
                "stage_total": len(STAGE_ORDER),
            },
        )

        action = build_action(config)

        try:
            await asyncio.wait_for(
                self._execute_action(action),
                timeout=self._stage_timeout(config),
            )
            result.status = (
                StageStatus.ABORTED if self.ctx.abort_requested else StageStatus.COMPLETED
            )

        except asyncio.TimeoutError:
            # Overrunning the budget is expected occasionally (a long memory
            # dump, a slow reboot). Record it rather than failing the run.
            _LOGGER.warning(
                "[%s] Stage %s exceeded %ds budget",
                self.analysis_id,
                stage_id.value,
                config.hard_timeout_sec,
            )
            result.status = StageStatus.TIMED_OUT
            result.error = f"Exceeded {config.hard_timeout_sec}s budget"

        except Exception as exc:
            _LOGGER.exception("[%s] Stage %s failed", self.analysis_id, stage_id.value)
            result.status = StageStatus.FAILED
            result.error = str(exc)

        finally:
            # Always try teardown so artifacts survive a failed stage
            try:
                await action.teardown(self.ctx)
            except Exception as exc:
                _LOGGER.warning("Teardown failed for %s: %s", stage_id.value, exc)

            result.ended_at = datetime.utcnow()
            result.duration_sec = (result.ended_at - result.started_at).total_seconds()
            result.findings = action.findings
            result.artifacts = action.artifacts
            result.risk_score_at_end = await self._current_risk_score()

            # Attribute events in this time window to this stage
            counts = await self._count_events(result.started_at, result.ended_at)
            result.event_count = sum(counts.values())
            result.event_counts_by_type = counts

            # Two independent activity signals, either of which is sufficient.
            #
            # The DB event count is the richer signal but is absent without a
            # database and lags when event ingestion is backed up. The action's
            # own observation is narrower but always available. Requiring both
            # would make the pipeline report "dormant" whenever telemetry is
            # degraded — and a false "dormant" reads as "clean", which is the
            # one wrong answer this system cannot afford to give.
            result.activity_detected = (
                result.event_count >= ACTIVITY_THRESHOLD
                or action.activity_observed
            )

            result.evasion_defeated = self._infer_evasion(config, result)

            self._current_stage = None

            await self._publish_pipeline_event(
                "stage_end",
                {
                    "stage_id": stage_id.value,
                    "status": result.status.value,
                    "duration_sec": result.duration_sec,
                    "event_count": result.event_count,
                    "event_counts_by_type": result.event_counts_by_type,
                    "activity_detected": result.activity_detected,
                    "risk_delta": result.risk_delta,
                    "findings": [
                        {
                            "title": f.title,
                            "detail": f.detail,
                            "severity": f.severity,
                            "mitre_techniques": f.mitre_techniques,
                        }
                        for f in result.findings
                    ],
                    "evasion_defeated": [e.value for e in result.evasion_defeated],
                },
            )

            _LOGGER.info(
                "[%s] ── Stage %s %s — %d events, risk %+d, %d finding(s)",
                self.analysis_id,
                config.display_name,
                result.status.value,
                result.event_count,
                result.risk_delta,
                len(result.findings),
            )

        return result

    async def _execute_action(self, action) -> None:
        await action.setup(self.ctx)
        await action.execute(self.ctx)

    # ------------------------------------------------------------------
    # Evasion inference
    # ------------------------------------------------------------------

    def _infer_evasion(self, config: StageConfig, result: StageResult) -> List[EvasionClass]:
        """
        Decide which evasion classes this stage actually *provoked*, versus the
        ones it was merely designed to target.

        The rule is the same in each case: the stage counts as having defeated
        an evasion class only if the sample was quiet before it and active
        during it. A sample that was already noisy in Stage 1 isn't evading
        anything.
        """
        if not result.activity_detected:
            return []

        # Was the sample quiet in every prior completed stage?
        prior = [
            r for r in self.result.stage_results
            if r.status == StageStatus.COMPLETED
        ]
        was_dormant = all(not r.activity_detected for r in prior) if prior else False

        defeated: List[EvasionClass] = []
        shared = self.ctx.shared

        if config.stage_id == StageId.USER_INTERACTION and was_dormant:
            defeated.append(EvasionClass.INTERACTION_GATE)

        if config.stage_id == StageId.INTERNET_SIMULATION and shared.get("network_gated"):
            defeated.append(EvasionClass.NETWORK_GATE)

        if config.stage_id == StageId.REBOOT and (
            shared.get("reboot_gated") or shared.get("persistence_survives_reboot")
        ):
            defeated.append(EvasionClass.REBOOT_GATE)

        if config.stage_id == StageId.LONG_EXECUTION and shared.get(
            "delayed_activation_at_sec"
        ):
            defeated.append(EvasionClass.TIME_DELAY)

        if config.stage_id == StageId.MEMORY_DUMP and any(
            "memory" in f.title.lower() or "unpacked" in f.title.lower()
            for f in result.findings
        ):
            defeated.append(EvasionClass.IN_MEMORY_ONLY)

        return defeated

    # ------------------------------------------------------------------
    # Live monitoring integration
    # ------------------------------------------------------------------

    async def _publish_pipeline_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Push a pipeline marker into the same Redis stream the live dashboard
        already consumes, so stage boundaries render inline with raw events.
        """
        if not self.redis:
            return

        try:
            stream = f"analysis:{self.analysis_id}:events"
            message = {
                "event_type": "pipeline",
                "pipeline_event": event_type,
                "analysis_id": str(self.analysis_id),
                "timestamp": datetime.utcnow().isoformat(),
                "payload": payload,
            }
            await self.redis.xadd(stream, {"data": json.dumps(message)})
        except Exception as exc:
            # Never let a telemetry failure take down the analysis
            _LOGGER.warning("Failed to publish %s: %s", event_type, exc)

    async def _count_events(
        self, start: datetime, end: datetime
    ) -> Dict[str, int]:
        """Count events recorded during a stage window, grouped by type."""
        if not self.db:
            return {}

        try:
            from backend.app.models.db_models import AnalysisEvent

            stmt = (
                select(AnalysisEvent.event_type, func.count(AnalysisEvent.id))
                .where(
                    and_(
                        AnalysisEvent.analysis_id == self.analysis_id,
                        AnalysisEvent.timestamp >= start,
                        AnalysisEvent.timestamp <= end,
                    )
                )
                .group_by(AnalysisEvent.event_type)
            )
            rows = self.db.execute(stmt).all()
            return {str(row[0]): int(row[1]) for row in rows}
        except Exception as exc:
            _LOGGER.warning("Event count query failed: %s", exc)
            return {}

    async def _current_risk_score(self) -> int:
        """Read the latest risk score written by the Phase 3 risk agent."""
        if not self.db:
            return 0

        try:
            from backend.app.models.db_models import RiskScore

            stmt = (
                select(RiskScore.score)
                .where(RiskScore.analysis_id == self.analysis_id)
                .order_by(RiskScore.timestamp.desc())
                .limit(1)
            )
            score = self.db.execute(stmt).scalar_one_or_none()
            return int(score) if score is not None else 0
        except Exception as exc:
            _LOGGER.warning("Risk score query failed: %s", exc)
            return 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _stage_timeout(self, config: StageConfig) -> float:
        """
        Wall-clock limit for one stage, honoring compression without pretending
        that everything compresses.

        A stage's *waiting* scales — that is the point of time_scale. Its work
        does not: the input synthesizer still issues hundreds of calls, and
        each one costs what it costs. Dividing the whole budget by the scale
        gave a stage 50ms to do several seconds of real work at scale 1000,
        so compressed runs reported TIMED_OUT stages that had not hung at all
        — which reaches the dashboard as instability or evasion that never
        happened.

        The floor keeps the timeout meaningful for its actual purpose, which
        is catching a genuinely wedged stage.
        """
        return max(config.hard_timeout_sec / self.time_scale, MIN_STAGE_TIMEOUT_SEC)

    def _skipped(self, stage_id: StageId, reason: str) -> StageResult:
        _LOGGER.info("[%s] Stage %s skipped: %s", self.analysis_id, stage_id.value, reason)
        return StageResult(
            analysis_id=self.analysis_id,
            stage_id=stage_id,
            status=StageStatus.SKIPPED,
            skip_reason=reason,
        )


# ============================================================================
# Convenience entrypoint
# ============================================================================

async def run_pipeline(
    analysis_id: UUID,
    platform: str,
    sample_path: str,
    controller: SandboxController,
    profile_name: str = "standard",
    redis_client: Optional[redis.Redis] = None,
    db_session: Optional[Session] = None,
    time_scale: float = 1.0,
) -> PipelineResult:
    """
    Run the multi-stage pipeline end to end.

    Example
    -------
        result = await run_pipeline(
            analysis_id=uuid4(),
            platform="windows",
            sample_path="/samples/suspect.exe",
            controller=CapeSandboxController(...),
            profile_name="standard",
            redis_client=redis_client,
            db_session=session,
        )
        print(result.activation_stage)   # e.g. StageId.LONG_EXECUTION
        print(result.evasion_profile)    # [TIME_DELAY, REBOOT_GATE]
    """
    orchestrator = StageOrchestrator(
        analysis_id=analysis_id,
        platform=platform,
        sample_path=sample_path,
        controller=controller,
        redis_client=redis_client,
        db_session=db_session,
        profile=get_profile(profile_name),
        time_scale=time_scale,
    )
    return await orchestrator.run()
