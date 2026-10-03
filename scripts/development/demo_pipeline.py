import asyncio, sys
from uuid import uuid4
sys.path.insert(0, "dynamic-sandbox")
from stages import (MockSandboxController, MockBehaviorScript,
                    StageOrchestrator, get_profile, render_markdown)
async def main():
    script = MockBehaviorScript(
        requires_user_interaction=True, requires_network=True,
        activates_after_reboot=True, installs_persistence=True,
        c2_domains=["update-svc.loanapp-verify.test"],
        memory_yara_hits=["india_scam_loanapp"])
    orch = StageOrchestrator(
        analysis_id=uuid4(), platform="windows",
        sample_path="/samples/suspect.exe",
        controller=MockSandboxController(script=script, speed=1000.0),
        profile=get_profile("standard"), time_scale=60.0)
    r = await orch.run()
    md = render_markdown(r)
    print("report chars:", len(md))
    print("activation:", r.activation_stage)
    print("evasion:", r.evasion_profile)
    print("dormant:", len(r.dormant_stages))
asyncio.run(main())
