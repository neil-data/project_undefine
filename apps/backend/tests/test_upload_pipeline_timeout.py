import asyncio

import pytest

from backend.app import pipeline_status as ps
from backend.app.routers import cases


@pytest.mark.asyncio
async def test_upload_pipeline_timeout_sets_failed_and_cleans_temp_files(tmp_path, monkeypatch):
    sample_dir = tmp_path / "upload"
    sample_dir.mkdir()
    sample_path = sample_dir / "sample.apk"
    sample_path.write_bytes(b"fixture")

    async def never_finishes(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(cases, "analyze_and_save", never_finishes)
    monkeypatch.setattr(cases, "_ANALYSIS_PIPELINE_TIMEOUT_SECONDS", 0.01)
    analysis_id = "upload-timeout-regression"

    await cases._run_analysis_pipeline(
        str(sample_path), str(sample_dir), analysis_id,
        user_email="timeout-test@example.invalid",
        original_filename="sample.apk",
        mime_type="application/vnd.android.package-archive",
        file_size_bytes=7,
    )

    job = await ps.get_job(analysis_id)
    assert job["status"] == ps.FAILED
    assert "exceeded 0.01 seconds" in job["error"]
    assert not sample_dir.exists()
