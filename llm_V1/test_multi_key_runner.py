import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path


def load_analysis_module(repo_root: Path):
    llm_dir = repo_root / "llm_V1"
    sys.path.insert(0, str(llm_dir))
    module_path = llm_dir / "modified_trial8_multiple_models.py"
    spec = importlib.util.spec_from_file_location("analysis_mod", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    mod = load_analysis_module(repo_root)

    root = Path(tempfile.mkdtemp(prefix="multi_key_validate_"))
    samples = root / "samples"
    report = root / "report"
    samples.mkdir()
    report.mkdir()

    for name in ["a.apk", "b.apk"]:
        (samples / name).write_bytes(b"PK\x03\x04dummy")

    original_isapk = mod.isapk
    original_create_llm_client = mod.create_llm_client
    original_analyze_sample = mod.analyze_sample_with_state
    original_register = mod.register_apk_tools
    original_sha = mod.compute_file_sha256

    try:
        mod.isapk = lambda path: path.endswith(".apk")
        mod.register_apk_tools = lambda: None
        mod.create_llm_client = lambda key_config: object()
        mod.compute_file_sha256 = lambda path: Path(path).stem

        call_log = []
        bad_key_failed = {"done": False}

        def fake_analyze_sample_with_state(*, apk_path, report_dir, state_db, master_log, llm_client, llm_key_name, runner_id, lease_duration_sec):
            apk_name = os.path.basename(apk_path)
            sha256 = mod.compute_file_sha256(apk_path)
            log_path = os.path.join(report_dir, f"{Path(apk_name).stem}_llm_analysis.log")
            verdict_path = os.path.join(report_dir, f"{Path(apk_name).stem}_verdict.json")

            existing = state_db.get(sha256)
            if existing and existing.get("status") in mod.TERMINAL_SAMPLE_STATUSES:
                call_log.append({"runner": llm_key_name, "apk": apk_name, "status": "skipped_terminal"})
                return "skipped_terminal"

            claimed = state_db.try_claim(
                sha256=sha256,
                apk_name=Path(apk_name).stem,
                apk_path=apk_path,
                log_path=log_path,
                verdict_path=verdict_path,
                runner_id=runner_id,
                llm_key_name=llm_key_name,
                lease_duration_sec=lease_duration_sec,
            )
            if not claimed:
                call_log.append({"runner": llm_key_name, "apk": apk_name, "status": "claimed_elsewhere"})
                return "claimed_elsewhere"

            if llm_key_name == "bad-key" and apk_name == "a.apk" and not bad_key_failed["done"]:
                bad_key_failed["done"] = True
                state_db.finish(
                    sha256=sha256,
                    status="failed",
                    last_error="synthetic llm outage",
                    runner_id=runner_id,
                )
                call_log.append({"runner": llm_key_name, "apk": apk_name, "status": "key_unavailable"})
                return "key_unavailable"

            state_db.finish(sha256=sha256, status="done", last_error=None, runner_id=runner_id)
            call_log.append({"runner": llm_key_name, "apk": apk_name, "status": "done"})
            return "done"

        mod.analyze_sample_with_state = fake_analyze_sample_with_state

        bad_rc = mod.run_single_runner(
            folder_path=str(samples),
            report_dir=str(report),
            llm_key_config=mod.LLMKeyConfig(name="bad-key", api_key="x"),
            lease_duration_sec=600.0,
            worker_mode=True,
        )
        good_rc = mod.run_single_runner(
            folder_path=str(samples),
            report_dir=str(report),
            llm_key_config=mod.LLMKeyConfig(name="good-key", api_key="y"),
            lease_duration_sec=600.0,
            worker_mode=True,
        )

        db = mod.AnalysisStateDB(str(report / "analysis_state.sqlite"))
        counts = db.status_counts()
        rows = [db.get("a"), db.get("b")]
        db.close()

        assert bad_rc == mod.RUNNER_KEY_UNAVAILABLE_EXIT_CODE, bad_rc
        assert good_rc == 0, good_rc
        assert counts == {"done": 2}, counts
        assert rows[0]["status"] == "done", rows[0]
        assert rows[0]["attempts"] == 2, rows[0]
        assert rows[1]["status"] == "done", rows[1]

        payload = {
            "bad_runner_exit": bad_rc,
            "good_runner_exit": good_rc,
            "final_counts": counts,
            "call_log": call_log,
        }
        print(json.dumps(payload, indent=2))
        return 0
    finally:
        mod.isapk = original_isapk
        mod.create_llm_client = original_create_llm_client
        mod.analyze_sample_with_state = original_analyze_sample
        mod.register_apk_tools = original_register
        mod.compute_file_sha256 = original_sha
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())