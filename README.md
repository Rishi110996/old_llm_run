# APK Analysis Pipeline

This repository contains the v2 APK analysis flow in `llm_V1/apk_pipeline_v2.py`, with the terminal runner in `llm_V1/modified_trial8_multiple_models.py`.

Use these commands only in an approved malware-analysis environment. APK samples may be malicious.

## What The Flow Does

For each APK in a sample directory, the runner:

1. Finds APK-like files by ZIP magic bytes.
2. Claims each sample in `<report-dir>/analysis_state.sqlite` so multiple runners do not analyze the same APK at the same time.
3. Runs `apk_pipeline_v2.run()`:
   - Stage 0: deterministic APK extraction through `APKContext`
   - Stage 0b: ssdeep similarity against `llm_V1/yara_exports/ssdeep.json`
   - Stage 0c: multi-DEX and embedded DEX/APK/JAR checks
   - Stage 0d: app-level class-name entropy checks
   - Stage 1: evidence normalization and YARA evidence conversion
   - Stage 1b: optional Zscaler SMBA enrichment
   - Stage 1c: optional VirusTotal behaviour enrichment
   - Stage 2: behavior clustering
   - Stage 3: deterministic pre-scoring
   - Stage 4: parallel LLM review of clusters that need review
   - Stage 5: final LLM synthesis verdict
4. Writes one log and one verdict JSON per APK.
5. Writes batch-level state and summary files.

## Setup

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.server.txt
```

Linux/macOS equivalent:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.server.txt
```

The static-analysis path can also use external tools when available:

```powershell
java -version
apktool --version
keytool -help
yara --version
```

## LLM Config

Create `llm_V1/config.json`.

Single-runner legacy config:

```json
{
  "base_url_zllama": "https://your-openai-compatible-endpoint.example/v1",
  "api_key_zllama": "YOUR_KEY",
  "llm_runner_name": "runner-1"
}
```

Multi-runner config:

```json
{
  "base_url_zllama": "https://your-openai-compatible-endpoint.example/v1",
  "llm_api_keys": [
    {"name": "runner-1", "api_key": "KEY_1"},
    {"name": "runner-2", "api_key": "KEY_2"},
    {"name": "runner-3", "api_key": "KEY_3"}
  ]
}
```

Use per-runner endpoints when needed:

```json
{
  "base_url_zllama": "https://default-endpoint.example/v1",
  "llm_api_keys": [
    {"name": "runner-east", "api_key": "KEY_1", "base_url": "https://east.example/v1"},
    {"name": "runner-west", "api_key": "KEY_2", "base_url": "https://west.example/v1"}
  ]
}
```

Optional guardrail-related request metadata:

```json
{
  "base_url_zllama": "https://your-openai-compatible-endpoint.example/v1",
  "api_key_zllama": "YOUR_KEY",
  "llm_request_metadata": {
    "guardrails": {
      "custom-pre-guard": true,
      "custom-post-guard": true
    }
  },
  "disable_guardrails_on_policy_error": true,
  "llm_guardrails_disabled_metadata": {
    "guardrails": {
      "custom-pre-guard": false,
      "custom-post-guard": false
    }
  }
}
```

## Analyze APK Samples In A Directory

Recommended layout:

```text
E:\Malware\samples\
  sample1.apk
  sample2.apk
  sample3.apk

E:\Malware\analysis_reports\
```

Run the analyzer over every APK-like file in a directory:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples
```

Write logs and verdicts to a separate report directory:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001
```

Linux/macOS equivalent:

```bash
python llm_V1/modified_trial8_multiple_models.py /mnt/malware/samples --report-dir /mnt/malware/analysis_reports/batch_001
```

## Runner Modes

### Automatic multi-runner mode

If `llm_V1/config.json` contains multiple active `llm_api_keys`, this command starts one subprocess per key:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001
```

Each worker claims samples through `analysis_state.sqlite`, so runners can safely share the same sample directory and report directory.

### Specific runner

Run only one configured runner by name:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --llm-key-name runner-2
```

Use this when you want to test one key, retry with one healthy key, or avoid launching every configured key.

### Worker mode

`--worker-mode` is normally used internally by the parent process, but it can be run manually for debugging one named worker:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --llm-key-name runner-2 --worker-mode
```

Worker mode writes worker-specific files such as:

```text
master_summary_runner-2_<pid>.log
analysis_run_summary_runner-2_<pid>.json
```

### Lease duration

Set how long an in-progress claim remains valid before another runner can recover it after a crash:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --lease-hours 2
```

The minimum effective lease is 300 seconds.

## Enrichment Switches

### SMBA enrichment

Use Zscaler SMBA sandbox data:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --use-smba
```

SMBA reads `ZSCALER_JSESSIONID` from `llm_V1/smba_data_pull/.env`.

Pass a fresh session token from the terminal:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --use-smba --smba-jsessionid "YOUR_JSESSIONID"
```

That updates `llm_V1/smba_data_pull/.env` and uses the token for this run.

### VirusTotal behaviour enrichment

Use VT behaviour data:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --vt-enrich
```

The VT key is loaded through `llm_V1/vt_enrichment.py` from the active VT downloader config.

Skip VT detection-ratio and threat-label evidence while keeping VT traffic, PCAP, IDS, and MITRE behaviour evidence:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --vt-enrich --no-vt-detection
```

Use this for VT-sourced sample batches where the detection ratio is already known and you do not want it to dominate the verdict.

### Combine enrichments

Run with SMBA and VT behaviour enrichment:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --use-smba --vt-enrich
```

Run with SMBA, VT behaviour enrichment, and VT detection evidence disabled:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001 --use-smba --vt-enrich --no-vt-detection
```

## Complete Switch Reference

`modified_trial8_multiple_models.py` supports:

```text
apk_folder
  Required. Directory containing APK samples.

--report-dir PATH
  Optional. Directory for logs, verdict JSON, SQLite state, and summaries.
  Defaults to apk_folder.

--llm-key-name NAME
  Optional. Run with one named entry from llm_V1/config.json.
  If omitted and multiple active keys exist, the parent launches all runners.

--worker-mode
  Internal/debug mode. Runs as a single worker and writes worker-specific summary files.

--lease-hours HOURS
  Optional. Sample claim lease duration. Default: 6.0.
  The runner enforces a minimum of 300 seconds.

--use-smba
  Optional. Add Zscaler SMBA sandbox enrichment.

--smba-jsessionid JSESSIONID
  Optional. Fresh SMBA session cookie. Also updates llm_V1/smba_data_pull/.env.

--vt-enrich
  Optional. Add VirusTotal behaviour enrichment.

--no-vt-detection
  Optional. Skip VT detection-ratio and threat-label evidence.
  Only meaningful with --vt-enrich.
```

Show the built-in help:

```powershell
python llm_V1\modified_trial8_multiple_models.py --help
```

## Outputs

Given:

```powershell
python llm_V1\modified_trial8_multiple_models.py E:\Malware\samples --report-dir E:\Malware\analysis_reports\batch_001
```

Expected report files:

```text
E:\Malware\analysis_reports\batch_001\
  analysis_state.sqlite
  analysis_run_summary.json
  master_summary.log
  worker_launch_manifest.json                 # multi-runner mode only
  master_summary_<runner>_<pid>.log            # worker mode / multi-runner mode
  analysis_run_summary_<runner>_<pid>.json     # worker mode / multi-runner mode
  sample1_llm_analysis.log
  sample1_verdict.json
  sample2_llm_analysis.log
  sample2_verdict.json
```

`sample*_verdict.json` contains:

```json
{
  "apk_file": "sample1.apk",
  "sha256": "...",
  "status": "done",
  "verdict": {
    "Malicious": 1,
    "Suspicious": 0,
    "Clean": 0,
    "Risk-Score": 95,
    "Summary": "...",
    "IOCs": []
  },
  "analysis_time_sec": 123.45,
  "llm_call_count": 4,
  "llm_input_tokens": 12345,
  "llm_output_tokens": 678,
  "llm_total_tokens": 13023
}
```

Status values:

```text
done      Analysis finished and verdict JSON was written.
corrupt   APK could not be parsed or is structurally unusable.
failed    Analysis failed and can be retried.
in_progress
          Sample is currently claimed by a runner, or the runner crashed before the lease expired.
```

Reruns skip `done` and `corrupt` rows, retry `failed` rows, and can reclaim stale `in_progress` rows after the lease expires.

## Debug Evidence Without LLM Calls

To inspect deterministic evidence through Stage 3 without calling the LLM:

```powershell
python llm_V1\debug_evidence_dump.py E:\Malware\samples
```

For a single APK:

```powershell
python llm_V1\debug_evidence_dump.py E:\Malware\samples\sample1.apk
```

With SMBA:

```powershell
python llm_V1\debug_evidence_dump.py E:\Malware\samples --use-smba
```

With VT enrichment:

```powershell
python llm_V1\debug_evidence_dump.py E:\Malware\samples --vt-enrich
```

With VT enrichment but without VT detection-ratio and threat-label evidence:

```powershell
python llm_V1\debug_evidence_dump.py E:\Malware\samples --vt-enrich --no-vt-detection
```

Debug switch reference:

```text
target
  Required. APK file or directory containing APKs.

--use-smba
  Optional. Add SMBA evidence.

--vt-enrich
  Optional. Add VT behaviour evidence.

--no-vt-detection
  Optional. Skip VT detection-ratio and threat-label evidence.
```

## Maintenance Commands

Rebuild `master_summary.log` from a report directory:

```powershell
python llm_V1\rebuild_master_summary.py E:\Malware\analysis_reports\batch_001
```

Choose the output path:

```powershell
python llm_V1\rebuild_master_summary.py E:\Malware\analysis_reports\batch_001 --output E:\Malware\analysis_reports\batch_001\master_summary.rebuilt.log
```

Overwrite an existing rebuilt summary:

```powershell
python llm_V1\rebuild_master_summary.py E:\Malware\analysis_reports\batch_001 --overwrite
```

Build or refresh the ssdeep corpus:

```powershell
python llm_V1\build_ssdeep_corpus.py --apk-dir E:\Malware\labelled_samples --out llm_V1\yara_exports\ssdeep.json
```

Dry-run the corpus build:

```powershell
python llm_V1\build_ssdeep_corpus.py --apk-dir E:\Malware\labelled_samples --dry-run
```

Use a different ssdeep threshold and print every processed file:

```powershell
python llm_V1\build_ssdeep_corpus.py --apk-dir E:\Malware\labelled_samples --out llm_V1\yara_exports\ssdeep.json --threshold 85 --verbose
```

Regression-test the multi-key scheduler without real APK tooling or real LLM calls:

```powershell
python llm_V1\test_multi_key_runner.py
```

## Exit Codes

Common analyzer exit codes:

```text
0  Run completed without failed or in-progress samples.
1  Invalid input or startup failure.
2  Failed/in-progress samples remain, or every LLM key became unavailable.
```

In worker mode, a runner can also return the internal key-unavailable code. The parent treats all workers becoming unavailable as a failed batch.

