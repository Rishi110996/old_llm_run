# VT APK Dataset Builder

This project helps you build an Android APK dataset using **VirusTotal Intelligence Search** while keeping storage usage manageable.

## What it does

- Queries VirusTotal Intelligence for APKs (≤500KB)
- Collects:
  - **Malicious** APK hashes grouped by malware family (tags)
  - **Benign** APK hashes with `malicious=0` and `suspicious=0`
- Stores dataset metadata:
  - `hashes.txt`
  - `metadata.jsonl`
  - `state.sqlite` (for resume/dedup)
- Optionally downloads a small batch of APKs to `/mnt/ext_storage`
- Optionally runs the analyzer in `../llm_V1/modified_trial8_multiple_models.py`
- Optionally deletes the downloaded sample batch after analysis so storage stays low

Use this only in an approved environment and stay within VirusTotal's Terms and your organization's handling policy for malware samples.

## Requirements

- Python 3.9+
- VirusTotal **premium** key(s) for Intelligence Search

## Setup

```bash
cd vt_apk_downloader
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Edit `config.yaml` and paste your API keys.

Tip: if you use git, keep your real `config.yaml` out of version control (see `.gitignore`) and commit `config.example.yaml` instead.

## Run

Collect both malicious + benign using whatever is configured in `config.yaml`:

```bash
python vt_downloader.py --config config.yaml
```

### Recommended low-storage workflow

The provided config is set up for an automatic staged run:

- all configured malicious families are indexed first
- the next malicious download batch is planned automatically
- the planner keeps each batch under `50 GB`
- binary downloads go to `/mnt/ext_storage/vt_apk_samples`
- analysis reports go to `/mnt/ext_storage/vt_analysis_reports`
- downloaded samples are deleted after successful analysis

That means you can keep building the metadata dataset over time without trying to keep every APK on disk at once, and without manually choosing how many samples to take from each family.

For malicious collection, `dataset.malicious.total_target` is treated as a global target across all configured families, not an equal split. If one family has fewer available samples, the remaining families can continue filling the overall 50k target on later runs.

The planner uses VT size metadata plus the set of already-assigned samples from prior batch manifests, so each rerun knows which malicious samples have already been planned/downloaded and only plans the next unassigned batch.

### Resume behavior

- VT collection is deduplicated by SHA256 in `state.sqlite`, so reruns do not collect or download the same sample again.
- Each downloaded batch gets a `batch_summary.json` manifest before download starts.
- If a run fails during download or analysis, rerun the same command and the downloader will resume pending batches before collecting anything new.
- If all eligible VT API keys are exhausted, the script stops cleanly, keeps progress/state, and can be rerun later.
- The analyzer now keeps `analysis_state.sqlite` in the batch report folder.
- Samples marked `done` are skipped on rerun.
- Samples marked `corrupt` are skipped on rerun.
- Samples marked `failed` are retried on rerun.
- Corrupt means the APK could not be parsed by the Androguard-based analysis stage.
- After each analysis pass, samples marked `done` or `corrupt` are deleted from the batch folder immediately.
- If the whole batch finishes successfully and `cleanup_samples_after_analysis` is enabled, the remaining batch directory is removed entirely.

### Override families or sample cap for one run

Analyze just one family:

```bash
python vt_downloader.py --config config.yaml --only malicious --families Ahmyth
```

Analyze two families with a hard cap of 25 samples in the planned batch:

```bash
python vt_downloader.py --config config.yaml --only malicious --families Ahmyth Spymax --batch-size 25
```

### Check batch status without running anything

Print existing batch status from `batch_summary.json` plus analyzer counts from `analysis_state.sqlite`:

```bash
python vt_downloader.py --config config.yaml --summary-only
```

Restrict the summary to selected malicious families:

```bash
python vt_downloader.py --config config.yaml --summary-only --only malicious --families Ahmyth Spymax
```

### Smoke test

Create only a very small planned batch to verify folder creation and resume logic:

```bash
python vt_downloader.py --config config.yaml --smoke 2
```

`--smoke N` still works as a quick override for "plan/download at most N total samples in this run".

Only malicious:

```bash
python vt_downloader.py --config config.yaml --only malicious
```

Only benign:

```bash
python vt_downloader.py --config config.yaml --only benign
```

Disable progress bars (useful for logs/CI):

```bash
python vt_downloader.py --config config.yaml --no-progress
```

## Output structure

```
output/
  Ahmyth/
    hashes.txt
    metadata.jsonl
  Spymax/
    ...
  benign/
    hashes.txt
    metadata.jsonl
state.sqlite
```

When binary downloading is enabled, each run also creates a timestamped batch directory under `/mnt/ext_storage/vt_apk_samples/`. If analysis is enabled, reports are written to the matching timestamped folder under `/mnt/ext_storage/vt_analysis_reports/`. If cleanup is enabled, the sample batch directory is removed after analysis completes successfully.

### Path resolution note

`dataset.output_dir` and `dataset.state_db_path` are resolved **relative to the directory containing your `config.yaml`** (unless you set them as absolute paths). This makes runs consistent even if you launch the script from different working directories.

## Notes on family matching

By default the malicious query now uses `engines:{family}` with `p:{min_positives}+` and the common APK filter uses `type:apk and size:{max_size_kb}KB-`. If your VT tenant uses a different field/operator, edit `search.malicious_template` in `config.yaml`.

## Key rotation / exhaustion

- Keys are used round-robin.
- On HTTP 429 (rate limit), a key goes into cooldown (based on `Retry-After` if present).
- On 401/403, the key is disabled for the rest of the run.
- If all eligible keys are exhausted, the script sleeps for `api.all_keys_exhausted_sleep_hours` (default 24h) and then resumes.

## Concurrency + rate limiting

This script supports parallel collection across families.

- `api.max_workers` controls how many worker threads collect different families in parallel.
- Keys are **never used concurrently** (per-key lock).
- You can optionally tune pacing in `api.rate_limit.*`:
  - `per_key_min_interval_sec.premium/free`: minimum delay between requests per key tier
  - `global_min_interval_sec`: global pacing across all requests (across keys/threads)
  - `max_in_flight_requests`: cap of concurrent HTTP requests

Practical tip: start with `api.max_workers: 1`, run `--smoke 5`, then increase workers only if you have multiple premium keys and enough quota.
