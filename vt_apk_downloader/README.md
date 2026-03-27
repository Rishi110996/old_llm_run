# VT APK Dataset Builder (hashes + metadata)

This project helps you build an Android APK dataset using **VirusTotal Intelligence Search**.

## What it does

- Queries VirusTotal Intelligence for APKs (≤500KB)
- Collects:
  - **Malicious** APK hashes grouped by malware family (tags)
  - **Benign** APK hashes with `malicious=0` and `suspicious=0`
- Stores **only**:
  - `hashes.txt`
  - `metadata.jsonl`
  - `state.sqlite` (for resume/dedup)

## What it does NOT do

This project **does not download APK binaries**.

Mass-downloading malware binaries can be harmful and may violate policies/terms. If you have a legitimate and approved workflow for obtaining binaries, you should use VirusTotal’s official datasets/feeds and follow their Terms.

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

Collect both malicious + benign:

```bash
python vt_downloader.py --config config.yaml
```

### Smoke test (recommended first run)

Create only a few entries per family and for benign, to verify folder creation and resume logic:

```bash
python vt_downloader.py --config config.yaml --smoke 2
```

### Note on smoke testing

`--smoke N` is meant for a *small real run* against VirusTotal (e.g. `--smoke 10`) to validate queries and output before running the full 100k collection.

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

### Path resolution note

`dataset.output_dir` and `dataset.state_db_path` are resolved **relative to the directory containing your `config.yaml`** (unless you set them as absolute paths). This makes runs consistent even if you launch the script from different working directories.

## Notes on family matching

By default the malicious query uses `tag:{family}` (configurable). If your VT tenant uses a different field/operator to represent the malware family, edit `search.malicious_template` in `config.yaml`.

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
