# SMBA Data Pull

This folder contains a small Python client scaffold for pulling report data from
the internal Zscaler BA UI.

## Setup

1. Create a virtual environment if you want one.
2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env`.
4. Paste your live `JSESSIONID` into `.env`.

Example:

```env
ZSCALER_BASE_URL=https://baui.zscalerfeed.net
ZSCALER_JSESSIONID=your_real_cookie_here
ZSCALER_TIMEOUT=30
ZSCALER_VERIFY_SSL=true
ZSCALER_MAX_WORKERS=8
```

## Current status

- `.env` loading is wired up.
- Session cookie authentication is wired up.
- The report JSON API endpoints from the Burp capture are wired up.
- High-level helpers are available for summary, files, traffic, permissions,
  behavior, MITRE, and screenshots.
- The module is designed to be imported by another Python file.

## Example

```python
from zscaler_report_client import build_client

client = build_client()
sample_id = "4ABF7735020C65C41F7EE12D91EBAA7B"

if client.sample_exists(sample_id):
    summary = client.get_summary(sample_id)
    permissions = client.get_permissions(sample_id)
    traffic = client.get_traffic(sample_id)
else:
    print("Sample not found")
```

If you call a component method for a missing sample, the client raises
`ReportNotFoundError`.

## Full Report Bundle

If another script wants the whole BA view for a sample in one call, use:

```python
from zscaler_report_client import build_client

client = build_client()
report = client.get_full_report(sample_id)
```

That bundle includes:
- top-level sample identifiers and report URL
- summary and classification
- file info and download summary
- traffic, permissions, behavior, MITRE, screenshots
- artifact availability plus metadata for original, dropped, and PCAP

If you want a smaller normalized subset for scoring or enrichment pipelines, use:

```python
core = client.get_core_signal_summary(sample_id)
```

## Downloads

The client also exposes artifact download helpers:

```python
from zscaler_report_client import (
    DownloadNotAvailableError,
    build_client,
)

client = build_client()

if client.has_original_file(sample_id):
    client.download_original_file(sample_id, "downloads/original.zip")

if client.has_pcap_file(sample_id):
    raw_pcap = client.get_pcap_file_bytes(sample_id)

try:
    client.download_dropped_file(sample_id, "downloads/dropped.zip")
except DownloadNotAvailableError:
    pass
```

Supported artifacts are original file content, dropped file content, and PCAP.

You can also inspect the actual file type before saving:

```python
metadata = client.get_original_file_metadata(sample_id)
print(metadata.filename)
print(metadata.detected_type)
print(metadata.extension)
```

If you save to a path with no extension or a `.zs` extension, the client will
rewrite it to the detected extension. For example, `sample.zs` becomes
`sample.zip` or `sample.pcap` based on the downloaded bytes.

## API shape identified from Burp

The capture shows the report page loads JSON from endpoints under:

```text
/ba/api/v1/reports/{sample_id}/...
```

The `bust` query value appears to be a cache-busting timestamp. The same value is
reused across many GET requests, so the client does not need to send it unless
the server later proves it is mandatory.

## Performance

The client fetches independent sections in parallel by default. You can tune the
parallelism with `ZSCALER_MAX_WORKERS` in `.env`.

If you want an async version for an existing `asyncio` pipeline, use
[async_zscaler_report_client.py](E:/LLM/old_llm_with_custom_agent_editor/llm_V1/smba_data_pull/async_zscaler_report_client.py):

```python
from async_zscaler_report_client import build_async_client

async with build_async_client() as client:
    report = await client.get_full_report(sample_id)
```

This keeps the current sync client unchanged while giving you an `aiohttp` path
to benchmark.
