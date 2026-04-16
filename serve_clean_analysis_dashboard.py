from __future__ import annotations

import argparse
import http.server
import socketserver
import subprocess
import sys
import threading
from functools import partial
from pathlib import Path


class DashboardRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in {"/", ""}:
            self.path = "/clean_analysis_dashboard.html"
        return super().do_GET()

    def log_message(self, format: str, *args):
        sys.stdout.write("[http] " + (format % args) + "\n")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Periodically rebuild the clean-sample APK dashboard and serve it over HTTP. "
            "Run this from the repository root on the machine that has access to the clean reports."
        )
    )
    parser.add_argument(
        "--report-root",
        required=True,
        help="Root directory containing the clean batch run IDs.",
    )
    parser.add_argument(
        "--output-dir",
        default="clean_dashboard_output",
        help="Directory where the generated dashboard files will be written and served from.",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host/interface to bind the HTTP server to. Defaults to 0.0.0.0",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9999,
        help="Port to serve the dashboard on. Defaults to 9999",
    )
    parser.add_argument(
        "--refresh-seconds",
        type=int,
        default=300,
        help="How often to regenerate the dashboard in seconds. Defaults to 300",
    )
    parser.add_argument(
        "--master-log-name",
        default="master_summary.log",
        help="Master summary filename to aggregate. Defaults to master_summary.log",
    )
    return parser.parse_args()


def build_dashboard(repo_root: Path, report_root: Path, output_dir: Path, master_log_name: str) -> None:
    cmd = [
        sys.executable,
        str(repo_root / "build_clean_analysis_dashboard.py"),
        "--report-root",
        str(report_root),
        "--output-dir",
        str(output_dir),
        "--master-log-name",
        master_log_name,
    ]
    print("[builder] running:", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode != 0:
        if result.stderr.strip():
            print(result.stderr.strip())
        raise RuntimeError(f"Dashboard build failed with exit code {result.returncode}")


def build_loop(
    *,
    stop_event: threading.Event,
    repo_root: Path,
    report_root: Path,
    output_dir: Path,
    master_log_name: str,
    refresh_seconds: int,
) -> None:
    while not stop_event.is_set():
        try:
            build_dashboard(repo_root, report_root, output_dir, master_log_name)
            print(f"[builder] next refresh in {refresh_seconds}s")
        except Exception as exc:
            print(f"[builder] refresh failed: {exc}")

        if stop_event.wait(max(1, refresh_seconds)):
            break


def serve_directory(host: str, port: int, directory: Path) -> None:
    handler = partial(DashboardRequestHandler, directory=str(directory))
    with ThreadingHTTPServer((host, port), handler) as httpd:
        print(f"[server] serving {directory} at http://{host}:{port}/clean_analysis_dashboard.html")
        httpd.serve_forever()


def main() -> int:
    args = parse_args()
    repo_root = Path.cwd().resolve()
    report_root = Path(args.report_root).expanduser().resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    build_dashboard(repo_root, report_root, output_dir, args.master_log_name)

    stop_event = threading.Event()
    builder_thread = threading.Thread(
        target=build_loop,
        kwargs={
            "stop_event": stop_event,
            "repo_root": repo_root,
            "report_root": report_root,
            "output_dir": output_dir,
            "master_log_name": args.master_log_name,
            "refresh_seconds": args.refresh_seconds,
        },
        daemon=True,
    )
    builder_thread.start()

    try:
        serve_directory(args.host, args.port, output_dir)
    except KeyboardInterrupt:
        print("\n[server] stopping")
    finally:
        stop_event.set()
        builder_thread.join(timeout=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())