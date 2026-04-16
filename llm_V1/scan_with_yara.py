import os
import re
import shutil
import subprocess


_SIGNATURE_PROFILES = [
    {
        "file_name": "zstatic-apk-sig.yara",
        "required": True,
    },
    {
        # Curated Bankbot rules adapted for the current static APK dump format.
        # These intentionally avoid loading the broader android_malware.yara set,
        # which contains signatures for different dump formats and would be noisy.
        "file_name": "bankbot-static-bridge.yara",
        "required": False,
    },
    {
        # Curated SMSthief rules adapted for the current static APK dump format.
        # These complement the existing static ruleset without importing the full
        # dynamic-oriented android_malware.yara file.
        "file_name": "smsthief-static-bridge.yara",
        "required": False,
    },
]


def _resolve_yara_executable(script_dir):
    yara_exe = (
        os.environ.get("YARA_BIN")
        or shutil.which("yara")
        or os.path.join(script_dir, "yara-master-v4.5.4-win64", "yara64.exe")
    )
    if not os.path.exists(yara_exe) and shutil.which(yara_exe) is None:
        raise FileNotFoundError(
            f"YARA executable not found: {yara_exe}. Set YARA_BIN or install `yara`."
        )
    return yara_exe


def _extract_rule_text(yara_file_content, detection_name):
    pattern = r"(rule\s+" + re.escape(detection_name) + r"\b[\s\S]*?\n\})"
    rule_match = re.search(pattern, yara_file_content)
    return rule_match.group(1).strip() if rule_match else "<not found in source>"


def _scan_with_signature_file(yara_exe, yara_sig_file, bin_file):
    with open(yara_sig_file, "r", encoding="utf-8") as f:
        yara_file_content = f.read()

    cmd = [yara_exe, yara_sig_file, bin_file]
    yara_output = None
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        yara_output = result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] YARA scan failed on {bin_file} with {os.path.basename(yara_sig_file)}: {exc.stderr}")
        return []

    reports = []
    if not yara_output:
        return reports

    signature_source = os.path.basename(yara_sig_file)
    for line in yara_output.splitlines():
        try:
            detection_name, _full_path = line.strip().split(maxsplit=1)
            reports.append(
                {
                    "detection_rule": detection_name,
                    "full_rule": _extract_rule_text(yara_file_content, detection_name),
                    "signature_source": signature_source,
                }
            )
        except Exception as exc:
            print(f"[ERROR] Failed parsing YARA line from {signature_source}: {line} ({exc})")

    return reports


def scan_this_bin_file_with_static_yara(bin_file):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    yara_exe = _resolve_yara_executable(script_dir)

    reports = []
    seen = set()
    for profile in _SIGNATURE_PROFILES:
        yara_sig_file = os.path.join(script_dir, "yara_exports", profile["file_name"])
        if not os.path.exists(yara_sig_file):
            if profile.get("required"):
                raise FileNotFoundError(f"YARA signature file not found: {yara_sig_file}")
            continue

        for report in _scan_with_signature_file(yara_exe, yara_sig_file, bin_file):
            key = (report.get("detection_rule"), report.get("signature_source"))
            if key in seen:
                continue
            seen.add(key)
            reports.append(report)

    return reports



# re = scan_this_bin_file_with_static_yara("E:\\Malware\\LLM\\samples\\yara_testing\\bin_754db816d70210fafa586aa725aac638.apk\\754db816d70210fafa586aa725aac638_apk_dump.bin")
# print(re)
