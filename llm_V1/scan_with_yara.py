import os
import subprocess
import re
import json
import shutil

def scan_this_bin_file_with_static_yara(bin_file):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    yara_exe = (
        os.environ.get("YARA_BIN")
        or shutil.which("yara")
        or os.path.join(script_dir, "yara-master-v4.5.4-win64", "yara64.exe")
    )
    yara_sig_file = os.path.join(script_dir, "yara_exports", "zstatic-apk-sig.yara")

    if not os.path.exists(yara_exe) and shutil.which(yara_exe) is None:
        raise FileNotFoundError(
            f"YARA executable not found: {yara_exe}. Set YARA_BIN or install `yara`."
        )

    if not os.path.exists(yara_sig_file):
        raise FileNotFoundError(f"YARA signature file not found: {yara_sig_file}")

    # Load yara rules content once
    with open(yara_sig_file, "r", encoding="utf-8") as f:
        yara_file_content = f.read()

    reports = []

    apk_name = os.path.basename(bin_file).split("_")[0]  # e.g. hash part before _
    apk_name_full = os.path.basename(bin_file)           # full file name

    cmd = [yara_exe, yara_sig_file, bin_file]
    yara_output = None
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        yara_output = result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] YARA scan failed on {bin_file}: {e.stderr}")

    # Parse YARA output
    if yara_output:
        for line in yara_output.splitlines():
            try:
                detection_name, full_path = line.strip().split(maxsplit=1)

                # Extract full rule including condition (match until closing brace)
                pattern = r"(rule\s+" + re.escape(detection_name) + r"\b[\s\S]*?\n\})"
                rule_match = re.search(pattern, yara_file_content)
                matched_rule = rule_match.group(1).strip() if rule_match else "<not found in source>"

                reports.append({
                    "detection_rule": detection_name,
                    "full_rule": matched_rule
                })

            except Exception as e:
                print(f"[ERROR] Failed parsing line: {line} ({e})")

    return reports



# re = scan_this_bin_file_with_static_yara("E:\\Malware\\LLM\\samples\\yara_testing\\bin_754db816d70210fafa586aa725aac638.apk\\754db816d70210fafa586aa725aac638_apk_dump.bin")
# print(re)
