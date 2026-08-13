# Certificate Extraction Scripts

Scripts to extract signing certificates from legitimate financial apps and populate the certificate baseline.

## Quick Start

```powershell
# 1. Connect Android device
adb devices

# 2. Extract certificates from apps on device
.\scripts\extract_app_certificates.ps1

# 3. Update financial_targets.json with extracted certificates
python scripts/update_financial_targets_from_csv.py financial_app_certificates.csv
```

## Scripts

### extract_app_certificates.ps1

PowerShell script that:
- Pulls APKs from connected Android device
- Extracts SHA-1 and SHA-256 certificate fingerprints using keytool
- Exports results to CSV
- Processes 20 high-priority financial apps (banks, UPI, trading)

### update_financial_targets_from_csv.py

Python script that:
- Reads certificate CSV
- Updates llm_V1/financial_targets.json
- Creates automatic backup
- Supports dry-run mode

## Requirements

- **ADB** (Android Debug Bridge)
- **Java JDK** (for keytool command)
- **Python 3.7+**
- **Android device or emulator** with financial apps installed

## Apps Processed (20 total)

**CRITICAL (7):** PhonePe, Google Pay, Paytm, SBI YONO, HDFC, ICICI, Axis  
**HIGH (6):** BHIM, Kotak, CRED, Amazon, Zerodha, Groww  
**MEDIUM (7):** MobiKwik, Upstox, Angel One, PNB, BOB, Canara, Union Bank

## Next Steps

1. Test with known-good APKs (should get "verified_official" status)
2. Test with repackaged malware (should trigger "cert_mismatch" at 0.95 strength)

For detailed usage, see the header comments in each script file.
