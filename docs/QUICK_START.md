# Quick Start: Extract Certificate Baselines

## Goal
Extract signing certificates from 20 critical financial apps to populate the certificate baseline in `financial_targets.json`.

## Prerequisites
- **ADB** installed and in PATH
- **Java JDK** installed (for keytool)
- **Android device** or emulator with **Google Play Store** (signed in)

## Step 1: Connect Device

```powershell
# Check devices
adb devices

# Should show something like:
# List of devices attached
# emulator-5554          device
```

## Step 2: Run Extraction Script

```powershell
# Navigate to project root
cd E:\LLM\old_llm_with_custom_agent_editor

# Run the script
.\scripts\extract_app_certificates.ps1
```

## What Happens

### For Apps ALREADY on Device
- ✅ Pulls APK from device
- ✅ Extracts certificate
- ✅ **App stays installed** (not touched)

### For Apps NOT on Device
- 📱 Script opens Play Store on your device
- 👆 You tap **INSTALL** button
- ⏳ Wait for installation to complete
- ▶️ Press ENTER in script
- ✅ Script extracts certificate
- 🗑️ **Uninstalls APK** (cleans up)

## Step 3: Install from Play Store (if needed)

For apps not on your device:

1. Script opens Play Store on your device automatically
2. You'll see:
   ```
   Play Store opened on device. Please:
     1. Tap INSTALL button for PhonePe
     2. Wait for installation to complete
     3. Press ENTER when done...
   ```

3. Tap INSTALL on your device
4. Wait for app to install
5. Press ENTER in the script
6. Script extracts cert and uninstalls the app

## Step 4: Update JSON

```powershell
# Preview changes
python scripts/update_financial_targets_from_csv.py financial_app_certificates.csv --dry-run

# Apply changes
python scripts/update_financial_targets_from_csv.py financial_app_certificates.csv
```

## Expected Output

```
==========================================================================
  Financial App Certificate Extractor
==========================================================================

How this works:
  - Apps ALREADY installed: Extract cert only (app stays installed)
  - Apps NOT installed: Download → Install → Extract cert → Uninstall

Processing 20 apps...

========================================================================
[1/20] Processing: PhonePe
    Package: com.phonepe.app
    Priority: CRITICAL
------------------------------------------------------------------------
[+] App already installed on device (will NOT be uninstalled)
[*] Pulling APK from device: /data/app/.../base.apk
[+] APK pulled from device
[*] Extracting certificate hashes from APK...
[+] Certificate extracted successfully
    SHA-1:   a1b2c3d4e5f6...
    SHA-256: 7f8e9d0c1b2a...

...

Summary Statistics:
  Total apps processed:      20
  Certificates extracted:    15
    - From device:           10  (were already installed)
    - Downloaded:            5   (downloaded, installed, then uninstalled)
  Failed:                    5

[+] Certificate extraction completed!
```

## Troubleshooting

### "No devices connected"
- Enable USB debugging on phone
- Or start Android emulator
- Run `adb devices` to verify

### "Failed to pull APK"
- Some system apps can't be pulled
- Download manually from APKPure instead

### "Installation failed"
- APK may be incompatible with device
- Try different APK version
- Or skip that app for now

## Files Created

```
temp_apks/                                  # Temporary APK storage
├── com.phonepe.app.apk                     # Manually downloaded
├── com.phonepe.app_from_device.apk         # Pulled from device (deleted unless -KeepApks)
└── ...

financial_app_certificates.csv             # Extraction results

llm_V1/
├── financial_targets.json                  # Updated with certs
└── financial_targets.json.backup           # Original backup
```

## Parameters

```powershell
# Specify device (if multiple connected)
.\scripts\extract_app_certificates.ps1 -DeviceSerial "emulator-5554"

# Keep APK files after extraction
.\scripts\extract_app_certificates.ps1 -KeepApks

# Custom output path
.\scripts\extract_app_certificates.ps1 -OutputCsv "C:\Baselines\certs.csv"
```

## Next Steps

After populating certificates:

1. Test with known-good APK → Should show `verified_official`
2. Test with repackaged malware → Should show `cert_mismatch` (0.95 strength)
3. Monitor for legitimate certificate rotations

---

**Ready to start?** Just run: `.\scripts\extract_app_certificates.ps1`
