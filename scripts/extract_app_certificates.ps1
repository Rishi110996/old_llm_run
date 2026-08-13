<#
.SYNOPSIS
    Extract signing certificates from legitimate financial apps for baseline verification.

.DESCRIPTION
    This script downloads APKs from Play Store (via APKPure URLs), installs them on a device,
    extracts signing certificate hashes (SHA-1 and SHA-256), and exports to CSV.
    
    Apps already installed on the device are NOT reinstalled or uninstalled.
    Downloaded apps are uninstalled after certificate extraction.

.PARAMETER DeviceSerial
    ADB device serial number. If not provided, uses the only connected device.
    Use 'adb devices' to see available devices.

.PARAMETER OutputCsv
    Path to output CSV file. Default: financial_app_certificates.csv

.PARAMETER TempDir
    Temporary directory for downloaded APKs. Default: .\temp_apks

.PARAMETER KeepApks
    If specified, downloaded APKs are not deleted after processing.

.EXAMPLE
    .\extract_app_certificates.ps1

.EXAMPLE
    .\extract_app_certificates.ps1 -DeviceSerial "emulator-5554"

.EXAMPLE
    .\extract_app_certificates.ps1 -OutputCsv "C:\Baselines\certs.csv" -KeepApks
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DeviceSerial,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputCsv = "financial_app_certificates.csv",
    
    [Parameter(Mandatory=$false)]
    [string]$TempDir = ".\temp_apks",
    
    [Parameter(Mandatory=$false)]
    [switch]$KeepApks
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Color output functions
function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

# ============================================================================
# APP CATALOG - CRITICAL & HIGH PRIORITY APPS
# ============================================================================

$AppCatalog = @(
    # CRITICAL PRIORITY - Most targeted by malware
    @{
        Name = "PhonePe"
        PackageName = "com.phonepe.app"
        Category = "upi_wallet"
        Priority = "CRITICAL"
    },
    @{
        Name = "Google Pay (India)"
        PackageName = "com.google.android.apps.nbu.paisa.user"
        Category = "upi_wallet"
        Priority = "CRITICAL"
    },
    @{
        Name = "Paytm"
        PackageName = "net.one97.paytm"
        Category = "upi_wallet"
        Priority = "CRITICAL"
    },
    @{
        Name = "SBI YONO"
        PackageName = "com.sbi.lotusintouch"
        Category = "bank"
        Priority = "CRITICAL"
    },
    @{
        Name = "HDFC Bank MobileBanking"
        PackageName = "com.snapwork.hdfc"
        Category = "bank"
        Priority = "CRITICAL"
    },
    @{
        Name = "ICICI Bank iMobile Pay"
        PackageName = "com.csam.icici.bank.imobile"
        Category = "bank"
        Priority = "CRITICAL"
    },
    @{
        Name = "Axis Mobile"
        PackageName = "com.axis.mobile"
        Category = "bank"
        Priority = "CRITICAL"
    },
    @{
        Name = "BHIM - Making India Cashless"
        PackageName = "in.org.npci.upiapp"
        Category = "upi_wallet"
        Priority = "HIGH"
    },
    @{
        Name = "Kotak Mobile Banking"
        PackageName = "com.msf.kbank.mobile"
        Category = "bank"
        Priority = "HIGH"
    },
    @{
        Name = "CRED"
        PackageName = "com.dreamplug.androidapp"
        Category = "finance"
        Priority = "HIGH"
    },
    @{
        Name = "Amazon Shopping"
        PackageName = "in.amazon.mShop.android.shopping"
        Category = "upi_wallet"
        Priority = "HIGH"
    },
    @{
        Name = "Zerodha Kite"
        PackageName = "com.zerodha.kite3"
        Category = "trading"
        Priority = "HIGH"
    },
    @{
        Name = "Groww - Stocks and Mutual Funds"
        PackageName = "com.nextbillion.groww"
        Category = "trading"
        Priority = "HIGH"
    },
    @{
        Name = "MobiKwik"
        PackageName = "com.mobikwik_new"
        Category = "upi_wallet"
        Priority = "MEDIUM"
    },
    @{
        Name = "Upstox"
        PackageName = "com.upstox.marketapp"
        Category = "trading"
        Priority = "MEDIUM"
    },
    @{
        Name = "Angel One"
        PackageName = "com.msf.angelmobile"
        Category = "trading"
        Priority = "MEDIUM"
    },
    @{
        Name = "Punjab National Bank"
        PackageName = "com.fss.pnb"
        Category = "bank"
        Priority = "MEDIUM"
    },
    @{
        Name = "Bank of Baroda M-Connect Plus"
        PackageName = "com.bobibanking.bobimobilebanking"
        Category = "bank"
        Priority = "MEDIUM"
    },
    @{
        Name = "Canara ai1"
        PackageName = "com.infrasofttech.CanaraBank"
        Category = "bank"
        Priority = "MEDIUM"
    },
    @{
        Name = "Union Bank of India"
        PackageName = "com.unionbank.ebanking"
        Category = "bank"
        Priority = "MEDIUM"
    }
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Test-AdbAvailable {
    try {
        $null = & adb version 2>&1
        return $true
    } catch {
        Write-Error-Custom "ADB not found. Please install Android SDK Platform Tools."
        Write-Host "Download from: https://developer.android.com/studio/releases/platform-tools" -ForegroundColor Yellow
        return $false
    }
}

function Test-KeytoolAvailable {
    try {
        $null = & keytool -help 2>&1
        return $true
    } catch {
        Write-Error-Custom "keytool not found. Please install Java JDK."
        Write-Host "Download from: https://www.oracle.com/java/technologies/downloads/" -ForegroundColor Yellow
        return $false
    }
}

function Get-AdbDeviceSerial {
    param([string]$PreferredSerial)
    
    if ($PreferredSerial) {
        Write-Status "Using specified device: $PreferredSerial"
        return $PreferredSerial
    }
    
    $devices = & adb devices | Select-Object -Skip 1 | Where-Object { $_ -match '\t' }
    
    if ($devices.Count -eq 0) {
        Write-Error-Custom "No devices connected. Please connect a device or start an emulator."
        return $null
    }
    
    if ($devices.Count -eq 1) {
        $serial = ($devices[0] -split '\t')[0]
        Write-Success "Using device: $serial"
        return $serial
    }
    
    Write-Warning "Multiple devices detected:"
    $devices | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""
    Write-Host "Please specify device with -DeviceSerial parameter" -ForegroundColor Yellow
    return $null
}

function Test-AppInstalled {
    param(
        [string]$DeviceSerial,
        [string]$PackageName
    )
    
    $adbCmd = if ($DeviceSerial) { @("adb", "-s", $DeviceSerial) } else { @("adb") }
    $result = & $adbCmd[0] $adbCmd[1..$adbCmd.Length] shell pm list packages $PackageName 2>&1
    
    return $result -match "package:$PackageName"
}

function Get-AppPath {
    param(
        [string]$DeviceSerial,
        [string]$PackageName
    )
    
    $adbCmd = if ($DeviceSerial) { @("adb", "-s", $DeviceSerial) } else { @("adb") }
    $result = & $adbCmd[0] $adbCmd[1..$adbCmd.Length] shell pm path $PackageName 2>&1
    
    if ($result -match "package:(.+)") {
        return $matches[1].Trim()
    }
    return $null
}

function Get-CertificateHashes {
    param([string]$ApkPath)
    
    if (-not (Test-Path $ApkPath)) {
        Write-Error-Custom "APK not found: $ApkPath"
        return $null
    }
    
    try {
        $output = & keytool -printcert -jarfile $ApkPath 2>&1 | Out-String
        
        $sha1 = $null
        $sha256 = $null
        
        if ($output -match "SHA1:\s*([A-F0-9:]+)") {
            $sha1 = $matches[1] -replace ":", "" | ForEach-Object { $_.ToLower() }
        }
        
        if ($output -match "SHA256:\s*([A-F0-9:]+)") {
            $sha256 = $matches[1] -replace ":", "" | ForEach-Object { $_.ToLower() }
        }
        
        return @{
            SHA1 = $sha1
            SHA256 = $sha256
        }
    } catch {
        Write-Error-Custom "Failed to extract certificate: $_"
        return $null
    }
}

# ============================================================================
# MAIN PROCESSING
# ============================================================================

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Magenta
Write-Host "  Financial App Certificate Extractor" -ForegroundColor Magenta
Write-Host "==========================================================================" -ForegroundColor Magenta
Write-Host ""

# Check prerequisites
if (-not (Test-AdbAvailable)) { exit 1 }
if (-not (Test-KeytoolAvailable)) { exit 1 }

# Get device serial
$device = Get-AdbDeviceSerial -PreferredSerial $DeviceSerial
if (-not $device) { exit 1 }

# Create temp directory
if (-not (Test-Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir | Out-Null
    Write-Success "Created temp directory: $TempDir"
}

# Results collection
$results = @()
$statsTotal = 0
$statsSuccess = 0
$statsAlreadyInstalled = 0
$statsFailed = 0

Write-Host ""
Write-Status "Processing $($AppCatalog.Count) apps..."
Write-Host ""
Write-Host "How this works:" -ForegroundColor White
Write-Host "  - Apps ALREADY installed: Extract cert only (app stays installed)" -ForegroundColor Cyan
Write-Host "  - Apps NOT installed: Auto-download APK → Install → Extract cert → Uninstall" -ForegroundColor Cyan
Write-Host ""
Write-Host "APKs will be downloaded from APKPure automatically" -ForegroundColor Green
Write-Host "No manual steps required!" -ForegroundColor Green
Write-Host ""

foreach ($app in $AppCatalog) {
    $statsTotal++
    
    Write-Host "========================================================================" -ForegroundColor DarkGray
    Write-Host "[$statsTotal/$($AppCatalog.Count)] Processing: $($app.Name)" -ForegroundColor White
    Write-Host "    Package: $($app.PackageName)" -ForegroundColor Gray
    Write-Host "    Priority: $($app.Priority)" -ForegroundColor Gray
    Write-Host "------------------------------------------------------------------------" -ForegroundColor DarkGray
    
    $wasAlreadyInstalled = Test-AppInstalled -DeviceSerial $device -PackageName $app.PackageName
    $apkPath = $null
    $certHashes = $null
    
    try {
        if ($wasAlreadyInstalled) {
            Write-Success "App already installed on device"
            $statsAlreadyInstalled++
            
            # Get app path from device
            $devicePath = Get-AppPath -DeviceSerial $device -PackageName $app.PackageName
            
            if ($devicePath) {
                # Pull APK from device
                $localApkPath = Join-Path $TempDir "$($app.PackageName)_from_device.apk"
                
                Write-Status "Pulling APK from device: $devicePath"
                $adbCmd = if ($device) { @("adb", "-s", $device) } else { @("adb") }
                & $adbCmd[0] $adbCmd[1..$adbCmd.Length] pull $devicePath $localApkPath 2>&1 | Out-Null
                
                if (Test-Path $localApkPath) {
                    $apkPath = $localApkPath
                    Write-Success "APK pulled from device"
                } else {
                    Write-Error-Custom "Failed to pull APK from device"
                }
            }
        } else {
            Write-Warning "App not installed - downloading APK and installing..."
            
            $adbCmd = if ($device) { @("adb", "-s", $device) } else { @("adb") }
            $downloadedApk = Join-Path $TempDir "$($app.PackageName).apk"
            
            # Check if already downloaded
            if (-not (Test-Path $downloadedApk)) {
                Write-Status "Downloading APK from APKPure..."
                
                # APKPure direct download URL format
                $apkpureUrl = "https://d.apkpure.com/b/APK/$($app.PackageName)?version=latest"
                
                try {
                    # Use Invoke-WebRequest with proper headers
                    $headers = @{
                        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                        "Accept" = "*/*"
                    }
                    
                    Write-Status "Downloading from: $apkpureUrl"
                    Invoke-WebRequest -Uri $apkpureUrl -OutFile $downloadedApk -Headers $headers -TimeoutSec 60 -ErrorAction Stop
                    
                    if (Test-Path $downloadedApk) {
                        $fileSize = (Get-Item $downloadedApk).Length / 1MB
                        Write-Success "Downloaded APK ($([math]::Round($fileSize, 2)) MB)"
                    } else {
                        throw "Download failed - file not created"
                    }
                } catch {
                    Write-Warning "APKPure download failed: $_"
                    Write-Status "Trying alternative: APKCombo..."
                    
                    # Try APKCombo as alternative
                    $apkcomboUrl = "https://apkcombo.com/downloader/#package=$($app.PackageName)"
                    
                    try {
                        # APKCombo requires a different approach - download page first
                        $response = Invoke-WebRequest -Uri "https://apkcombo.com/$($app.PackageName)/" -Headers $headers -ErrorAction Stop
                        
                        # Extract actual download link from page
                        if ($response.Content -match 'href="(https://download[^"]+\.apk[^"]*)"') {
                            $realDownloadUrl = $matches[1]
                            Write-Status "Found download link, downloading..."
                            Invoke-WebRequest -Uri $realDownloadUrl -OutFile $downloadedApk -Headers $headers -TimeoutSec 60 -ErrorAction Stop
                            
                            if (Test-Path $downloadedApk) {
                                Write-Success "Downloaded from APKCombo"
                            }
                        } else {
                            throw "Could not find download link"
                        }
                    } catch {
                        Write-Error-Custom "All automatic download methods failed"
                        Write-Host ""
                        Write-Host "Please manually download APK from one of these sources:" -ForegroundColor Yellow
                        Write-Host "  1. APKPure: https://apkpure.com/$($app.PackageName)" -ForegroundColor Cyan
                        Write-Host "  2. APKMirror: https://www.apkmirror.com/" -ForegroundColor Cyan
                        Write-Host "  3. Save as: $downloadedApk" -ForegroundColor Cyan
                        Write-Host ""
                        Write-Host "Press ENTER after downloading (or Ctrl+C to skip)..." -ForegroundColor Yellow
                        Read-Host
                    }
                }
            } else {
                Write-Success "APK already downloaded"
            }
            
            # Install the APK if we have it
            if (Test-Path $downloadedApk) {
                Write-Status "Installing APK to device..."
                $installOutput = & $adbCmd[0] $adbCmd[1..$adbCmd.Length] install -r $downloadedApk 2>&1 | Out-String
                
                if ($installOutput -match "Success") {
                    Write-Success "Installed successfully"
                    $needsUninstall = $true
                    $apkPath = $downloadedApk
                } else {
                    Write-Error-Custom "Installation failed: $installOutput"
                }
            } else {
                Write-Warning "APK not found - skipping this app"
            }
        }
        
        # Extract certificate if we have an APK
        if ($apkPath -and (Test-Path $apkPath)) {
            Write-Status "Extracting certificate hashes..."
            $certHashes = Get-CertificateHashes -ApkPath $apkPath
            
            if ($certHashes -and $certHashes.SHA1 -and $certHashes.SHA256) {
                Write-Success "Certificate extracted successfully"
                Write-Host "    SHA-1:   $($certHashes.SHA1)" -ForegroundColor Green
                Write-Host "    SHA-256: $($certHashes.SHA256)" -ForegroundColor Green
                
                $results += [PSCustomObject]@{
                    App_Name = $app.Name
                    Package_Name = $app.PackageName
                    Category = $app.Category
                    Priority = $app.Priority
                    SHA1 = $certHashes.SHA1
                    SHA256 = $certHashes.SHA256
                    Already_Installed = $wasAlreadyInstalled
                    Source = if ($wasAlreadyInstalled) { "Device" } else { "Manual" }
                }
                
                $statsSuccess++
            } else {
                Write-Error-Custom "Failed to extract certificate hashes"
                $statsFailed++
            }
        } else {
            Write-Warning "No APK available for certificate extraction"
            $statsFailed++
        }
        
    } finally {
        # Uninstall if we installed it (not if it was already there)
        if ($needsUninstall) {
            Write-Host ""
            Write-Status "Uninstalling $($app.PackageName) (it was NOT previously installed)..."
            $adbCmd = if ($device) { @("adb", "-s", $device) } else { @("adb") }
            $uninstallOutput = & $adbCmd[0] $adbCmd[1..$adbCmd.Length] uninstall $app.PackageName 2>&1 | Out-String
            
            if ($uninstallOutput -match "Success") {
                Write-Success "Uninstalled successfully"
            } else {
                Write-Warning "Uninstall may have failed: $uninstallOutput"
            }
        }
        
        # Cleanup: Delete pulled APK if not keeping
        if (-not $KeepApks -and $wasAlreadyInstalled -and $apkPath -and (Test-Path $apkPath)) {
            Remove-Item $apkPath -Force -ErrorAction SilentlyContinue
            Write-Status "Deleted temporary pulled APK"
        }
    }
    
    Write-Host ""
}

# ============================================================================
# EXPORT RESULTS
# ============================================================================

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Magenta
Write-Host "  Export Results" -ForegroundColor Magenta
Write-Host "==========================================================================" -ForegroundColor Magenta
Write-Host ""

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Success "Results exported to: $OutputCsv"
    Write-Host ""
    
    # Display summary table
    $results | Format-Table -AutoSize
    
} else {
    Write-Warning "No certificates extracted. CSV not created."
}

# ============================================================================
# STATISTICS
# ============================================================================

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Magenta
Write-Host "  Summary Statistics" -ForegroundColor Magenta
Write-Host "==========================================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "Total apps processed:      $statsTotal" -ForegroundColor White
Write-Host "Certificates extracted:    $statsSuccess" -ForegroundColor Green
Write-Host "  - From device:           $statsAlreadyInstalled" -ForegroundColor Cyan
Write-Host "Failed/Skipped:            $statsFailed" -ForegroundColor Red
Write-Host ""

if ($statsSuccess -gt 0) {
    Write-Success "Certificate extraction completed!"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Review the CSV file: $OutputCsv" -ForegroundColor Yellow
    Write-Host "2. Update llm_V1/financial_targets.json with the certificate hashes" -ForegroundColor Yellow
    Write-Host "3. For apps not found, manually download APKs to: $TempDir" -ForegroundColor Yellow
    Write-Host "   Name them as: <package.name>.apk (e.g., com.phonepe.app.apk)" -ForegroundColor Yellow
    Write-Host "4. Re-run this script to process manually downloaded APKs" -ForegroundColor Yellow
} else {
    Write-Warning "No certificates were successfully extracted."
    Write-Host "Please ensure you have financial apps installed on your device or" -ForegroundColor Yellow
    Write-Host "manually download APKs to: $TempDir" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Magenta
Write-Host ""
