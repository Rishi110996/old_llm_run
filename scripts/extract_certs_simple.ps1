<#
.SYNOPSIS
    Extract certificates from apps already installed on device

.DESCRIPTION
    Simple script - no download, no install, just extract certs from apps YOU installed

.EXAMPLE
    .\extract_certs_simple.ps1
#>

param(
    [string]$DeviceSerial,
    [string]$OutputCsv = "financial_app_certificates.csv"
)

# App list
$Apps = @(
    @{ Name = "PhonePe"; Pkg = "com.phonepe.app"; Cat = "upi_wallet"; Pri = "CRITICAL" },
    @{ Name = "Google Pay"; Pkg = "com.google.android.apps.nbu.paisa.user"; Cat = "upi_wallet"; Pri = "CRITICAL" },
    @{ Name = "Paytm"; Pkg = "net.one97.paytm"; Cat = "upi_wallet"; Pri = "CRITICAL" },
    @{ Name = "SBI YONO"; Pkg = "com.sbi.lotusintouch"; Cat = "bank"; Pri = "CRITICAL" },
    @{ Name = "HDFC Bank"; Pkg = "com.snapwork.hdfc"; Cat = "bank"; Pri = "CRITICAL" },
    @{ Name = "ICICI iMobile"; Pkg = "com.csam.icici.bank.imobile"; Cat = "bank"; Pri = "CRITICAL" },
    @{ Name = "Axis Mobile"; Pkg = "com.axis.mobile"; Cat = "bank"; Pri = "CRITICAL" },
    @{ Name = "BHIM"; Pkg = "in.org.npci.upiapp"; Cat = "upi_wallet"; Pri = "HIGH" },
    @{ Name = "Kotak Bank"; Pkg = "com.msf.kbank.mobile"; Cat = "bank"; Pri = "HIGH" },
    @{ Name = "CRED"; Pkg = "com.dreamplug.androidapp"; Cat = "finance"; Pri = "HIGH" },
    @{ Name = "Amazon"; Pkg = "in.amazon.mShop.android.shopping"; Cat = "upi_wallet"; Pri = "HIGH" },
    @{ Name = "Zerodha Kite"; Pkg = "com.zerodha.kite3"; Cat = "trading"; Pri = "HIGH" },
    @{ Name = "Groww"; Pkg = "com.nextbillion.groww"; Cat = "trading"; Pri = "HIGH" },
    @{ Name = "MobiKwik"; Pkg = "com.mobikwik_new"; Cat = "upi_wallet"; Pri = "MEDIUM" },
    @{ Name = "Upstox"; Pkg = "com.upstox.marketapp"; Cat = "trading"; Pri = "MEDIUM" },
    @{ Name = "Angel One"; Pkg = "com.msf.angelmobile"; Cat = "trading"; Pri = "MEDIUM" },
    @{ Name = "PNB"; Pkg = "com.fss.pnb"; Cat = "bank"; Pri = "MEDIUM" },
    @{ Name = "Bank of Baroda"; Pkg = "com.bobibanking.bobimobilebanking"; Cat = "bank"; Pri = "MEDIUM" },
    @{ Name = "Canara Bank"; Pkg = "com.infrasofttech.CanaraBank"; Cat = "bank"; Pri = "MEDIUM" },
    @{ Name = "Union Bank"; Pkg = "com.unionbank.ebanking"; Cat = "bank"; Pri = "MEDIUM" }
)

# Check tools
try { $null = & adb version 2>&1 } catch { Write-Host "[-] ADB not found" -ForegroundColor Red; exit 1 }
try { $null = & keytool -help 2>&1 } catch { Write-Host "[-] keytool not found" -ForegroundColor Red; exit 1 }

# Get device
if (-not $DeviceSerial) {
    $devs = & adb devices | Select-Object -Skip 1 | Where-Object { $_ -match '\t' }
    if ($devs.Count -eq 0) { Write-Host "[-] No devices" -ForegroundColor Red; exit 1 }
    if ($devs.Count -eq 1) { $DeviceSerial = ($devs[0] -split '\t')[0] }
    else { Write-Host "[-] Multiple devices. Use -DeviceSerial" -ForegroundColor Red; exit 1 }
}

Write-Host "[+] Device: $DeviceSerial" -ForegroundColor Green

$results = @()
$found = 0
$notFound = 0

foreach ($app in $Apps) {
    Write-Host "`n[$($app.Name)]" -ForegroundColor White
    
    # Check if installed
    $check = & adb -s $DeviceSerial shell pm list packages $app.Pkg 2>&1
    if ($check -notmatch "package:$($app.Pkg)") {
        Write-Host "  Not installed - SKIP" -ForegroundColor Yellow
        $notFound++
        continue
    }
    
    # Get path
    $pathOut = & adb -s $DeviceSerial shell pm path $app.Pkg 2>&1
    if ($pathOut -notmatch "package:(.+)") {
        Write-Host "  Failed to get path" -ForegroundColor Red
        continue
    }
    $devicePath = $matches[1].Trim()
    
    # Pull APK
    $tempApk = "temp_$($app.Pkg).apk"
    Write-Host "  Pulling APK..." -NoNewline
    & adb -s $DeviceSerial pull $devicePath $tempApk 2>&1 | Out-Null
    
    if (-not (Test-Path $tempApk)) {
        Write-Host " FAILED" -ForegroundColor Red
        continue
    }
    Write-Host " OK" -ForegroundColor Green
    
    # Extract cert
    Write-Host "  Extracting cert..." -NoNewline
    $certOut = & keytool -printcert -jarfile $tempApk 2>&1 | Out-String
    
    $sha1 = if ($certOut -match "SHA1:\s*([A-F0-9:]+)") { ($matches[1] -replace ":", "").ToLower() } else { $null }
    $sha256 = if ($certOut -match "SHA256:\s*([A-F0-9:]+)") { ($matches[1] -replace ":", "").ToLower() } else { $null }
    
    if ($sha1 -and $sha256) {
        Write-Host " OK" -ForegroundColor Green
        Write-Host "    SHA1:   $sha1" -ForegroundColor Cyan
        Write-Host "    SHA256: $sha256" -ForegroundColor Cyan
        
        $results += [PSCustomObject]@{
            App_Name = $app.Name
            Package_Name = $app.Pkg
            Category = $app.Cat
            Priority = $app.Pri
            SHA1 = $sha1
            SHA256 = $sha256
            Already_Installed = $true
            Source = "Device"
        }
        $found++
    } else {
        Write-Host " FAILED" -ForegroundColor Red
    }
    
    # Cleanup
    Remove-Item $tempApk -Force -ErrorAction SilentlyContinue
}

# Export
Write-Host "`n========================================" -ForegroundColor Magenta
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Exported: $OutputCsv" -ForegroundColor Green
    Write-Host "`nSummary:" -ForegroundColor White
    Write-Host "  Found:     $found" -ForegroundColor Green
    Write-Host "  Not found: $notFound" -ForegroundColor Yellow
    Write-Host "`nNext step:" -ForegroundColor Yellow
    Write-Host "python scripts/update_financial_targets_from_csv.py $OutputCsv" -ForegroundColor Cyan
} else {
    Write-Host "[-] No apps found. Install the apps first!" -ForegroundColor Red
}
Write-Host ""
