

import "pe"
rule genericWindowsInstaller_1640 
 {
	meta:
		sigid = 1640
		date = "2016-02-01 08:00 AM"
		threatname = "genericWindowsInstaller"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "InstallSolution" wide ascii
		$c0 = "Windows Installer" wide ascii
		$d0 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer" wide ascii

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them

}

rule genericMSI_1637 
 {
	meta:
		sigid = 1637
		date = "2016-02-01 08:00 AM"
		threatname = "genericMSI"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { d0 cf 11 e0 a1 b1 1a e1 } // compound document header
$b0 = "Installation Database"
$c0 = "Windows Installer XML" wide ascii
$d0 = { 4d 00  73 00 69 00 45 00 72 00 72 00 6f 00 72 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } // MsiErrorObject as wide since wide is not working

	condition:
		$a0 at 0 and ($b0 or $c0 or $d0 )

}

rule FreeExtractor_2561 
 {
	meta:
		sigid = 2561
		date = "2016-04-01 07:00 AM"
		threatname = "FreeExtractor"
		category = "Adware"
		risk = 0
		
	strings:
		$byte1 = {5B 46 45 5D 0A 4E 61 6D 65 3D}
		$byte2 = "FreeExtractor" wide

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (any of ($byte*))

}

rule genericWise_Installer_1957 
 {
	meta:
		sigid = 1957
		date = "2016-02-01 08:00 AM"
		threatname = "genericWise_Installer"
		category = "Adware"
		risk = 0
		
	strings:
		$wise1 = "WiseInitSuffix"
		$wise2 = "Wise Installation Wizard"

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them

}

rule genericWinZipArchive_1804 
 {
	meta:
		sigid = 1804
		date = "2016-02-01 08:00 AM"
		threatname = "genericWinZipArchive"
		category = "Adware"
		risk = 0
		
	strings:
		$a0 = "_winzip_"
		$a1 = "WinZip Self-Extractor"
		$a2 = "http://www.winzip.com"

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them

}

rule genericCabinetFileUnpacker_1639 
 {
	meta:
		sigid = 1639
		date = "2016-02-01 08:00 AM"
		threatname = "genericCabinetFileUnpacker"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "CabinetSelfExtractor"
		$b0 = "_sfx_manifest_"
		$c0 = "_SFX_CAB_EXE_"

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them

}

rule genericMicrosoftInstaller_1638 
 {
	meta:
		sigid = 1638
		date = "2016-02-01 08:00 AM"
		threatname = "genericMicrosoftInstaller"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "InstallSolution" wide ascii
		$b0 = "InstallConditions" wide ascii
		$c0 = "EstimatedInstallSeconds" wide ascii
		$d0 = "Microsoft.Windows.Installer" wide ascii
		$e0 = "PackageFile=\"WindowsInstaller"
		$f0 = "\\Microsoft\\Windows\\CurrentVersion\\Installer"

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them

}

rule genericCabinetArchive_1636 
 {
	meta:
		sigid = 1636
		date = "2016-02-01 08:00 AM"
		threatname = "genericCabinetArchive"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 4d 53 43 46 00 00 00 00 } // MSCF\0\0\0\0 -- standard header for these files

	condition:
		$a0 at 0

}


rule genericInnoSetupEntrypoint_1634 
 {
	meta:
		sigid = 1634
		date = "2016-02-01 08:00 AM"
		threatname = "genericInnoSetupEntrypoint"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$InnoSetupModule1 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }
		
		$InnoSetupModulev109a = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }
		
		$InnoSetupModulev129 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (for any of them : ($ at pe.entry_point))

}


rule genericWiseInstallerEntrypoint_1631 
 {
	meta:
		sigid = 1631
		date = "2016-02-01 08:00 AM"
		threatname = "genericWiseInstallerEntrypoint"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$WiseInstallerStub2 = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ?? 20 }
		
		$WiseInstallerStub3 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 }
		
		$WiseInstallerStub1 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF }
		
		$WiseInstallerStubv11010291 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 }

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (for any of them : ($ at pe.entry_point))

}

rule genericWiseInstaller_1630 
 {
	meta:
		sigid = 1630
		date = "2016-02-01 08:00 AM"
		threatname = "genericWiseInstaller"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "WiseMain"
		$a1 = "Initializing Wise Installation Wizard"
		$a2 = "Could not extract Wise"

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them

}


rule genericNSISEntrypoint_1627 
 {
	meta:
		sigid = 1627
		date = "2016-02-01 08:00 AM"
		threatname = "genericNSISEntrypoint"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$NullsoftInstallSystemv1xx_1 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
		
		$NullsoftPIMPInstallSystemv13x = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }
		
		$NullsoftInstallSystemv198 = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }
		
		$NullsoftPIMPInstallSystemv1x2 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (for any of them : ($ at pe.entry_point))

}

rule genericInstallShield_1802 
 {
	meta:
		sigid = 1802
		date = "2016-02-01 08:00 AM"
		threatname = "genericInstallShield"
		category = "Adware"
		risk = 0
		
	strings:
		$a0 = "www.installshield.com"
		$a1 = "Software\\InstallShield" wide ascii
		$a2 = "InstallShield"

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and 2 of them

}

rule genericInstallShield_1629 
 {
	meta:
		sigid = 1629
		date = "2016-02-01 08:00 AM"
		threatname = "genericInstallShield"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "Installer : Wrapper.CreateFile"
		$a1 = "InstallShield"
		$a2 = "InstallerLocation"
		$a3 = "\\Microsoft\\Windows\\CurrentVersion\\Installer"
		$a4 = "InstallShield for Windows Installer"
		
		$b0 = "WATAUAVAWH"      // unique to itunes installers?
		$b1 = "Installing package"
		$b2 = "msi.dll"
		$b3 = "\\msiexec.exe"
		$b4 = "CABINET"

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (all of ($a*) or all of ($b*))

}

