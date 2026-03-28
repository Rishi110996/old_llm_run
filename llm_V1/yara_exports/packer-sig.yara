

import "pe"

rule Win32_Packer_BoxedApp_132489 
 {
	meta:
		sigid = 132489
		date = "2024-06-07 12:10 PM"
		threatname = "Win32.Packer.BoxedApp"
		category = "Malware & Botnet"
		risk = 0
		description = "Detects Native PE binary packed by BoxedApp Packer (result is Native PE binary)"
        author = "Jiri Vinopal @ Check Point Research"
        date = "2024-04-29"
        modified = "2024-04-29"
        reference = "https://www.boxedapp.com/boxedapppacker/"
        hash = "77c30d1e3f12151b4e3d3090355c8ce06582f4d0dd3cdb395caa836bd80a97f6"
        tags = "BoxedApp"
        tool = "BoxedApp"
	
    strings:
        $boxedapp_s1 = "bxsdk" ascii wide
        $boxedapp_s2 = "BoxedAppSDK_Init" ascii
        $boxedapp_dotnet1 = "DotNetAppStub" ascii
    condition:
        (uint16(0) == 0x5a4d) and (uint16(uint32(0x3c)) == 0x4550) and
        all of ($boxedapp_s*) and not $boxedapp_dotnet1 and
        for any i in (0..pe.number_of_sections-1) : (pe.sections[i].name == ".bxpck" )

}


rule Win32_Packer_BoxedApp_132490 
 {
	meta:
		sigid = 132490
		date = "2024-06-07 12:13 PM"
		threatname = "Win32.Packer.BoxedApp"
		category = "Malware & Botnet"
		risk = 0
		description = "Detects .NET PE binary packed by BoxedApp Packer (result is Native PE binary)"
        author = "Jiri Vinopal @ Check Point Research"
        date = "2024-04-29"
        modified = "2024-04-29"
        reference = "https://www.boxedapp.com/boxedapppacker/"
        hash = "c76d2e396d654f6f92ea7cd58d43e739b9f406529369709adece23638436cd25"
        tags = "BoxedApp"
        tool = "BoxedApp"
	

    strings:
        $boxedapp_s1 = "bxsdk" ascii wide
        $boxedapp_s2 = "BoxedAppSDK_Init" ascii
        $boxedapp_dotnet1 = "DotNetAppStub" ascii
    condition:
        (uint16(0) == 0x5a4d) and (uint16(uint32(0x3c)) == 0x4550) and
        all of ($boxedapp_*) and
        for any i in (0..pe.number_of_sections-1) : (pe.sections[i].name == ".bxpck" )

}


rule Packer_MSLRH_z_940 
 {
	meta:
		sigid = 940
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}

rule Packer_SPLayer_z_938 
 {
	meta:
		sigid = 938
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SPLayer.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8D 40 00 B9 ?? ?? ?? ?? 6A ?? 58 C0 0C ?? ?? 48 ?? ?? 66 13 F0 91 3B D9 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }
	condition:
		$a0


}


rule Packer_EXELOCK_z_834 
 {
	meta:
		sigid = 834
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXELOCK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Petite_z_747 
 {
	meta:
		sigid = 747
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8D ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 83 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_662 
 {
	meta:
		sigid = 662
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_576 
 {
	meta:
		sigid = 576
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 04 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PCShrink_z_475 
 {
	meta:
		sigid = 475
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PCShrink.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_IDApplicationProtector_z_399 
 {
	meta:
		sigid = 399
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.IDApplicationProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F2 0B 47 00 B9 19 22 47 00 81 E9 EA 0E 47 00 89 EA 81 C2 EA 0E 47 00 8D 3A 89 FE 31 C0 E9 D3 02 00 00 CC CC CC CC E9 CA 02 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 6F 66 74 57 61 72 65 50 72 6F 74 65 63 74 6F 72 5C }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Upack_z_416 
 {
	meta:
		sigid = 416
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }

	condition:
		$a0

}

rule Packer_MoleBox_z_414 
 {
	meta:
		sigid = 414
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MoleBox.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 00 8B 4D F0 8B 11 89 15 ?? ?? ?? 00 8B 45 FC A3 ?? ?? ?? 00 5F 5E 8B E5 5D C3 CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 24 61 58 58 FF D0 E8 ?? ?? 00 00 6A 00 FF 15 ?? ?? ?? 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC }
	condition:
		$a0


}


rule Packer_Armadillo_z_420 
 {
	meta:
		sigid = 420
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 48 11 00 00 59 89 7D FC FF 75 08 E8 01 49 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 66 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 AF F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 EE 0F 00 00 59 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Krypton_z_419 
 {
	meta:
		sigid = 419
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Krypton.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Krypton_z_417 
 {
	meta:
		sigid = 417
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Krypton.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_413 
 {
	meta:
		sigid = 413
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEPack_z_411 
 {
	meta:
		sigid = 411
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEEncrypt_z_410 
 {
	meta:
		sigid = 410
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEEncrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D 0F 05 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_themida_z_407 
 {
	meta:
		sigid = 407
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }
		$a1 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA ?? ?? ?? ?? 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }
	condition:
		$a0 or $a1


}

rule Packer_PolyBox_z_405 
 {
	meta:
		sigid = 405
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PolyBox.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 33 C9 51 51 51 51 51 53 33 C0 55 68 84 2C 40 00 64 FF 30 64 89 20 C6 45 FF 00 B8 B8 46 40 00 BA 24 00 00 00 E8 8C F3 FF FF 6A 24 BA B8 46 40 00 8B 0D B0 46 40 00 A1 94 46 40 00 E8 71 FB FF FF 84 C0 0F 84 6E 01 00 00 8B 1D D0 46 40 00 8B C3 83 C0 24 03 05 D8 46 40 00 3B 05 B4 46 40 00 0F 85 51 01 00 00 8D 45 F4 BA B8 46 40 00 B9 10 00 00 00 E8 A2 EC FF FF 8B 45 F4 BA 9C 2C 40 00 E8 F1 ED FF FF }
	condition:
		$a0


}


rule Packer_DEF_z_403 
 {
	meta:
		sigid = 403
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DEF.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { FC 06 1E 0E 8C C8 01 ?? ?? ?? BA ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_402 
 {
	meta:
		sigid = 402
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_400 
 {
	meta:
		sigid = 400
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_329 
 {
	meta:
		sigid = 329
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 B4 4C CD 21 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_246 
 {
	meta:
		sigid = 246
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASProtect_z_160 
 {
	meta:
		sigid = 160
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 68 01 ?? ?? ?? C3 AA }
	condition:
		$a0 at pe.entry_point


}

rule Packer_AlexProtector_z_75 
 {
	meta:
		sigid = 75
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AlexProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 }
	condition:
		$a0


}


rule Packer_EXEShield_z_359 
 {
	meta:
		sigid = 359
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEShield.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 }
		$a1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 90 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_PEProtect_z_466 
 {
	meta:
		sigid = 466
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NorthStarPEShrinker_z_464 
 {
	meta:
		sigid = 464
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NorthStarPEShrinker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_463 
 {
	meta:
		sigid = 463
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_461 
 {
	meta:
		sigid = 461
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Petite_z_458 
 {
	meta:
		sigid = 458
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 B8 00 90 90 00 6A 00 68 90 90 90 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_codeCrypter_z_455 
 {
	meta:
		sigid = 455
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.codeCrypter.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VProtector_z_454 
 {
	meta:
		sigid = 454
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_432 
 {
	meta:
		sigid = 432
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 7B 11 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_430 
 {
	meta:
		sigid = 430
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CrunchPE_z_429 
 {
	meta:
		sigid = 429
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CrunchPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_UPX_z_427 
 {
	meta:
		sigid = 427
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 }
	condition:
		$a0


}


rule Packer_PKLITE_z_426 
 {
	meta:
		sigid = 426
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 20 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_424 
 {
	meta:
		sigid = 424
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 60 33 C9 75 02 EB 15 EB 33 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_422 
 {
	meta:
		sigid = 422
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEiDBundle_z_153 
 {
	meta:
		sigid = 153
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEiDBundle.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ExcaliburV103forgot_z_151 
 {
	meta:
		sigid = 151
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExcaliburV103forgot.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PCGuard_z_322 
 {
	meta:
		sigid = 322
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PCGuard.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_321 
 {
	meta:
		sigid = 321
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 53 03 00 00 8D 9D 02 02 00 00 33 FF E8 ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Packman_z_148 
 {
	meta:
		sigid = 148
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Packman.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PELock_z_393 
 {
	meta:
		sigid = 393
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PELock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_GameGuardnProtect_z_391 
 {
	meta:
		sigid = 391
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.GameGuardnProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE ?? ?? ?? ?? 31 FF 74 06 61 E9 4A 4D 50 30 8D BE ?? ?? ?? ?? 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B 40 0C 8B 40 0C C7 40 20 00 10 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 85 C0 75 16 E9 12 00 00 00 31 C0 64 A0 20 00 00 00 85 C0 75 05 E9 01 00 00 00 61 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_390 
 {
	meta:
		sigid = 390
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 BF A4 42 00 81 E9 8E 74 42 00 8B D5 81 C2 8E 74 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 63 29 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AnslymFUDCrypter_z_388 
 {
	meta:
		sigid = 388
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AnslymFUDCrypter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CrunchPE_z_386 
 {
	meta:
		sigid = 386
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CrunchPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 09 C6 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Krypton_z_385 
 {
	meta:
		sigid = 385
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Krypton.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Krypton_z_383 
 {
	meta:
		sigid = 383
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Krypton.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Krypton_z_382 
 {
	meta:
		sigid = 382
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Krypton.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_377 
 {
	meta:
		sigid = 377
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_376 
 {
	meta:
		sigid = 376
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? 02 00 00 F7 D1 83 F1 FF 59 BA 32 21 ?? 00 F7 D1 83 F1 FF F7 D1 83 F1 FF 80 02 E3 F7 D1 83 F1 FF C0 0A 05 F7 D1 83 F1 FF 80 02 6F F7 D1 83 F1 FF 80 32 A4 F7 D1 83 F1 FF 80 02 2D F7 D1 83 F1 FF 42 49 85 C9 75 CD 1C 4F 8D 5B FD 62 1E 1C 4F 8D 5B FD 4D 9D B9 ?? ?? ?? 1E 1C 4F 8D 5B FD 22 1C 4F 8D 5B FD 8E A2 B9 B9 E2 83 DB E2 E5 4D CD 1E BF 60 AB 1F 4D DB 1E 1E 3D 1E 92 1B 8E DC 7D EC A4 E2 4D E5 20 C6 CC B2 8E EC 2D 7D DC 1C 4F 8D 5B FD 83 56 8E E0 3A 7D D0 8E 9D 6E 7D D6 4D 25 06 C2 AB 20 CC 3A 4D 2D 9D 6B 0B 81 45 CC 18 4D 2D 1F A1 A1 6B C2 CC F7 E2 4D 2D 9E 8B 8B CC DE 2E 2D F7 1E AB 7D 45 92 30 8E E6 B9 7D D6 8E 9D 27 DA FD FD 1E 1E 8E DF B8 7D CF 8E A3 4D 7D DC 1C 4F 8D 5B FD 33 D7 1E 1E 1E A6 0B 41 A1 A6 42 61 6B 41 6B 4C 45 1E 21 F6 26 BC E2 62 1E 62 1E 62 1E 23 63 59 ?? 1E 62 1E 62 1E 33 D7 1E 1E 1E 85 6B C2 41 AB C2 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 20 33 9E 1E 1E 1E 85 A2 0B 8B C2 27 41 EB A1 A2 C2 1E C0 FD F0 FD 30 62 1E 33 7E 1E 1E 1E C6 2D 42 AB 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 C0 FD F0 8E 1D 1C 4F 8D 5B FD E0 00 33 5E 1E 1E 1E BF 0B EC C2 E6 42 A2 C2 45 1E C0 FD F0 FD 30 CE 36 CC F2 1C 4F 8D 5B FD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_374 
 {
	meta:
		sigid = 374
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }
		$a1 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_PeCompact_z_373 
 {
	meta:
		sigid = 373
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ExeSmasher_z_371 
 {
	meta:
		sigid = 371
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeSmasher.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_VMProtect_z_369 
 {
	meta:
		sigid = 369
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VMProtect.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
	condition:
		$a0


}

rule Packer_ASProtect_z_366 
 {
	meta:
		sigid = 366
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0


}


rule Packer_Armadillo_z_365 
 {
	meta:
		sigid = 365
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_364 
 {
	meta:
		sigid = 364
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VxNecropolis_z_362 
 {
	meta:
		sigid = 362
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VxNecropolis.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B4 30 CD 21 3C 03 ?? ?? B8 00 12 CD 2F 3C FF B8 ?? ?? ?? ?? B4 4A BB 40 01 CD 21 ?? ?? FA 0E 17 BC ?? ?? E8 ?? ?? FB A1 ?? ?? 0B C0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Shrink_z_361 
 {
	meta:
		sigid = 361
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Shrink.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 ?? ?? 50 9C FC BE ?? ?? 8B FE 8C C8 05 ?? ?? 8E C0 06 57 B9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_299 
 {
	meta:
		sigid = 299
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_356 
 {
	meta:
		sigid = 356
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASProtect_z_354 
 {
	meta:
		sigid = 354
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXEShield_z_353 
 {
	meta:
		sigid = 353
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEShield.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_FreeCryptor_z_351 
 {
	meta:
		sigid = 351
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FreeCryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 90 68 27 ?? ?? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }
	condition:
		$a0


}


rule Packer_EXEShield_z_350 
 {
	meta:
		sigid = 350
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEShield.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 }
		$a1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 90 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Shrinker_z_346 
 {
	meta:
		sigid = 346
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Shrinker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_344 
 {
	meta:
		sigid = 344
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CrunchPE_z_140 
 {
	meta:
		sigid = 140
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CrunchPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 55 BB ?? ?? ?? ?? 03 DD 53 64 67 FF 36 ?? ?? 64 67 89 26 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_146 
 {
	meta:
		sigid = 146
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SLVc0deProtector_z_319 
 {
	meta:
		sigid = 319
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SLVc0deProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
		$a1 = { E8 01 00 00 00 A0 5D EB 01 69 81 ED 5F 1A 40 00 8D 85 92 1A 40 00 F3 8D 95 83 1A 40 00 8B C0 8B D2 2B C2 83 E8 05 89 42 01 E8 FB FF FF FF 69 83 C4 08 E8 06 00 00 00 69 E8 F2 FF FF FF F3 B9 05 00 00 00 51 8D B5 BF 1A 40 00 8B FE B9 58 15 00 00 AC 32 C1 F6 }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_FreeJoiner_z_318 
 {
	meta:
		sigid = 318
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FreeJoiner.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 32 ?? 66 8B C3 58 E8 ?? FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PEArmor_z_316 
 {
	meta:
		sigid = 316
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEArmor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 }
	condition:
		$a0


}

rule Packer_Rpolycrypt_z_315 
 {
	meta:
		sigid = 315
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rpolycrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 58 ?? ?? ?? ?? ?? ?? ?? E8 00 00 00 58 E8 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? 04 }
	condition:
		$a0


}


rule Packer_WWPack_z_313 
 {
	meta:
		sigid = 313
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 05 C0 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_309 
 {
	meta:
		sigid = 309
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_307 
 {
	meta:
		sigid = 307
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 }
		$a1 = { 60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E }
		$a2 = { BE ?? ?? ?? ?? AD 50 FF ?? ?? EB }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point


}


rule Packer_Obsidium_z_306 
 {
	meta:
		sigid = 306
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_304 
 {
	meta:
		sigid = 304
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 00 50 40 00 6A 00 68 BB 21 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Packman_v_z_302 
 {
	meta:
		sigid = 302
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Packman.v.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? 48 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Djoin_z_301 
 {
	meta:
		sigid = 301
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Djoin.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Shrinker_z_164 
 {
	meta:
		sigid = 164
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Shrinker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04 }
	condition:
		$a0


}


rule Packer_Armadillo_z_717 
 {
	meta:
		sigid = 717
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_595 
 {
	meta:
		sigid = 595
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ACProtect_z_594 
 {
	meta:
		sigid = 594
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ACProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 55 53 45 52 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 6F 72 74 5F 45 6E 64 73 73 00 }
	condition:
		$a0


}


rule Packer_ThinstallEmbedded_z_592 
 {
	meta:
		sigid = 592
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ThinstallEmbedded.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_591 
 {
	meta:
		sigid = 591
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
		$a1 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_AlexProtector_z_587 
 {
	meta:
		sigid = 587
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AlexProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DxPack_z_584 
 {
	meta:
		sigid = 584
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DxPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_531 
 {
	meta:
		sigid = 531
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_UPX_z_582 
 {
	meta:
		sigid = 582
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }

	condition:
		$a0

}


rule Packer_SimplePack_z_579 
 {
	meta:
		sigid = 579
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimplePack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD ?? ?? ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PEQuake_z_578 
 {
	meta:
		sigid = 578
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEQuake.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E8 A5 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? ?? 00 5B ?? ?? 00 6E ?? ?? 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 }
	condition:
		$a0


}


rule Packer_FSG_z_474 
 {
	meta:
		sigid = 474
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
		$a1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_UPX_z_572 
 {
	meta:
		sigid = 572
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF ?? ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF ?? ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB E1 FF ?? ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? ?? ?? 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
	condition:
		$a0


}


rule Packer_PeCompact_z_494 
 {
	meta:
		sigid = 494
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_DragonArmorOrient_z_447 
 {
	meta:
		sigid = 447
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DragonArmorOrient.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BF 4C ?? ?? 00 83 C9 FF 33 C0 68 34 ?? ?? 00 F2 AE F7 D1 49 51 68 4C ?? ?? 00 E8 11 0A 00 00 83 C4 0C 68 4C ?? ?? 00 FF 15 00 ?? ?? 00 8B F0 BF 4C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 4C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 5C ?? ?? 00 E8 C0 09 00 00 8B 1D 04 ?? ?? 00 83 C4 0C 68 5C ?? ?? 00 56 FF D3 A3 D4 ?? ?? 00 BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 5C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 }
	condition:
		$a0


}


rule Packer_Obsidium_z_269 
 {
	meta:
		sigid = 269
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_codeCrypter_z_681 
 {
	meta:
		sigid = 681
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.codeCrypter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PECrypt_z_635 
 {
	meta:
		sigid = 635
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PECrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SimpleUPXCryptor_z_633 
 {
	meta:
		sigid = 633
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimpleUPXCryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_631 
 {
	meta:
		sigid = 631
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
		$a1 = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_ThinstallEmbedded_z_630 
 {
	meta:
		sigid = 630
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ThinstallEmbedded.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEMangle_z_526 
 {
	meta:
		sigid = 526
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEMangle.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AntiDote_z_628 
 {
	meta:
		sigid = 628
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AntiDote.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 00 6A 00 FF 15 08 10 60 00 68 90 03 00 00 E8 68 FD FF FF 68 69 D6 00 00 E8 5E FD FF FF 50 E8 58 FD FF FF 50 E8 52 FD FF FF E8 DD FE FF FF 50 68 A4 10 60 00 68 94 10 60 00 68 10 22 60 00 E8 58 FD FF FF 83 C4 20 33 C0 C2 10 00 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_nBinder_z_389 
 {
	meta:
		sigid = 389
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.nBinder.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 5C 6E 62 34 5F 74 6D 70 5F 30 31 33 32 34 35 34 33 35 30 5C 00 00 00 00 00 00 00 00 00 E9 55 43 4C FF 01 1A 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E 32 88 DB 0E A4 B8 DC 79 }
	condition:
		$a0


}


rule Packer_WWPack_z_278 
 {
	meta:
		sigid = 278
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_UPX_z_275 
 {
	meta:
		sigid = 275
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
		$a0

}


rule Packer_NsPack_z_627 
 {
	meta:
		sigid = 627
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEiDBundle_z_266 
 {
	meta:
		sigid = 266
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEiDBundle.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		$a0 at pe.entry_point


}

rule Packer_BeRoEXEPacker_z_113 
 {
	meta:
		sigid = 113
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.BeRoEXEPacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BA ?? ?? ?? ?? 8D B2 ?? ?? ?? ?? 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15 ?? ?? ?? ?? 5F 5A 85 C0 74 2F 8B C8 8B 03 85 C0 74 22 0F BA F0 1F 72 04 8D 44 ?? ?? 51 52 57 50 51 FF 15 ?? ?? ?? ?? 5F 5A 59 85 C0 74 0B AB 83 C3 04 EB D8 83 C6 14 EB AA 61 C3 }
	condition:
		$a0


}


rule Packer_PeCompact_z_110 
 {
	meta:
		sigid = 110
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 8B 11 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_126 
 {
	meta:
		sigid = 126
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_107 
 {
	meta:
		sigid = 107
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_diProtector_z_135 
 {
	meta:
		sigid = 135
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.diProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 01 00 A0 E3 14 00 00 EB 00 00 20 E0 44 10 9F E5 03 2A A0 E3 40 30 A0 E3 AE 00 00 EB 30 00 8F E5 00 20 A0 E1 3A 0E 8F E2 00 00 80 E2 1C 10 9F E5 20 30 8F E2 0E 00 00 EB 14 00 9F E5 14 10 9F E5 7F 20 A0 E3 C5 00 00 EB 04 C0 8F E2 00 F0 9C E5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Pelles_z_132 
 {
	meta:
		sigid = 132
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pelles.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 ?? E8 ?? ?? ?? ?? 59 A3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_131 
 {
	meta:
		sigid = 131
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ABCCryptor_z_124 
 {
	meta:
		sigid = 124
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ABCCryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 FF 64 24 F0 68 58 58 58 58 90 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 ?? ?? ?? ?? BF 00 ?? ?? ?? B9 00 ?? ?? ?? 80 37 ?? 47 39 CF 75 F8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BF 00 ?? ?? ?? B9 00 ?? ?? ?? 80 37 ?? 47 39 CF 75 F8 }
	condition:
		$a0


}

rule Packer_Crypter_z_119 
 {
	meta:
		sigid = 119
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Crypter.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 68 FF 64 24 F0 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 }
	condition:
		$a0


}


rule Packer_PeCompact_z_116 
 {
	meta:
		sigid = 116
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_625 
 {
	meta:
		sigid = 625
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 C3 27 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PENinja_z_622 
 {
	meta:
		sigid = 622
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PENinja.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_621 
 {
	meta:
		sigid = 621
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }
		$a1 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B 50 EB 03 8A 0B 93 33 C0 EB 02 28 B9 8B 00 EB 01 04 C3 EB 04 65 B3 54 0A E9 FA 00 00 00 EB 01 A2 E8 D5 FF FF FF EB 02 2B 49 EB 03 7C 3E 76 58 EB 04 B8 94 92 56 EB 01 72 64 67 8F 06 00 00 EB 02 23 72 83 C4 04 EB 02 A9 CB E8 47 26 00 00 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_NeoLite_z_530 
 {
	meta:
		sigid = 530
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NeoLite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_BeRoEXEPacker_z_394 
 {
	meta:
		sigid = 394
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.BeRoEXEPacker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESpin_z_163 
 {
	meta:
		sigid = 163
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
	condition:
		$a0 at pe.entry_point


}

rule Packer_SimplePack_z_387 
 {
	meta:
		sigid = 387
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimplePack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 86 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }
	condition:
		$a0


}


rule Packer_SecuPack_z_384 
 {
	meta:
		sigid = 384
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SecuPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 ?? ?? ?? 6A 03 6A ?? 6A 01 ?? ?? ?? 80 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DCryptPrivate_z_514 
 {
	meta:
		sigid = 514
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DCryptPrivate.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B9 ?? ?? ?? 00 E8 00 00 00 00 58 68 ?? ?? ?? 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NTKrnlPacker_z_511 
 {
	meta:
		sigid = 511
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NTKrnlPacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 8D 4D EC BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FC FF FF 8B 55 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 8D 4D E8 BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FE FF FF 8B 55 E8 B8 ?? ?? 40 00 E8 ?? ?? FF FF B8 ?? ?? 40 00 E8 ?? FB FF FF 8B D8 A1 ?? ?? 40 00 BA ?? ?? 40 00 E8 ?? ?? FF FF 75 26 8B D3 A1 ?? ?? 40 00 E8 ?? ?? FF FF 84 C0 75 2A 8D 55 E4 33 C0 E8 ?? ?? FF FF 8B 45 E4 8B D3 E8 ?? ?? FF FF EB 14 8D 55 E0 33 C0 E8 ?? ?? FF FF 8B 45 E0 8B D3 E8 ?? ?? FF FF 6A 00 E8 ?? ?? FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? 40 00 8D 45 E0 BA 04 00 00 00 E8 ?? ?? FF FF C3 E9 ?? ?? FF FF EB EB 5B E8 ?? ?? FF FF 00 00 00 FF FF FF FF 01 00 00 00 25 00 00 00 FF FF FF FF 01 00 00 00 5C 00 00 00 FF FF FF FF 06 00 00 00 53 45 52 56 45 52 00 00 FF FF FF FF 01 00 00 00 31 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MZ0oPE_z_508 
 {
	meta:
		sigid = 508
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MZ0oPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 }
		$a1 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4C 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_ASPack_z_506 
 {
	meta:
		sigid = 506
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ANDpak_z_500 
 {
	meta:
		sigid = 500
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ANDpak.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }
	condition:
		$a0


}


rule Packer_Thinstall_z_499 
 {
	meta:
		sigid = 499
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Thinstall.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 }
		$a1 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_UPX_z_498 
 {
	meta:
		sigid = 498
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_497 
 {
	meta:
		sigid = 497
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
		$a1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_PESpin_z_493 
 {
	meta:
		sigid = 493
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
		$a1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_MPress_v2_1665 
 {
	meta:
		sigid = 1665
		date = "2016-02-01 08:00 AM"
		threatname = "Packer.MPress_v2"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$signature1={21 46 00 69 00 6C 00 65 00 20 00 69 00 73 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 2E 00 00 0D 4D 00 50 00 52 00 45 00 53 00 53 00 00 00 00 00 2D 2D 93 6B 35 04 2E 43 85 EF}

	condition:
		$signature1

}


rule Packer_YodaCrypter_1_3_1663 
 {
	meta:
		sigid = 1663
		date = "2016-02-01 08:00 AM"
		threatname = "Packer.YodaCrypter_1.3"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$signature1={55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC}

	condition:
		$signature1 at pe.entry_point

}


rule Packer_DxPack_z_937 
 {
	meta:
		sigid = 937
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DxPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_935 
 {
	meta:
		sigid = 935
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 00 00 00 00 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 00 C3 8B FE B9 3C 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_930 
 {
	meta:
		sigid = 930
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PCGuard_z_929 
 {
	meta:
		sigid = 929
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PCGuard.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 ?? ?? ?? 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }
	condition:
		$a0 at pe.entry_point


}

rule Packer_NsPack_z_927 
 {
	meta:
		sigid = 927
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 }
	condition:
		$a0


}


rule Packer_FSG_z_926 
 {
	meta:
		sigid = 926
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_924 
 {
	meta:
		sigid = 924
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? ?? 05 00 ?? ?? ?? A3 08 ?? ?? ?? A1 08 ?? ?? ?? B9 81 ?? ?? ?? 2B 48 18 89 0D 0C ?? ?? ?? 83 3D 10 ?? ?? ?? 00 74 16 A1 08 ?? ?? ?? 8B 0D 0C ?? ?? ?? 03 48 14 }
		$a1 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? ?? 05 00 ?? ?? ?? A3 08 ?? ?? ?? A1 08 ?? ?? ?? B9 81 ?? ?? ?? 2B 48 18 89 0D 0C ?? ?? ?? 83 3D 10 ?? ?? ?? 00 74 16 A1 08 ?? ?? ?? 8B 0D 0C ?? ?? ?? 03 48 14 89 4D CC }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_BeRoEXEPacker_z_923 
 {
	meta:
		sigid = 923
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.BeRoEXEPacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEDiminisher_z_914 
 {
	meta:
		sigid = 914
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEDiminisher.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 }
		$a1 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Armadillo_z_912 
 {
	meta:
		sigid = 912
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SDProtect_z_911 
 {
	meta:
		sigid = 911
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SDProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_UPX_z_907 
 {
	meta:
		sigid = 907
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 }
	condition:
		$a0


}


rule Packer_FSG_z_905 
 {
	meta:
		sigid = 905
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_904 
 {
	meta:
		sigid = 904
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_901 
 {
	meta:
		sigid = 901
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_899 
 {
	meta:
		sigid = 899
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WinUpack_z_896 
 {
	meta:
		sigid = 896
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WinUpack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 }

	condition:
		$a0 at pe.entry_point

}


rule Packer_ASPack_z_895 
 {
	meta:
		sigid = 895
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_832 
 {
	meta:
		sigid = 832
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 72 05 00 00 EB 4C }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EncryptPE_z_919 
 {
	meta:
		sigid = 919
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EncryptPE.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_917 
 {
	meta:
		sigid = 917
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_915 
 {
	meta:
		sigid = 915
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasCrypter_z_898 
 {
	meta:
		sigid = 898
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasCrypter.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_810 
 {
	meta:
		sigid = 810
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_891 
 {
	meta:
		sigid = 891
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ED 10 00 00 C3 83 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASProtect_z_890 
 {
	meta:
		sigid = 890
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Crinkler_z_888 
 {
	meta:
		sigid = 888
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Crinkler.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_aPack_z_886 
 {
	meta:
		sigid = 886
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.aPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_885 
 {
	meta:
		sigid = 885
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Pelles_z_871 
 {
	meta:
		sigid = 871
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pelles.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 C7 45 FC ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 BE ?? ?? ?? ?? EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_869 
 {
	meta:
		sigid = 869
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ExeSafeguard_z_868 
 {
	meta:
		sigid = 868
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeSafeguard.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE }
	condition:
		$a0


}

rule Packer_NTKrnlPacker_z_866 
 {
	meta:
		sigid = 866
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NTKrnlPacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 8B 44 24 04 05 ?? ?? ?? ?? 50 E8 01 00 00 00 C3 C3 }
	condition:
		$a0


}


rule Packer_DxPack_z_865 
 {
	meta:
		sigid = 865
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DxPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EnigmaProtector_z_863 
 {
	meta:
		sigid = 863
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }
		$a1 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 01 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 05 F6 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 B9 3D 1A }
	condition:
		$a0 or $a1


}


rule Packer_PeCompact_z_862 
 {
	meta:
		sigid = 862
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_nPack_z_860 
 {
	meta:
		sigid = 860
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.nPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Packman_z_859 
 {
	meta:
		sigid = 859
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Packman.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 0F 85 ?? FF FF FF 8D B3 ?? ?? ?? ?? EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00 }
	condition:
		$a0


}


rule Packer_MSLRH_z_857 
 {
	meta:
		sigid = 857
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SoftwareCompress_z_856 
 {
	meta:
		sigid = 856
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SoftwareCompress.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_854 
 {
	meta:
		sigid = 854
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? 05 0E }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AntiDote_z_853 
 {
	meta:
		sigid = 853
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AntiDote.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC 11 DB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DBPE_z_851 
 {
	meta:
		sigid = 851
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DBPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_848 
 {
	meta:
		sigid = 848
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 79 29 00 00 8D 9D 2C 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_846 
 {
	meta:
		sigid = 846
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_845 
 {
	meta:
		sigid = 845
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Rcryptor_z_842 
 {
	meta:
		sigid = 842
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 }
		$a1 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 or $a1


}


rule Packer_PCPEEncryptor_z_840 
 {
	meta:
		sigid = 840
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PCPEEncryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 00 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEProtect_z_815 
 {
	meta:
		sigid = 815
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_812 
 {
	meta:
		sigid = 812
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 74 1F 00 00 8D 9D 1E 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_804 
 {
	meta:
		sigid = 804
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 05 40 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_802 
 {
	meta:
		sigid = 802
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B ?? ?? ?? EB 04 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESpin_z_801 
 {
	meta:
		sigid = 801
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_iPBProtect_z_799 
 {
	meta:
		sigid = 799
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.iPBProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_779 
 {
	meta:
		sigid = 779
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_778 
 {
	meta:
		sigid = 778
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { BE 48 01 40 00 AD ?? ?? ?? A5 ?? C0 33 C9 ?? ?? ?? ?? ?? ?? ?? F3 AB ?? ?? 0A ?? ?? ?? ?? AD 50 97 51 ?? 87 F5 58 8D 54 86 5C ?? D5 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B6 5F FF C1 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Xpack_z_776 
 {
	meta:
		sigid = 776
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Xpack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3 }
	condition:
		$a0


}


rule Packer_AntiDote_z_775 
 {
	meta:
		sigid = 775
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AntiDote.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74 2F 68 04 01 00 00 68 B0 21 60 00 6A 00 FF 15 08 10 60 00 E8 29 FF FF FF 50 68 88 10 60 00 68 78 10 60 00 68 B0 21 60 00 E8 A4 FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 90 90 90 90 90 90 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_772 
 {
	meta:
		sigid = 772
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 ?? 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PackMaster_z_770 
 {
	meta:
		sigid = 770
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PackMaster.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
		$a1 = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_ASProtect_z_768 
 {
	meta:
		sigid = 768
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 ?? ?? ?? 00 }
	condition:
		$a0


}


rule Packer_FSG_z_767 
 {
	meta:
		sigid = 767
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ThinstallEmbedded_z_765 
 {
	meta:
		sigid = 765
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ThinstallEmbedded.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 58 BB AD 19 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 1C 00 00 68 80 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_762 
 {
	meta:
		sigid = 762
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_809 
 {
	meta:
		sigid = 809
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AppEncryptor_z_807 
 {
	meta:
		sigid = 807
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AppEncryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_805 
 {
	meta:
		sigid = 805
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 83 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB 14 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_718 
 {
	meta:
		sigid = 718
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_715 
 {
	meta:
		sigid = 715
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_798 
 {
	meta:
		sigid = 798
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_796 
 {
	meta:
		sigid = 796
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }

	condition:
		$a0 at pe.entry_point

}


rule Packer_MSLRH_z_795 
 {
	meta:
		sigid = 795
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_793 
 {
	meta:
		sigid = 793
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CelsiusCrypt_z_790 
 {
	meta:
		sigid = 790
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CelsiusCrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 84 92 44 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 84 92 44 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D C4 92 44 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D AC 92 44 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 77 C2 00 00 90 90 90 90 90 90 90 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }
		$a1 = { 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_Armadillo_z_788 
 {
	meta:
		sigid = 788
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 28 ?? ?? ?? 68 E4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 0C }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_787 
 {
	meta:
		sigid = 787
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_785 
 {
	meta:
		sigid = 785
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PCShrink_z_784 
 {
	meta:
		sigid = 784
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PCShrink.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_BeRoEXEPacker_z_782 
 {
	meta:
		sigid = 782
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.BeRoEXEPacker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_hmimys_z_781 
 {
	meta:
		sigid = 781
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.hmimys.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 95 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5E AD 50 AD 50 97 AD 50 AD 50 AD 50 E8 C0 01 00 00 AD 50 AD 93 87 DE B9 ?? ?? ?? ?? E3 1D 8A 07 47 04 ?? 3C ?? 73 F7 8B 07 3C ?? 75 F3 B0 00 0F C8 05 ?? ?? ?? ?? 2B C7 AB E2 E3 AD 85 C0 74 2B 97 56 FF 13 8B E8 AC 84 C0 75 FB 66 AD 66 85 C0 74 E9 AC 83 EE 03 84 C0 74 08 56 55 FF 53 04 AB EB E4 AD 50 55 FF 53 04 AB EB E0 C3 8B 0A 3B 4A 04 75 0A C7 42 10 01 00 00 00 0C FF C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_687 
 {
	meta:
		sigid = 687
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_LY_WGKX_z_761 
 {
	meta:
		sigid = 761
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.LY_WGKX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 4D 79 46 75 6E 00 62 73 }
	condition:
		$a0


}


rule Packer_FSG_z_759 
 {
	meta:
		sigid = 759
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_755 
 {
	meta:
		sigid = 755
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
		$a1 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Petite_z_753 
 {
	meta:
		sigid = 753
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_751 
 {
	meta:
		sigid = 751
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PackMaster_z_750 
 {
	meta:
		sigid = 750
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PackMaster.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_748 
 {
	meta:
		sigid = 748
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 00 00 00 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Upack_z_740 
 {
	meta:
		sigid = 740
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 }
	condition:
		$a0


}


rule Packer_UPX_z_738 
 {
	meta:
		sigid = 738
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_737 
 {
	meta:
		sigid = 737
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 05 C0 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_codeCrypter_z_735 
 {
	meta:
		sigid = 735
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.codeCrypter.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 50 58 53 5B 90 BB ?? ?? ?? 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }
	condition:
		$a0 at pe.entry_point


}

rule Packer_RLP_z_734 
 {
	meta:
		sigid = 734
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLP.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8 42 31 40 00 BB 41 30 40 00 2B C3 03 C5 33 D2 8A 10 40 B9 ?? ?? 00 00 8B F9 30 10 8A 10 40 49 75 F8 64 EF 86 3D 30 00 00 0F B9 FF 4B 89 52 5C 4C BD 77 C2 0C CE 88 4E 2D E8 00 00 00 5D 0D DB 5E 56 }
	condition:
		$a0


}


rule Packer_PECrc32_z_732 
 {
	meta:
		sigid = 732
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PECrc32.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_731 
 {
	meta:
		sigid = 731
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 08 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PENightMare_z_729 
 {
	meta:
		sigid = 729
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PENightMare.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_724 
 {
	meta:
		sigid = 724
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 CD 09 00 00 89 85 14 0A 00 00 EB 14 60 FF B5 14 0A }
		$a1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 EB 09 00 00 89 85 3A 0A 00 00 EB 14 60 FF B5 3A 0A }
		$a2 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 0C 00 00 EB 03 0C 00 00 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 47 02 00 00 EB 03 15 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 9B 0A }
		$a3 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 CD 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 14 0A }
		$a4 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 3A 0A }
		$a5 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 ?? ?? ?? ?? EB 03 ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 9B 0A }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point or $a4 at pe.entry_point or $a5 at pe.entry_point


}


rule Packer_yodasCrypter_z_723 
 {
	meta:
		sigid = 723
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasCrypter.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_721 
 {
	meta:
		sigid = 721
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_720 
 {
	meta:
		sigid = 720
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
		$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_ASPack_z_792 
 {
	meta:
		sigid = 792
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_728 
 {
	meta:
		sigid = 728
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_714 
 {
	meta:
		sigid = 714
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_712 
 {
	meta:
		sigid = 712
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_711 
 {
	meta:
		sigid = 711
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_709 
 {
	meta:
		sigid = 709
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_707 
 {
	meta:
		sigid = 707
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Petite_z_706 
 {
	meta:
		sigid = 706
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }
	condition:
		$a0


}

rule Packer_Petite_z_704 
 {
	meta:
		sigid = 704
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1 }
	condition:
		$a0


}


rule Packer_Upack_z_703 
 {
	meta:
		sigid = 703
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_701 
 {
	meta:
		sigid = 701
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_700 
 {
	meta:
		sigid = 700
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 26 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_697 
 {
	meta:
		sigid = 697
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 83 BD 9C 38 40 00 01 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_695 
 {
	meta:
		sigid = 695
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_693 
 {
	meta:
		sigid = 693
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_692 
 {
	meta:
		sigid = 692
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_690 
 {
	meta:
		sigid = 690
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_nPack_z_688 
 {
	meta:
		sigid = 688
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.nPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 2D 02 00 00 E8 DD 06 00 00 E8 2C 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PECrypt_z_667 
 {
	meta:
		sigid = 667
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PECrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 E0 53 56 33 C0 89 45 E4 89 45 E0 89 45 EC ?? ?? ?? ?? 64 82 40 00 E8 7C C7 FF FF 33 C0 55 68 BE 84 40 00 64 FF 30 64 89 20 68 CC 84 40 00 ?? ?? ?? ?? 00 A1 10 A7 40 00 50 E8 1D C8 FF FF 8B D8 85 DB 75 39 E8 3A C8 FF FF 6A 00 6A 00 68 A0 A9 40 00 68 00 04 00 00 50 6A 00 68 00 13 00 00 E8 FF C7 FF FF 6A 00 68 E0 84 40 00 A1 A0 A9 40 00 50 6A 00 E8 ?? ?? ?? ?? E9 7D 01 00 00 53 A1 10 A7 40 00 50 E8 42 C8 FF FF 8B F0 85 F6 75 18 6A 00 68 E0 84 40 00 68 E4 84 40 00 6A 00 E8 71 C8 FF FF E9 53 01 00 00 53 6A 00 E8 2C C8 FF FF A3 ?? ?? ?? ?? 83 3D 48 A8 40 00 00 75 18 6A 00 68 E0 84 40 00 68 F8 84 40 00 6A 00 E8 43 C8 FF FF E9 25 01 00 00 56 E8 F8 C7 FF FF A3 4C A8 40 00 A1 48 A8 40 00 E8 91 A1 FF FF 8B D8 8B 15 48 A8 40 00 85 D2 7C 16 42 33 C0 8B 0D 4C A8 40 00 03 C8 8A 09 8D 34 18 88 0E 40 4A 75 ED 8B 15 48 A8 40 00 85 D2 7C 32 42 33 C0 8D 34 18 8A 0E 80 F9 01 75 05 C6 06 FF EB 1C 8D 0C 18 8A 09 84 ?? ?? ?? ?? ?? 00 EB 0E 8B 0D 4C A8 40 00 03 C8 0F B6 09 49 88 0E 40 4A 75 D1 8D ?? ?? ?? ?? E8 A5 A3 FF FF 8B 45 E8 8D 55 EC E8 56 D5 FF FF 8D 45 EC BA 18 85 40 00 E8 79 BA FF FF 8B 45 EC E8 39 BB FF FF 8B D0 B8 54 A8 40 00 E8 31 A6 FF FF BA 01 00 00 00 B8 54 A8 40 00 E8 12 A9 FF FF E8 DD A1 FF FF 68 50 A8 40 00 8B D3 8B 0D 48 A8 40 00 B8 54 A8 40 00 E8 56 A7 FF FF E8 C1 A1 FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_665 
 {
	meta:
		sigid = 665
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8A 06 3C 00 74 12 8B F5 8D B5 ?? ?? FF FF 8A 06 3C 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXELOCK_z_647 
 {
	meta:
		sigid = 647
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXELOCK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BA ?? ?? BF ?? ?? EB ?? EA ?? ?? ?? ?? 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SVKProtector_z_645 
 {
	meta:
		sigid = 645
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SVKProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_642 
 {
	meta:
		sigid = 642
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_641 
 {
	meta:
		sigid = 641
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 }
		$a1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_EnigmaProtector_z_639 
 {
	meta:
		sigid = 639
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31 }
	condition:
		$a0


}


rule Packer_EXE32Pack_z_685 
 {
	meta:
		sigid = 685
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXE32Pack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXE32Pack_z_684 
 {
	meta:
		sigid = 684
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXE32Pack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_683 
 {
	meta:
		sigid = 683
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_682 
 {
	meta:
		sigid = 682
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 }
		$a1 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_EXE32Pack_z_680 
 {
	meta:
		sigid = 680
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXE32Pack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXE32Pack_z_679 
 {
	meta:
		sigid = 679
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXE32Pack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D 40 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ThinstallEmbedded_z_677 
 {
	meta:
		sigid = 677
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ThinstallEmbedded.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 ?? ?? ?? ?? 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SDProtect_z_675 
 {
	meta:
		sigid = 675
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SDProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_671 
 {
	meta:
		sigid = 671
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXE32Pack_z_670 
 {
	meta:
		sigid = 670
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXE32Pack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? E8 ?? ?? ?? ?? 3B 74 01 ?? 5D 8B D5 81 ED }
	condition:
		$a0 at pe.entry_point


}

rule Packer_MEW_z_556 
 {
	meta:
		sigid = 556
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MEW.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = {8B DE AD AD 50 AD 97 B2 ?? A4 B6 ?? FF 13 }
		$a1 = "MEW"
		$a2 = "DAP"

	condition:
		$a0 and ($a1 or $a2)

}


rule Packer_Armadillo_z_555 
 {
	meta:
		sigid = 555
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_TPACK_z_553 
 {
	meta:
		sigid = 553
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.TPACK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_551 
 {
	meta:
		sigid = 551
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESpin_z_550 
 {
	meta:
		sigid = 550
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEPack_z_541 
 {
	meta:
		sigid = 541
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_539 
 {
	meta:
		sigid = 539
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_CrunchPE_z_618 
 {
	meta:
		sigid = 618
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CrunchPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 E9 06 ?? ?? 89 85 E1 06 ?? ?? FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }
	condition:
		$a0


}


rule Packer_EXERefactor_z_619 
 {
	meta:
		sigid = 619
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXERefactor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Pencrypt_z_606 
 {
	meta:
		sigid = 606
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pencrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 ?? ?? ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 ?? ?? ?? FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_519 
 {
	meta:
		sigid = 519
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3A 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 C3 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_379 
 {
	meta:
		sigid = 379
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
		$a1 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_ORiEN_z_335 
 {
	meta:
		sigid = 335
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ORiEN.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_312 
 {
	meta:
		sigid = 312
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? 00 14 00 00 00 00 ?? ?? 00 ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? 00 ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 }
		$a1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }
		$a2 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 10 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point


}


rule Packer_Armadillo_z_254 
 {
	meta:
		sigid = 254
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SpecialEXEPasswordProtector_z_233 
 {
	meta:
		sigid = 233
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SpecialEXEPasswordProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_664 
 {
	meta:
		sigid = 664
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
		$a1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_ACProtect_z_575 
 {
	meta:
		sigid = 575
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ACProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_656 
 {
	meta:
		sigid = 656
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SimplePack_z_655 
 {
	meta:
		sigid = 655
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimplePack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EXECryptor_z_653 
 {
	meta:
		sigid = 653
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 56 57 53 31 DB 89 C6 89 D7 0F B6 06 89 C2 83 E0 1F C1 EA 05 74 2D 4A 74 15 8D 5C 13 02 46 C1 E0 08 89 FA 0F B6 0E 46 29 CA 4A 29 C2 EB 32 C1 E3 05 8D 5C 03 04 46 89 FA 0F B7 0E 29 CA 4A 83 C6 02 EB 1D C1 E3 04 46 89 C1 83 E1 0F 01 CB C1 E8 05 73 07 43 89 F2 01 DE EB 06 85 DB 74 0E EB A9 56 89 D6 89 D9 F3 A4 31 DB 5E EB 9D 89 F0 5B 5F 5E C3 }
	condition:
		$a0


}


rule Packer_NXPEPackerv_z_652 
 {
	meta:
		sigid = 652
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NXPEPackerv.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_UPolyX_z_650 
 {
	meta:
		sigid = 650
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPolyX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC ?? 00 BD 46 00 8B ?? B9 ?? 00 00 00 80 ?? ?? 51 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a1 = { 83 EC 04 89 14 24 59 BA ?? 00 00 00 52 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
		$a2 = { BB 00 BD 46 00 83 EC 04 89 1C 24 ?? B9 ?? 00 00 00 80 33 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a3 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 ?? 00 BD 46 00 83 EC 04 89 ?? 24 B9 ?? 00 00 00 81 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a4 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 ?? 00 BD 46 00 ?? B9 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a5 = { EB 01 C3 ?? 00 BD 46 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0 or $a1 or $a2 or $a3 or $a4 or $a5


}


rule Packer_FSG_z_648 
 {
	meta:
		sigid = 648
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CRYPToCRACksPEProtector_z_638 
 {
	meta:
		sigid = 638
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CRYPToCRACksPEProtector.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_636 
 {
	meta:
		sigid = 636
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 05 40 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_603 
 {
	meta:
		sigid = 603
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
		$a1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Upack_z_602 
 {
	meta:
		sigid = 602
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 }
		$a1 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 59 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }
		$a2 = { AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 ?? 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }
	condition:
		$a0 or $a1 at pe.entry_point or $a2 at pe.entry_point


}


rule Packer_MSLRH_z_600 
 {
	meta:
		sigid = 600
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_599 
 {
	meta:
		sigid = 599
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BA ?? ?? A1 ?? ?? 2D ?? ?? 8C CB 81 C3 ?? ?? 3B C3 77 ?? 05 ?? ?? 3B C3 77 ?? B4 09 BA ?? ?? CD 21 CD 20 90 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_597 
 {
	meta:
		sigid = 597
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 F7 26 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_570 
 {
	meta:
		sigid = 570
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_568 
 {
	meta:
		sigid = 568
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_547 
 {
	meta:
		sigid = 547
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_JDPack_z_545 
 {
	meta:
		sigid = 545
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.JDPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rpolycrypt_z_544 
 {
	meta:
		sigid = 544
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rpolycrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 58 97 97 60 61 8B 04 24 80 78 F3 6A E8 00 00 00 00 58 E8 00 00 00 00 58 91 91 EB 00 0F 85 6B F4 76 6F E8 00 00 00 00 83 C4 04 E8 00 00 00 00 58 90 E8 00 00 00 00 83 C4 04 8B 04 24 80 78 F1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Packman_z_542 
 {
	meta:
		sigid = 542
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Packman.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_150 
 {
	meta:
		sigid = 150
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 }
		$a1 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 48 02 00 00 56 FF D3 83 C4 08 8B B5 48 02 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 83 C0 04 89 85 44 02 00 00 EB 7A 56 FF 95 F1 01 00 00 89 85 40 02 00 00 8B C6 EB 4F 8B 85 44 02 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 44 02 00 00 C7 00 20 20 20 00 EB 06 FF B5 44 02 00 00 FF B5 40 02 00 00 FF 95 F5 01 00 00 89 07 83 C7 04 8B 85 44 02 00 00 EB 01 40 80 38 00 75 FA 40 89 85 44 02 00 00 80 38 00 75 AC EB 01 46 80 3E 00 75 FA 46 40 8B 38 83 C0 04 89 85 44 02 00 00 80 3E 01 75 81 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 48 02 00 00 FF 95 FD 01 00 00 61 68 ?? ?? ?? ?? C3 60 8B 74 24 24 8B 7C }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_PKLITE_z_538 
 {
	meta:
		sigid = 538
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 73 ?? 2D ?? ?? FA 8E D0 FB 2D ?? ?? 8E C0 50 B9 ?? ?? 33 FF 57 BE ?? ?? FC F3 A5 CB B4 09 BA ?? ?? CD 21 CD 20 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_536 
 {
	meta:
		sigid = 536
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 90 83 C4 14 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_535 
 {
	meta:
		sigid = 535
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEShit_z_533 
 {
	meta:
		sigid = 533
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEShit.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXEShield_z_154 
 {
	meta:
		sigid = 154
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEShield.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_hmimys_z_616 
 {
	meta:
		sigid = 616
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.hmimys.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 }
		$a1 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 00 00 00 }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_VProtector_z_615 
 {
	meta:
		sigid = 615
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Pelles_z_613 
 {
	meta:
		sigid = 613
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pelles.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D ?? ?? ?? ?? 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEDiminisher_z_611 
 {
	meta:
		sigid = 611
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEDiminisher.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 50 E8 02 01 00 00 8B FD 8D 9D 9A 33 40 00 8B 1B 8D 87 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_609 
 {
	meta:
		sigid = 609
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SimplePack_z_608 
 {
	meta:
		sigid = 608
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimplePack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC }
		$a1 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC F3 A5 89 C1 83 E1 03 F3 A4 5F 5E 8B 04 24 89 EA 03 57 0C E8 3F 01 00 00 58 68 00 40 00 00 FF 77 10 50 FF 93 3C 03 00 00 83 C7 28 4E 75 9E BE ?? ?? ?? ?? 09 F6 0F 84 0C 01 00 00 01 EE 8B 4E 0C 09 C9 0F 84 FF 00 00 00 01 E9 89 CF 57 FF 93 30 03 00 00 09 C0 75 3D 6A 04 68 00 10 00 00 68 00 10 00 00 6A 00 FF 93 38 03 00 00 89 C6 8D 83 6F 02 00 00 57 50 56 FF 93 44 03 00 00 6A 10 6A 00 56 6A 00 FF 93 48 03 00 00 89 E5 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Rcryptor_z_605 
 {
	meta:
		sigid = 605
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 33 D0 68 ?? ?? ?? ?? FF D2 }
		$a1 = { 33 D0 68 ?? ?? ?? ?? FF D2 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_NakedPacker_z_567 
 {
	meta:
		sigid = 567
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NakedPacker.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 60 FC 0F B6 05 34 ?? ?? ?? 85 C0 75 31 B8 50 ?? ?? ?? 2B 05 04 ?? ?? ?? A3 30 ?? ?? ?? A1 00 ?? ?? ?? 03 05 30 ?? ?? ?? A3 38 ?? ?? ?? E8 9A 00 00 00 A3 50 ?? ?? ?? C6 05 34 ?? ?? ?? 01 83 3D 50 ?? ?? ?? 00 75 07 61 FF 25 38 ?? ?? ?? 61 FF 74 24 04 6A 00 FF 15 44 ?? ?? ?? 50 FF 15 40 ?? ?? ?? C3 FF 74 24 04 6A 00 FF 15 44 ?? ?? ?? 50 FF 15 48 ?? ?? ?? C3 8B 4C 24 04 56 8B 74 24 10 57 85 F6 8B F9 74 0D 8B 54 24 10 8A 02 88 01 }
	condition:
		$a0


}


rule Packer_FSG_z_565 
 {
	meta:
		sigid = 565
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ActiveMARK_z_564 
 {
	meta:
		sigid = 564
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ActiveMARK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67 }
	condition:
		$a0


}


rule Packer_Armadillo_z_562 
 {
	meta:
		sigid = 562
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_AsCrypt_z_561 
 {
	meta:
		sigid = 561
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AsCrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 51 ?? ?? ?? 01 00 00 00 83 ?? ?? E2 }
	condition:
		$a0


}


rule Packer_yzpack_z_559 
 {
	meta:
		sigid = 559
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yzpack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 25 ?? ?? ?? ?? 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3C AA EB DC FF 54 24 04 2B CB 75 0F FF 54 24 08 EB 27 AC D1 E8 74 30 13 C9 EB 1B 91 48 C1 E0 08 AC FF 54 24 08 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 99 BD ?? ?? ?? ?? FF 65 28 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DotFixNiceProtect_z_548 
 {
	meta:
		sigid = 548
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DotFixNiceProtect.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEProtect_z_504 
 {
	meta:
		sigid = 504
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_502 
 {
	meta:
		sigid = 502
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MEW_z_488 
 {
	meta:
		sigid = 488
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MEW.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SVKProtector_z_486 
 {
	meta:
		sigid = 486
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SVKProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Morphine_z_483 
 {
	meta:
		sigid = 483
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Morphine.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

	condition:
		$a0 or $a1

}


rule Packer_PPCPROTECT_z_481 
 {
	meta:
		sigid = 481
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PPCPROTECT.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_nPack_z_480 
 {
	meta:
		sigid = 480
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.nPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PolyCryptor_z_298 
 {
	meta:
		sigid = 298
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PolyCryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45 }
	condition:
		$a0


}


rule Packer_Petite_z_295 
 {
	meta:
		sigid = 295
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasCrypter_z_293 
 {
	meta:
		sigid = 293
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasCrypter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_292 
 {
	meta:
		sigid = 292
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Petite_z_290 
 {
	meta:
		sigid = 290
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Petite_z_289 
 {
	meta:
		sigid = 289
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_DotFixNiceProtect_z_327 
 {
	meta:
		sigid = 327
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DotFixNiceProtect.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 B8 ?? ?? ?? ?? 03 C5 50 B8 ?? ?? ?? ?? 03 C5 FF 10 BB ?? ?? ?? ?? 03 DD 83 C3 0C 53 50 B8 ?? ?? ?? ?? 03 C5 FF 10 6A 40 68 00 10 00 00 FF 74 24 2C 6A 00 FF D0 89 44 24 1C 61 C3 }
	condition:
		$a0


}

rule Packer_Crunch_z_528 
 {
	meta:
		sigid = 528
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Crunch.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 15 03 ?? ?? ?? 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 55 E8 }
	condition:
		$a0


}


rule Packer_MSLRH_z_527 
 {
	meta:
		sigid = 527
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_525 
 {
	meta:
		sigid = 525
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }
	condition:
		$a0 at pe.entry_point


}

rule Packer_NorthStarPEShrinker_z_524 
 {
	meta:
		sigid = 524
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NorthStarPEShrinker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01 }
	condition:
		$a0


}


rule Packer_PeCompact_z_522 
 {
	meta:
		sigid = 522
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_521 
 {
	meta:
		sigid = 521
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 01 00 00 00 90 5D 81 ED 00 00 00 00 BB 00 00 00 00 03 DD 2B 9D }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_518 
 {
	meta:
		sigid = 518
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_515 
 {
	meta:
		sigid = 515
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }
		$a1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 97 FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_kkrunchy_z_513 
 {
	meta:
		sigid = 513
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.kkrunchy.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? ?? 57 BE ?? ?? ?? ?? 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SkDUndetectabler_z_512 
 {
	meta:
		sigid = 512
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SkDUndetectabler.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 00 00 EB 0F 8B 8D F4 FD FF FF 83 C1 01 89 8D F4 FD FF FF 8B 95 F4 FD FF FF 3B 15 ?? 16 00 01 73 1C 8B 85 F4 FD FF FF 8B 0D ?? 16 00 01 8D 54 01 07 81 FA 74 10 00 01 75 02 EB 02 EB C7 8B 85 F4 FD FF FF 50 E8 ?? 00 00 00 83 C4 04 89 85 F0 FD FF FF 8B 8D F0 FD FF FF 89 4D FC C7 45 F8 00 00 00 00 EB 09 8B 55 F8 83 C2 01 89 55 F8 8B 45 F8 3B 85 F4 FD FF FF 73 15 8B 4D FC 03 4D F8 8B 15 ?? 16 00 01 03 55 F8 8A 02 88 01 EB D7 83 3D ?? 16 00 01 00 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SexeCrypter_z_510 
 {
	meta:
		sigid = 510
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SexeCrypter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 D8 39 00 10 E8 30 FA FF FF 33 C0 55 68 D4 3A 00 10 64 FF 30 64 89 ?? ?? ?? ?? E4 3A 00 10 A1 00 57 00 10 50 E8 CC FA FF FF 8B D8 53 A1 00 57 00 10 50 E8 FE FA FF FF 8B F8 53 A1 00 57 00 10 50 E8 C8 FA FF FF 8B D8 53 E8 C8 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 14 57 00 10 E8 AD F6 FF FF B8 14 57 00 10 E8 9B F6 FF FF 8B CF 8B D6 E8 DA FA FF FF 53 E8 84 FA FF FF 8D 4D EC BA F8 3A 00 10 A1 14 57 00 10 E8 0A FB FF FF 8B 55 EC B8 14 57 00 10 E8 65 F5 FF FF B8 14 57 00 10 E8 63 F6 FF FF E8 52 FC FF FF 33 C0 5A 59 59 64 89 10 68 DB 3A 00 10 8D 45 EC E8 ED F4 FF FF C3 E9 83 EF FF FF EB F0 5F 5E 5B E8 ED F3 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 12 00 00 00 6B 75 74 68 37 36 67 62 62 67 36 37 34 76 38 38 67 79 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VxGotcha_z_509 
 {
	meta:
		sigid = 509
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VxGotcha.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? 5B 81 EB ?? ?? 9C FC 2E ?? ?? ?? ?? ?? ?? ?? 8C D8 05 ?? ?? 2E ?? ?? ?? ?? 50 2E ?? ?? ?? ?? ?? ?? 8B C3 05 ?? ?? 8B F0 BF 00 01 B9 20 00 F3 A4 0E B8 00 01 50 B8 DA DA CD 21 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_505 
 {
	meta:
		sigid = 505
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 E8 ?? ?? ?? 00 89 45 F8 E9 ?? ?? ?? ?? 0F 83 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 14 24 5A 57 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 58 81 C0 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 81 C8 ?? ?? ?? ?? 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? ?? C3 BF ?? ?? ?? ?? 81 CB ?? ?? ?? ?? BA ?? ?? ?? ?? 52 E9 ?? ?? ?? 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 34 24 5E 66 8B 00 66 25 ?? ?? E9 ?? ?? ?? ?? 8B CD 87 0C 24 8B EC 51 89 EC 5D 8B 05 ?? ?? ?? ?? 09 C0 E9 ?? ?? ?? ?? 59 81 C1 ?? ?? ?? ?? C1 C1 ?? 23 0D ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? E9 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 13 D0 0B F9 E9 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 64 24 08 31 C0 64 8F 05 00 00 00 00 5A E9 ?? ?? ?? ?? 3C A4 0F 85 ?? ?? ?? 00 8B 45 FC 66 81 38 ?? ?? 0F 84 05 00 00 00 E9 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 3C 24 5F 31 DB 31 C9 31 D2 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 89 45 FC 33 C0 89 45 F4 83 7D FC 00 E9 ?? ?? ?? ?? 53 52 8B D1 87 14 24 81 C0 ?? ?? ?? ?? 0F 88 ?? ?? ?? ?? 3B CB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Hardlock_z_478 
 {
	meta:
		sigid = 478
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Hardlock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_477 
 {
	meta:
		sigid = 477
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PE_Admin_z_471 
 {
	meta:
		sigid = 471
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PE_Admin.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
		$a1 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_PeCompact_z_324 
 {
	meta:
		sigid = 324
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_iPBProtect_z_145 
 {
	meta:
		sigid = 145
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.iPBProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 }
	condition:
		$a0


}


rule Packer_tElock_z_248 
 {
	meta:
		sigid = 248
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_143 
 {
	meta:
		sigid = 143
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_270 
 {
	meta:
		sigid = 270
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 E5 24 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 8F 15 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 20 15 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 D7 23 00 00 59 89 7D FC FF 75 08 E8 EC 53 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 2B C5 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 19 ED FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 7D 22 00 00 59 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_268 
 {
	meta:
		sigid = 268
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CryptoLock_z_267 
 {
	meta:
		sigid = 267
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CryptoLock.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 }
		$a1 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
		$a2 = { 60 BE ?? 90 40 00 8D BE ?? ?? FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point


}

rule Packer_PeCompact_z_265 
 {
	meta:
		sigid = 265
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 C9 11 00 10 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 5A 8B F8 50 52 8B 33 8B 43 20 03 C2 8B 08 89 4B 20 8B 43 1C 03 C2 8B 08 89 4B 1C 03 F2 8B 4B 0C 03 CA 8D 43 1C 50 57 56 FF }
	condition:
		$a0


}


rule Packer_FlyCrypter_z_263 
 {
	meta:
		sigid = 263
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FlyCrypter.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 53 56 57 55 BB 2C ?? ?? 44 BE 00 30 44 44 BF 20 ?? ?? 44 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 44 44 00 74 06 FF 15 58 30 44 44 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 20 30 44 44 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 18 30 44 44 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 2F FA FF FF FF 15 24 30 44 44 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 ?? ?? 44 00 74 06 FF 15 10 ?? ?? 44 8B 06 50 E8 51 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 44 44 E8 26 FF FF FF C3 }
		$a1 = { 55 8B EC 83 C4 F0 53 B8 18 22 44 44 E8 7F F7 FF FF E8 0A F1 FF FF B8 09 00 00 00 E8 5C F1 FF FF 8B D8 85 DB 75 05 E8 85 FD FF FF 83 FB 01 75 05 E8 7B FD FF FF 83 FB 02 75 05 E8 D1 FD FF FF 83 FB 03 75 05 E8 87 FE FF FF 83 FB 04 75 05 E8 5D FD FF FF 83 FB 05 75 05 E8 B3 FD FF FF 83 FB 06 75 05 E8 69 FE FF FF 83 FB 07 75 05 E8 5F FE FF FF 83 FB 08 75 05 E8 95 FD FF FF 83 FB 09 75 05 E8 4B FE FF FF 5B E8 9D F2 FF FF 90 }
	condition:
		$a0 or $a1 at pe.entry_point


}


rule Packer_MSLRH_z_262 
 {
	meta:
		sigid = 262
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Protector_z_260 
 {
	meta:
		sigid = 260
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Protector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VProtector_z_259 
 {
	meta:
		sigid = 259
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 CA 31 41 00 68 06 32 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_RSCsProcessPatcher_z_257 
 {
	meta:
		sigid = 257
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RSCsProcessPatcher.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 }
	condition:
		$a0


}


rule Packer_FSG_z_253 
 {
	meta:
		sigid = 253
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_RLPack_z_251 
 {
	meta:
		sigid = 251
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? 60 }
	condition:
		$a0


}


rule Packer_UPX_z_165 
 {
	meta:
		sigid = 165
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UG2002Cruncher_z_74 
 {
	meta:
		sigid = 74
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UG2002Cruncher.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Packanoid_z_159 
 {
	meta:
		sigid = 159
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Packanoid.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 9D 00 00 00 B8 ?? ?? ?? ?? 8B 30 8B 78 04 BB ?? ?? ?? ?? 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_242 
 {
	meta:
		sigid = 242
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_themida_z_287 
 {
	meta:
		sigid = 287
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 }
		$a1 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_ExeJoiner_z_286 
 {
	meta:
		sigid = 286
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeJoiner.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SDProtect_z_282 
 {
	meta:
		sigid = 282
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SDProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 7B 03 00 00 03 C8 74 C4 75 C2 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E2 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PECrypt_z_280 
 {
	meta:
		sigid = 280
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PECrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EXECryptor_z_279 
 {
	meta:
		sigid = 279
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 }
	condition:
		$a0


}


rule Packer_GHFProtector_z_277 
 {
	meta:
		sigid = 277
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.GHFProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 00 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 61 B9 FC FF FF FF 8B 1C 08 89 99 ?? ?? ?? ?? E2 F5 90 90 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 01 D6 8B 46 0C 85 C0 0F 84 87 00 00 00 01 D0 89 C3 50 B8 ?? ?? ?? ?? FF 10 85 C0 75 08 53 B8 ?? ?? ?? ?? FF 10 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 BA ?? ?? ?? ?? 8B 06 85 C0 75 03 8B 46 10 01 D0 03 05 ?? ?? ?? ?? 8B 18 8B 7E 10 01 D7 03 3D ?? ?? ?? ?? 85 DB 74 2B F7 C3 00 00 00 80 75 04 01 D3 43 43 81 E3 FF FF FF 0F 53 FF 35 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 89 07 83 05 ?? ?? ?? ?? 04 EB AE 83 C6 14 BA ?? ?? ?? ?? E9 6E FF FF FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 8B 15 ?? ?? ?? ?? 52 FF D0 61 BA ?? ?? ?? ?? FF E2 90 C3 }
		$a1 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 00 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_yzpack_z_276 
 {
	meta:
		sigid = 276
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yzpack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 8D 40 7C 8B 40 3C 89 45 04 E8 F3 07 00 00 60 8B 5D 04 8B 73 3C 8B 74 33 78 03 F3 56 8B 76 20 03 F3 33 C9 49 92 41 AD 03 C3 52 33 FF 0F B6 10 38 F2 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yzpack_z_274 
 {
	meta:
		sigid = 274
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yzpack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 ?? ?? ?? ?? B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 E0 00 ?? ?? 0B 01 ?? ?? ?? ?? 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_273 
 {
	meta:
		sigid = 273
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Petite_z_271 
 {
	meta:
		sigid = 271
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_162 
 {
	meta:
		sigid = 162
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Lite_z_139 
 {
	meta:
		sigid = 139
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Lite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_240 
 {
	meta:
		sigid = 240
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_239 
 {
	meta:
		sigid = 239
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_237 
 {
	meta:
		sigid = 237
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_hmimys_z_236 
 {
	meta:
		sigid = 236
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.hmimys.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 5D 83 ED 05 6A 00 FF 95 E1 0E 00 00 89 85 85 0E 00 00 8B 58 3C 03 D8 81 C3 F8 00 00 00 80 AD 89 0E 00 00 01 89 9D 63 0F 00 00 8B 4B 0C 03 8D 85 0E 00 00 8B 53 08 80 BD 89 0E 00 00 00 75 0C 03 8D 91 0E 00 00 2B 95 91 0E 00 00 89 8D 57 0F 00 00 89 95 5B 0F 00 00 8B 5B 10 89 9D 5F 0F 00 00 8B 9D 5F 0F 00 00 8B 85 57 0F 00 00 53 50 E8 B7 0B 00 00 89 85 73 0F 00 00 6A 04 68 00 10 00 00 50 6A 00 FF 95 E9 0E 00 00 89 85 6B 0F 00 00 6A 04 68 00 10 00 00 68 D8 7C 00 00 6A 00 FF 95 E9 0E 00 00 89 85 6F 0F 00 00 8D 85 67 0F 00 00 8B 9D 73 0F 00 00 8B 8D 6B 0F 00 00 8B 95 5B 0F 00 00 83 EA 0E 8B B5 57 0F 00 00 83 C6 0E 8B BD 6F 0F 00 00 50 53 51 52 56 68 D8 7C 00 00 57 E8 01 01 00 00 8B 9D 57 0F 00 00 8B 03 3C 01 75 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXEPACKLINK_z_234 
 {
	meta:
		sigid = 234
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEPACKLINK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 50 B8 ?? ?? 50 CB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_231 
 {
	meta:
		sigid = 231
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 89 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_NTKrnlPacker_z_230 
 {
	meta:
		sigid = 230
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NTKrnlPacker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }
	condition:
		$a0


}


rule Packer_ASPack_z_225 
 {
	meta:
		sigid = 225
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_223 
 {
	meta:
		sigid = 223
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 3F DF FF FF 00 00 00 ?? ?? ?? ?? 04 ?? ?? 00 00 00 00 00 00 00 00 00 24 ?? ?? 00 14 ?? ?? 00 0C ?? ?? 00 00 00 00 00 00 00 00 00 31 ?? ?? 00 1C ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASProtect_z_222 
 {
	meta:
		sigid = 222
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Imploder_z_220 
 {
	meta:
		sigid = 220
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Imploder.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEiDBundle_z_219 
 {
	meta:
		sigid = 219
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEiDBundle.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXELOCK_z_217 
 {
	meta:
		sigid = 217
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXELOCK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 06 8C C8 8E C0 BE ?? ?? 26 ?? ?? 34 ?? 26 ?? ?? 46 81 ?? ?? ?? 75 ?? 40 B3 ?? B3 ?? F3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EnigmaProtector_z_216 
 {
	meta:
		sigid = 216
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 C4 04 EB 02 ?? ?? 60 E8 24 00 00 00 00 00 ?? EB 02 ?? ?? 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 ?? ?? 89 C4 61 EB 2E ?? ?? ?? ?? ?? ?? ?? EB 01 ?? 31 C0 EB 01 ?? 64 FF 30 EB 01 ?? 64 89 20 EB 02 ?? ?? 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 ?? 58 61 EB 01 }
	condition:
		$a0


}


rule Packer_MSLRH_z_214 
 {
	meta:
		sigid = 214
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_213 
 {
	meta:
		sigid = 213
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
		$a1 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_hmimys_z_211 
 {
	meta:
		sigid = 211
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.hmimys.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_kkrunchy_z_209 
 {
	meta:
		sigid = 209
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.kkrunchy.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
		$a1 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF ?? ?? ?? 01 31 C9 41 8D 74 09 01 B8 CA 8E 2A 2E 99 F7 F6 01 C3 89 D8 C1 E8 15 AB FE C1 75 E8 BE }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_PolyEnE_z_208 
 {
	meta:
		sigid = 208
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PolyEnE.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C }
	condition:
		$a0


}

rule Packer_EXEStealth_z_206 
 {
	meta:
		sigid = 206
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 }
	condition:
		$a0


}


rule Packer_ASPack_z_202 
 {
	meta:
		sigid = 202
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
		$a1 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
		$a2 = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point


}


rule Packer_ASPack_z_200 
 {
	meta:
		sigid = 200
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PROPACK_z_199 
 {
	meta:
		sigid = 199
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PROPACK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ASDPack_z_197 
 {
	meta:
		sigid = 197
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASDPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 56 53 E8 5C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 ?? ?? ?? 00 00 00 00 00 00 00 40 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 ?? 00 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5B 81 EB E6 1D 40 00 83 7D 0C 01 75 11 55 E8 4F 01 00 00 E8 6A 01 00 00 5D E8 2C 00 00 00 8B B3 1A 1E 40 00 03 B3 FA 1D 40 00 8B 76 0C AD 0B C0 74 0D FF 75 10 FF 75 0C FF 75 08 FF D0 EB EE B8 01 00 00 00 5B 5E C9 C2 0C 00 55 6A 00 FF 93 20 21 40 00 89 83 FA 1D 40 00 6A 40 68 00 10 00 00 FF B3 02 1E 40 00 6A 00 FF 93 2C 21 40 00 89 83 06 1E 40 00 8B 83 F2 1D 40 00 03 83 FA 1D 40 00 50 FF B3 06 1E 40 00 50 E8 6D 01 00 00 5F }
	condition:
		$a0


}

rule Packer_ORiEN_z_196 
 {
	meta:
		sigid = 196
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ORiEN.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D }
	condition:
		$a0


}


rule Packer_WWPack_z_194 
 {
	meta:
		sigid = 194
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ARMProtector_z_193 
 {
	meta:
		sigid = 193
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ARMProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 13 24 40 00 EB 02 83 09 8D B5 A4 24 40 00 EB 02 83 09 BA 4B 15 00 00 EB 01 00 8D 8D EF 39 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }
	condition:
		$a0


}


rule Packer_yodasCrypter_z_191 
 {
	meta:
		sigid = 191
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasCrypter.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ExeBundle_z_190 
 {
	meta:
		sigid = 190
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeBundle.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EXECryptor_z_188 
 {
	meta:
		sigid = 188
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { CC ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? B4 ?? ?? ?? 08 ?? ?? ?? 00 00 00 00 FF FF FF FF E8 ?? ?? ?? 04 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? 60 ?? ?? ?? 70 ?? ?? ?? 84 ?? ?? ?? 94 ?? ?? ?? A4 ?? ?? ?? 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 }
	condition:
		$a0


}


rule Packer_Armadillo_z_187 
 {
	meta:
		sigid = 187
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 E9 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Morphine_z_185 
 {
	meta:
		sigid = 185
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Morphine.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 }
		$a1 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
	condition:
		$a0 or $a1


}


rule Packer_MSLRH_z_183 
 {
	meta:
		sigid = 183
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ORiEN_z_182 
 {
	meta:
		sigid = 182
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ORiEN.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE ?? 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_180 
 {
	meta:
		sigid = 180
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 9C 60 8B 44 24 24 E8 00 00 00 00 5D 81 ED 00 00 00 00 50 E8 ED 02 00 00 8C C0 0F 84 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_179 
 {
	meta:
		sigid = 179
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
		$a1 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }
		$a2 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }
		$a3 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point


}


rule Packer_ExeShieldProtector_z_177 
 {
	meta:
		sigid = 177
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeShieldProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_themida_z_176 
 {
	meta:
		sigid = 176
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
		$a1 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 5A ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_StealthPE_z_174 
 {
	meta:
		sigid = 174
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.StealthPE.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BA ?? ?? ?? 00 FF E2 BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_173 
 {
	meta:
		sigid = 173
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AppEncryptor_z_171 
 {
	meta:
		sigid = 171
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AppEncryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }
	condition:
		$a0 at pe.entry_point


}

rule Packer_aPack_z_168 
 {
	meta:
		sigid = 168
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.aPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 1E 06 8C C8 8E D8 05 ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B2 ?? BD ?? ?? 33 C9 50 A4 BB ?? ?? 3B F3 76 }
	condition:
		$a0


}

rule Packer_EXEStealth_z_166 
 {
	meta:
		sigid = 166
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC }
	condition:
		$a0


}


rule Packer_SimbiOZPoly_z_89 
 {
	meta:
		sigid = 89
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimbiOZPoly.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Armadillo_z_128 
 {
	meta:
		sigid = 128
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8 }
	condition:
		$a0


}

rule Packer_EXEStealth_z_127 
 {
	meta:
		sigid = 127
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }
	condition:
		$a0


}


rule Packer_FSG_z_123 
 {
	meta:
		sigid = 123
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_121 
 {
	meta:
		sigid = 121
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_RLPack_z_120 
 {
	meta:
		sigid = 120
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }
	condition:
		$a0


}


rule Packer_MSLRH_z_118 
 {
	meta:
		sigid = 118
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DxPack_z_117 
 {
	meta:
		sigid = 117
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DxPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_115 
 {
	meta:
		sigid = 115
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESHiELD_z_114 
 {
	meta:
		sigid = 114
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESHiELD.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B9 1B 01 ?? ?? D1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_112 
 {
	meta:
		sigid = 112
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_111 
 {
	meta:
		sigid = 111
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_109 
 {
	meta:
		sigid = 109
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 D0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 7C A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 78 A5 4C 00 C1 E1 08 03 CA 89 0D 74 A5 4C 00 C1 E8 10 A3 70 A5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AverCryptor_z_108 
 {
	meta:
		sigid = 108
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AverCryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_106 
 {
	meta:
		sigid = 106
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXEStealth_z_104 
 {
	meta:
		sigid = 104
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PECrypt_z_100 
 {
	meta:
		sigid = 100
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PECrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 55 20 40 00 B9 7B 09 00 00 8D BD 9D 20 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SDProtect_z_98 
 {
	meta:
		sigid = 98
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SDProtect.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_87 
 {
	meta:
		sigid = 87
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_156 
 {
	meta:
		sigid = 156
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8 }
		$a1 = { 65 58 50 72 2D 76 2E 31 2E 34 2E }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_NsPack_z_133 
 {
	meta:
		sigid = 133
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PeCompact_z_130 
 {
	meta:
		sigid = 130
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

	condition:
		$a0

}


rule Packer_ASPack_z_129 
 {
	meta:
		sigid = 129
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_103 
 {
	meta:
		sigid = 103
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_101 
 {
	meta:
		sigid = 101
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_62 
 {
	meta:
		sigid = 62
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 74 72 42 00 8B D5 81 C2 C3 72 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3F A9 42 00 81 E9 6E 73 42 00 8B D5 81 C2 6E 73 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 98 2E 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ARMProtector_z_56 
 {
	meta:
		sigid = 56
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ARMProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 }
	condition:
		$a0


}


rule Packer_Petite_z_54 
 {
	meta:
		sigid = 54
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_43 
 {
	meta:
		sigid = 43
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_41 
 {
	meta:
		sigid = 41
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 67 30 00 00 8D 9D 66 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A }
	condition:
		$a0 at pe.entry_point


}

rule Packer_INCrypter_z_40 
 {
	meta:
		sigid = 40
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.INCrypter.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8D 58 20 C7 03 00 00 00 00 E8 00 00 00 00 5D 81 ED 4D 16 40 00 8B 9D 0E 17 40 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 83 F8 01 75 05 03 DB C1 CB 10 8B 8D 12 17 40 00 8B B5 06 17 40 00 51 81 3E 2E 72 73 72 74 65 8B 85 16 17 40 00 E8 23 00 00 00 8B 85 1A 17 40 00 E8 18 00 00 00 8B 85 1E 17 40 00 E8 0D 00 00 00 8B 85 22 17 40 00 E8 02 00 00 00 EB 18 8B D6 3B 46 0C 72 0A 83 F9 01 74 0B 3B 46 34 72 06 BA 00 00 00 00 C3 58 83 FA 00 75 1A 8B 4E 10 8B 7E 0C 03 BD 02 17 40 00 83 F9 00 74 09 F6 17 31 0F 31 1F 47 E2 F7 59 83 C6 28 49 83 F9 00 75 88 8B 85 0A 17 40 00 89 44 24 1C 61 50 C3 }
	condition:
		$a0


}


rule Packer_WWPack_z_38 
 {
	meta:
		sigid = 38
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 05 80 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_37 
 {
	meta:
		sigid = 37
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_BobPack_z_97 
 {
	meta:
		sigid = 97
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.BobPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_95 
 {
	meta:
		sigid = 95
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }
		$a1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_SVKProtector_z_94 
 {
	meta:
		sigid = 94
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SVKProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 0C 61 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 18 61 00 00 5D 6A FF FF 95 10 61 00 00 44 65 62 75 67 67 65 72 20 6F 72 20 74 6F 6F 6C 20 66 6F 72 20 6D 6F 6E 69 74 6F 72 69 6E 67 20 64 65 74 65 63 74 65 64 21 21 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_92 
 {
	meta:
		sigid = 92
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Pelles_z_91 
 {
	meta:
		sigid = 91
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pelles.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Xpack_z_86 
 {
	meta:
		sigid = 86
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Xpack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB }
	condition:
		$a0 at pe.entry_point


}

rule Packer_SimplePack_z_83 
 {
	meta:
		sigid = 83
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimplePack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 8A 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }
	condition:
		$a0


}


rule Packer_Petite_z_81 
 {
	meta:
		sigid = 81
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_80 
 {
	meta:
		sigid = 80
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RECrypt_z_78 
 {
	meta:
		sigid = 78
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RECrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MEW_z_77 
 {
	meta:
		sigid = 77
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MEW.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_70 
 {
	meta:
		sigid = 70
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_68 
 {
	meta:
		sigid = 68
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Protector_z_67 
 {
	meta:
		sigid = 67
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Protector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_65 
 {
	meta:
		sigid = 65
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
		$a1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_RLPack_z_64 
 {
	meta:
		sigid = 64
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 73 26 00 00 8D 9D 58 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_53 
 {
	meta:
		sigid = 53
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 3B 27 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SmokesCrypt_z_51 
 {
	meta:
		sigid = 51
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SmokesCrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Pencrypt_z_50 
 {
	meta:
		sigid = 50
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pencrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB ?? ?? ?? ?? AD 33 C3 E2 FA }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_46 
 {
	meta:
		sigid = 46
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 2D ?? ?? 8E D0 51 2D ?? ?? 8E C0 50 B9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_44 
 {
	meta:
		sigid = 44
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 39 39 39 20 4E 65 6F 57 6F 72 78 20 49 6E 63 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 31 39 39 39 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 00 00 00 00 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_15 
 {
	meta:
		sigid = 15
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_14 
 {
	meta:
		sigid = 14
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 09 00 00 00 C3 F6 00 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_12 
 {
	meta:
		sigid = 12
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ACProtect_z_11 
 {
	meta:
		sigid = 11
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ACProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 53 45 52 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 47 65 74 50 72 6F 63 }
	condition:
		$a0


}


rule Packer_DalKrypt_z_35 
 {
	meta:
		sigid = 35
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DalKrypt.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 68 00 10 40 00 58 68 ?? ?? ?? 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? 00 72 EB FF E7 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_34 
 {
	meta:
		sigid = 34
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 ?? ?? ?? ?? 00 00 23 C1 81 E9 ?? ?? ?? ?? 57 E9 ED 00 00 00 0F 88 ?? ?? ?? ?? E9 2C 0D 00 00 81 ED BB 43 CB 79 C1 E0 1C E9 9E 14 00 00 0B 15 ?? ?? ?? ?? 81 E2 2A 70 7F 49 81 C2 9D 83 12 3B E8 0C 50 00 00 E9 A0 16 00 00 59 5B C3 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 41 42 00 00 E9 93 33 00 00 31 DB 89 D8 59 5B C3 A1 ?? ?? ?? ?? 8A 00 2C 99 E9 82 30 00 00 0F 8A ?? ?? ?? ?? B8 01 00 00 00 31 D2 0F A2 25 FF 0F 00 00 E9 72 21 00 00 0F 86 57 0B 00 00 E9 ?? ?? ?? ?? C1 C0 03 E8 F0 36 00 00 E9 41 0A 00 00 81 F7 B3 6E 85 EA 81 C7 ?? ?? ?? ?? 87 3C 24 E9 74 52 00 00 0F 8E ?? ?? ?? ?? E8 5E 37 00 00 68 B1 74 96 13 5A E9 A1 04 00 00 81 D1 49 C0 12 27 E9 50 4E 00 00 C1 C8 1B 1B C3 81 E1 96 36 E5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_32 
 {
	meta:
		sigid = 32
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 }
		$a1 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 }
	condition:
		$a0 or $a1 at pe.entry_point


}

rule Packer_VProtector_z_31 
 {
	meta:
		sigid = 31
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F 32 30 30 35 5F 33 5F 31 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }
	condition:
		$a0


}


rule Packer_EPProtector_z_29 
 {
	meta:
		sigid = 29
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_27 
 {
	meta:
		sigid = 27
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 5C 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_26 
 {
	meta:
		sigid = 26
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EncryptPE_z_24 
 {
	meta:
		sigid = 24
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EncryptPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEBundle_z_23 
 {
	meta:
		sigid = 23
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEBundle.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_21 
 {
	meta:
		sigid = 21
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_20 
 {
	meta:
		sigid = 20
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }
		$a1 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Packanoid_z_18 
 {
	meta:
		sigid = 18
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Packanoid.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BF 00 ?? 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 ?? ?? ?? 00 8B 30 8B 78 04 BB ?? ?? ?? 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 5E EB DB B9 ?? ?? 00 00 BE 00 ?? ?? 00 EB 01 00 BF ?? ?? ?? 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EncryptPE_z_17 
 {
	meta:
		sigid = 17
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EncryptPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PKLITE_z_137 
 {
	meta:
		sigid = 137
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "PKLITE32 Copyright"
		$a1 = "PKWARE Inc"
		$a2 = ".pklstb"

	condition:
		all of them

}


rule Packer_Pencrypt_z_136 
 {
	meta:
		sigid = 136
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pencrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 28 03 00 00 BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PEBundle_z_134 
 {
	meta:
		sigid = 134
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEBundle.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01 }
	condition:
		$a0


}


rule Packer_MSLRH_z_59 
 {
	meta:
		sigid = 59
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 20 64 65 63 6F 6D 70 72 65 73 73 69 6F 6E 20 72 6F 75 74 69 6E 65 20 76 65 72 73 69 6F 6E 20 31 2E 31 32 0D 0A 28 63 29 20 31 39 39 38 20 50 69 6F 74 72 20 57 61 72 65 7A 61 6B 20 61 6E 64 20 52 61 66 61 6C 20 57 69 65 72 7A 62 69 63 6B 69 0D 0A 0D 0A 5D 5B 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}

rule Packer_SimplePack_z_138 
 {
	meta:
		sigid = 138
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimplePack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }
	condition:
		$a0


}


rule Packer_EXEStealth_z_826 
 {
	meta:
		sigid = 826
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 00 EB 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 90 E8 00 00 00 00 5D }
	condition:
		$a0 at pe.entry_point


}

rule Packer_NTKrnlPacker_z_745 
 {
	meta:
		sigid = 745
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NTKrnlPacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }

	condition:
		$a0

}

rule Packer_NTPacker_z_928 
 {
	meta:
		sigid = 928
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NTPacker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50 E8 71 FB FF FF 8B D8 85 DB 74 2F 53 A1 14 31 00 10 50 E8 97 FB FF FF 85 C0 74 1F 53 A1 14 31 00 10 50 E8 5F FB FF FF 85 C0 74 0F 50 E8 5D FB FF FF 85 C0 74 05 E8 70 FC FF FF 5B E8 F2 F6 FF FF 00 00 48 45 41 52 54 }
	condition:
		$a0


}


rule Packer_DBPE_z_769 
 {
	meta:
		sigid = 769
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DBPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA }
	condition:
		$a0 at pe.entry_point


}


rule Packer_codeCrypter_z_614 
 {
	meta:
		sigid = 614
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.codeCrypter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ExeJoiner_z_476 
 {
	meta:
		sigid = 476
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeJoiner.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_themida_z_337 
 {
	meta:
		sigid = 337
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_235 
 {
	meta:
		sigid = 235
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_RLP_z_589 
 {
	meta:
		sigid = 589
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLP.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }
	condition:
		$a0


}


rule Packer_SLVc0deProtector_z_122 
 {
	meta:
		sigid = 122
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SLVc0deProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 }
		$a1 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 9D 11 40 00 8D 95 B4 11 40 00 E8 CB 2E 00 00 33 C0 F7 F0 69 8D B5 05 12 40 00 B9 5D 2E 00 00 8B FE AC }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_ExeShield_z_99 
 {
	meta:
		sigid = 99
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeShield.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_71 
 {
	meta:
		sigid = 71
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_STProtector_z_507 
 {
	meta:
		sigid = 507
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.STProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 }
	condition:
		$a0


}


rule Packer_Shrinker_z_348 
 {
	meta:
		sigid = 348
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Shrinker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }
		$a1 = { BB ?? ?? BA ?? ?? 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Armadillo_z_284 
 {
	meta:
		sigid = 284
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EXEStealth_z_204 
 {
	meta:
		sigid = 204
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 }
	condition:
		$a0


}


rule Packer_ZCodeWin32PEProtector_z_125 
 {
	meta:
		sigid = 125
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ZCodeWin32PEProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 12 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 FB FF FF FF C3 68 ?? ?? ?? ?? 64 FF 35 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_48 
 {
	meta:
		sigid = 48
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC 90 2C 8A C0 C0 78 90 04 62 EB 01 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VxKeypress_z_839 
 {
	meta:
		sigid = 839
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VxKeypress.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? E8 ?? ?? E8 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EA ?? ?? ?? ?? 1E 33 DB 8E DB BB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VProtector_z_837 
 {
	meta:
		sigid = 837
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_836 
 {
	meta:
		sigid = 836
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 47 26 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_743 
 {
	meta:
		sigid = 743
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Escargot01finalMeat_z_829 
 {
	meta:
		sigid = 829
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Escargot01finalMeat.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 92 ?? ?? ?? 8B 00 FF D0 50 B8 CD ?? ?? ?? 81 38 DE C0 37 13 75 2D 68 C9 ?? ?? ?? 6A 40 68 00 ?? 00 00 68 00 00 ?? ?? B8 96 ?? ?? ?? 8B 00 FF D0 8B 44 24 F0 8B 4C 24 F4 EB 05 49 C6 04 01 40 0B C9 75 F7 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 }
	condition:
		$a0 at pe.entry_point


}

rule CVE_2016_6943_3340 
 {
	meta:
		sigid = 3340
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6943"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/Linearized 1/L 592287/O 31/E 500915/N 1/T 591969/H [ 546 220]" ascii
		$const1 = "/DecodeParms<</Columns 5/Predictor 12" ascii
		$const2 = "/Length 88481/Subtype/XML/Type/Metadata" ascii
		$const3 = "<?xpacket begin=" ascii
		$const4 = "<?xpacket end=" ascii 
		$const5 = "<stEvt:when>"

	condition:
		// 25 50 44 46 2D 31 2E 35 0D 
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x352E and uint8(8) == 0x0D)
		and (all of ($const*))
		and #const1 == 2
		and #const5 == 75

}


rule Packer_NoodleCrypt_z_828 
 {
	meta:
		sigid = 828
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NoodleCrypt.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }
		$a1 = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_Upack_z_824 
 {
	meta:
		sigid = 824
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AnslymCrypter_z_822 
 {
	meta:
		sigid = 822
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AnslymCrypter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A 68 30 1C 05 10 A1 60 56 05 10 50 E8 68 47 FB FF 8B D8 85 DB 0F 84 B6 02 00 00 53 A1 60 56 05 10 50 E8 F2 48 FB FF 8B F0 85 F6 0F 84 A0 02 00 00 E8 F3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ARMProtector_z_821 
 {
	meta:
		sigid = 821
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ARMProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 09 20 40 00 EB 02 83 09 8D B5 9A 20 40 00 EB 02 83 09 BA 0B 12 00 00 EB 01 00 8D 8D A5 32 40 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEiDBundle_z_819 
 {
	meta:
		sigid = 819
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEiDBundle.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Pe123v_z_818 
 {
	meta:
		sigid = 818
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pe123v.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B }
	condition:
		$a0 at pe.entry_point


}

rule Packer_dUP2xPatcher_z_816 
 {
	meta:
		sigid = 816
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.dUP2xPatcher.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }
	condition:
		$a0


}


rule Packer_UPX_z_764 
 {
	meta:
		sigid = 764
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECrypt_z_668 
 {
	meta:
		sigid = 668
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECrypt.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 90 90 60 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 4E 28 40 00 8B F7 AC }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Upack_z_797 
 {
	meta:
		sigid = 797
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0 }

	condition:
		$a0

}


rule Packer_PKLITE_z_640 
 {
	meta:
		sigid = 640
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_349 
 {
	meta:
		sigid = 349
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 08 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESHiELD_z_167 
 {
	meta:
		sigid = 167
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESHiELD.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_1496 
 {
	meta:
		sigid = 1496
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$signature = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }
	condition:
		$signature at pe.entry_point


}


rule Packer_PEProtect_z_910 
 {
	meta:
		sigid = 910
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEProtect.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }
		$a1 = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_FSG_z_906 
 {
	meta:
		sigid = 906
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF }
		$a1 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point

}


rule Packer_tElock_z_827 
 {
	meta:
		sigid = 827
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXEManager_z_825 
 {
	meta:
		sigid = 825
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEManager.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_803 
 {
	meta:
		sigid = 803
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_791 
 {
	meta:
		sigid = 791
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 5F 81 EF 00 00 00 00 BE 00 00 40 00 8B 87 00 00 00 00 03 C6 57 56 8C A7 00 00 00 00 FF 10 89 87 00 00 00 00 5E 5F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SimpleUPXCryptor_z_800 
 {
	meta:
		sigid = 800
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimpleUPXCryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? ?? ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EnigmaProtector_z_939 
 {
	meta:
		sigid = 939
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 52 65 67 43 6C 6F 73 65 4B 65 79 00 00 00 53 79 73 46 72 65 65 53 74 72 69 6E 67 00 00 00 43 72 65 61 74 65 46 6F 6E 74 41 00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 00 00 }
	condition:
		$a0


}


rule Packer_FSG_z_936 
 {
	meta:
		sigid = 936
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 }
		$a1 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00 }
		$a2 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }
		$a3 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }
		$a4 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point or $a4 at pe.entry_point


}


rule Packer_EXEStealth_z_934 
 {
	meta:
		sigid = 934
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Upack_z_931 
 {
	meta:
		sigid = 931
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { BE 88 01 ?? ?? AD 50 ?? ?? AD 91 F3 A5 }
		$a1 = { BE 88 01 ?? ?? AD 50 ?? AD 91 ?? F3 A5 }
	condition:
		$a0 or $a1


}


rule Packer_AcidCrypt_z_925 
 {
	meta:
		sigid = 925
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AcidCrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
		$a1 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_VProtector_z_921 
 {
	meta:
		sigid = 921
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 8A 8E 40 00 68 C6 8E 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_918 
 {
	meta:
		sigid = 918
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_916 
 {
	meta:
		sigid = 916
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_913 
 {
	meta:
		sigid = 913
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_908 
 {
	meta:
		sigid = 908
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESpin_z_744 
 {
	meta:
		sigid = 744
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 26 E8 01 00 00 00 EA 5A 33 C9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_903 
 {
	meta:
		sigid = 903
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PeCompact_z_900 
 {
	meta:
		sigid = 900
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F }
	condition:
		$a0


}


rule Packer_Armadillo_z_897 
 {
	meta:
		sigid = 897
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_aPack_z_893 
 {
	meta:
		sigid = 893
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.aPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ExeShieldCryptor_z_889 
 {
	meta:
		sigid = 889
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeShieldCryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_nPack_z_887 
 {
	meta:
		sigid = 887
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.nPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 EC 01 00 00 E8 F8 06 00 00 E8 03 06 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASDPack_z_884 
 {
	meta:
		sigid = 884
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASDPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8D 49 00 1F 01 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 90 }
		$a1 = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }
		$a2 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }
	condition:
		$a0 or $a1 or $a2 at pe.entry_point


}


rule Packer_themida_z_881 
 {
	meta:
		sigid = 881
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 05 89 48 01 61 E9 }

	condition:
		$a0 at pe.entry_point

}


rule Packer_mPack_z_878 
 {
	meta:
		sigid = 878
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.mPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 F0 33 C0 89 45 F0 B8 A8 76 00 10 E8 67 C4 FF FF 33 C0 55 68 C2 78 00 10 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 08 A5 00 10 33 C0 55 68 A5 78 00 10 64 FF 30 64 89 20 A1 08 A5 00 10 E8 FA C9 FF FF 83 F8 FF 75 0A E8 88 B2 FF FF E9 1B 01 00 00 C7 05 14 A5 00 10 32 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 C9 C9 FF FF BA 14 A5 00 10 A1 08 A5 00 10 B9 04 00 00 00 E8 C5 C9 FF FF 83 3D 14 A5 00 10 32 77 0A E8 47 B2 FF FF E9 DA 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 92 C9 FF FF BA 18 A5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_875 
 {
	meta:
		sigid = 875
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_872 
 {
	meta:
		sigid = 872
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_870 
 {
	meta:
		sigid = 870
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_867 
 {
	meta:
		sigid = 867
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_864 
 {
	meta:
		sigid = 864
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 45 78 50 72 2D 76 2E 31 2E 32 2E }
		$a1 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? ?? 2B 05 84 ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 16 A1 ?? ?? ?? ?? 03 05 80 ?? ?? ?? 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 68 04 }
		$a2 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? ?? 2B 05 84 ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 16 A1 ?? ?? ?? ?? 03 05 80 ?? ?? ?? 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 }
	condition:
		$a0 or $a1 at pe.entry_point or $a2 at pe.entry_point


}

rule Packer_Obsidium_z_861 
 {
	meta:
		sigid = 861
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 }
	condition:
		$a0


}

rule Packer_ASProtect_z_858 
 {
	meta:
		sigid = 858
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0


}

rule Packer_themida_z_855 
 {
	meta:
		sigid = 855
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 }
	condition:
		$a0


}

rule Packer_ASProtect_z_852 
 {
	meta:
		sigid = 852
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0

}


rule Packer_NsPack_z_850 
 {
	meta:
		sigid = 850
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00 }

	condition:
		$a0 at pe.entry_point

}


rule Packer_Alloyv_z_847 
 {
	meta:
		sigid = 847
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Alloyv.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_841 
 {
	meta:
		sigid = 841
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_838 
 {
	meta:
		sigid = 838
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_XXPack_z_835 
 {
	meta:
		sigid = 835
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.XXPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 00 68 00 ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_833 
 {
	meta:
		sigid = 833
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED D5 E4 41 00 8B D5 81 C2 23 E5 41 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_678 
 {
	meta:
		sigid = 678
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_676 
 {
	meta:
		sigid = 676
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CrypKey_z_820 
 {
	meta:
		sigid = 820
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CrypKey.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EnigmaProtector_z_780 
 {
	meta:
		sigid = 780
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 81 ED ?? ?? ?? ?? E9 49 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8A 84 24 28 00 00 00 80 F8 01 0F 84 07 00 00 00 B8 ?? ?? ?? ?? FF E0 E9 04 00 00 00 ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 81 C0 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 30 10 40 49 0F 85 F6 FF FF FF E9 04 00 00 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_VProtector_z_777 
 {
	meta:
		sigid = 777
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C }
		$a1 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C 00 00 00 00 }
		$a2 = { 00 00 00 00 55 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 64 69 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 6C 65 61 73 65 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 }
	condition:
		$a0 or $a1 or $a2


}


rule Packer_ASPack_z_774 
 {
	meta:
		sigid = 774
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SVKProtector_z_766 
 {
	meta:
		sigid = 766
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SVKProtector.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E }
	condition:
		$a0 at pe.entry_point


}


rule Packer_StarForceProtection_z_763 
 {
	meta:
		sigid = 763
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.StarForceProtection.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_760 
 {
	meta:
		sigid = 760
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_757 
 {
	meta:
		sigid = 757
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 EB EB 03 CD 20 03 61 9D 83 C4 04 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_754 
 {
	meta:
		sigid = 754
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EnigmaProtector_z_752 
 {
	meta:
		sigid = 752
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 }
		$a1 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 E9 51 0B C4 80 BC 7E 35 09 37 E7 C9 3D C9 45 C9 4D 74 92 BA E4 E9 24 6B DF 3E 0E 38 0C 49 10 27 80 51 A1 8E 3A A3 C8 AE 3B 1C 35 }
	condition:
		$a0 or $a1


}

rule Packer_Upack_z_749 
 {
	meta:
		sigid = 749
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }
	condition:
		$a0


}


rule Packer_ExeTools_z_746 
 {
	meta:
		sigid = 746
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeTools.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_KGCrypt_z_520 
 {
	meta:
		sigid = 520
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.KGCrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 64 A1 30 ?? ?? ?? 84 C0 74 ?? 64 A1 20 ?? ?? ?? 0B C0 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Packman_z_580 
 {
	meta:
		sigid = 580
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Packman.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_577 
 {
	meta:
		sigid = 577
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NorthStarPEShrinker_z_574 
 {
	meta:
		sigid = 574
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NorthStarPEShrinker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_563 
 {
	meta:
		sigid = 563
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASProtect_z_560 
 {
	meta:
		sigid = 560
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ExeJoiner_z_552 
 {
	meta:
		sigid = 552
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeJoiner.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_549 
 {
	meta:
		sigid = 549
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WinUpack_z_571 
 {
	meta:
		sigid = 571
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WinUpack.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_742 
 {
	meta:
		sigid = 742
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }

	condition:
		$a0 at pe.entry_point

}

rule Packer_NsPack_z_739 
 {
	meta:
		sigid = 739
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 BB 01 47 65 74 53 79 73 74 65 6D 49 6E 66 6F 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 5E 00 5F 43 6F 72 ?? ?? ?? 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C }
	condition:
		$a0


}


rule Packer_ExeGuarder_z_736 
 {
	meta:
		sigid = 736
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeGuarder.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEnguinCrypt_z_733 
 {
	meta:
		sigid = 733
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEnguinCrypt.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_730 
 {
	meta:
		sigid = 730
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CrypKey_z_727 
 {
	meta:
		sigid = 727
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CrypKey.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_725 
 {
	meta:
		sigid = 725
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 05 00 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_722 
 {
	meta:
		sigid = 722
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_719 
 {
	meta:
		sigid = 719
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? E0 ?? ?? ?? ?? 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 38 }
		$a1 = { 55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Obsidium_z_716 
 {
	meta:
		sigid = 716
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_713 
 {
	meta:
		sigid = 713
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_710 
 {
	meta:
		sigid = 710
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_MoleBox_z_708 
 {
	meta:
		sigid = 708
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MoleBox.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 42 04 E8 ?? ?? 00 00 A3 ?? ?? ?? 00 8B 4D F0 8B 11 89 15 ?? ?? ?? 00 ?? 45 FC A3 ?? ?? ?? 00 5F 5E 8B E5 5D C3 CC CC CC CC CC CC CC CC CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 20 61 58 FF D0 E8 ?? ?? 00 00 CC CC CC CC CC CC CC }
	condition:
		$a0


}


rule Packer_Petite_z_705 
 {
	meta:
		sigid = 705
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_themida_z_702 
 {
	meta:
		sigid = 702
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_699 
 {
	meta:
		sigid = 699
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_696 
 {
	meta:
		sigid = 696
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 B4 96 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_themida_z_694 
 {
	meta:
		sigid = 694
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_689 
 {
	meta:
		sigid = 689
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_kkrunchy_z_686 
 {
	meta:
		sigid = 686
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.kkrunchy.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 ?? 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 ?? 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 ?? 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 ?? 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE ?? ?? ?? 00 BB ?? ?? ?? 00 55 46 AD 85 C0 74 ?? 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 ?? 56 55 FF 53 04 AB 85 C0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_523 
 {
	meta:
		sigid = 523
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_669 
 {
	meta:
		sigid = 669
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CrunchPE_z_666 
 {
	meta:
		sigid = 666
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CrunchPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yzpack_z_663 
 {
	meta:
		sigid = 663
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yzpack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_660 
 {
	meta:
		sigid = 660
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SVKProtector_z_657 
 {
	meta:
		sigid = 657
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SVKProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_654 
 {
	meta:
		sigid = 654
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 }
		$a1 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 }
		$a2 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF FF FF 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C }
	condition:
		$a0 or $a1 or $a2 at pe.entry_point


}


rule Packer_Shrink_z_586 
 {
	meta:
		sigid = 586
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Shrink.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 9C FC BE ?? ?? BF ?? ?? 57 B9 ?? ?? F3 A4 8B ?? ?? ?? BE ?? ?? BF ?? ?? F3 A4 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_nPack_z_583 
 {
	meta:
		sigid = 583
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.nPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_465 
 {
	meta:
		sigid = 465
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_462 
 {
	meta:
		sigid = 462
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DBPE_z_459 
 {
	meta:
		sigid = 459
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DBPE.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_UnnamedScrambler_z_456 
 {
	meta:
		sigid = 456
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UnnamedScrambler.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 ?? ?? ?? ?? 40 00 E8 11 F4 FF FF BE 30 6B 40 00 33 C0 55 68 C9 42 40 00 64 FF 30 64 89 20 E8 C9 FA FF FF BA D8 42 40 00 8B ?? ?? ?? ?? FF FF 8B D8 B8 28 6B 40 00 8B 16 E8 37 F0 FF FF B8 2C 6B 40 00 8B 16 E8 2B F0 FF FF B8 28 6B 40 00 E8 19 F0 FF FF 8B D0 8B C3 8B 0E E8 42 E3 FF FF BA DC 42 40 00 8B C6 E8 2A FA FF FF 8B D8 B8 20 6B 40 00 8B 16 E8 FC EF FF FF B8 24 6B 40 00 8B 16 E8 F0 EF FF FF B8 20 6B 40 00 E8 DE EF FF FF 8B D0 8B C3 8B 0E E8 07 E3 FF FF 6A 00 6A 19 6A 00 6A 32 A1 28 6B 40 00 E8 59 EF FF FF 83 E8 05 03 C0 8D 55 EC E8 94 FE FF FF 8B 55 EC B9 24 6B 40 00 A1 20 6B 40 00 E8 E2 F6 FF FF 6A 00 6A 19 6A 00 6A 32 }
	condition:
		$a0


}


rule Packer_SoftDefender_z_445 
 {
	meta:
		sigid = 445
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SoftDefender.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VirogensPEShrinker_z_442 
 {
	meta:
		sigid = 442
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VirogensPEShrinker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 55 E8 ?? ?? ?? ?? 87 D5 5D 60 87 D5 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 57 56 AD 0B C0 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_439 
 {
	meta:
		sigid = 439
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEArmor_z_569 
 {
	meta:
		sigid = 569
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEArmor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 81 C5 ?? ?? ?? ?? 55 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VProtector_z_566 
 {
	meta:
		sigid = 566
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PackItBitch_z_546 
 {
	meta:
		sigid = 546
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PackItBitch.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 28 ?? ?? ?? 35 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 ?? ?? ?? 50 ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? ?? ?? 79 ?? ?? ?? 7D ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0


}


rule Packer_Upack_z_543 
 {
	meta:
		sigid = 543
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EXECryptor_z_537 
 {
	meta:
		sigid = 537
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3 }
	condition:
		$a0


}


rule Packer_PrivatePersonalPacker_z_534 
 {
	meta:
		sigid = 534
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PrivatePersonalPacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DrWebVirusFindingEngineInSoftEDVSysteme_z_532 
 {
	meta:
		sigid = 532
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DrWebVirusFindingEngineInSoftEDVSysteme.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_529 
 {
	meta:
		sigid = 529
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EA ?? ?? ?? ?? F3 A5 C3 59 2D ?? ?? 8E D0 51 2D ?? ?? 50 80 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_495 
 {
	meta:
		sigid = 495
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_634 
 {
	meta:
		sigid = 634
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_AntiDote_z_632 
 {
	meta:
		sigid = 632
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AntiDote.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 65 73 75 6D 65 54 68 72 65 61 64 00 00 29 03 53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 94 03 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 00 6B 03 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 00 00 A6 02 52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 CA 01 47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 62 00 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C }
	condition:
		$a0


}


rule Packer_AverCryptor_z_629 
 {
	meta:
		sigid = 629
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AverCryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 BC 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 98 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_NsPack_z_626 
 {
	meta:
		sigid = 626
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD }
		$a1 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 56 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }
	condition:
		$a0 or $a1


}


rule Packer_NsPack_z_623 
 {
	meta:
		sigid = 623
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_NTKrnlPacker_z_620 
 {
	meta:
		sigid = 620
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NTKrnlPacker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 }
	condition:
		$a0


}


rule Packer_Armadillo_z_355 
 {
	meta:
		sigid = 355
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Shrinker_z_347 
 {
	meta:
		sigid = 347
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Shrinker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 00 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Splasherv10_z_352 
 {
	meta:
		sigid = 352
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Splasherv10.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VxEddie_z_492 
 {
	meta:
		sigid = 492
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VxEddie.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? 4F 4F 0E E8 ?? ?? 47 47 1E FF ?? ?? CB E8 ?? ?? 84 C0 ?? ?? 50 53 56 57 1E 06 B4 51 CD 21 8E C3 ?? ?? ?? ?? ?? ?? ?? 8B F2 B4 2F CD 21 AC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AZProtect_z_490 
 {
	meta:
		sigid = 490
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AZProtect.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 60 BE 00 ?? ?? 00 BF 00 00 40 00 EB 17 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 FF 25 ?? ?? ?? 00 8B C6 03 C7 8B F8 57 55 8B EC 05 7F 00 00 00 50 E8 E5 FF FF FF BA 8C ?? ?? 00 89 02 E9 1A 01 00 00 ?? 00 00 00 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 47 65 74 56 6F 6C 75 6D 65 49 6E 66 6F 72 6D 61 74 69 6F 6E 41 00 4D 65 73 73 61 67 65 42 6F 78 41 00 45 78 69 74 50 72 6F 63 65 73 73 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 }
		$a1 = { FC 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 8B C2 C1 C0 10 66 8B C1 C3 F0 DA 55 8B EC 53 56 33 C9 33 DB 8B 4D 0C 8B 55 10 8B 75 08 4E 4A 83 FB 08 72 05 33 DB 43 EB 01 43 33 C0 8A 04 31 8A 24 13 2A C4 88 04 31 E2 E6 5E 5B C9 C2 0C }
	condition:
		$a0 at pe.entry_point or $a1


}


rule Packer_UPX_z_489 
 {
	meta:
		sigid = 489
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
		$a1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point

}


rule Packer_Obsidium_z_487 
 {
	meta:
		sigid = 487
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ExeSplitter_z_485 
 {
	meta:
		sigid = 485
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeSplitter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 95 02 00 00 64 A1 00 00 00 00 83 38 FF 74 04 8B 00 EB F7 8B 40 04 C3 55 8B EC B8 00 00 00 00 8B 75 08 81 E6 00 00 FF FF B9 06 00 00 00 56 56 E8 B0 00 00 00 5E 83 F8 01 75 06 8B C6 C9 C2 04 00 81 EE 00 00 01 00 E2 E5 C9 C2 04 00 55 8B EC 8B 75 0C 8B DE 03 76 3C 8D 76 18 8D 76 60 8B 36 03 F3 56 8B 76 20 03 F3 33 D2 8B C6 8B 36 03 F3 8B 7D 08 B9 0E 00 00 00 FC F3 A6 0B C9 75 02 EB 08 }
	condition:
		$a0


}


rule Packer_diPacker_z_482 
 {
	meta:
		sigid = 482
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.diPacker.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EnigmaProtector_z_479 
 {
	meta:
		sigid = 479
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }
	condition:
		$a0


}


rule Packer_PEiDBundle_z_473 
 {
	meta:
		sigid = 473
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEiDBundle.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_470 
 {
	meta:
		sigid = 470
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_bambam_z_468 
 {
	meta:
		sigid = 468
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.bambam.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF ?? ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SecurePE_z_453 
 {
	meta:
		sigid = 453
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SecurePE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8B 04 24 E8 00 00 00 00 5D 81 ED 4C 2F 40 00 89 85 61 2F 40 00 8D 9D 65 2F 40 00 53 C3 00 00 00 00 8D B5 BA 2F 40 00 8B FE BB 65 2F 40 00 B9 C6 01 00 00 AD 2B C3 C1 C0 03 33 C3 AB 43 81 FB 8E 2F 40 00 75 05 BB 65 2F 40 00 E2 E7 89 AD 1A 31 40 00 89 AD 55 34 40 00 89 AD 68 34 40 00 8D 85 BA 2F 40 00 50 C3 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Upack_z_450 
 {
	meta:
		sigid = 450
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 }
		$a1 = { FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF }

	condition:
		$a0 or $a1

}


rule Packer_PeCompact_z_448 
 {
	meta:
		sigid = 448
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 00 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E }
	condition:
		$a0 at pe.entry_point


}

rule Packer_MaskPE_z_294 
 {
	meta:
		sigid = 294
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MaskPE.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }

	condition:
		$a0

}


rule Packer_Armadillo_z_436 
 {
	meta:
		sigid = 436
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_433 
 {
	meta:
		sigid = 433
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SDProtect_z_431 
 {
	meta:
		sigid = 431
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SDProtect.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 }
		$a1 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 93 03 00 00 03 C8 74 C4 75 C2 E8 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_CICompress_z_428 
 {
	meta:
		sigid = 428
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CICompress.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ExeTools_z_425 
 {
	meta:
		sigid = 425
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeTools.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? 5D 83 ED ?? 8C DA 2E 89 96 ?? ?? 83 C2 ?? 8E DA 8E C2 2E 01 96 ?? ?? 60 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_423 
 {
	meta:
		sigid = 423
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 2B 00 00 00 0D 0A 0D 0A 0D 0A 52 65 67 69 73 74 41 72 65 64 20 74 6F 3A 20 4E 4F 4E 2D 43 4F 4D 4D 45 52 43 49 41 4C 21 21 0D 0A 0D 0A 0D 00 58 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NsPack_z_421 
 {
	meta:
		sigid = 421
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 00 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Krypton_z_418 
 {
	meta:
		sigid = 418
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Krypton.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }
	condition:
		$a0 at pe.entry_point


}

rule Packer_AlexProtector_z_415 
 {
	meta:
		sigid = 415
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AlexProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25 }
	condition:
		$a0


}


rule Packer_PESpin_z_412 
 {
	meta:
		sigid = 412
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 }
		$a1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_iLUCRYPT_z_409 
 {
	meta:
		sigid = 409
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.iLUCRYPT.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_StonesPEEncryptor_z_406 
 {
	meta:
		sigid = 406
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.StonesPEEncryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EnigmaProtector_z_401 
 {
	meta:
		sigid = 401
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 C5 FA 81 ED ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_WWPack_z_398 
 {
	meta:
		sigid = 398
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 05 80 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_395 
 {
	meta:
		sigid = 395
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_392 
 {
	meta:
		sigid = 392
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_255 
 {
	meta:
		sigid = 255
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_hmimys_z_252 
 {
	meta:
		sigid = 252
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.hmimys.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 }
	condition:
		$a0


}


rule Packer_SDC_z_378 
 {
	meta:
		sigid = 378
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SDC.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 A0 91 40 00 E8 DB FE FF FF 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 3B 3D 8D 00 00 C0 72 4B BB 01 00 00 00 C7 44 24 04 00 00 00 00 C7 04 24 08 00 00 00 E8 CE 24 00 00 83 F8 01 0F 84 C4 00 00 00 85 C0 0F 85 A9 00 00 00 31 C0 83 C4 14 5B 5D C2 04 00 3D 94 00 00 C0 74 56 3D 96 00 00 C0 74 1E 3D 93 00 00 C0 75 E1 EB B5 3D 05 00 00 C0 8D B4 26 00 00 00 00 74 43 3D 1D 00 00 C0 75 CA C7 44 24 04 00 00 00 00 C7 04 24 04 00 00 00 E8 73 24 00 00 83 F8 01 0F 84 99 00 00 00 85 C0 74 A9 C7 04 24 04 00 00 00 FF D0 B8 FF FF FF FF EB 9B 31 DB 8D 74 26 00 E9 69 FF FF FF C7 44 24 04 00 00 00 00 C7 04 24 0B 00 00 00 E8 37 24 00 00 83 F8 01 74 7F 85 C0 0F 84 6D FF FF FF C7 04 24 0B 00 00 00 8D 76 00 FF D0 B8 FF FF FF FF E9 59 FF FF FF C7 04 24 08 00 00 00 FF D0 B8 FF FF FF FF E9 46 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 08 00 00 00 E8 ED 23 00 00 B8 FF FF FF FF 85 DB 0F 84 25 FF FF FF E8 DB 15 00 00 B8 FF FF FF FF E9 16 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 04 00 00 00 E8 BD 23 00 00 B8 FF FF FF FF E9 F8 FE FF FF C7 44 24 04 01 00 00 00 C7 04 24 0B 00 00 00 E8 9F 23 00 00 B8 FF FF FF FF E9 DA FE FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_375 
 {
	meta:
		sigid = 375
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? F3 0D }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Packman_z_372 
 {
	meta:
		sigid = 372
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Packman.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA 8B E8 C6 06 E9 8B 43 0C 89 46 01 6A 04 68 00 10 00 00 FF 73 08 51 FF 55 08 8B }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEArmor_z_370 
 {
	meta:
		sigid = 370
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEArmor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_LameCryptv_z_367 
 {
	meta:
		sigid = 367
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.LameCryptv.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_eXPressor_z_363 
 {
	meta:
		sigid = 363
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 01 68 EB 01 ?? ?? ?? ?? 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 59 59 EB 01 C8 EB 02 66 F0 68 ?? ?? ?? ?? E8 0E 05 00 00 59 EB 01 DD 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 DA 1A 8B 45 F4 0F ?? ?? ?? ?? ?? ?? 33 45 F4 8B 4D F4 88 ?? ?? ?? ?? ?? EB 01 EB EB }
	condition:
		$a0


}

rule Packer_Anti007_z_172 
 {
	meta:
		sigid = 172
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Anti007.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 57 72 69 74 65 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 }
	condition:
		$a0


}


rule Packer_WWPack_z_169 
 {
	meta:
		sigid = 169
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_345 
 {
	meta:
		sigid = 345
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SoftProtect_z_342 
 {
	meta:
		sigid = 342
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SoftProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_340 
 {
	meta:
		sigid = 340
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? 00 68 80 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 ?? ?? 00 33 D2 8A D4 89 15 30 ?? ?? 00 8B C8 81 E1 FF 00 00 00 89 0D 2C ?? ?? 00 C1 E1 08 03 CA 89 0D 28 ?? ?? 00 C1 E8 10 A3 24 }
		$a1 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_PeCompact_z_334 
 {
	meta:
		sigid = 334
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESpin_z_331 
 {
	meta:
		sigid = 331
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PENinja_z_328 
 {
	meta:
		sigid = 328
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PENinja.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_325 
 {
	meta:
		sigid = 325
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 C1 C0 0F E9 ?? ?? ?? 00 87 04 24 58 89 45 FC E9 ?? ?? ?? FF FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 18 E9 ?? ?? ?? ?? 8B 55 08 09 42 F8 E9 ?? ?? ?? FF 83 7D F0 01 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 ?? ?? ?? 00 BA ?? ?? ?? ?? E8 ?? ?? ?? 00 A3 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 C3 83 C4 04 C3 E9 ?? ?? ?? FF 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? FF C1 C2 03 81 CA ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 03 C2 5A E9 ?? ?? ?? FF 81 E7 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? 89 07 E9 ?? ?? ?? ?? 0F 89 ?? ?? ?? ?? 87 14 24 5A 50 C1 C8 10 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_SimplePack_z_323 
 {
	meta:
		sigid = 323
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimplePack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 }
		$a1 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }
	condition:
		$a0 or $a1


}


rule Packer_PeCompact_z_320 
 {
	meta:
		sigid = 320
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SLVc0deProtector_z_317 
 {
	meta:
		sigid = 317
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SLVc0deProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 97 11 40 00 8D B5 EF 11 40 00 B9 FE 2D 00 00 8B FE AC F8 ?? ?? ?? ?? ?? ?? 90 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DBPE_z_314 
 {
	meta:
		sigid = 314
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DBPE.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_311 
 {
	meta:
		sigid = 311
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CRYPToCRACksPEProtector_z_308 
 {
	meta:
		sigid = 308
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CRYPToCRACksPEProtector.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_EXECryptor_z_305 
 {
	meta:
		sigid = 305
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a="VWS1"
		$b={58 56 57 51 53 50 8B 1C 24 81 EB ?? ?? ?? ?? B8}

	condition:
		all of them

}


rule Packer_UPX_z_303 
 {
	meta:
		sigid = 303
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
		$a1 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
		$a2 = { E8 ?? ?? ?? ?? 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point


}


rule Packer_themida_z_300 
 {
	meta:
		sigid = 300
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_297 
 {
	meta:
		sigid = 297
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PCGuard_z_60 
 {
	meta:
		sigid = 60
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PCGuard.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Petite_z_291 
 {
	meta:
		sigid = 291
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VProtector_z_288 
 {
	meta:
		sigid = 288
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 1A 89 40 00 68 56 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_285 
 {
	meta:
		sigid = 285
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_283 
 {
	meta:
		sigid = 283
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 00 00 59 EB 01 EB AC 54 E8 03 00 00 00 5C EB 08 8D 64 24 04 FF 64 24 FC 6A 05 D0 2C 24 72 01 E8 01 24 24 5C F7 DC EB 02 CD 20 8D 64 24 FE F7 DC EB 02 CD 20 FE C8 E8 00 00 00 00 32 C1 EB 02 82 0D AA EB 03 82 0D 58 EB 02 1D 7A 49 EB 05 E8 01 00 00 00 7F AE 14 7E A0 77 76 75 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_kkrunchy_z_281 
 {
	meta:
		sigid = 281
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.kkrunchy.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_HidePE_z_105 
 {
	meta:
		sigid = 105
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.HidePE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D }
	condition:
		$a0 at pe.entry_point


}


rule Packer_JExeCompressor_z_218 
 {
	meta:
		sigid = 218
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.JExeCompressor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8D 2D D3 4A E5 14 0F BB F7 0F BA E5 73 0F AF D5 8D 0D 0C 9F E6 11 C0 F8 EF F6 DE 80 DC 5B F6 DA 0F A5 C1 0F C1 F1 1C F3 4A 81 E1 8C 1F 66 91 0F BE C6 11 EE 0F C0 E7 33 D9 64 F2 C0 DC 73 0F C0 D5 55 8B EC BA C0 1F 41 00 8B C2 B9 97 00 00 00 80 32 79 50 B8 02 00 00 00 50 03 14 24 58 58 51 2B C9 B9 01 00 00 00 83 EA 01 E2 FB 59 E2 E1 FF E0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_z_215 
 {
	meta:
		sigid = 215
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
		$a1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_EnigmaProtector_z_212 
 {
	meta:
		sigid = 212
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E EB 04 ?? ?? ?? ?? B8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 01 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 05 F6 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 B9 44 1A }
	condition:
		$a0


}


rule Packer_JDPack_z_210 
 {
	meta:
		sigid = 210
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.JDPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? 05 00 00 00 00 83 C4 0C 5D 60 E8 00 00 00 00 5D 8B D5 64 FF 35 00 00 00 00 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Winkript_z_207 
 {
	meta:
		sigid = 207
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Winkript.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AHPack_z_205 
 {
	meta:
		sigid = 205
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AHPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PolyCryptor_z_203 
 {
	meta:
		sigid = 203
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PolyCryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Pencrypt_z_201 
 {
	meta:
		sigid = 201
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Pencrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 25 00 00 F7 BF 00 00 00 00 00 00 00 00 00 00 12 00 E8 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 00 00 E8 00 00 00 00 5D 81 ED 2C 10 40 00 8D B5 14 10 40 00 E8 33 00 00 00 89 85 10 10 40 00 BF 00 00 40 00 8B F7 03 7F 3C 8B 4F 54 51 56 8D 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_HACKSTOP_z_198 
 {
	meta:
		sigid = 198
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.HACKSTOP.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 ?? ?? 58 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_StonesPEEncryptor_z_195 
 {
	meta:
		sigid = 195
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.StonesPEEncryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasCrypter_z_192 
 {
	meta:
		sigid = 192
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasCrypter.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_189 
 {
	meta:
		sigid = 189
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_186 
 {
	meta:
		sigid = 186
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PCShrink_z_184 
 {
	meta:
		sigid = 184
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PCShrink.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_181 
 {
	meta:
		sigid = 181
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_eXPressor_z_161 
 {
	meta:
		sigid = 161
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? 00 2B 05 84 ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 16 A1 ?? ?? ?? 00 03 05 80 ?? ?? 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 68 04 }
	condition:
		$a0


}

rule Packer_SCObfuscatorSuperCRacker_z_158 
 {
	meta:
		sigid = 158
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SCObfuscatorSuperCRacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 33 C9 8B 1D 00 ?? ?? ?? 03 1D 08 ?? ?? ?? 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D 04 ?? ?? ?? 75 E7 A1 08 ?? ?? ?? 01 05 0C ?? ?? ?? 61 FF 25 0C }
	condition:
		$a0


}


rule Packer_SkDUndetectabler_z_155 
 {
	meta:
		sigid = 155
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SkDUndetectabler.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_152 
 {
	meta:
		sigid = 152
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PrivateEXE_z_149 
 {
	meta:
		sigid = 149
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PrivateEXE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 53 E8 00 00 00 00 5B 8B C3 2D }
		$a1 = { 06 60 C8 ?? ?? ?? 0E 68 ?? ?? 9A ?? ?? ?? ?? 3D ?? ?? 0F ?? ?? ?? 50 50 0E 68 ?? ?? 9A ?? ?? ?? ?? 0E }
		$a2 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D ?? ?? ?? ?? 50 81 ?? ?? ?? ?? ?? 8B }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point


}


rule Packer_ASPack_z_147 
 {
	meta:
		sigid = 147
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
		$a1 = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_PrivateEXEProtector_z_144 
 {
	meta:
		sigid = 144
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PrivateEXEProtector.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB BA 00 00 00 80 C7 44 24 14 08 00 00 00 43 8D A4 24 00 00 00 00 8B FF 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 2C 8B 4C 24 10 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 02 44 24 0C 88 07 47 EB C6 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 82 6E 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 83 DC 00 00 00 B9 04 00 00 00 33 C0 8D A4 24 00 00 00 00 8D 64 24 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 48 74 B1 0F 89 EF 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 42 BD 00 01 00 00 B9 08 00 00 00 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 88 07 47 4D 75 D6 }
	condition:
		$a0


}


rule Packer_tElock_z_141 
 {
	meta:
		sigid = 141
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 }
		$a1 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_DBPE_z_96 
 {
	meta:
		sigid = 96
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DBPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_v_z_93 
 {
	meta:
		sigid = 93
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.v.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_hmimys_z_90 
 {
	meta:
		sigid = 90
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.hmimys.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 ?? ?? 01 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 74 ?? ?? ?? 00 00 00 00 00 }
	condition:
		$a0


}


rule Packer_AVPACK_z_88 
 {
	meta:
		sigid = 88
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AVPACK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 ?? ?? FC F3 A5 06 BB ?? ?? 53 CB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UltraPro_z_85 
 {
	meta:
		sigid = 85
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UltraPro.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_82 
 {
	meta:
		sigid = 82
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RECrypt_z_79 
 {
	meta:
		sigid = 79
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RECrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ExeSmasher_z_76 
 {
	meta:
		sigid = 76
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ExeSmasher.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FishPEShield_z_73 
 {
	meta:
		sigid = 73
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FishPEShield.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 AD FF FF FF 89 45 DC E8 C1 FE FF FF 8B 10 03 55 DC 89 55 E4 83 C0 04 8B 10 89 55 FC 83 C0 04 8B 10 89 55 F4 83 C0 04 8B 10 89 55 F8 83 C0 04 8B 10 89 55 F0 83 C0 04 8B 10 89 55 EC 83 C0 04 8B 00 89 45 E8 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B 46 C7 45 E0 00 00 00 00 83 7B 04 00 74 14 }
		$a1 = { 60 E8 12 FE FF FF C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 28 88 00 00 40 ?? 4B 00 00 00 02 00 00 00 A0 00 00 18 01 00 00 40 ?? 4C 00 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 40 ?? 4E 00 00 00 00 00 00 00 C0 00 00 40 39 00 00 40 ?? 4E 00 00 00 08 00 00 00 00 01 00 C8 06 00 00 40 }
	condition:
		$a0 or $a1 at pe.entry_point


}


rule Packer_Rcryptor_z_69 
 {
	meta:
		sigid = 69
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_66 
 {
	meta:
		sigid = 66
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ACProtect_z_63 
 {
	meta:
		sigid = 63
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ACProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 76 03 77 01 7B 74 03 75 01 78 47 87 EE E8 01 00 00 00 76 83 C4 04 85 EE EB 01 7F 85 F2 EB 01 79 0F 86 01 00 00 00 FC EB 01 78 79 02 87 F2 61 51 8F 05 19 38 01 01 60 EB 01 E9 E9 01 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PECrypt_z_57 
 {
	meta:
		sigid = 57
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PECrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_55 
 {
	meta:
		sigid = 55
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }
		$a1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 8E FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_SDProtect_z_52 
 {
	meta:
		sigid = 52
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SDProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_CrypWrap_z_49 
 {
	meta:
		sigid = 49
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.CrypWrap.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 B8 ?? ?? ?? E8 90 02 ?? ?? 83 F8 ?? 75 07 6A ?? E8 ?? ?? ?? ?? FF 15 49 8F 40 ?? A9 ?? ?? ?? 80 74 0E }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EP_z_47 
 {
	meta:
		sigid = 47
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EP.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_45 
 {
	meta:
		sigid = 45
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 3B C4 73 ?? 8B C4 2D ?? ?? 25 ?? ?? 8B F8 B9 ?? ?? BE ?? ?? FC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ZealPack_z_42 
 {
	meta:
		sigid = 42
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ZealPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { C7 45 F4 00 00 40 00 C7 45 F0 ?? ?? ?? ?? 8B 45 F4 05 ?? ?? ?? ?? 89 45 F4 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 F0 7D 22 8B 45 F4 03 45 FC 8A 08 88 4D F8 0F BE 55 F8 83 F2 0F 88 55 F8 8B 45 F4 03 45 FC 8A 4D F8 88 08 EB CD FF 65 F4 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Morphine_z_39 
 {
	meta:
		sigid = 39
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Morphine.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 }
	condition:
		$a0


}


rule Packer_Armadillo_z_36 
 {
	meta:
		sigid = 36
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 F0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 84 A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 80 A5 4C 00 C1 E1 08 03 CA 89 0D 7C A5 4C 00 C1 E8 10 A3 78 A5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EnigmaProtector_z_33 
 {
	meta:
		sigid = 33
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EnigmaProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_codeCrypter_z_30 
 {
	meta:
		sigid = 30
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.codeCrypter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 58 53 5B 90 BB ?? ?? 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }
	condition:
		$a0


}

rule Packer_RLPack_z_28 
 {
	meta:
		sigid = 28
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 10 }
	condition:
		$a0


}


rule Packer_PESpinv11Cyberbob_z_25 
 {
	meta:
		sigid = 25
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpinv11Cyberbob.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_22 
 {
	meta:
		sigid = 22
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_19 
 {
	meta:
		sigid = 19
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 EB ?? 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_16 
 {
	meta:
		sigid = 16
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_13 
 {
	meta:
		sigid = 13
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 50 8B C6 87 04 24 68 ?? ?? ?? ?? 5E E9 ?? ?? ?? ?? 85 C8 E9 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 0F 81 ?? ?? ?? 00 81 FA ?? ?? ?? ?? 33 D0 E9 ?? ?? ?? 00 0F 8D ?? ?? ?? 00 81 D5 ?? ?? ?? ?? F7 D1 0B 15 ?? ?? ?? ?? C1 C2 ?? 81 C2 ?? ?? ?? ?? 9D E9 ?? ?? ?? ?? C1 E2 ?? C1 E8 ?? 81 EA ?? ?? ?? ?? 13 DA 81 E9 ?? ?? ?? ?? 87 04 24 8B C8 E9 ?? ?? ?? ?? 55 8B EC 83 C4 F8 89 45 FC 8B 45 FC 89 45 F8 8B 45 08 E9 ?? ?? ?? ?? 8B 45 E0 C6 00 00 FF 45 E4 E9 ?? ?? ?? ?? FF 45 E4 E9 ?? ?? ?? 00 F7 D3 0F 81 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 34 24 5E 8B 45 F4 E8 ?? ?? ?? 00 8B 45 F4 8B E5 5D C3 E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VProtector_z_449 
 {
	meta:
		sigid = 449
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 }
		$a1 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 E8 05 00 00 00 0F 01 EB 05 E8 EB FB 00 00 83 C4 04 E8 08 00 00 00 0F 01 83 C0 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}

rule Packer_Apex_z_438 
 {
	meta:
		sigid = 438
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Apex.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 ?? ?? 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 ?? ?? ?? 00 C3 }
	condition:
		$a0


}


rule Packer_SimbiOZPoly_z_437 
 {
	meta:
		sigid = 437
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimbiOZPoly.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_435 
 {
	meta:
		sigid = 435
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 64 84 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_434 
 {
	meta:
		sigid = 434
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 74 81 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_444 
 {
	meta:
		sigid = 444
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_443 
 {
	meta:
		sigid = 443
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_441 
 {
	meta:
		sigid = 441
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }
		$a1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
		$a2 = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point


}


rule Packer_ACProtect_z_440 
 {
	meta:
		sigid = 440
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ACProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_themida_z_446 
 {
	meta:
		sigid = 446
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 16
		
	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_264 
 {
	meta:
		sigid = 264
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_muckisprotector_z_261 
 {
	meta:
		sigid = 261
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.muckisprotector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 E8 85 C0 74 12 64 8B 3D 18 00 00 00 8B 7F 30 0F B6 47 02 85 C0 74 01 C3 C7 04 24 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_v_z_258 
 {
	meta:
		sigid = 258
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.v.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_StonesPEEncryptor_z_102 
 {
	meta:
		sigid = 102
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.StonesPEEncryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_247 
 {
	meta:
		sigid = 247
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 F4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 F4 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_244 
 {
	meta:
		sigid = 244
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXEPACK_z_241 
 {
	meta:
		sigid = 241
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEPACK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 06 ?? ?? 8E C0 8B 0E ?? ?? 8B F9 4F 8B F7 FD F3 A4 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PrivateEXEProtector_z_238 
 {
	meta:
		sigid = 238
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PrivateEXEProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 FF 31 F6 C3 }
	condition:
		$a0


}


rule Packer_Rcryptor_z_232 
 {
	meta:
		sigid = 232
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? ?? EB F3 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Petite_z_229 
 {
	meta:
		sigid = 229
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_227 
 {
	meta:
		sigid = 227
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ARMProtector_z_224 
 {
	meta:
		sigid = 224
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ARMProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_StealthPE_z_909 
 {
	meta:
		sigid = 909
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.StealthPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA ?? ?? ?? ?? FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EPProtector_z_844 
 {
	meta:
		sigid = 844
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EPProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED 42 30 40 00 FF 95 32 35 40 00 B8 37 30 40 00 03 C5 2B 85 1B 34 40 00 89 85 27 34 40 00 83 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_DEF_z_823 
 {
	meta:
		sigid = 823
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.DEF.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_BeRoEXEPacker_z_794 
 {
	meta:
		sigid = 794
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.BeRoEXEPacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_691 
 {
	meta:
		sigid = 691
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_VProtector_z_673 
 {
	meta:
		sigid = 673
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }
	condition:
		$a0


}


rule Packer_SafeGuard_z_643 
 {
	meta:
		sigid = 643
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SafeGuard.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 EB 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 9C 81 C1 E2 FF FF FF EB 01 ?? 9D FF E1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_540 
 {
	meta:
		sigid = 540
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? FF 50 C1 C8 18 89 05 ?? ?? ?? ?? C3 C1 C0 18 51 E9 ?? ?? ?? FF 84 C0 0F 84 6A F9 FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF E8 CF E9 FF FF B8 01 00 00 00 E9 ?? ?? ?? FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 ?? ?? ?? FF 84 C0 0F 84 8E EC FF FF E9 ?? ?? ?? FF C3 87 3C 24 5F 8B 00 03 45 FC 83 C0 18 E9 ?? ?? ?? FF 87 0C 24 59 B8 01 00 00 00 D3 E0 23 D0 E9 02 18 00 00 0F 8D DB 00 00 00 C1 E8 14 E9 CA 00 00 00 9D 87 0C 24 59 87 1C 24 68 AE 73 B9 96 E9 C5 10 00 00 0F 8A ?? ?? ?? ?? E9 ?? ?? ?? FF 81 FD F5 FF 8F 07 E9 4F 10 00 00 C3 E9 5E 12 00 00 87 3C 24 E9 ?? ?? ?? FF E8 ?? ?? ?? FF 83 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 8D 55 EC B8 ?? ?? ?? ?? E9 ?? ?? ?? FF E8 A7 1A 00 00 E8 2A CB FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF 59 89 45 E0 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_Armadillo_z_516 
 {
	meta:
		sigid = 516
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43 }
	condition:
		$a0


}


rule Packer_VProtector_z_496 
 {
	meta:
		sigid = 496
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 E8 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 05 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PECrypt_z_404 
 {
	meta:
		sigid = 404
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PECrypt.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PELOCKNT_z_381 
 {
	meta:
		sigid = 381
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PELOCKNT.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EncryptPE_z_357 
 {
	meta:
		sigid = 357
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EncryptPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NoodleCrypt_z_272 
 {
	meta:
		sigid = 272
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NoodleCrypt.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESpin_z_249 
 {
	meta:
		sigid = 249
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_221 
 {
	meta:
		sigid = 221
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PEArmor_z_933 
 {
	meta:
		sigid = 933
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEArmor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
		$a1 = { E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_JDPack_z_920 
 {
	meta:
		sigid = 920
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.JDPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_902 
 {
	meta:
		sigid = 902
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_843 
 {
	meta:
		sigid = 843
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_NsPack_z_831 
 {
	meta:
		sigid = 831
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NsPack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }

	condition:
		$a0

}


rule Packer_Armadillo_z_813 
 {
	meta:
		sigid = 813
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 38 ?? ?? ?? 68 40 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 F4 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PELOCKNT_z_756 
 {
	meta:
		sigid = 756
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PELOCKNT.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB ?? CD ?? ?? ?? ?? ?? CD ?? ?? ?? ?? ?? EB ?? EB ?? EB ?? EB ?? CD ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 50 C3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_741 
 {
	meta:
		sigid = 741
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_726 
 {
	meta:
		sigid = 726
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 }
		$a1 = { EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_Petite_z_674 
 {
	meta:
		sigid = 674
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Petite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0D 00 0F 00 11 00 13 00 17 00 1B 00 1F 00 23 00 2B 00 33 00 3B 00 43 00 53 00 63 00 73 00 83 00 A3 00 C3 00 E3 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 02 02 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXECryptor_z_659 
 {
	meta:
		sigid = 659
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXECryptor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 51 68 ?? ?? ?? ?? 87 2C 24 8B CD 5D 81 E1 ?? ?? ?? ?? E9 ?? ?? ?? 00 89 45 F8 51 68 ?? ?? ?? ?? 59 81 F1 ?? ?? ?? ?? 0B 0D ?? ?? ?? ?? 81 E9 ?? ?? ?? ?? E9 ?? ?? ?? 00 81 C2 ?? ?? ?? ?? E8 ?? ?? ?? 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C E9 ?? ?? ?? 00 F7 D6 2B D5 E9 ?? ?? ?? 00 87 3C 24 8B CF 5F 87 14 24 1B CA E9 ?? ?? ?? 00 83 C4 08 68 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? 00 E9 ?? ?? ?? 00 50 8B C5 87 04 24 8B EC 51 0F 88 ?? ?? ?? 00 FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 99 03 04 24 E9 ?? ?? ?? 00 C3 81 D5 ?? ?? ?? ?? 9C E9 ?? ?? ?? 00 81 FA ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 15 81 CB ?? ?? ?? ?? 81 F3 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 87 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_644 
 {
	meta:
		sigid = 644
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B ?? ?? ?? 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AHPack_z_585 
 {
	meta:
		sigid = 585
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AHPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_573 
 {
	meta:
		sigid = 573
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Passwordprotector_z_558 
 {
	meta:
		sigid = 558
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Passwordprotector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 8B FD 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 46 80 ?? ?? 74 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_484 
 {
	meta:
		sigid = 484
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_RLPack_z_472 
 {
	meta:
		sigid = 472
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_457 
 {
	meta:
		sigid = 457
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E ?? ?? 00 00 00 00 00 00 00 00 00 3E ?? ?? 00 2E ?? ?? 00 26 ?? ?? 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 36 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EncryptPE_z_408 
 {
	meta:
		sigid = 408
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EncryptPE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 }
		$a1 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_ASProtect_z_396 
 {
	meta:
		sigid = 396
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ASProtect.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_338 
 {
	meta:
		sigid = 338
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXEStealth_z_326 
 {
	meta:
		sigid = 326
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { EB 65 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 59 4F 55 52 20 41 44 20 48 45 52 45 21 50 69 52 41 43 59 20 69 53 20 41 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Cryptic_z_310 
 {
	meta:
		sigid = 310
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Cryptic.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 00 00 40 00 BB ?? ?? ?? 00 B9 00 10 00 00 BA ?? ?? ?? 00 03 D8 03 C8 03 D1 3B CA 74 06 80 31 ?? 41 EB F6 FF E3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_256 
 {
	meta:
		sigid = 256
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_NeoLite_z_243 
 {
	meta:
		sigid = 243
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NeoLite.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_228 
 {
	meta:
		sigid = 228
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 00 80 ?? 40 90 90 01 85 9E 80 ?? 40 BB F8 10 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_170 
 {
	meta:
		sigid = 170
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXEStealth_z_157 
 {
	meta:
		sigid = 157
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXEStealth.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_FSG_z_142 
 {
	meta:
		sigid = 142
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 }

	condition:
		$a0

}


rule Packer_PeCompact_z_84 
 {
	meta:
		sigid = 84
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_72 
 {
	meta:
		sigid = 72
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_61 
 {
	meta:
		sigid = 61
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E9 59 E4 FF FF 00 00 00 00 00 00 00 ?? ?? ?? ?? EE ?? ?? 00 00 00 00 00 00 00 00 00 0E ?? ?? 00 FE ?? ?? 00 F6 ?? ?? 00 00 00 00 00 00 00 00 00 1B ?? ?? 00 06 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VProtector_z_469 
 {
	meta:
		sigid = 469
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_BorlandDelphi_z_467 
 {
	meta:
		sigid = 467
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.BorlandDelphi.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_ASPack_1668 
 {
	meta:
		sigid = 1668
		date = "2016-02-01 08:00 AM"
		threatname = "Packer.ASPack"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$str1={60 E8 00 00 00 00 5D 81 ED 5D 3B 40 00 64 A1 30 00 00 00 0F B6 40 02 0A C0 74 04 33 C0 87 00 B9 ?? ?? 00 00 8D BD B7 3B 40 00 8B F7 AC}

	condition:
		$str1 at pe.entry_point

}

rule Packer_MEW_11_1664 
 {
	meta:
		sigid = 1664
		date = "2016-02-01 08:00 AM"
		threatname = "Packer.MEW_11"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$signature1={50 72 6F 63 41 64 64 72 65 73 73 00 E9 [6-7] 00 00 00 00 00 00 00 00 00 [7] 00}
		$signature2="MEW"

	condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $signature1 and $signature2

}


rule Packer_PEPack_z_806 
 {
	meta:
		sigid = 806
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PolyBox_z_651 
 {
	meta:
		sigid = 651
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PolyBox.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 E4 41 00 10 E8 3A E1 FF FF 33 C0 55 68 11 44 00 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 6A 0A 68 20 44 00 10 A1 1C 71 00 10 50 E8 CC E1 ?? ?? ?? ?? 85 DB 0F 84 77 01 00 00 53 A1 1C 71 00 10 50 E8 1E E2 FF FF 8B F0 85 F6 0F 84 61 01 00 00 53 A1 1C 71 00 10 50 E8 E0 E1 FF FF 85 C0 0F 84 4D 01 00 00 50 E8 DA E1 FF FF 8B D8 85 DB 0F 84 3D 01 00 00 56 B8 70 80 00 10 B9 01 00 00 00 8B 15 98 41 00 10 E8 9E DE FF FF 83 C4 04 A1 70 80 00 10 8B CE 8B D3 E8 E1 E1 FF FF 6A 00 6A 00 A1 70 80 00 10 B9 30 44 00 10 8B D6 E8 F8 FD FF FF }
	condition:
		$a0


}


rule Packer_eXPressor_z_617 
 {
	meta:
		sigid = 617
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C }
	condition:
		$a0 at pe.entry_point


}


rule Packer_FSG_z_612 
 {
	meta:
		sigid = 612
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FSG.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Upack_z_610 
 {
	meta:
		sigid = 610
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 ?? F3 AB C1 E0 ?? B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C ?? 73 ?? B0 ?? 3C ?? 72 02 2C ?? 50 0F B6 5F FF C1 E3 ?? B3 ?? 8D 1C 5B 8D ?? ?? ?? ?? ?? ?? B0 ?? 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_XtremeProtector_z_607 
 {
	meta:
		sigid = 607
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.XtremeProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_yodasProtector_z_604 
 {
	meta:
		sigid = 604
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PKLITE_z_601 
 {
	meta:
		sigid = 601
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PKLITE.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 2E 8C 1E ?? ?? 8B 1E ?? ?? 8C DA 81 C2 ?? ?? 3B DA 72 ?? 81 EB ?? ?? 83 EB ?? FA 8E D3 BC ?? ?? FB FD BE ?? ?? 8B FE }
	condition:
		$a0 at pe.entry_point


}


rule Packer_UPX_z_598 
 {
	meta:
		sigid = 598
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point

}


rule Packer_Armadillo_z_596 
 {
	meta:
		sigid = 596
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PENinja_z_593 
 {
	meta:
		sigid = 593
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PENinja.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_590 
 {
	meta:
		sigid = 590
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_yCv_z_588 
 {
	meta:
		sigid = 588
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yCv.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }
	condition:
		$a0


}


rule Packer_Upack_z_557 
 {
	meta:
		sigid = 557
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Upack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_TPACK_z_554 
 {
	meta:
		sigid = 554
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.TPACK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 8E FE }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESpin_z_360 
 {
	meta:
		sigid = 360
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E }
	condition:
		$a0 at pe.entry_point


}

rule Packer_VMProtect_z_178 
 {
	meta:
		sigid = 178
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VMProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }
	condition:
		$a0


}


rule Packer_eXPressor_z_175 
 {
	meta:
		sigid = 175
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_yPv10bby_z_452 
 {
	meta:
		sigid = 452
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yPv10bby.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 C2 E8 03 00 00 00 EB 01 ?? AC ?? ?? ?? ?? ?? ?? ?? EB 01 E8 }
	condition:
		$a0


}


rule Packer_MSLRH_z_451 
 {
	meta:
		sigid = 451
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F }
		$a1 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F CA C0 C7 91 0F CB C1 D9 0C 86 F9 86 D7 D1 D9 EB 01 A5 EB 01 11 EB 01 1D 0F C1 C2 0F CB 0F C1 C2 EB 01 A1 C0 E9 FD 0F C1 D1 EB 01 E3 0F CA 87 D9 EB 01 F3 0F CB 87 C2 0F C0 F9 D0 F7 EB 01 2F 0F C9 C0 DC C4 EB 01 35 0F CA D3 D1 86 C8 EB 01 01 0F C0 F5 87 C8 D0 DE EB 01 95 EB 01 E1 EB 01 FD EB 01 EC 87 D3 0F CB C1 DB 35 D3 E2 0F C8 86 E2 86 EC C1 FB 12 D2 EE 0F C9 D2 F6 0F CA 87 C3 C1 D3 B3 EB 01 BF D1 CB 87 C9 0F CA 0F C1 DB EB 01 44 C0 CA F2 0F C1 D1 0F CB EB 01 D3 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }
	condition:
		$a0 or $a1 at pe.entry_point


}


rule Packer_PEBundle_z_343 
 {
	meta:
		sigid = 343
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEBundle.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_NTKrnlPacker_z_341 
 {
	meta:
		sigid = 341
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.NTKrnlPacker.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 4B 57 69 6E 64 6F 77 73 00 10 55 54 79 70 65 73 00 00 3F 75 6E 74 4D 61 69 6E 46 75 6E 63 74 69 6F 6E 73 00 00 47 75 6E 74 42 79 70 61 73 73 00 00 B7 61 50 4C 69 62 75 00 00 00 }
	condition:
		$a0


}


rule Packer_FucknJoy_z_339 
 {
	meta:
		sigid = 339
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.FucknJoy.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 }
		$a1 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 00 0B C0 0F 84 EC 00 00 00 89 85 4D 08 40 00 8D 85 51 08 40 00 50 FF B5 6C 08 40 00 E8 AF 02 00 00 0B C0 0F 84 CC 00 00 00 89 85 5C 08 40 00 8D 85 67 07 40 00 E8 7B 02 00 00 8D B5 C4 07 40 00 56 6A 64 FF 95 74 07 40 00 46 80 3E 00 75 FA C7 06 74 6D 70 2E 83 C6 04 C7 06 65 78 65 00 8D 85 36 07 40 00 E8 4C 02 00 00 33 DB 53 53 6A 02 53 53 68 00 00 00 40 8D 85 C4 07 40 00 50 FF 95 74 07 40 00 89 85 78 07 40 00 8D 85 51 07 40 00 E8 21 02 00 00 6A 00 8D 85 7C 07 40 00 50 68 00 ?? ?? 00 8D 85 F2 09 40 00 50 FF }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_yodasProtector_z_336 
 {
	meta:
		sigid = 336
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.yodasProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PESpin_z_333 
 {
	meta:
		sigid = 333
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESpin.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Rcryptor_z_332 
 {
	meta:
		sigid = 332
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Rcryptor.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 }
		$a1 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_PELOCKNT_z_330 
 {
	meta:
		sigid = 330
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PELOCKNT.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_themida_z_245 
 {
	meta:
		sigid = 245
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 ?? 89 48 01 61 E9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_JDPack_z_250 
 {
	meta:
		sigid = 250
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.JDPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD 45 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_SimplePack_z_882 
 {
	meta:
		sigid = 882
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.SimplePack.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 ?? ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_tElock_z_880 
 {
	meta:
		sigid = 880
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_879 
 {
	meta:
		sigid = 879
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F }
	condition:
		$a0 at pe.entry_point


}

rule Packer_themida_z_877 
 {
	meta:
		sigid = 877
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.themida.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0

}

rule Packer_WinUpack_z_876 
 {
	meta:
		sigid = 876
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WinUpack.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 }
		$a1 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 }
	condition:
		$a0 or $a1


}


rule Packer_Armadillo_z_874 
 {
	meta:
		sigid = 874
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC }
	condition:
		$a0 at pe.entry_point


}


rule Packer_EXELOCK_z_873 
 {
	meta:
		sigid = 873
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.EXELOCK.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_817 
 {
	meta:
		sigid = 817
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PolyCryptor_z_811 
 {
	meta:
		sigid = 811
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PolyCryptor.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }
	condition:
		$a0


}


rule Packer_AINEXEv_z_808 
 {
	meta:
		sigid = 808
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AINEXEv.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8 36 A3 ?? ?? 05 ?? ?? 36 A3 ?? ?? 2E A1 ?? ?? 8A D4 B1 04 D2 EA FE C9 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_codeCrypter_z_649 
 {
	meta:
		sigid = 649
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.codeCrypter.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_637 
 {
	meta:
		sigid = 637
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_AdysGlue_z_646 
 {
	meta:
		sigid = 646
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.AdysGlue.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 2E 8C 06 ?? ?? 0E 07 33 C0 8E D8 BE ?? ?? BF ?? ?? FC B9 ?? ?? 56 F3 A5 1E 07 5F }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_789 
 {
	meta:
		sigid = 789
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_UPX_z_786 
 {
	meta:
		sigid = 786
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.UPX.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
		$a0

}


rule Packer_HASPHLProtection_z_397 
 {
	meta:
		sigid = 397
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.HASPHLProtection.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 }
		$a1 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B 15 }
	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point


}


rule Packer_PESHiELD_z_460 
 {
	meta:
		sigid = 460
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PESHiELD.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_PeCompact_z_368 
 {
	meta:
		sigid = 368
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PeCompact.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Armadillo_z_358 
 {
	meta:
		sigid = 358
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Armadillo.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_VProtector_z_581 
 {
	meta:
		sigid = 581
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.VProtector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 60 8B B4 24 24 00 00 00 8B BC 24 28 00 00 00 FC C6 C2 80 33 DB A4 C6 C3 02 E8 A9 00 00 00 0F 83 F1 FF FF FF 33 C9 E8 9C 00 00 00 0F 83 2D 00 00 00 33 C0 E8 8F 00 00 00 0F 83 37 00 00 00 C6 C3 02 41 C6 C0 10 E8 7D 00 00 00 10 C0 0F 83 F3 FF FF FF }
		$a1 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 FF FF C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 }
	condition:
		$a0 or $a1 at pe.entry_point


}


rule Packer_WWPack_z_830 
 {
	meta:
		sigid = 830
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.WWPack.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_Obsidium_z_624 
 {
	meta:
		sigid = 624
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.Obsidium.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_TheHypersprotector_z_501 
 {
	meta:
		sigid = 501
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.TheHypersprotector.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 ?? ?? 01 01 ?? ?? 01 01 ?? ?? ?? 00 ?? ?? 01 01 ?? ?? 02 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_eXPressor_z_932 
 {
	meta:
		sigid = 932
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.eXPressor.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 45 78 50 72 2D 76 2E 31 2E 33 2E }
		$a1 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 13 A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 ?? ?? E9 ?? ?? 00 00 C7 05 }
	condition:
		$a0 or $a1 at pe.entry_point


}


rule Packer_tElock_z_849 
 {
	meta:
		sigid = 849
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.tElock.z"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 }
	condition:
		$a0 at pe.entry_point


}


rule Packer_MSLRH_z_661 
 {
	meta:
		sigid = 661
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.MSLRH.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_ACProtect_z_698 
 {
	meta:
		sigid = 698
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.ACProtect.z"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 }
	condition:
		$a0


}


rule Packer_RLPack_z_226 
 {
	meta:
		sigid = 226
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.RLPack.z"
		category = "Malware & Botnet"
		risk = 8
		
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }
	condition:
		$a0 at pe.entry_point


}

rule Packer_PEArmor_z_58 
 {
	meta:
		sigid = 58
		date = "2016-01-01 08:00 AM"
		threatname = "Packer.PEArmor.z"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 00 08 00 00 00 00 00 00 00 60 E8 00 00 00 00 }
	condition:
		$a0


}

