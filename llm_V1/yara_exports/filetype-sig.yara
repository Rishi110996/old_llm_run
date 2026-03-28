rule rtf_document_2006 
 {
	meta:
		sigid = 2006
		date = "2016-03-01 08:00 AM"
		threatname = "rtf_document"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$rtfmagic = "{\\rtf"

	condition:
		$rtfmagic at 0

}

rule chm_file_9 
 {
	meta:
		sigid = 9
		date = "2016-01-01 08:00 AM"
		threatname = "chm_file"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$magic = { 49 54 53 46 03 00 00 00  60 00 00 00 01 00 00 00 }

	condition:
		$magic

}

rule word_7 
 {
	meta:
		sigid = 7
		date = "2016-01-01 08:00 AM"
		threatname = "word"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$worddoc = "WordDocument" wide
		$msworddoc = "MSWordDoc" nocase

	condition:
		$rootentry and ($worddoc or $msworddoc)

}

rule powerpoint_6 
 {
	meta:
		sigid = 6
		date = "2016-01-01 08:00 AM"
		threatname = "powerpoint"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$pptdoc = "PowerPoint Document" wide nocase
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		all of them

}

rule APK_4 
 {
	meta:
		sigid = 4
		date = "2016-01-01 08:00 AM"
		threatname = "APK"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a = { 50 4b}
		$b = { 00 41 6e 64 72 6f 69 64 4d 61 6e 69 66 65 73 74  2e 78 6d 6c }
		$c = { 63 6c 61 73 73 65 73 2e 64 65 78 }

	condition:
		$a and $b and $c

}

rule flash_3 
 {
	meta:
		sigid = 3
		date = "2016-01-01 08:00 AM"
		threatname = "flash"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a = {43 57 53}
		$b = {46 57 53}
		$c = {5A 57 53}

	condition:
		($a at 0) or ($b at 0) or ($c at 0)

}

rule JARArchive_2 
 {
	meta:
		sigid = 2
		date = "2016-01-01 08:00 AM"
		threatname = "JARArchive"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$magic = { 50 4b 03 04 ( 14 | 0a ) 00 }
		$string_1 = "META-INF/"
		$string_2 = ".class" nocase

	condition:
		$magic at 0 and 1 of ($string_*)

}

rule PDF_Exploit_CVE_2018_5067_124549 
 {
	meta:
		sigid = 124549
		date = "2021-11-11 09:07 AM"
		threatname = "PDF.Exploit.CVE-2018-5067"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
$emf = {20 45 4d 46}
$emr_count = {0D 40 ?? 40 ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 50 EB 45 00 A0 AA 45}

condition:
(uint32(0)==0x00000001) and $emf at 40 and $emr_count
}

rule Silverlight_file_1543 
 {
	meta:
		sigid = 1543
		date = "2016-02-01 08:00 AM"
		threatname = "Silverlight_file"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$magic = {50 4b 03 04} 
		$string1 = {41 70 70 4d 61 6e 69 66 65 73 74 2e 78 61 6d 6c} 
		$string2 = {2e 64 6c 6c}

	condition:
		all of them

}

rule office_10 
 {
	meta:
		sigid = 10
		date = "2016-01-01 08:00 AM"
		threatname = "office"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }

	condition:
		$magic

}

rule excel_8 
 {
	meta:
		sigid = 8
		date = "2016-01-01 08:00 AM"
		threatname = "excel"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$workbook = "Workbook" wide nocase
		$msexcel = "Microsoft Excel" nocase

	condition:
		all of them

}

rule pdf_5 
 {
	meta:
		sigid = 5
		date = "2016-01-01 08:00 AM"
		threatname = "pdf"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a = "%PDF-"

	condition:
		$a at 0

}

rule zip_file_1 
 {
	meta:
		sigid = 1
		date = "2016-01-01 08:00 AM"
		threatname = "zip_file"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$magic = { 50 4b 03 04 }
		$magic2 = { 50 4b 05 06 }
		$magic3 = { 50 4b 07 08 }
	condition:
		all of them

}

