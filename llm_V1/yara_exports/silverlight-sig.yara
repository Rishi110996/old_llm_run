rule CVE_2013_0074_Win32_XAP_Exploit_1615 
 {
	meta:
		sigid = 1615
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2013-0074.Win32.XAP.Exploit"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$string0 = {50 4b 03 04} //magic no of zip format
		$string1 = {41 70 70 4d 61 6e 69 66 65 73 74 2e 78 61 6d 6c} //AppManifest.xaml
		$string2 = {2e 64 6c 6c} //.dll
		$name0 = "jlgrqoa789.dll"
		$name1 = "brplcyuw46.dll"
		$name2 = "onus.dll"
		$name3 = "counter.dll"
		$name4 = "a6w2fdfw2.dll"
		$name5 = "webstat.dll"
		$name6 = "dies.dll"
		$name7 = "pede5"
		$name8 = "tuynlged30.dll"
		$name9 = "asdgsd.dll"
		$name10 = "cbddss.dll"
		$name11 = "kind.dll"
		$name12 = "aattscss.dll"
		$name13 = "fuasldi653.dll"
		$name14 = "aaatscss.dll"
		$name15 = "OV3goU159re.dll"
		$name16 = "uimxhrq67.dll"
		$name17 = "SilverlightApplication1.dll"
		$name18 = "pbgoacs345.dll"
		$name19 = "vKrNMbH7vX1LxRVh.dll"
		$name20 = "rkomafw264.dll"
		$name21 = "VbDhgsiQhVFYJUCf.dll"
		$name22 = "raw.dll"
		$name23 = "VbNrTeQhVqYuUCf.dll"
		$name24 = "wbsotrz34.dll"
		$name25 = "webhelp.dll"
		$name26 = "dike.dll"
		$name27 = "VbnRTeQhVqYuUCf.dll"
		$name28 = "tics.dll"
		$name29 = "dig.dll"
		$name30 = "pvisngbw369.dll"
		$name31 = "naqmjxbg270.dll"
		$name32 = "usus.dll"
		$name33 = "VbNrHerhEzDYuUCf.dll"
		$name34 = "Silverlight.dll"
		$name35 = "ycrdael653.dll"
		$name36 = "bFbiYcS7T7flGX0.dll"
		$name37 = "webads.dll"
		$name38 = "crtmiqg408.dll"
		$name39 = "jerkem"
		$name40 = "iframe.dll"
		$name41 = "Preloader.dll"
		$name42 = "kpoqhvj36.dll"
		$name43 = "minn.dll"
		$name44 = "dsfdgrr333.dll"
		$name46 = "FlEornHheLekdghE.dll"
		$name47 = "pvisngb369.dll"
		$name48 = "aVbtTTscsC.dll"
		$name49 = "pbgoacs34.dll"
		$name50 = "star.dll"
		$name51 = "gods.dll"
		$name52 = "wart.dll"
		$name53 = "elrhkto23.dll"
		$name54 = "zhuitel542.dll"
		$name55 = "cbdddssT.dll"
		$name56 = "jest.dll"
		$name57 = "xervamanepe4enki.dll"
		$name58 = "aVRtTTscsC.dll"
		$name59 = "loop.dll"
		$name60 = "jillrez.dll"
		$name61 = "SilverApp1.dll"
		$name62 = "ukqpysd562.dll"
		$name63 = "wfhjitcg56.dll"
		$name64 = "cuss.dll"
		$name65 = "zhuitel54.dll"
		$name66 = "fileso.dll"
		$name67 = "payload324.dll"
		$name68 = "aVbtTTfcsC.dll"
		$name69 = "pvisngbw36.dll"
		$name70 = "main.dll"

	condition:
		all of ($string*) and any of ($name*)
}

rule XPS_Exploit_CVE_2018_12837_118749 
 {
	meta:
		sigid = 118749
		date = "2018-10-03 06:33 AM"
		threatname = "XPS.Exploit.CVE-2018-12837"
		category = "Malware & Botnet"
		risk = 0
		Description = "Rule to detect JPEG data (within XPS) that triggers the vulnerability." 
Disclaimer = "This rule is provided for informational purposes only."
Author = "Adobe PSIRT" 
Date = "08/13/2018"
Distribution = "Microsoft MAPP Program Only" 
Revision = 1
	strings:
$hex_data_jpeg = {FF E0 00 10 4A 46 49 46 00 01 01 01 01 2C FF FF 00 00}

condition: 
(uint16(0) == 0xD8FF) and $hex_data_jpeg
}

