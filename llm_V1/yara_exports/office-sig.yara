rule VBA_Downloader_SnakeKeylogger_136901 
 {
	meta:
		sigid = 136901
		date = "2025-05-19 08:35 AM"
		modified_date = "2025-05-19 12:14 PM"
		threatname = "VBA.Downloader.SnakeKeylogger"
		category = "Malware & Botnet"
		risk = 100
		threat = "VBA.Downloader.SnakeKeylogger"
Date = "19May2025"
Author = "Gayathri Anbalagan"
Comment = "SMBA"
sample = "11bf382b3d15e97bc4b4daf474e7d020"
	strings:
	$s1 = "CreateObject(\"WScript.Shell\")" wide ascii
        $s2 = ".Run \"excel.exe\", 1" wide ascii
        $s3 = /wp-includes\/assets\/[A-Za-z0-9]{4,12}\/[A-Za-z0-9]{6,12}.bat/ wide ascii
        $s4 = "Environ(\"TEMP\")" wide ascii
        $s5 = "CreateObject(\"MSXML2.XMLHTTP\")" wide ascii
        $s6 = ".Open \"GET\"," wide ascii
        $s7 = "CreateObject(\"ADODB.Stream\")" wide ascii
        $s8 = ".Type = 1 ' Binary" wide ascii

    condition:
        all of ($s*)
}

rule VBA_Trojan_Agent_131412 
 {
	meta:
		sigid = 131412
		date = "2024-03-26 13:27 PM"
		threatname = "VBA.Trojan.Agent"
		category = "Malware & Botnet"
		risk = 100
		threat = "VBA.Trojan.Agent"
Date = "24Mar2024"
Author = "Gayathri Anbalagan"
Comment = "SMBA"
sample = "397a68f5a6631b02d1a2ba4c6f965b8a"
	strings:
		$s1 = "Sub Workbook_Open()"
		$s2 = "Get_IP"
		$s3 = "Get_Username"
		$s4 = "Get_AppleID"
		$s5 = "Left(BASE, InStr(BASE, EOS) - 1)"
		$s6 = ".Mangle_Request(" wide
		$s7 = ".Trigger_Token (" wide
		$s8 = ".o3n.io" wide
condition:
		$s1 and $s2 and $s3 and $s4 and $s5 and $s6 and $s7 and $s8
}

rule VBA_Trojan_ProxyChanger_131071 
 {
	meta:
		sigid = 131071
		date = "2024-03-20 13:00 PM"
		threatname = "VBA.Trojan.ProxyChanger"
		category = "Malware & Botnet"
		risk = 90
		threat = " VBA.Trojan.ProxyChanger"
Date = "19Feb2024"
Author = "Gayathri Anbalagan"
Comment = "SMBA Case"
Reference = "http://10.66.10.53:8005/get-file-sample-info/4755c5cd71792e332a76f6e873323700"
	strings:
	$str1 = "Sub Auto_Open()"
	$str2 = "Sub Workbook_Open()"
	$str3 = "Shell(\"Powershell Invoke-command { wget http://"
	$str4 = "-OutFile $env:temp\\"
	$str5 = "Start-Process"
	$str6 = ", vbHide)"

condition:
		$str1 and $str2 and $str3 and $str4 and $str5 and $str6 and filesize <=50KB
}

rule VBA_Trojan_Agent_126163 
 {
	meta:
		sigid = 126163
		date = "2022-08-26 10:04 AM"
		threatname = "VBA.Trojan.Agent"
		category = "Malware & Botnet"
		risk = 10
		filehash = "e7f3e494c46b17b6df2ba810516a8214"
	strings:
       $mgic = {D0CF11E0A1B11AE1}
       $suspicious_cmd= "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring(" wide ascii nocase
       $vba_project = "VBA_PROJECT" wide nocase
condition:
      $mgic at 0 and  $suspicious_cmd and $vba_project
}

rule VBA_Downloader_RokRat_123985 
 {
	meta:
		sigid = 123985
		date = "2021-09-08 07:12 AM"
		threatname = "VBA.Downloader.RokRat"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Document_Open()"
$str2 = "Application.Run"
$str3 = "CreateMutex Lib \"kernel32\" Alias \"CreateMutexA\""
$str4 = "& \"S\" & \"cr\" & \"ip\" & \"t.\" & \"sh\" & \"ell\")"
$str5 = "Sof\" & \"tware\\Mic\" & \"rosoft\\Of\" & \"fice"
$str6 = ".RegWrite"
$str7 = "C:\\Windows\\"
$str8 = "ord.Ap\" & \"pli\" & \"cat\" & \"ion"

condition:
all of them
}

rule VBA_Downloader_TransparentTribe_123511 
 {
	meta:
		sigid = 123511
		date = "2021-07-06 07:28 AM"
		threatname = "VBA.Downloader.TransparentTribe"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Environ$(\"ALLUSERSPROFILE\") &"
$str2 = ".TextBox11.Text"
$str3 = "Application.OperatingSystem"
$str4 = "Split("
$str5 = "For Binary Access Write As #2"
$str6 = "Put #2"
$str7 = "Shell"

condition:
all of them
}

rule VBA_Downloader_Agent_122979 
 {
	meta:
		sigid = 122979
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 50
		
	strings:

$str1 = "Environ$(\"AppData\")"
$str2 = "& \"\\\" & file_Nave_name & \".vbe\""
$str4 = "UserForm1.TextBox1.Text"
$str5 = "For Output As #1"
$str6 = "Print #1, vbe"
$str7 = "Close #1"

condition:
all of them
}

rule Win32_Downloader_Kimsuky_122929 
 {
	meta:
		sigid = 122929
		date = "2021-03-26 06:30 AM"
		threatname = "Win32.Downloader.Kimsuky"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "WinExec Lib \"kernel32.dll\""
$str2 = ".Path & \"\\\" &"
$str3 = "cmVnLmV4ZSBhZGQg"
$str4 = "XFdvcmRc"
$str5 = "IFZCQVdhcm5pbmdzIC90IHJlZ19kd29yZCAvZCAxIC9m"
$str6 = ".OperatingSystem"
$str7 = ".Open \"GET\""
$str8 = ".Send"

condition:
all of them
}

rule VBA_Dropper_Hancitor_122987 
 {
	meta:
		sigid = 122987
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Dropper.Hancitor"
		category = "Malware & Botnet"
		risk = 100
		hash = "de80e1d7d9f5b1c64ec9f8d4f5063989"
	strings:
		$mgic = {D0CF11}
		$str1 = "DllRegisterServer" wide ascii
		$str2 = "DllUnregisterServer" wide ascii
		$str3 = "Fourfeet" wide ascii
		$str4 = "Plantexercise" wide ascii
		$str5 ="Propertykept" wide ascii
		$str6 = "Scalewindow" wide ascii
		$str7 = "Supportclimb" wide ascii
		$str8 = "This program cannot be run in DOS mode." wide ascii
condition:
		$mgic at 0 and all of ($str*)
}

rule VBA_Dropper_PythonRAT_122980 
 {
	meta:
		sigid = 122980
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Dropper.PythonRAT"
		category = "Malware & Botnet"
		risk = 50
		
	strings:

$str1 = "Document_Close()"
$str2 = "Document_Open()"
$str3 = "VBA.CreateObject("
$str4 = "Shell"
$str5 = "vbDirectory) <> vbNullString Then"
$str6 = "VBA.CreateObject("
$str7 = "Environ("
$str8 = ".Documents.Add(ActiveDocument.FullName)"
$str9 = "For Binary Access Write As #1"
$str10 = ".Namespace(unZipFolderName).CopyHere"
$str11 = "If Cell.Value Mod 2 = 0 Then"
$caseCnt = "case \"" nocase


condition:
all of ($str*) and #caseCnt > 80
}

rule VBA_Dropper_TransparentTribe_122732 
 {
	meta:
		sigid = 122732
		date = "2021-02-12 06:01 AM"
		threatname = "VBA.Dropper.TransparentTribe"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"Shell.Application\")"
$str2 = "Environ$(\"ALLUSERSPROFILE\") &"
$str3 = "& \".zip\""
$str4 = "& \".exe\""
$str5 = "Application.System.Version, \"6.2\") > 0"
$str6 = "Split(UserForm1."
$str7 = "Write As #2"
$str8 = "Put #2"

condition:
all of them
}

rule VBA_Downloader_Ursnif_122626 
 {
	meta:
		sigid = 122626
		date = "2021-01-28 09:06 AM"
		threatname = "VBA.Downloader.Ursnif"
		category = "Malware & Botnet"
		risk = 100
		
	strings: 

$str1 = "Public MemArrayList"
$str2 = ".AddItem (Logo.ControlTipText)"
$str3 = "C:\\users\\Public\\"
$str4 = "\"http\""
$str5 = ".Open \"GET\","
$str6 = "ListBox1.List("
$str7 = ".Write"
$str8 = ".SaveToFile"
$str9 = "Shell% ("

condition:
all of them
}

rule VBA_Downlaoder_EmbeddedVBS_3819 
 {
	meta:
		sigid = 3819
		date = "2017-05-23 01:42 AM"
		threatname = "VBA_Downlaoder_EmbeddedVBS"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "new this[\"ActiveXObject\"]"
		$s2 = "WScript.Shell"
		$s3 = "\\x52\\165\\156"
		$s4 = "Normal.dotm"
		$s5= "AppData\\Local\\Temp\\"

	condition:
		all of ($s*)

}

rule CVE_2016_0021_2526 
 {
	meta:
		sigid = 2526
		date = "2016-04-01 07:00 AM"
		threatname = "CVE-2016-0021"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = "\\objdata{" wide ascii
		$s1 = "496e666f506174682e44657369676e6572457863656c496d706f7274" wide ascii
		$s2 = "496e666f506174682e44657369676e6572576f7264496d706f7274" wide ascii

	condition:
		$a1 and any of ($s*)

}

rule VBA_Trojan_Agent_124262 
 {
	meta:
		sigid = 124262
		date = "2021-10-08 14:26 PM"
		threatname = "VBA.Trojan.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Workbook_Activate()"
$str2 = "JABQAHIAbwBjAE4AYQBt"
$str3 = "Replace("
$str4 = "werShell\\v1.0\\pow"
$str5 = ".bat\""
$str6 = "For Output As #1"
$str7 = "Print #1, \"start"
$str8 = "Shell("

condition:
all of them
}

rule VBA_Trojan_OctopusC2_124150 
 {
	meta:
		sigid = 124150
		date = "2021-09-27 16:40 PM"
		threatname = "VBA.Trojan.OctopusC2"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"Scripting.FileSystemObject\")"
$str2 = "Environ$(\"Username\")"
$str3 = "\\\\Start Menu\\\\Programs\\\\Startup\\\\Word$Data$PHCCP$.bat"
$str4 = ".Write \"p\""
$str5 = ".Write \"o\""
$str6 = ".Write \"w\""
$str7 = ".DownloadString('http"
$str8 = "php');Invoke-Expression"
$str9 = "Shell("
$str10 = "Document_Open()"

condition:
all of them
}

rule VBA_Dropper_Lazarus_123094 
 {
	meta:
		sigid = 123094
		date = "2021-05-07 06:00 AM"
		threatname = "VBA.Dropper.Lazarus"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "VGhpcyBwcm9ncmFtIGNhbm5v"
$str2 = ".Run \"cmd /c copy /b %systemroot%\\system32\\certut"
$str3 = "-decode"
$str4 = "& del"
$str5 = "GetObject(\"winmgmts:\\\\.\\root\\cimv2\""
$str6 = ".ExecQuery(\"Select * from Win32_Process where name="
$str7 = "mavinject.exe"
$str8 = "/injectrunning"

condition:
all of them
}

rule VBA_Downloader_Agent_123598 
 {
	meta:
		sigid = 123598
		date = "2021-07-16 11:53 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "document_Open()"
$str2 = "winmgmts:\\\\.\\root\\cimv2"
$str3 = "Select * from Win32_NetworkAdapter where physicaladapter="
$str4 = ".MACAddress"
$str5 = "msoFileDialogSaveAs"
$str6 = ".SaveAs2 FileName:="
$str7 = ".ExecQuery("
$str8 = "Application.ScreenUpdating = True"

condition:
all of them
}

rule VBA_Downloader_Kimsuky_123592 
 {
	meta:
		sigid = 123592
		date = "2021-07-16 05:36 AM"
		threatname = "VBA.Downloader.Kimsuky"
		category = "Malware & Botnet"
		risk = 80
		
	strings:

$str1 = "Document_Open()"
$str2 = "= CreateObject(\"Shell.Application\")"
$str3 = ".ShellExecute"
$str4 = "Selection.TypeText Text:=\"a\""
$str5 = "Selection.TypeText Text:=\"b\""
$str6 = "Application.Run MacroName:=\"Project.NewMacros."
$str7 = "election.MoveDown Unit:=wdScreen, Count:=1"
$Cnt = "Replace("

condition:
all of ($str*) and #Cnt > 5
}

rule VBA_Downloader_Valyria_124895 
 {
	meta:
		sigid = 124895
		date = "2022-01-04 08:24 AM"
		threatname = "VBA.Downloader.Valyria"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "STARTUPINFO"
$str2 = "\"kernel32\" Alias \"CreateRemoteThread\""
$str3 = "\"kernel32\" Alias \"VirtualAllocEx\""
$str4 = "\"kernel32\" Alias \"WriteProcessMemory\""
$str5 = "\"kernel32\" Alias \"CreateProcessA\""
$str6 = "\\\\rundll32.exe"
$str7 = "Auto_Open"

condition:
all of them
}

rule VBA_Downloader_Agent_124879 
 {
	meta:
		sigid = 124879
		date = "2021-12-28 16:51 PM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Environ(clearText(\"Ap6pp6pDa1at0ta1a\")) &"
$str2 = "Mi9ic3cr8ro5os9so5of6ft0t"
$str3 = "C:\\ProgramData"
$str4 = ".txt"
$str5 = ".vbs"
$str6 = "CreateObject(\"Scripting.FileSystemObject\")"

condition:
all of them
}

rule XLS_Downloader_Agent_124877 
 {
	meta:
		sigid = 124877
		date = "2021-12-28 12:45 PM"
		threatname = "XLS.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "llehsrewop"
$str2 = "swodniW\\:C"
$str3 = ".bat"
$str4 = "StrReverse("
$str5 = "For Output As #1"
$str6 = "Shell("

condition:
all of them
}

rule CVE_2015_1770_1973 
 {
	meta:
		sigid = 1973
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_1770"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = "{\\rt"
		$str1="{\\object\\objocx{\\*\\objdata"
		$str2="6f746b6c6f6164722e5752417373656d626c792e31"
		$str3="\\object\\objemb\\objsetsize\\objw9361\\objh764{\\*\\objclass Word.Document.12"
		$str4="d0cf11e0a1b11ae1"
		$str6="504b0304140000000800000021003361f6a414020000"

	condition:
		($magic at 0) and (all of ($str*))

}

rule VBA_Downloader_Macro_3586 
 {
	meta:
		sigid = 3586
		date = "2017-02-16 16:28 PM"
		threatname = "VBA_Downloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$hex1 = {D0 CF 11 E0}
		$str1 = {70 61 6C 6D 61 74 69 66 69 64 71 E4 30 00 07 80 00 00 FF 03 03 00 72 65 65 6E 74 72 79 A6 BC 30} //palmatifid = reentry
		$str2 = { FF 03 03 00 74 61 6E 74 72 75 6D 73 C4} // Dim Tanrurum
		$str3 = {03 03 00 62 72 69 62 65 72 79 F5 B9} // Bribery
		$str4 = {03 03 00 67 75 6D 77 6565 64 DC B1} //gumweed
		$str5 = {03 03 00 76 69 74 75 70 65 72 61 74 65 A0 25 30} //vituperateá
		$str6 = {03 03 00 70 65 63 74 6F 72 65 0C B0} //Pectore
		$str7 = {03 03 00 62 61 6C 6C 75 70 03 03 00 61 6E 61 7263 68 69 73 74 B5 4A 30 00 06}
		$str8 = {03 03 00 63 6F 63 6B 66 69 67 68 74 C9 4F 30 00 0A 84 08 00 FF 03 03 00 66 61 63 69 6C 69 74 61}

	condition:
		$hex1 and (all of ($str*))

}

rule VBA_Downloader_Ursnif_121687 
 {
	meta:
		sigid = 121687
		date = "2022-03-02 11:58 AM"
		threatname = "VBA.Downloader.Ursnif"
		category = "Malware & Botnet"
		risk = 0
		
	
    strings:
        $string = ".txt.text"
        $string_1 = "End Function"
		$string_2 = "Public Function"
		$string_3 = {285265706C61636528 [10-20] 22222929}
		$string_4 = "AutoOpen()"
		$string_5 = {536574 [4-10] 3D204E6577205773685368656C6C}
		$string_6 = {2E65786563}    
    condition:
         all of them

}

rule VBA_Downloader_2564 
 {
	meta:
		sigid = 2564
		date = "2016-04-01 07:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a1={42 6C 6F 71 75 65 61 72 60 4D 65 6E 75}
		$a2="establecerPapel"
		$a3="FinProg"
		$a4="ModifyTibiaRSAs"
		$a5="CerrarRecorset"
		$a6="AbrirRecorset"
		$a7={41 64 6A 75 6E 74 6F 20 3D 20 22}
		$a8="DevEstadoDespacho"

	condition:
		($magic at 0) and (all of ($a*))

}

rule VBA_Downloader_Amphitryon_125013 
 {
	meta:
		sigid = 125013
		date = "2022-01-28 06:53 AM"
		threatname = "VBA.Downloader.Amphitryon"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"MSXML2.ServerXMLHTTP\")"
$str2 = ".Open \"GET\", URL, False"
$str3 = "setRequestHeader \"User-Agent\", \"Microsoft BITS"
$str4 = "CreateObject(\"ADODB.Stream\")"
$str5 = ".ResponseBody"
$str6 = ".SaveToFile"
$str7 = "Environ(\"LocalAppData\") & \"\\Temp\\"
$str8 = "StrReverse"
$str9 = "CreateObject(\"Shell.Application\")"

condition:
all of them
}

rule VBA_Downloader_QuasarRAT_124887 
 {
	meta:
		sigid = 124887
		date = "2021-12-30 05:46 AM"
		threatname = "VBA.Downloader.QuasarRAT"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Lib \"shell32\" Alias \"ShellExecuteW\""
$str2 = "Document_Open()"
$str3 = "\\Public\\"
$str4 = "powers"
$str5 = "Start-BitsT"
$str6 = "Close #"
$str7 = "Replace("
$str8 = "StrConv(\""

condition:
all of them
}

rule VBA_Dropper_Agent_124321 
 {
	meta:
		sigid = 124321
		date = "2021-10-14 13:13 PM"
		threatname = "VBA.Dropper.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Document_open()"
$str2 = "(\"c:\\programdata"
$str3 = "& \"ta\""
$str4 = "Microsoft Word"
$str5 = ".Execute"
$str6 = "ReplaceWith"
$str7 = ".SaveAs2"
$str8 = "New WshShell"
$str9 = ".run"

condition:
all of them
}

rule VBA_Downloader_XtremeRAT_124380 
 {
	meta:
		sigid = 124380
		date = "2021-10-21 12:20 PM"
		threatname = "VBA.Downloader.XtremeRAT"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Auto_Open()"
$str2 = "= \"P\":"
$str3 = "= \"o\":"
$str4 = "= \"w\":"
$str5 = "= \"e\":"
$str6 = "= \"r\":"
$str7 = "= \"s\":"
$str8 = "= \"h\":"
$str9 = "= \"e\":"
$str10 = "= \"l\":"
$str11 = "= \"l\":"
$str12 = "-e  SQBFAFgAIAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAg"
$str13 = "AE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbA"

condition:
all of them
}

rule VBA_Trojan_Ethan_124264 
 {
	meta:
		sigid = 124264
		date = "2021-10-08 16:19 PM"
		threatname = "VBA.Trojan.Ethan"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Document_Close()"
$str2 = "Application.EnableCancelKey"
$str3 = "Print #1"
$str4 = "If Dir(\"c:\\"
$str5 = ".sys\") <> \"\" Then Kill \"c:\\"
$str6 = "Open \"c:\\ethan."
$str7 = ".Execute:"
$str8 = "ActiveDocument.VBProject.VBComponents.Item(1)"

condition:
all of them
}

rule VBA_Trojan_Agent_124263 
 {
	meta:
		sigid = 124263
		date = "2021-10-08 14:27 PM"
		threatname = "VBA.Trojan.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateThread Lib \"KERNEL32\""
$str2 = "VirtualAllocEx Lib \"KERNEL32\""
$str3 = "RtlMoveMemory Lib \"KERNEL32\""
$str4 = "GetCurrentProcess Lib \"KERNEL32\""
$str5 = "CreateThread("
$str6 = "VirtualAllocEx("
$str7 = "&H3000, &H40)"
$str8 = "Document_Open()"
$str9 = "WaitForSingleObject("
$str10 = "&HFFFFFFFF)"

condition:
all of them
}

rule VBA_Downloader_Agent_124261 
 {
	meta:
		sigid = 124261
		date = "2021-10-08 14:24 PM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "AutoOpen()"
$str2 = "'hello'"
$str3 = "ShellExecute("
$str4 = "CreateObject(\"WScript.Shell\")"
$str5 = ".Run \"C:\\"
$str6 = ".exe\""
$cnt1 = "CStr("
$cnt2 = "Sin("
$cnt3 = "Tan("
$cnt4 = "Hex("

condition:
all of ($str*) and #cnt1 > 15 and (#cnt2  > 30 and #cnt3 > 30 and #cnt4 > 30)
}

rule VBA_Trojan_Agent_124066 
 {
	meta:
		sigid = 124066
		date = "2021-09-17 06:23 AM"
		threatname = "VBA.Trojan.Agent"
		category = "Malware & Botnet"
		risk = 50
		
	strings:

$str1 = "AutoOpen()"
$str2 = "Shell \"nslookup"
$str3 = "+ Environ$(\"Username\")"
$str4 = "+ Environ$(\"Userdomain\")"
$str5 = "Environ$(\"Computername\")"
$str6 = "MsgBox"
$str7 = ", \"Microsoft Word"

condition:
all of them
}

rule VBA_Downloader_TA551_124223 
 {
	meta:
		sigid = 124223
		date = "2021-10-06 05:58 AM"
		threatname = "VBA.Downloader.TA551"
		category = "Malware & Botnet"
		risk = 80
		
	strings:

$str1 = "Open \"\" &"
$str2 = "For Output As #"
$str3 = "Print #"
$str4 = ".run"
$str5 = "AutoOpen()"
$str6 = "\"cleanEarthExcel\""
$str7 = "windowsPopEarth"
$str8 = ".....hta."
$str9 = "Replace("

condition:
all of them
}

rule VBA_TrojanDropper_Madeba_3093 
 {
	meta:
		sigid = 3093
		date = "2016-08-08 06:44 AM"
		threatname = "VBA_TrojanDropper_Madeba"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$string = { 48 75 7A 6F 77 55 83 F7 30 00 05 84 08 00 FF 03 03 00 66 79 65 32 45 17 }
		$string2 = { 52 77 6A 74 56 76 F6 30 00 07 80 00 00 FF 03 03 00 67 63 6F 43 6D 74 30 }

	condition:
		($magic at 0) and all of them

}

rule VBA_Dropper_TransparentTribe_123212 
 {
	meta:
		sigid = 123212
		date = "2021-05-31 09:25 AM"
		threatname = "VBA.Dropper.TransparentTribe"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"Shell.Application\")"
$str2 = "Environ$(\"ALLUSERSPROFILE\") &"
$str3 = "Application.System.Version, \"6.1\""
$str4 = "\".zip\" For Binary Access Write As #2"
$str5 = "Put #2"
$str6 = "Close #2"

condition:
all of them
}

rule VBA_Downloader_Lazarus_123020 
 {
	meta:
		sigid = 123020
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Lazarus"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"ADODB.Stream\")"
$str2 = "_Open()"
$str3 = "Shell"
$str4 = "d2lubWdtdHM6Ly8uL3Jvb3QvY2ltdjI6V2luMzJfUHJvY2Vz"
$str5 = "bXNodGE="
$str6 = "Script"
$str7 = "Environ(\"Temp\") & \"\\\" &"

condition:
all of them
}

rule VBA_Downloader_AggahAPT_122974 
 {
	meta:
		sigid = 122974
		date = "2021-04-06 12:43 PM"
		threatname = "VBA.Downloader.AggahAPT"
		category = "Malware & Botnet"
		risk = 80
		
	strings:

$str1 = "Auto_Close"
$str2 = "MsgBox \"Microsoft Office not Installed\""
$str3 = ".EXEC"

$keywords = "Function"
$keywords2 = "\" + \""

condition:
all of ($str*) and #keywords > 15 and #keywords2 > 25
}

rule VBA_Dropper_TransparentTribe_122913 
 {
	meta:
		sigid = 122913
		date = "2021-03-25 03:57 AM"
		threatname = "VBA.Dropper.TransparentTribe"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Split(UserForm1.TextBox"
$str2 = "\\ProgramData\\"
$str3 = "Binary Access Write As"
$str4 = "Put #"
$str5 = "CreateObject(\"WScript.Shell\")"
$str6 = "\\CurrentVersion\\CurrentBuildNumber"
$str7 = "> 7601) = True"
$str8 = "Close #"

condition:
all of them
}

rule VBA_Downloader_Qakbot_122869 
 {
	meta:
		sigid = 122869
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Qakbot"
		category = "Malware & Botnet"
		risk = 50
		hash = "1defa9216b9455154b38c0775991e30f"
	strings:
		$mgic = {D0CF11E0A1B11AE1}
		$str1 = ".\\Runtime.brok1" wide ascii 
		$str2 = ".\\Runtime.brok2" wide ascii 
		$str3 = ".\\Runtime.brok3" wide ascii 
		$str4 = ".\\Runtime.brok4"  wide ascii
		$str5 = ".\\Runtime.brok"  wide ascii
		$str6 = "URLDownloadToFileA" wide ascii 
		$str7 = "RegisterServer" wide ascii 
condition:
		$mgic at 0 and all of ($str*)
}

rule VBA_Dropper_PoetRAT_122856 
 {
	meta:
		sigid = 122856
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Dropper.PoetRAT"
		category = "Malware & Botnet"
		risk = 100
		hash = "74393a272d26f540a735301332e94674"
	strings:
		$mgic = {D0CF11}
		$str1 = ".WriteL8iner" wide ascii
		$str2 = "Document_Open" wide ascii
		$str3 = "vbBinaryCompare" wide ascii
		$str4 = "\\Sh@ell ru" wide ascii
		$str5 = "WriteLinee" wide ascii
		$str6 = "E@nvirono" wide ascii
		$str7 = "set DIR=%" wide ascii
	condition:
		$mgic at 0 and all of ($str*)
}

rule VBA_Downloader_DonotAPT_122850 
 {
	meta:
		sigid = 122850
		date = "2021-03-11 10:09 AM"
		threatname = "VBA.Downloader.DonotAPT"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "WoRKBoOk_opEN"
$str2 = "http"
$str3 = "Environ(\"USERPROFILE\") & \""
$str4 = "= CreateObject(\"Microsoft.XMLHTTP\")"
$str5 = ".Open \"GET\","
$str6 = ".send"
$str7 = ".Write"
$str8 = "Shell(\"C:\\"
$str9 = ".bat\", vbHide)"

condition:
all of them
}

rule VBA_Downloader_Agent_122797 
 {
	meta:
		sigid = 122797
		date = "2021-03-03 05:43 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Lib \"KERNEL32\" Alias"
$str2 = "CreateProcessA"
$str3 = "6269747361646d696e202f7472616e73666572"
$str4 = "68747470"
$str5 = "2e657865"
$str6 = "64656c65746520736861646f7773202f616c6c202f7175696574"

condition:
all of them
}

rule VBA_Downloader_Agent_122785 
 {
	meta:
		sigid = 122785
		date = "2021-03-02 05:25 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "_Open()"
$str2 = "Environ(\"TMP\")"
$str3 = "appdata\\"
$str4 = "MZ%90%00%0"
$str5 = "This%20program%20cannot"
$str6 = "CreateObject(\"\"WScript.Shell\"\")"
$str7 = ".dll"

condition:
all of them
}

rule VBA_Downloader_Gen_122575 
 {
	meta:
		sigid = 122575
		date = "2021-01-15 05:35 AM"
		threatname = "VBA.Downloader.Gen"
		category = "Malware & Botnet"
		risk = 100
		
	strings: 

$str1 = {636D6420[3-6]2F4320[3-6]657865[3-6]66696E676572[3-6]256170706461746125}
$str2 = "= Split("
$str3 = {636572747574696C[1-4]202D6465636F6465}
$str4 = "GetObject(\"winmgmts:{impersonationLevel=impersonate}"
$str5 = "\\root\\cimv2"
$str6 = ".Get(\"Win32_ProcessStartup\")"
$str7 = "GetObject(\"winmgmts:Win32_Process\")"
$str8 = "ExecMethod"

condition:
all of them
}

rule VBA_Downloader_Hancitor_122621 
 {
	meta:
		sigid = 122621
		date = "2021-01-27 07:00 AM"
		threatname = "VBA.Downloader.Hancitor"
		category = "Malware & Botnet"
		risk = 80
		
	strings:

$str1 = "Dir("
$str2 = "& \"\\\" & \"W0rd.dll\""
$str3 = "t\" & \"m\" & \"p\""
$str4 = "ActiveDocument.Application.StartupPath & \"\\\" & \"W0rd.dll\""

condition:
all of them
}

rule VBA_Downloader_Gamaredon_122684 
 {
	meta:
		sigid = 122684
		date = "2021-02-08 06:27 AM"
		threatname = "VBA.Downloader.Gamaredon"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "connect Lib \"ws2_32.dll\""
$str2 = "closesocket Lib \"ws2_32.dll\""
$str3 = "Lib \"kernel32\" Alias \"RtlMoveMemory\""
$str4 = "CreateProc Lib \"kernel32\""
$str5 = "WSAStartup failed with error"
$str6 = ".ai_protocol, ByVal 0&, 0, 0)"
$str7 = "connect("
$str8 = "CreateProc(vbNullString, \"cmd\", ByVal"
$str9 = "True, &H8000000, 0, vbNullString,"

condition:
all of them
}

rule VBA_Dropper_Hancitor_122407 
 {
	meta:
		sigid = 122407
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Dropper.Hancitor"
		category = "Malware & Botnet"
		risk = 100
		hash = "838df14794a2f312ea0368cc6cf584c9"
	strings:
		$mgic = {D0 CF 11 E0 A1 B1 1A}
		$str1 = "This program cannot be run in DOS mode." wide ascii
		$str2 = "\\W0rd.dll" wide ascii //...Name of Dll at %temp% location
		$str3 = "DllUnregisterServer" wide ascii
		$str4 = "ShellExecute" wide ascii
		$str5 = "Document_Open" wide ascii
		$str6 = "Windows PowerShell" wide ascii
		$str7 = "ActiveDocument" wide ascii
condition:
		$mgic at 0 and all of ($str*)
}

rule VBA_Downloader_Kimsuky_123943 
 {
	meta:
		sigid = 123943
		date = "2021-09-01 09:21 AM"
		threatname = "VBA.Downloader.Kimsuky"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Document_Open()"
$str2 = "Environ(\"PROGRAMDATA\")"
$str3 = "Shell(\"regsvr32.exe /s"
$str4 = "vbHide)"
$str5 = "CreateObject(\"Microsoft.XMLHTTP\")"
$str6 = ".Open \"GET\","
$str7 = ".SaveToFile"

condition:
all of them
}

rule VBA_Downloader_Gen_122422 
 {
	meta:
		sigid = 122422
		date = "2020-12-17 13:17 PM"
		threatname = "VBA.Downloader.Gen"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1 = "Open()"
$str2 = "powershell.exe -exec bypass -enc"
$str3 = "ACAAIgApACcAMQBzAHAA"
$str4 = "ADoAcwBwAHQAdABoACcAKABnAG4AaQByAHQAUwBkAGEAbwBsAG4AdwBvAEQA"
$str5 = "LgApAHQAbgBlAGkAbABDAGIAZQBXAC4AdABlAE4AIAB0AGMAZQBqAGIATwAtAHcAZQBO"
$str6 = "aQBuACAAJwAnACkAIAB8ACAASQBFAFgA"

condition:
all of them
}

rule VBA_Dropper_InfyAPT_122415 
 {
	meta:
		sigid = 122415
		date = "2020-12-16 14:02 PM"
		threatname = "VBA.Dropper.InfyAPT"
		category = "Malware & Botnet"
		risk = 50
		
	strings: 
$str1 = "_Open"
$str2 = "If Application.System.Version >= 6.2 Then"
$str3 = "Environ(\""
$str4 = "Replace("
$str5 = "CreateObject(\"Shell.Application\")"
$str6 = ".exe"

condition:
all of them
}

rule VBA_Downloader_Ursnif_122402 
 {
	meta:
		sigid = 122402
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Ursnif"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1 = "_Click"
$str2 = "CreateObject("
$str3 = ".Open \"GET\", \"http://\" & ListBox1.List("
$str4 = ".SaveToFile (\"C:\\"
$str5 = ".cpl\")"
$str6 = ".Run ("
$str7 = "Microsoft.XMLHTTP"
$str8 = "regsvr32"
$str9 = "WScript.Shell"

condition:
all of them
}

rule VBA_Downloader_Qakbot_122364 
 {
	meta:
		sigid = 122364
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Qakbot"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$header = {D0 CF 11 E0 A1 B1 1A}
$str2 = {89 50 4E 47}
$str3 = {49 48 44 52}
$str4 = "URLMon"
$str5 = "RLDownloadToFileA"
$str6 = "http://"
$str7 = "please click Enable Editing"
$str8 = "click Enable Content"
$str9 = "\\AppData\\"
$str10 = "Excel 4.0"

condition:
$header at 0 and all of ($str*)
}

rule VBA_Downloader_Ursnif_122361 
 {
	meta:
		sigid = 122361
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Ursnif"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1 = {73 73 65 ?? 63 6F 72 ?? 50 5F 32 ?? 33 6E 69 ?? 57 3A 32 ?? 76 6D 69 ?? 63 5C 74 ?? 6F 6F 72 ?? 3A 73 74 ?? 6D 67 6D ?? 6E 69 77}
$str2 = {50 75 62 6C 69 63 20 43 6F 6E 73 74 20 [5-8] 20 41 73 20 49 6E 74 65 67 65 72 20 3D}
$str3 = {20 3D 20 41 63 74 69 76 65 44 6F 63 75 6D 65 6E 74 2E 42 75 69 6C 74 49 6E 44 6F 63 75 6D 65 6E 74 50 72 6F 70 65 72 74 69 65 73 28 [5-8] 29}
$str4 = {50 75 62 6C 69 63 20 53 75 62 20 [5-8] 28 29}
$str5 = "Call "

condition:
all of them
}

rule VBA_Downloader_Agent_122225 
 {
	meta:
		sigid = 122225
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1 = "Sub Auto_Close()"
$str2 = "j.mp/"
$str3 = "\"hta\"\" ht"
$str4 = "\"\"\"ms\""
$str5 = "MsgBox (\""
$str6 = ": Shell (\"WINWORD\"): Shell (WINWORD +"

condition:
all of ($str*)
}

rule VBA_Downloader_Qakbot_122201 
 {
	meta:
		sigid = 122201
		date = "2020-11-26 21:34 PM"
		threatname = "VBA.Downloader.Qakbot"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$magic = {D0CF11E0A1B11AE1}
$str1 = "http://ski-travel.pl" wide ascii 
$str2 = "C:\\" wide ascii 
$str3 = "ShellExecute" wide ascii 
$str4 = "fwpxeohi.dll" wide ascii 
$str5 = "RLDownloadToFile" wide ascii

condition:
		($magic at 0) and (all of ($str*))
}

rule VBA_Downloader_Gen_122200 
 {
	meta:
		sigid = 122200
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Gen"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$magic = {D0 CF 11 E0 A1 B1 1A E1}
$str1 = "powe^rshell -w"
$str2 = "nEw-oBje`cT Net.WebcL`IENt)"
$str3 = "Down'+'loadFile"
$str4 = ".exe"
$str5 = "cmd /c"
$str6 = ".exe\" -Destination \"${enV`:appdata"
$str7 = "Macros Excel 4.0"

condition:
$magic and all of ($str*)
}

rule VBA_Downloader_Dridex_122188 
 {
	meta:
		sigid = 122188
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Dridex"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1="[\"m\",\"a\",\"e\",\"r\",\"t\",\"s\",\".\",\"b\",\"d\",\"o\",\"d\",\"a\"].reverse().join(\"\");"
$str2="[\"l\",\"l\",\"e\",\"h\",\"s\"].reverse().join(\"\");"
$str3="\"wscript.\".concat("
$str4="\"G\".concat([\"T\",\"E\"].reverse().join(\"\"))"
$str5=".concat([\"l\",\"l\",\"d\",\".\"].reverse().join(\"\"));"
$str6="\"C:/Windows/Temp/\".concat(\"/\".concat("
condition:
all of ($str*)
}

rule VBA_Downloader_NetWire_122159 
 {
	meta:
		sigid = 122159
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.NetWire"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$magic = {D0CF11E0A1B1}
		$str1 = {28 6E 45 77 2D 6F 42 60 6A 65 63 54 20 4E 65 74 2E 57 65 62 63 4C 60 49 45 4E 74 29}
		$str2 = {28 27 44 6F 77 6E 27 2B 27 6C 6F 61 64 46 69 6C 65 27 29}
		$str3 = {49 6E 76 6F 6B 65}
		$str4 = ".exe"
		$str5 = {24 7B 65 6E 56 60 3A 61 70 70 64 61 74 61}
	
condition:
		$magic at 0 and all of ($str*)
}

rule VBA_Downloader_MuddyWaterAPT_122158 
 {
	meta:
		sigid = 122158
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.MuddyWaterAPT"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
	$str1="Environ(\"AppData\")"
	$str2="Start Menu\\Programs\\Startup\\"
	$str3="_Open()"
	$str4="Replace("
	$str5="CreateObject(\"Scripting.FileSystemObject\")"
	$str6={43616C6C206372656174655465787446696C6528706174685361766520262022 [6-20] 2E766273222C}
	$str7={28 27[2-8]65[2-8]78[2-8]70[2-8]6C[2-8]6F[2-8]72[2-8]65[2-8]722E[2-8]65[2-8]78[2-8]65}

condition:
all of ($str*)
}

rule VBA_Virus_Story_122077 
 {
	meta:
		sigid = 122077
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Virus.Story"
		category = "Malware & Botnet"
		risk = 100
		hash = "5a1e167f5b47baefd2c548214a9ab33c"
	strings:
		$magic = {D0CF11E0A1B1}
		$str1 = "Jack-In-The-Box" wide ascii nocase
		$str2 = "C:\\Windows\\Story.doc" wide ascii nocase
		$str3 = "C:\\mirc\\mirc32.exe" wide ascii nocase
		$str4 = "C:\\mirc\\mirc.ini" wide ascii nocase
		$str5 = "Mirc Worm" wide ascii nocase
		$str6 = "*virus*" wide ascii nocase
		$str7 = "*infect*" wide ascii nocase
condition:
		$magic at 0 and all of ($str*)
}

rule VBA_Downloader_Konni_123890 
 {
	meta:
		sigid = 123890
		date = "2021-08-24 06:01 AM"
		threatname = "VBA.Downloader.Konni"
		category = "Malware & Botnet"
		risk = 100
		
	strings: 
$header = {D0 CF 11 E0 A1 B1 1A E1}
$str1 = "/d %USERPROFILE% && type"
$str2 = "vbHide"
$str3 = ".js\");"
$str4 = ".ps1\");"
$str5 = ".Run(\"wscript.exe"
$str6 = ".Run(\"powershell.exe"
$str7 = "-ep bypass"
$str8 = "cmd /c findstr /r"

condition:
$header at 0 and all of ($str*)
}

rule VBA_Trojan_Agent_123880 
 {
	meta:
		sigid = 123880
		date = "2021-08-23 05:56 AM"
		threatname = "VBA.Trojan.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "GetObject(\"winmgmts:{impersonationLevel=impersonate"
$str2 = "rundll32.exe"
$str3 = "ShellExec_RunDLL"
$str5 = "ProgramData"
$str6 = ".vbs"
$str7 = "wscript"
$str8 = "Shell"
$str9 = "Select * from AntiVirusProduct"
$str10 = ".ExecQuery("


condition:
all of them
}

rule VBA_Downloader_SnakeKeylogger_123019 
 {
	meta:
		sigid = 123019
		date = "2021-04-14 11:52 AM"
		threatname = "VBA.Downloader.SnakeKeylogger"
		category = "Malware & Botnet"
		risk = 80
		
	strings:

$str1 = "_Open()"
$str2 = ".CreateObject(\"wscript."
$str3 = ".exec(\"powe"
$str4 = "-w Hidden Invoke"
$str5 = "http"
$str6 = " -OutF"
$str7 = ".ex\" & Chr(101)"

condition:
all of them
}

rule VBA_Downloader_Agent_123705 
 {
	meta:
		sigid = 123705
		date = "2021-07-30 09:43 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "winmgmts:"	nocase
$str2 = "\\root\\cimv2"	nocase
$str3 = "HIDDEN_WINDOW"	nocase
$str4 = ".Create(\"powershell.exe"	nocase
$str5 = "-exec bypass -enc"	nocase
$str6 = "SQBFAFgAKABOAGUA"	nocase
$str7 = "Win32_ProcessStartup"	nocase

condition:
all of them
}

rule VBA_Dropper_TransparentTribe_123839 
 {
	meta:
		sigid = 123839
		date = "2021-08-18 05:33 AM"
		threatname = "VBA.Dropper.TransparentTribe"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "GetObject(\"winmgmts:\\\\.\\root\\cimv2\")"
$str2 = ".ExecQuery(\""
$str3 = "Select * From Win32_"
$str4 = "Shell"
$str5 = "cmd /c start"
$str6 = "Microsoft.NET\\Framework\\v4"
$str7 = ".exe"
$str8 = "CreateObject(\"Microsoft.XMLHTTP\")"
$str9 = ".SaveToFile \"C:\\"
$str10 = ".Status = 200 Then"

condition:
all of them
}

rule VBA_Dropper_PoetRAT_123829 
 {
	meta:
		sigid = 123829
		date = "2021-08-16 16:23 PM"
		threatname = "VBA.Dropper.PoetRAT"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "document_open"
$str2 = "\\Public"
$str3 = "Call Shell(\"cmd /c copy"
$str4 = ".py\" & \"\"\"\", vbHide)"
$str5 = ".zip"
$str6 = "Unzip"
$str7 = "\\Python37\\python.exe"
$str8 = "Write As #"
$str9 = "CreateObject(\"Shell.Application\")"
$str10 = ".CopyHere"

condition:
all of them
}

rule CVE_2017_0199_116638 
 {
	meta:
		sigid = 116638
		date = "2017-06-28 10:31 AM"
		threatname = "CVE_2017_0199"
		category = "Malware & Botnet"
		risk = 100
		author = "dpk"

	strings:
$magic = "{\\rt"
$str1 = "\\objdata 0105000002000000010"
$str4 = "5c010000e0c9ea79f9bace118c8200aa004b" 
$str5 = "d0cf11e0a1b11ae10"
$hardcodedip = "5C005C00380034002e003200300030002e00310036002e003200340032002f"

condition:
($magic at 0) and (all of ($str*)) and ($hardcodedip)
}

rule VBA_Downloader_PowerShdll_123782 
 {
	meta:
		sigid = 123782
		date = "2021-08-09 13:03 PM"
		threatname = "VBA.Downloader.PowerShdll"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"WScript.Shell\")"
$str2 = ".ExpandEnvironmentStrings(\"%COMPUTERNAME%\")"
$str3 = "Parameters\\Hostname"
$str4 = "powershell"
$str5 = "-w hidden"
$str6 = ".exec("
$str7 = ".exe"

condition:
all of them
}

rule CVE_2017_0199_3742 
 {
	meta:
		sigid = 3742
		date = "2017-05-08 05:55 AM"
		threatname = "CVE_2017_0199"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic="{\\rt"
		$str1="4f4c45324c696e6b"
		$str2="d0cf11e0a1b11ae1"
		$str3="4d45544146494c4550494354"
		$str4="504b"
		$str5="4d73786d6c322e534158584d4c5265616465722e362e30"
		$url1="6800740074007000"
		$url2="68747470"
		$url3="http"

	condition:
		($magic at 0)and (all of ($str*))and (1 of ($url*))

}

rule vba_download_macro_3762 
 {
	meta:
		sigid = 3762
		date = "2017-05-03 14:38 PM"
		threatname = "vba_download_macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$hex1={2E446F776E}
$hex2={696C652827}
$hex3={5368656C6C61}
$hex4={32302F7661727661722E64}
$pat1={5C41707044610074615C4C6F63616C005C54656D70}
$pat2={5C41707000446174615C4C6F6300616C5C54656D70}
$mag1={D0CF11E0}

	condition:
		$mag1 at 0 and all of ($hex*) and ($pat1 or $pat2)

}

rule VBA_TrojanDownloader_Macro_3671 
 {
	meta:
		sigid = 3671
		date = "2017-04-06 14:36 PM"
		threatname = "VBA_TrojanDownloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "Attention! This document was created by a newer version of"
		$s2 = "Macros must be enabled to display the contents of the document"
		$s3 = "2. Select Enable this content and click"
		$s4 = "PROJECT.NEWMACROS.AUTOOPEN" wide
		$s5 = "Fantasy profligate tuft sigma nourishing"

	condition:
		(all of ($s*)) and filesize < 230KB
		and filesize > 180KB and $s1 in (2304 .. 2816)

}

rule CVE_2015_2424_1840 
 {
	meta:
		sigid = 1840
		date = "2017-03-27 06:48 AM"
		threatname = "CVE_2015_2424"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic="{\\rt"
		$str1="\\object"
		$str2="\\objocx"
		$str3="\\objclass Control.TaskSymbol.1"
		$str4="\\objdata"
		$str5="436f6e74726f6c2e5461736b53796d626f6c2e31"
		$str6="d0cf11e0a1b11ae1000000" 
		$hex1="74303074"
		$hex2="3074"
		$hex3="7430"
		$hex4="90909090909090909090"
		$hex5="f19a807c"
		$hex6="e9190000005e31db"

	condition:
		(($magic at 0) and (all of them))

}

rule VBA_Downloader_Macro_3599 
 {
	meta:
		sigid = 3599
		date = "2017-03-01 14:45 PM"
		threatname = "VBA_Downloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$hex1 = {D0 CF 11 E0}
$str1 = {2D 2D 2D 2D 2D 20 45 78 65 63 75 74 65 20 56 42 53 20 66 69 6C 65 20 2D 2D 2D 2D 2D} //----- Execute VBS file -----
$str2 = {00 1E 00 20 2D 2D 2D 2D 2D 20 44 6F 77 6E 6C 6F 61 64 20 56 42 53 20 66 69 6C 65 20 2D 2D 2D 2D}
$str3 = {54 45 4D 50 24 00 34 02 01 00 B6 00 0B 00 5C 68 47 59 64 73 66 2E 76 62 73 00 11 00} // /hGYdsf.vbs
$str4 = {50 4F 53 54 B6 00 34 00 68 74 74 70 73 3A 2F 2F 64 6C 2E 64 72 6F 70 62 6F 78 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D}

	condition:
		$hex1 and (all of ($str*))

}

rule W97_hancitor_dropper_3593 
 {
	meta:
		sigid = 3593
		date = "2017-02-22 15:12 PM"
		threatname = "W97_hancitor_dropper"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$api_01 = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }  // VirtualAlloc
$api_02 = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }  // RtlMoveMemory
$api_04 = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }  // CallWindowProcAi
$magic = { 50 4F 4C 41 } // POLA

	condition:
		uint32be(0) == 0xD0CF11E0 and all of ($api_*) and $magic

}

rule W97Downloader_3438 
 {
	meta:
		sigid = 3438
		date = "2016-12-13 09:31 AM"
		threatname = "W97Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="SHCreateThread"
		$a2="ChangeTimerQueueTimer"
		$a3="GetCPInfoExA"
		$a4="ZwAllocateVirtualMemory"
		$a5="WriteProcessMemory"
		$a6="FindFirstFileA"
		$a7="AttachConsole"
		$a8="OpenMutexA"

	condition:
		all of them

}

rule MW_Tadpole_3454 
 {
	meta:
		sigid = 3454
		date = "2016-11-23 15:45 PM"
		threatname = "MW_Tadpole"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$h1 = { 68 74 74 70 0F 85 86 01 00 00 AC 66 AD 66 3D 2F 2F 0F }
$h2 = { C7 45 ?? 61 64 76 61 C7 45 ?? 70 69 33 32 C7 45 ?? 2E 64 6C 6C }
$h3 = { 30 10 49 44 41 54 74 }

	condition:
		all of them

}

rule MD_VernalDrop_DOC_3452 
 {
	meta:
		sigid = 3452
		date = "2016-11-23 15:45 PM"
		threatname = "MD_VernalDrop_DOC"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$t1 = "WScript.Shell"
		$t2 = "Scripting.FileSystemObject"
		$t3 = "Execzy"
		$t4 = "AutoOpen"
		$t5 = "DocumentBeforeClose"
		$t6 = "SMBIOSBIOSVersion"
		$h1 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F 4E 61 6D 00 65 }
		//Attribut.e VB_Nam.e

	condition:
		all of them

}

rule VBA_Downloader_2473 
 {
	meta:
		sigid = 2473
		date = "2016-12-13 10:56 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="Tybgeywq"
		$a2="POKNDJWQ"
		$a3="YRwfvq"
		$a4={52 54 51 43 44 57 01 C0 08 4B 6F 6A 66 4E 42 65 50 71 28}

	condition:
		(all of ($a*))

}

rule VBA_Downloader_2498 
 {
	meta:
		sigid = 2498
		date = "2016-12-13 10:56 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={44 76 6F 72 00 65 63 47 6F 6C 64 65}
		$a2={4B 72 69 70 6F 74 61 28 00 31 31 29}
		$a3="purgeOldAutosaveData2h"
		$a4="notifyCleanShutdown"
		$a5="KillFile"
		$a6="ShishilMishelPernulVishel"

	condition:
		(all of ($a*))

}

rule VBA_Downloader_2633 
 {
	meta:
		sigid = 2633
		date = "2016-12-13 10:55 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={53 61 76 65 53 01 00 94[31]6A 76 6E 68 48 00 55 6B 72}
		$a2={20 00 4A 4B 72 74 49 43 71 6E 00 2C 20 72 56 48}
		$a3={77 6C 47 69 4F 64 6C 7A[6]55 76 41 71 73 4E 77 64 73 D4}
		$a4={53 61 76 65 63 8A 80 54 6F 46 69 6C[8] 33 46 59 55 68 67 00 79 62 63 6A 61 73 6B 62 0C}

	condition:
		(all of them)

}

rule VBA_Downloader_2665 
 {
	meta:
		sigid = 2665
		date = "2016-12-13 10:54 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={6D 6B 55 43 62 71 4E 53 74 6B 5E}
		$a2={76 50 78 6B 6C 48 30 70 48 55 6C A2 12 76 49 43 49 80 48 4A 4F 56}
		$a3={63 77 7A 72 6F 4B 59 48 6A 7A 52[37]50 66 48 69 76 46 62 64}
		$a4={63 44 53 65[14]32 37 35 35 20 2B 20 33 48 32 34 38}

	condition:
		(all of them)

}

rule VBA_Downloader_2673 
 {
	meta:
		sigid = 2673
		date = "2016-12-13 10:54 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={20 46 00 75 6E 63 74 69 6F 6E 20 00 50 65 72 64 65 72 46 6F 00 63 6F 47 6E 72 61}
		$a2={50 00 75 62 6C 69 63 20 53 74 00 64 50 69 6E 4F 6B 30}
		$a3={50 6F 6E 65 72 46 6F 84 63 6F 44}
		$a4={69 6F 6E 20 00 53 61 6D 63 61 53 72 69}
		$a5={41 62 72 69 72 20 63 6F 6E 65 78 69 6F}

	condition:
		(all of them)

}

rule VBA_Downloader_2676 
 {
	meta:
		sigid = 2676
		date = "2016-12-13 10:53 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={50 75 62 6C 69 63 20 00 63 68 65 63 6B 54 61 78 00 61 54 61 20 41}
		$a2={46 65 75 69 6C 00 6C 65 45 78 69 73 74 65 00 20 3D 20 4E 6F 74}
		$a3={41 70 70 6C 69 66 66 66 00 2E 61 63 61 74 69 6F 6E 00 2E 53 68}
		$a4="Plantae"
		$a5="tempFile"
		$a6="super_phylum"

	condition:
		(all of them)

}

rule VBA_Downloader_2709 
 {
	meta:
		sigid = 2709
		date = "2016-12-13 10:53 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="LvcTRgbw61"
		$a2="CYEyWscI48"
		$a3="ecOPItZX1241"
		$a4={75 74 6F 6F 70 65 6E D9[16]00 53 68 65 6C 6C 56[9]64 68 73 6A 68 6A 56 4B 42 4C 64 73 66 AA 23}

	condition:
		(all of them)

}

rule VBA_Downloader_2717 
 {
	meta:
		sigid = 2717
		date = "2016-12-13 10:53 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="deletemonsters"
		$a2="AbrirConexionAridoc"
		$a3="NuloNeNule"
		$a5="FEDREZ"
		$a4={41 70 70 72 6F 73 73 69 6D 61 45 EC 30 00 09 04 4D 69 61 56 61 6C 75 74 61 51}

	condition:
		(all of them)

}

rule VBA_Downloader_2855 
 {
	meta:
		sigid = 2855
		date = "2016-12-13 10:51 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={6B 69 70 74 22 2C 20 32[3]05 38 57 72 69 74 65 54 07 40}
		$a2="vxdtu"
		$a3={7A 78 68 65 61 4F 3E[4]72 74 61 42 75 66}
		$a4="SaveToFile"
		$a5={57 72 69 74 65 54 07 40 61 44 59 43 13 78 63 76 63 62}

	condition:
		(all of them)

}

rule VBA_Downloader_2879 
 {
	meta:
		sigid = 2879
		date = "2016-12-13 10:51 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={61 75 74 6F 6F 70 65 6E 00 28 29 0D[6]78 64 74 71 5A 6D 6D 68 00}
		$a2={75 79 47 42 73 64 73 66 01 20 07 6B 6B 42 48 4A 61 73 02 64 00}
		$a3="kihyevik"
		$a4={47 48 72 4A 4F 53 56 41 33 05 30 00 08 04 7A 58 48}

	condition:
		(all of them)

}

rule VBA_Downloader_3025 
 {
	meta:
		sigid = 3025
		date = "2016-12-13 10:49 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="laryngoscope"
		$a2="bioluminescence"
		$a3="axonalherchfratricide"
		$a4="sticbedizened"
		$a5="fecklessness"

	condition:
		(all of them)

}

rule VBA_Downloader_3029 
 {
	meta:
		sigid = 3029
		date = "2016-12-13 10:45 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={67 75 6D 62 6F 6C 46 69 00 02 8A 18 64 6F}
		$a2="brassbandmeinterdigitate"
		$a3="haemoproteidae"
		$a4={65 20 4C 49 4B 45 20 27 50 79 74 68 6F 6E 20 25 27 72}
		$a5="reamorphophallus"

	condition:
		(all of them)

}

rule VBA_Downloader_3127 
 {
	meta:
		sigid = 3127
		date = "2016-12-13 10:44 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="lisMTAXVhGZSoyUvEYxn"
		$a2="RhvUbQdqwMgpfoTGsaD"
		$a3="tzPLsGmaEZSNrBWge"
		$a4="osUXbTISwRMfJmDEu"
		$a5="DgUrFeNQdzhbmvm"

	condition:
		(all of them)

}

rule VBA_Downloader_3433 
 {
	meta:
		sigid = 3433
		date = "2016-12-13 10:42 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="RtlMoveMemory"
		$str2="OpenClipboard"
		$str3="VirtualAllocEx"
		$str4="GetUpdateRect"
		$str5="EnumCalendarInfoW"
		$str6="Sleep"
		$str7="user32\" Alias \"SetParent"

	condition:
		all of them

}

rule MW_Spikerush_3455 
 {
	meta:
		sigid = 3455
		date = "2016-11-23 15:45 PM"
		threatname = "MW_Spikerush"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$h1 = { 49 44 41 54 08 C9 DC 62 2F 04 89 DD A9 01 B2 A5 C0 22 5C BF 29 28 }
$h2 = { 49 44 41 54 78 DA ED BD 79 BC 64 65 7D E7 FF FE 3E E7 9C AA BA 6B }

	condition:
		all of them

}

rule VBA_TrojanDropper_Macro_3375 
 {
	meta:
		sigid = 3375
		date = "2016-10-26 15:26 PM"
		threatname = "VBA_TrojanDropper_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$docfile = { D0 CF 11 E0 }
$str1 = { 67 61 74 68 65 72 69 6E 67 00 67 00 61 00 74 00 68 00 65 00 72 00 69 00 6E 00 67 }
$str2 = { 73 65 6C 6C 6F 75 74 00 73 00 65 00 6C 00 6C 00 6F 00 75 00 74 }
$str3 = { 73 65 6C 6C 6F 75 74 [12] 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 }

	condition:
		$docfile at 0
and (all of them)

}

rule word_cve_2016_3317_3176 
 {
	meta:
		sigid = 3176
		date = "2016-10-05 05:36 AM"
		threatname = "word.cve_2016_3317"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$t0 = "{\\rtf1"
		$s1 = "\\trowd" ascii wide nocase
		$s2 = "\\nestrow" ascii wide nocase
		$s3 = /\\nestcell.{,50}\\gridtbl/ ascii wide nocase
		$s4 = "\\mmath" ascii wide nocase
		$s5 = "nesttableprops" ascii wide nocase

	condition:
		(all of ($s*)) and $t0 at 0

}

rule VBA_TrojanDropper_3044 
 {
	meta:
		sigid = 3044
		date = "2016-07-18 08:53 AM"
		threatname = "VBA_TrojanDropper"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$string = { 5C 63 79 61 6C 6B 61 6C 69 6D 65 74 72 79 AC 00 03 00 24 00 DC 00 02 00 0B 00 B6 00 0B 00 65 78 65 2E 73 69 73 70 6F 6D 61 }
		$string2 = { 57 48 45 52 B6 00 21 00 45 20 4E 61 6D 65 20 4C 49 4B 45 20 27 50 79 74 68 6F 6E 20 25 27 72 65 65 73 74 61 62 }

	condition:
		($magic at 0) and all of them

}

rule VBA_TrojanDropper_Madeba_3216 
 {
	meta:
		sigid = 3216
		date = "2016-08-24 12:43 PM"
		threatname = "VBA_TrojanDropper_Madeba"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$string = { FF 03 03 00 57 69 6E 36 34 46 11 }
		$str2 = { 73 6C 61 73 68 65 64 AE F5 30 00 05 84 08 00 FF 03 03 00 63 68 69 72 70 03 CF 30 00 05 84 08 00 FF 03 03 00 66 69 6E 69 73 }
		$song = "I'm just a sucker for pain"

	condition:
		($magic at 0) and all of them

}

rule CVE_2016_3279_3095 
 {
	meta:
		sigid = 3095
		date = "2016-07-13 07:45 AM"
		threatname = "CVE_2016_3279"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 ="http://" ascii wide nocase 
 $s2 ="https://" ascii wide nocase
 $s3 =".swf" ascii wide nocase 
 $s4 = "ShockwaveFlashObjects" ascii wide nocase 
 $s5 = "AE6D-11CF-96B8- 444553540000" ascii wide nocase

	condition:
		($s1 or $s2) and $s3 and $s4 and $s5

}

rule VBA_Downloader_Macro_2038 
 {
	meta:
		sigid = 2038
		date = "2016-07-28 13:14 PM"
		threatname = "VBA_Downloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$hex1 = {D0 CF 11 E0}
		$str1 = "softbuzzingN"
		$str2 = "tooling"
		$str3 = "diapensiales"
		$str4 = "anaglyphy"
		$str5 = "ambiversion"
		$str6 = "chytridialesA"
		$str7 = "tripoliN"
		$str8 = "blindworm"
		$str9 = "knurrQ@0"

	condition:
		$hex1 and (all of ($str*))

}

rule Symantec_Malicious_MIME_Doc_Name_Overflow_3019 
 {
	meta:
		sigid = 3019
		date = "2016-07-04 06:11 AM"
		threatname = "Symantec_Malicious_MIME_Doc_Name_Overflow"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a = "58 35 4f 21 50 25 40 41 50 5b 34 5c 50 5a 58 35 34 28 50 5e 29 37 43 43 29 37 7d 24 45 49 43 41 52 2d"
		$b = "57 44 56 50 49 56 41 6c 51 45 46 51 57 7a 52 63 55 46 70 59 4e 54 51 6f 55 46 34 70 4e 30 4e 44 4b 54 64 39 4a 45 56 4a 51 30 46 53"

	condition:
		$a or $b

}

rule Macro_Powershell_Downloader_3017 
 {
	meta:
		sigid = 3017
		date = "2016-07-04 06:11 AM"
		threatname = "Macro_Powershell_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a = "cmd.exe /c powershell -ExecutionPolicy bypass -noprofile -windowstyle hidden"
		$b = ".DownloadFile('http://"
		$c = ".blushy.nl/u/putty.exe"
		$d = "'%TEMP%"
		$e = "Win64x"

	condition:
		($magic at 0) and (all of them)

}

rule CVE_2015_1671_1685 
 {
	meta:
		sigid = 1685
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-1671"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$MaxPDataSeq = {CF F4 00 03 7F FF 00 00 00 00 00 00 00 0A 00 00 00 00 00 64 00 00 00 00 00 02}
		$glyfItrpSeq = {B0 27 B0 15 B0 38 43 60 42 B0 01 68}

	condition:
		$MaxPDataSeq and $glyfItrpSeq

}

rule VBA_Trojan_Downloader_2693 
 {
	meta:
		sigid = 2693
		date = "2016-05-05 11:50 AM"
		threatname = "VBA_Trojan_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = {D0CF11E0}
		$hex1 = { 4C 37 52 5365 6E 5A 3843 53 0D 0A}
		$hex2 = { 576F 4C 71 4956 75 5A 0D}
		$hex3 = { 50 3937 79 30 49 6C 39 51 7632 48 10 0011}
		$hex4 = { 4C 37 52 5365 6E 5A 3843 53 0D 0A}
		$hex5 = {53 64 4C00 45 52 4C56 38 74 6D68 00 49 5A78 72 75}

	condition:
		$magic at 0 and all of ($hex*)

}

rule VBA_Trojan_Downloader_2690 
 {
	meta:
		sigid = 2690
		date = "2016-05-05 11:50 AM"
		threatname = "VBA_Trojan_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = {D0CF11E0}
		$hex1 = {426D4B616178654C4F584F6E79490D0A}
		$hex2 = {446F63756D656E745F4F70656E28290D0A50326158644945344948}
		$hex3 = {45316666715220004C69622022426C32004A457457783922}
		$hex4 = {4B656B004F63434F6D796E6A}

	condition:
		$magic at 0 and all of ($hex*)

}

rule VBA_Trojan_Downloader_2671 
 {
	meta:
		sigid = 2671
		date = "2016-05-05 11:48 AM"
		threatname = "VBA_Trojan_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = {D0CF11E0}
		$hex1 = {58614579526D6D5A697251444857E5}
		$hex2 = {6E75496B4F6C6258624346}
		$hex3 = {706E456B574C6C530075614C5A706A0D0A00}
		$hex4 = {6173733D6A6E6D43544F7379446C4F4E420D0A4D}

	condition:
		$magic at 0 and all of ($hex*)

}

rule VBA_Downloader_2599 
 {
	meta:
		sigid = 2599
		date = "2016-04-01 07:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a1="rsPurch"
		$a2="rsCostSqlf"
		$a3="HanSoloVud"
		$a4="QtyoutBal"
		$a5="tudaGdeLetli"

	condition:
		($magic at 0) and (all of them)

}

rule VBA_Downloader_2584 
 {
	meta:
		sigid = 2584
		date = "2016-04-01 07:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a1={58 55 4F 5A 4B 4D 70 4C 00}
		$a2={42 6F 66 66 36 53 47 50 00 69 4A 75 36 28 4F 6C 6C 00 6F}
		$a3={4A 75 36 28 41 75 68 56 00 44 61 54 66 55 33 66 61 00 53 41}
		$a4={53 79 78 49 51 00 67 4B 74 74 78 55 66 35}
		$a5="Te8LikdiEVUGiUQn"

	condition:
		($magic at 0) and (all of them)

}

rule W97M_Vawtrak_dropper_2578 
 {
	meta:
		sigid = 2578
		date = "2016-04-01 07:00 AM"
		threatname = "W97M_Vawtrak_dropper"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$asterismal="asterismal"
		$bootlicking="bootlicking"
		$shell="WScript.Shell"
		$temp="%temp%"
		$oxygon="oxygon.exe"
		$saxhorn = "saxhorn"
		$fire = "Fire"
		$bin= "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e"

	condition:
		all of them

}

rule CVE_2016_0134_2512 
 {
	meta:
		sigid = 2512
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0134"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "Application.DisplayStatusBar = False"
$s2 = "Options.VirusProtection = False"
$s3 = "Options.SaveNormalPrompt = False"
$s4 = "APMP"
$s5 = "KILL"
$s6 = ".DeleteLines 1, .CountOfLines"
$s7 = ".InsertLines 1, MyCode"

	condition:
		all of them

}

rule VBA_Downloader_2450 
 {
	meta:
		sigid = 2450
		date = "2016-03-01 08:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a1="SufijoOEM"
		$a2="EsPersonaJuridica2"
		$a3="bordizb"
		$a4="miRsAux"
		$a5="Cadena"
		$a6={53 61 6D 62 6F 46 2E[0-4]61 62 65 6C 36 2E 43}

	condition:
		($magic at 0) and (all of ($a*))

}

rule CVE_2016_0016_2350 
 {
	meta:
		sigid = 2350
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0016"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$hex_CLSID1 = {93 1a dc 62 24 ae 4c 46 a4 3e 45 2f 82 4c 42 50}
		$hex_CLSID2 = {0d 49 7c 63 e3 ee 0a 4c 97 3f 37 19 58 80 2d a2}
		$hex_CLSID3 = {cb 31 41 87 cc 4e 3b 44 89 48 74 6b 89 59 5d 20}
		$hex_CLSID4 = {77 93 74 96 91 33 D2 11 9E E3 00 C0 4F 79 73 96}

	condition:
		any of ($hex_CLSID*)

}

rule CVE_2016_0022_2430 
 {
	meta:
		sigid = 2430
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0022"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a = {7B 5C 72 74 66}
$s = /\{\\\*\\do\\dpgroup\\dpcount\d+\\dpgroup\\dpcount\d+\}/ wide ascii nocase

	condition:
		$a at 0 and $s

}

rule CVE_2016_0053_2417 
 {
	meta:
		sigid = 2417
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0053"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$s1 = "\\ffdefres-" wide ascii nocase
		        $s2 = "\\formfield" wide ascii nocase
		        $s3 = "\\rtf" wide ascii nocase
		        $s4 = "\\field" wide ascii nocase
		        $s5 = "\\fldinst" wide ascii nocase

	condition:
		all of ($s*)

}

rule W97MDownloader_2411 
 {
	meta:
		sigid = 2411
		date = "2016-03-01 08:00 AM"
		threatname = "W97MDownloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$str1={43 68 61 72 53 69 6E 43 61 72 67 61 72 51[5]73 53 4E 49 46 54 44 5F 45 58 50 41 4E 44}
		$str2={53 00 41 6D 6F 65 74 75 74 32[3]15 44 69 6D 20 68 5F 00 6B 65 79 5F 4C 4D 5F 37}
		$str3={45 78 00 74 72 61 65 44 61 74 2E 00 6F 49 7A 71 64 61 28 43}
		$str4={53 61 6C 69 72 47 75 61 72 64 61 72 50 72 6F 63[6]4D 73 67}
		$str5="ztauckos.txt"

	condition:
		($magic at 0) and (all of ($str*))

}

rule CVE_2016_0008_2353 
 {
	meta:
		sigid = 2353
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0008"
		category = "Malware & Botnet"
		risk = 80
		
	strings:
		$str1={4B DF 5D 19 2A 10 C3 E0 45 4D 78 33 8A F1 B9 EB}
		$str2={0F 24 5D 76 D2 BB 4E A2 83 15 D5 82 73 37 61 22}
		$str3={FD DF 80 76 B3 F4 50 23 D1 FE 4D 71 23 FF 3F E9}
		$str4={5D 5B 77 CD 15 BB 62 7C BD 71 4B 05 64 88 C6 8E}
		$str5={65 74 74 69 6E 67 73 2E 78 6D 6C B4}
		$str6={6B 39 4D B5 93 33 54 67 39 5B 75 97 0B C9 81 15}

	condition:
		all of them

}

rule VBA_Downloader_2342 
 {
	meta:
		sigid = 2342
		date = "2016-03-01 08:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="erfgerggggg"
		$str2="D16C4EB2/suprr.htm"
		$str3="defwefwef"
		$str4="FYFugfsyidfvhdsff"
		$str5="TydfvghFJHsdf"

	condition:
		all of them

}

rule CVE_2015_0097_2341 
 {
	meta:
		sigid = 2341
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_0097"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "<html><head></head>"
$string2 = "navigator.userAgent"
$string3 = "Unescape("
$string4 = ".RegRead(\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Local AppData\")"
$string5 = "&strValue&\"\\mm.dll"
$string6 = "\\ss.vbs"
$string7 = "\\t.doc"
$string8 = "file:///"
$string9 = "?.html"
$string10 = "/c taskkill  -f -im winword.exe"
$string11 = ".ShellExecute"

	condition:
		all of them

}

rule VBA_Downloader_AggahAPT_123621 
 {
	meta:
		sigid = 123621
		date = "2021-07-21 06:36 AM"
		threatname = "VBA.Downloader.AggahAPT"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "cmd.exe" nocase
$str2 = "DllMain("	nocase
$str3 = "ExtractDll"	nocase
$str4 = "RunPE"	nocase
$str5 = "Function CreateProcess Lib \"kernel32\" Alias \"CreateProcessA\""	nocase
$str6 = "Procedurecall"	nocase
$str7 = "CreateProcess(0&"	nocase

condition:
all of them
}

rule VBA_Dropper_APT40_123615 
 {
	meta:
		sigid = 123615
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Dropper.APT40"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Wscript.exe" nocase
$str2 = "%windir%\\temp\\" nocase
$str3 = "Win32_Process" nocase
$str4 = "ExecQuery" nocase
$str5 = "cmd /c" nocase
$str6 = "winmgmts:" nocase
$str7 = ".vbs" nocase
$str8 = ".DeleteValue &H80000002,\"SOFTWARE" nocase
$str9 = "root/cimv2" nocase

condition:
all of them
}

rule VBA_Dropper_APT40_123614 
 {
	meta:
		sigid = 123614
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Dropper.APT40"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
 
$str1 = ".CreateTextFile(" nocase
$str2 = ".base64" nocase
$str3 = "Environ(\"ALLUSERSPROFILE\")" nocase
$str4 = "CreateObject(\"WScript.Shell\")" nocase
$str5 = "\\Start Menu\\Programs\\Startup" nocase
$str6 = "java.exe" nocase
$str7 = "_Open()" nocase
$str8 = ".createElement(\"binary\")" nocase
$str9 = "vbHidden" nocase

condition:
all of them
}

rule W97MDownloader_2281 
 {
	meta:
		sigid = 2281
		date = "2016-03-01 08:00 AM"
		threatname = "W97MDownloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="UoydOGwesliOrBtT35"
		$str2="skePAqliqdijlteT58"
		$str3="jwKGayTymifqsnKP32"
		$str4="HzSvNYHaiVTwNSSe82"
		$str5={6C 69 37 75 57 62 75 55 35 45 70 58[5]43 72 65 61 74 65 4F 62 6A 65 63 74}
		$str6="xUjg7BZun2Oca"

	condition:
		all of them

}

rule VBA_Downloader_Kimsuky_123607 
 {
	meta:
		sigid = 123607
		date = "2021-07-19 15:47 PM"
		threatname = "VBA.Downloader.Kimsuky"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "AutoOpen()"	nocase
$str2 = "CreateObject(\"wscript.shell\")"	nocase
$str3 = "CreateObject(\"MSXML2.ServerXMLHTTP"	nocase
$str4 = ".Open \"GET\""	nocase
$str5 = ".exe"	nocase
$str6 = "DeleteFile"	nocase
$str7 = "WinExec"	nocase

condition:
all of them
}

rule W97M_Dropper_2234 
 {
	meta:
		sigid = 2234
		date = "2016-03-01 08:00 AM"
		threatname = "W97M_Dropper"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="oquwdqgw jahsd kjqwuidhq"
		$str2="Juhbnsdg"
		$str3={53 65 74 00 20 68 68 67 67 64 47 68[5]65 4F 62 6A 65[1]63[1]6F 57 6F 72 64 2E 41 00 70 70 6C 69 63 61 74}
		$str4={54 54 54 44 41 4453 53 66[1]52 52 54 46 44 41 53 44 D0[19]42 68 62 64 61 64 77}

	condition:
		all of them

}

rule VBA_Downloader_Pony_2142 
 {
	meta:
		sigid = 2142
		date = "2016-03-01 08:00 AM"
		threatname = "VBA_Downloader_Pony"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="Environ$(BBDHWHDAS) & ABYQWGHDJA"
		$str2="Filani"
		$str3="JoFidda"
		$str4="askdh A*S*"
		$str5="POQJIODAKLSD"
		$str6="Makavata"
		$str7="kasjhdjkash"
		$str8="Malfsad"
		$str9="lasjkd klasd9j8u"
		$str10="asjkd klasdKNA SDHjkhasd8yasdiu"

	condition:
		all of them

}

rule VBA_Downloader_2114 
 {
	meta:
		sigid = 2114
		date = "2016-03-01 08:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str11={61 75 74 6F 6F 70 65 6E[13]43 48 48 44 4D}
		$str12="IsComment"
		$str13="//Somth"
		$str14="haystackJoRe"
		$str15={2E 68 61 79 00 73 74 61 63 6B 4A 6F 52 00 65 2E 72 65 73 70 6F 6E[1]73 65 42 6F 64[3]73[1]61 76 65 74 6F 66 69}
		
		$str21={6E 74 65 64 65 63 65[12]65 78 65 00}
		$str22={56 62 4D 65 74 68 6F 64[12]5A 65 72 64 4D 61 6E[52]5A 65 72 64 4D 61 6E 32[12]5A 65 72 64 4D 61 6E 33 31}
		$str23="responseBody"
		$str24="savetofile"
		$str25={73 68 65 6C 6C 41 70 70 00 2E 4F 70 65 6E 20[3]65 6D 70 46 69 6C 65}

	condition:
		all of ($str1*) or all of ($str2*)

}

rule X97_Downloader_2108 
 {
	meta:
		sigid = 2108
		date = "2016-03-01 08:00 AM"
		threatname = "X97_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str12="Module=MM2"
		$str13="Module=MM3"
		$str14="Module=MM4"
		$str15="controlacobranzacheq"
		$str16="ansferenciaingresoH"
		$str17="empresatransaccioningreso"
		$str18="codigooperaciontransferencia"
		$str19="sistemanumnivelcosto"
		$str10="savetofile"
		$str11="Configurar_Conexiones"
		$str1={50 52 4F 43 41 44 44 [1] 52 [5] 52 32 2E 00 4F 70 65 6E 20 22 47 22 00 20 2B 20 43 68 72 28 36 [1] 39 29}
		$str241="tyrtyaag"
		$str242="squgrcbcquq/fsojhejsy/jlkoqs.rkr"
		$str243="VV6AgfVVap"
		$str244="NL4UZNpa4U"
		$str245="%GRZC%\\WVBvbqsuvbVU.rkr"

	condition:
		all of ($str1*) or all of ($str24*)

}

rule CVE_2012_0158_3102_2070 
 {
	meta:
		sigid = 2070
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2012_0158_3102"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$str1="TreeView1"
		$str2="MSComctlLib"
		$str3="TreeView"
		$str4="Compobj" wide
		$str5={54 65 6D 70 5C 45 78 63 60 65 6C 38}                                                           
		$str6="tlb#OLE"

	condition:
		($magic at 0) and (5 of ($str*))

}

rule W97M_Bartallex_2058 
 {
	meta:
		sigid = 2058
		date = "2016-03-01 08:00 AM"
		threatname = "W97M_Bartallex"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="Undetrolka"
		$str2="Visavi"
		$str3=".txt"
		$str4="Auto_Open"
		$str5="dbnvqhwjgdj asvdbcab"
		$str6=".bat"
		$str7="NHdjhasbdhas"
		$str8="Creasqwdqwjdk"
		$str9="Stkjrhbs"
		$str10="s9102e jkheiy2eui1h"

	condition:
		all of them

}

rule CVE_2015_2431_1911 
 {
	meta:
		sigid = 1911
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_2431"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$random1 = {0B 4E 57 53 EF 53 24 52 AD 65 41 00 B9 70 28 57 45 00 B9 70 84 76 63 6B 17 53 B9 65 1B FF 42}
$random2 = {2B 15 68 16 13 A5 00 16 68 2F 7D 31 00 35 08 81 43 4A 20 00 61 4A 20 00 66 48 00 99 6F 28 01 71}
$random3 = {17 53 B9 65 02 30 1C 4E 7F 89 B9 65 11 54 84 76 6E 78 9A 5B 1A FF 41 00 B9 70 30 52 42 00 B9 70}
$random4 = {3D B8 1E E0 83 9F 58 10 8E 79 61 56 AD 46 1D 02 30 5D 3B AF E0 F0 5B 99 06 7F C5 FA B1 98 DD A9}
$random5 = {F8 78 B8 E2 FF 6B 39 6B 79 ED ED D8 D0 9A 5C 42 26 93 73 4E A4 D8 B3 E7 F5 8E EF A3 01 FF C7 E2}
$random6 = {87 8B F8 78 B8 E2 FF 6B 39 6B 79 ED ED D8 D0 9A 5C 42 26 93 73 4E A4 D8 B3 E7 F5 8E EF A3 01 FF}

	condition:
		all of them

}

rule Microsoft_Integer_overflow:_CVE_2015_2470_1907 
 {
	meta:
		sigid = 1907
		date = "2016-02-01 08:00 AM"
		threatname = "Microsoft Integer overflow: CVE-2015-2470"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = {D7 82 CF 65 F2 53 69 8A}
$a1 = {E4 53 42 66 19 50 9E 5F 29}
$a2 = {86 4F 94 4E 8A 62 6B 70}
$a3 = {30 97 5B 59 65 DC 62 6B 70 59 65}
$a4 = {4E 4D 62 FD}
$a5 = {E2 96 66 53 31 75}
$a6 = {7D 66 53 4B 4E 61 8C E5 4E}
$a7 = {98 7A 7A 23 6C A9 52 C3 71}
$a8 = {66 73 53 BA 70 E5 4E 6B 70}
$a10 = {4D 62 FD ?? 62 6B BC 65 F3}
$a11 = {E4 53 E3 4E AE 79}
$a12 = {66 8B 4E 61 4B 4E 8C 8C}
$a13 = {A4 D1 37 F1 D8 8C 31 EC 64 D1}
$a14 = {D7 DE 2B F3 42 6C D0 8C 47 F4}

	condition:
		all of them

}

rule Trojan_Downloader_Win32_Ramath_1757 
 {
	meta:
		sigid = 1757
		date = "2016-02-01 08:00 AM"
		threatname = "Trojan-Downloader.Win32.Ramath"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$vbastring1 = "\\NTUSER.dat"
		$vbastring2 = ".exe" 
		$vbastring3 = "REG ADD" 
		$vbastring4 = "CurrentVersion\\Run"
		$vbastring5 = "del tmp.bat"
		$vbastring6 = "USERPROFILE" 
		$vbastring8 = "ShellExecuteA"
		$vbastring9 = "RetVal = ShellExecute(0,"

	condition:
		all of them

}

rule VBA_Downloader_Valyria_124978 
 {
	meta:
		sigid = 124978
		date = "2022-01-21 15:00 PM"
		threatname = "VBA.Downloader.Valyria"
		category = "Malware & Botnet"
		risk = 80
		
	strings:

$str1 = "Document_Open()"
$str2 = "CreateObject(\"Shell.Application\")"
$str3 = "Replace("
$str4 = ".ShellExecute"
$str5 = "\"\", \"open\", 0"
$str6 = "Selection.Delete Unit:=wdCharacter, Count:=1"
$str7 = "Selection.WholeStory"
$str8 = ".Hidden = False"
$str9 = ".Name = \"\""

condition:
all of them
}

rule CVE_2014_1761_1531 
 {
	meta:
		sigid = 1531
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2014-1761"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$hex_string1 = { 7b 5c 72 74 7b }
		$hex_string2 = { 5c 6f 62 6a 6f 63 78 5c } 
		$hex_string3 = { 4d 53 43 6f 6d 63 74 6c 4c 69 62 }
		$hex_string4 = { 3f 5c 75 2d 35 35 34 }
		$hex_string5 = { 53 31 38 74 }

	condition:
		($hex_string1 at 0) and ($hex_string2) and ($hex_string3) and ($hex_string4) and ($hex_string5)

}

rule SA2953095_RTF_1526 
 {
	meta:
		sigid = 1526
		date = "2016-02-01 08:00 AM"
		threatname = "SA2953095_RTF"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$badHdr   = "{\\rt{"
		$ocxTag   = "\\objocx\\"
		$mscomctl = "MSComctlLib."
		$rop      = "?\\u-554"

	condition:
		filesize > 100KB and filesize < 500KB and $badHdr and $ocxTag and $mscomctl and #rop>8

}

rule CVE_2010_3219_shellcode_1525 
 {
	meta:
		sigid = 1525
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2010-3219-shellcode"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = {A9 A9 E9 A9 A9 3A A9 A9 A9 9D 69 E1 69 D9 69 2D 69 11 69 FC 69}
		$b = {61 23 61 73 61 72 61 69 65 78 65}

	condition:
		all of them

}

rule CVE_2013_5331_SWF_1523 
 {
	meta:
		sigid = 1523
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2013-5331-SWF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$header = {66 55 66 55 ?? ?? ?? 00 5A 57 53}
		$control = "CONTROL ShockwaveFlash.ShockwaveFlash"

	condition:
		all of them

}

rule CVE_2011_0609_XLS_SWF_1522 
 {
	meta:
		sigid = 1522
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2011-0609-XLS-SWF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "fUfUG"
		$b = "FWS"
		$c = "141414141414141414"

	condition:
		all of them

}

rule CVE_2015_0085_1641 
 {
	meta:
		sigid = 1641
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-0085"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$rt = "{\\rtf"
		$a0 = "\\dppolyline"
		$a1 = "\\dppolycount2"
		$a2 = "\\dptxtbx\\dptxtbx"

	condition:
		(($rt at 0) and all of ($a*))

}

rule VBA_Dropper_Hacktool_123941 
 {
	meta:
		sigid = 123941
		date = "2021-09-01 05:09 AM"
		threatname = "VBA.Dropper.Hacktool"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1 = "Base64Encode(EncryptAES("
$str2 = "DecryptAES("
$str3 = "Environ(\"AppData\") &"
$str4 = "RC4(Base64Decode(\""
$str5 = ".CreateTextFile("
$str6 = "GetObject(\"new:72C24DD5-D70A-438B-8A42-98424B88AFB8\")"
$str7 = ".Run"
$str8 = "StrConv("

condition:
all of them
}

rule CVE_2016_7245_3395 
 {
	meta:
		sigid = 3395
		date = "2016-11-09 01:16 AM"
		threatname = "CVE_2016_7245"
		category = "Malware & Botnet"
		risk = 70
		
	strings:
		$m1 = "<w:documentProtection w:edit=\"forms\" w:enforcement=\"1\"/>" ascii nocase

	condition:
		all of ($m*)

}

rule VBA_Downloader_Macro_125073 
 {
	meta:
		sigid = 125073
		date = "2022-02-08 16:32 PM"
		threatname = "VBA.Downloader.Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$magic = {D0CF11E0A1B11AE1}
$str1 = "updatewin32.xyz/office365/" wide ascii 
$str2 = "Win32_Process" wide ascii 
$str3 = "winmgmts:" wide ascii 

condition:
		($magic at 0) and (all of ($str*))
}

rule VBA_Downloader_Emotet_117778 
 {
	meta:
		sigid = 117778
		date = "2018-02-06 10:31 AM"
		threatname = "VBA_Downloader_Emotet"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$magic={D0CF11}
$Str1 = ".AutoOpen" wide ascii
$Str2 = "[sTring]::jOIN" wide ascii nocase
$Str3 = "\\system3" wide ascii nocase
$Str4 = "ShellV" wide ascii nocase
$Str5 = "fwfMFjfdo" wide ascii
condition:
($magic at 0) and (all of them)
}

rule App_Exploit_Oracle_129187 
 {
	meta:
		sigid = 129187
		date = "2023-08-21 07:18 AM"
		threatname = "App.Exploit.Oracle"
		category = "Malware & Botnet"
		risk = 100
		CVE = "Notassigned"
Date = "28Jul2023"
Author = "Gayathri Anbalagan"
Comment = "CyberRating 2023"
Reference = "https://tisportal.trendmicro.com/threat/TSL20120124-05"
	strings:
    $vul = /<Relationship\s+Id="rId\d+"\s+Type="http:\/\/schemas\.openxmlformats\.org\/officeDocument\/\d{4}\/relationships\/image"\s+Target="[a-z\/\.\-_\+=:]{512}/ nocase

  condition:
    $vul
}

rule XLS_Downloader_Buerloader_123271 
 {
	meta:
		sigid = 123271
		date = "2021-06-08 06:50 AM"
		threatname = "XLS.Downloader.Buerloader"
		category = "Malware & Botnet"
		risk = 80
		
	strings:

$str1 = "Binary Access Write As #"
$str2 = "\\ProgramData\\"
$str3 = "Shell("
$str4 = "regsvr32"
$str5 = ".dll"
$str6 = "WriteFile("

condition:
all of them
}

rule VBA_TrojanDropper_BlackEnergy_2402 
 {
	meta:
		sigid = 2402
		date = "2016-03-01 08:00 AM"
		threatname = "VBA_TrojanDropper_BlackEnergy"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$Bytes1 = {54 00 AC 00 68 00 AC 00 69 00 AC 00 73 00 AC 00 20 00 AC 00 70 00 AC 00 72 00 AC 00 6F 00 AC 00 67 00 AC 00 72 00 AC 00 61 00 AC 00 6D 00 AC}
$Bytes2 = {50 00 AC 00 45 00 AC}
$bytes3 = {AC 00 4D 00 AC 00 75 00 AC 00 74 00 AC 00 65 00 AC 00 78 00 AC}
$bytes4 = {AC 00 4D 00 AC 00 5A 00 AC}
$string1 = "\\vba_macro.exe"

	condition:
		all of them

}

rule VBA_Dropper_Agent_124265 
 {
	meta:
		sigid = 124265
		date = "2021-10-08 16:20 PM"
		threatname = "VBA.Dropper.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"Scripting.FileSystemObject\")"
$str2 = "Environ$(\"Username\")"
$str3 = "C:\\\\users"
$str4 = "Startup\\\\Word$Data$"
$str5 = "Environ$(\"TEMP\")"
$str6 = ".WriteLine \"pyclient"
$str7 = "& \".e\" & \"xe\""
$str8 = "Shell("
$str9 = "vbHide)"

condition:
all of them
}

rule VBA_Downloader_Trickbot_123879 
 {
	meta:
		sigid = 123879
		date = "2021-08-23 05:23 AM"
		threatname = "VBA.Downloader.Trickbot"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "WinExec Lib \"kernel32"
$str2 = "= 3.14159"
$str3 = "WinExec \"cscript c:\\programdata\\"
$str4 = ".vbe"
$str5 = ".ScreenUpdating = True"
$str6 = ".CreateTextFile(\"c:\\programdata\\"

condition:
all of them
}

rule VBA_Downloader_Agent_123704 
 {
	meta:
		sigid = 123704
		date = "2021-07-30 09:34 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "cmd.exe /c"	nocase
$str2 = "powershell"	nocase
$str3 = "-ExecutionPolicy BypasS"	nocase
$str4 = "Win32_ProcessStartup"	nocase
$str5 = "GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\")"	nocase
$str6 = ".ShowWindow = 0"	nocase

condition:
all of them
}

rule VBA_Backdoor_Poshc2_123338 
 {
	meta:
		sigid = 123338
		date = "2021-06-16 14:52 PM"
		threatname = "VBA.Backdoor.Poshc2"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Open()"
$str2 = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AH"
$str3 = "IAZQBhAG0AUgBlAGEAZABlAHIAKAAoAE4AZQB3AC0ATwBiAG"
$str4 = "cgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG"
$str5 = "4AZwBdADoAOgBBAFMAQwBJAEkAKQApAC4AUgBlAGEAZABUAG"
$str6 = "-exec bypass"
$str7 = "-windowstyle hidden"
$str8 = "Shell("

condition:
all of them
}

rule VBA_Dropper_TransparentTribe_122834 
 {
	meta:
		sigid = 122834
		date = "2021-03-09 05:29 AM"
		threatname = "VBA.Dropper.TransparentTribe"
		category = "Malware & Botnet"
		risk = 75
		
	strings:

$str1 = "Split(UserForm1.TextBox"
$str2 = "PathExists("
$str3 = "For Binary Access Write As #2"
$str4 = "Put #2, , CByte("
$str5 = "Close #2"
$str6 = "CreateObject(\"Excel.Sheet\")"
$str7 = "CreateObject(\"WScript.Shell\")"

condition:
all of them
}

rule VBA_Backdoor_Unicorn_123641 
 {
	meta:
		sigid = 123641
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Backdoor.Unicorn"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Auto_Open()"
$str2 = "/w 1 /C \"\"sv"
$str3 = ".value.toString()"
$str4 = "\"S\" & \"h\" & \"e\" & \"l\" & \"l\""
$str5 = "\"W\" & \"S\" & \"c\" & \"r\" & \"i\" & \"p\" & \"t\""
$str6 = "\"p\" & \"o\" & \"w\" & \"e\" & \"r\" & \"s\" & \"h\" & \"e\" & \"l\" & \"l\" & \".\" & \"e\" & \"x\" & \"e\""
$str7 = "Microsoft Office (Compatibility Mode)"

condition:
all of them
}

rule VBA_Downloader_Lokibot_122789 
 {
	meta:
		sigid = 122789
		date = "2021-03-02 07:12 AM"
		threatname = "VBA.Downloader.Lokibot"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$call = "Call"
$str1 = "_Close()"
$str2 = "CreateObject(\"WScript.Shell\")"
$str3 = "CreateObject(\"microsoft.xmlhttp\")"
$str4 = "CreateObject(\"Shell.Application\")"
$str5 = ".Open \"get\","
$str6 = ".send"
$str7 = ".SaveToFile"
$str8 = "StrReverse("
$str9 = "#If VBA7 Then"

condition:
#call >= 100 and all of ($str*)
}

rule VBA_Downloader_Agent_123848 
 {
	meta:
		sigid = 123848
		date = "2021-08-19 05:28 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "&OS=\" + EncodeBase64("
$str2 = "Microsoft.XMLDOM\").createElement(\"b64\")"
$str3 = "GetObject(\"winmgmts:\\\\.\\root\\cimv2"
$str4 = ".ExecQuery(\"Select * from Win32_ComputerSystem"
$str5 = ".ExecQuery(\"Select * from Win32_OperatingSystem"
$str6 = ".OSArchitecture"
$str7 = ".ExecQuery(\"Select * from Win32_Process"
$str8 = ".LastBootUptime"

condition:
all of them
}

rule VBA_Downloader_Qakbot_124100 
 {
	meta:
		sigid = 124100
		date = "2021-09-21 07:02 AM"
		threatname = "VBA.Downloader.Qakbot"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "auto_open()"
$str2 = ".ScreenUpdating = False"
$str3 = "Excel4IntlMacroSheets"
$str4 = "UserForm1.Label1.Caption"
$str5 = "=HALT()"
$str6 = ".dll"
$str7 = "regsvr32 -silent"
$str8 = "=EXEC("
$str9 = "auto_close()"
$str10 = ").Delete"

condition:
all of them
}

rule CVE_2015_6092_Microsoft_DOC_UAF_in_PmwdFromDoc_2160 
 {
	meta:
		sigid = 2160
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_6092 Microsoft DOC UAF in PmwdFromDoc"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$fileid = {D0 CF 11 E0  A1 B1 1A E1}
		// ChpxFkp section signature
		$s1 = {18 0C 02 00 60 0D 02 00 14 0F 02 00 52 10 02 00 00 11 02 00 E8 11 02 00 D8 12 02 00}
		$s2 = {38 13 02 00 9E 13 02 00 A0 13 02 00 44 14 02 00 FE 14 02 00 82 16 02 00 E0 16 02 00}
		$s3 = {92 18 02 00 D0 19 02 00 BA 1A 02 00 1A 1B 02 00 80 1B 02 00 8C 1B 02 00 8E 1B 02 00}
		$s4 = {6E 1C 02 00 EF 00 00 00 00 00 00 00 00 00 00 00 00 DB 00 00 00 00 00 00 00 00 00 00}
		//$s5 = {00 00 DB 00 00 00 00 00 00 00 00 00 00 00 00 EF 00 00 00 00 00 00 00 00 00 00 00 00}
		//$s6 = {EF 00 00 00 00 00 00 00 00 00 00 00 00 EF 00 00 00 00 00 00 00 00 00 00 00 00 EF 00}
		//$s7 = {00 00 00 00 00 00 00 00 00 00 00 DB 00 00 00 00 00 00 00 00 00 00 00 00 DB 00 00 00}

	condition:
		$fileid at 0 and (all of ($s*))

}

rule CVE_2015_1641_T9000_2427 
 {
	meta:
		sigid = 2427
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_1641_T9000"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic="{\\rt"
		$str1="{\\object"
		$str2="\\objocx"
		$str3="\\objdata"
		$str4="6f746b6c6f6164722e5752417373656d626c792e31"
		$str5="\\objemb"
		$str6="XXXYY"
		$str7 = {7E 74 6D 70 2E 64 6F 63}
		$str8 = {34 55 4A 72 DC 56 43 87 8F 46 EC F0 49 A4 1F 3E 16}

	condition:
		($magic at 0)and (all of ($str*))

}

rule VBA_Downloader_Macro_1865 
 {
	meta:
		sigid = 1865
		date = "2016-07-28 13:14 PM"
		threatname = "VBA_Downloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$hex1 = {D0 CF 11 E0}
		$str1 = "anagyris"
		$str2 = "lugworm"
		$str3 = "deglutitionZp0"
		$str4 = "indestructible"
		$str5 = "radicchio"
		$str6 = "bloodbath"
		$str7 = "purifierzd0"
		$str8 = "quadrifoliolateyH0"
		$str9 = "architeuthis7&0"

	condition:
		$hex1 and (all of ($str*))

}

rule VBA_Downloader_Turla_119038 
 {
	meta:
		sigid = 119038
		date = "2023-04-12 14:25 PM"
		threatname = "VBA.Downloader.Turla"
		category = "Malware & Botnet"
		risk = 90
		
	
        strings:
                $str1 = "Xor 99) Xor (i Mod 254)"
                $str2 = "Sub AutoClose()"
                $str3 = "CreateObject(\"Scripting.FileSystemObject\")"
                $str4 = "Kill"
                $str5 = ".DeleteFile"
                $str6 = "(\"vbscript.regexp\")"
                $str7 = "\"appdata\") & \"\\Microsoft\\Windows\\\""
                $str8 = "CreateObject(\"WScript.Shell\")"
                $str9 = "Run \"\"\"\""
                $str10 = ".Save"
        condition:
                (all of them)

}

rule DOC_Downloader_Squirrelwaffle_124076 
 {
	meta:
		sigid = 124076
		date = "2021-09-20 05:46 AM"
		threatname = "DOC.Downloader.Squirrelwaffle"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "AutoOpen()"
$str2 = "StrReverse(\"\\ataDmargorP\\:C\")"
$str3 = "StrReverse(\"sbv."
$str4 = "Print #"
$str5 = "Close #"
$str6 = "Shell(StrReverse(\"sbv."
$str7 = "exe."
$str8 = "/ dmc\"),"

condition:
all of them
}

rule VBA_Downloader_Kimsuky_122527 
 {
	meta:
		sigid = 122527
		date = "2021-01-08 07:07 AM"
		threatname = "VBA.Downloader.Kimsuky"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "On Error Resume Next"
$str2 = "617070646174"
$str3 = "5c4d6963726f736f66745c54656d706c617465735c"
$str4 = "3d4372656174654f626a65637428"
$str5 = "4d53584d4c322e536572766572584d4c485454502e362e"
$str6 = "6f70656e20"
$str7 = "687474703a2f2f"
$str8 = "3a4578656375746528"
$str9 = "7363726970742e65786520"
$str10 = "AutoOpen()"

condition:
all of them
}

rule VBA_Downloader_Ursnif_122362 
 {
	meta:
		sigid = 122362
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.Ursnif"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1 = {50 75 62 6C 69 63 20 43 6F 6E 73 74 20 [5-8] 20 41 73 20 53 74 72 69 6E 67 20 3D 20 22 2D 2D 2D 2D 2D 22}
$str2 = {3D 20 53 70 6C 69 74 28 41 63 74 69 76 65 44 6F 63 75 6D 65 6E 74 2E 53 68 61 70 65 73 28 31 23 29 2E 54 69 74 6C 65 2C 20 [5-8] 29}
$str3 = "End Function"
$str4 = {3D 20 22 63 3A 5C 70 72 6F 67 72 61 6D 64 61 74 61 5C [5-8] 2E 70 64 66 22}

condition:
all of ($str*)
}

rule VBA_Downloader_APT34_121876 
 {
	meta:
		sigid = 121876
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.APT34"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$a1 = "_Open()"
$a2 = "CreateObject(\"WScript.Shell\")"
$a3 = ".ExpandEnvironmentStrings(\"%userprofile%\")"
$a4 = "\\appdata\\local\\microsoft\\Feed"
$a5 = ".Run"
$a6 = "\"\"\"'wscript.exe"

$ext1 = ".vbs"
$ext2 = ".ps1"

condition:
all of ($a*) and ($ext1 or $ext2)
}

rule VBA_TrojanDownloader_Macro_3462 
 {
	meta:
		sigid = 3462
		date = "2016-12-05 16:08 PM"
		threatname = "VBA_TrojanDownloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$docfile = {D0 CF 11 E0}
		$str1 = { 4C 61 62 65 6C 31 5F 43 6C 69 63 6B [5-19] 73 6A 75 63 }
		$str2 = {54 68 69 73 44 6F 63 75 6D 65 6E 74 00 54 00 68 00 69 00 73 00 44 00 6F 00 63 00 75 00 6D 00 65 00 6E 00 74 00 00 00 6D 6F 64 75 6C 65 31 00 6D 00 6F 00 64 00 75 00 6C 00 65 00 31 00 00 00 6E 65 77 66 6F 72 6D 00 6E 00 65 00 77 00 66 00 6F 00 72 00 6D 00 00 00 71 77 65 71 77 65 00 71 00 77 00 65 00 71 00 77 00 65}

	condition:
		$docfile at 0
		and (all of them)
		and filesize < 80KB
		and filesize > 76KB

}

rule VBA_Trojan_RunPE_120130 
 {
	meta:
		sigid = 120130
		date = "2019-11-01 06:14 AM"
		threatname = "VBA.Trojan.RunPE"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1 = "RunPE"
$str2 = "~~~ IMPORT WINDOWS API FUNCTIONS ~~~"
$str3 = "#If Win64 Then"
$str4 = "Private Declare PtrSafe"
$str5 = "CreateProcess"
$str6 = "VirtualAllocEx"
$str7 = "WriteProcessMemory"
$str8 = "SetThreadContext"
$str9 = "IMAGE_FILE_HEADER"
$str10 = "NumberOfSections"
$str11 = "IMAGE_OPTIONAL_HEADER" 
$str12 = "~~~ CONSTANTS USED IN WINDOWS API CALLS ~~~" 
$str13 = "ByteArrayToString" 
$str14 = "Private Function PE0() As String" 
$str15 = "~~~ EMBEDDED PE ~~~" 
$str16 = "[+] |__ Magic number is OK." 
$str17 = "[-] |__ Input file is not a valid PE." 
$str18 = "[-] You're trying to inject a 32 bits binary into a 64 bits process!" 
$str19 = "lGetThreadContext = GetThreadContext(structProcessInformation.hThread, structContext)" 
$str20 = "lProcessImageBase = VirtualAllocEx(structProcessInformation.hProcess, structNTHeaders.OptionalHeader.ImageBase, structNTHeaders" 
$str21 = "Call TerminateProcess(structProcessInformation.hProcess, 0)" 
$str22 = "lWriteProcessMemory = WriteProcessMemory(structProcessInformation.hProcess, lNewAddress, " 
condition: 
14 of ($str*)
}

rule VBA_Trojan_APT28_122760 
 {
	meta:
		sigid = 122760
		date = "2021-02-22 08:58 AM"
		threatname = "VBA.Trojan.APT28"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "WinExec Lib \"kernel32\""
$str2 = "_Open()"
$str3 = "Environ(\"temp\")"
$str4 = "UserForm1"
$str5 = "CreateObject(\"Microsoft.XMLDOM\")"
$str6 = "\"bin.base64\""
$str7 = "CreateObject(\"ADODB.Stream\")"
$str8 = ".Write"
$str9 = "SaveToFile"

condition:
all of them
}

rule RTF_Dropper_Troldesh_122875 
 {
	meta:
		sigid = 122875
		date = "2022-03-02 11:59 AM"
		threatname = "RTF.Dropper.Troldesh"
		category = "Malware & Botnet"
		risk = 50
		hash = "70edefbefaee9a7a1f520b5552ac1a38"
	strings:
		$mgic = {7B 5C 72 74}
		$str1 = "\\objw9361 000000000000\\objh874{\\*\\objclass Word.Document.12}" wide ascii
		$str2 = "\\d1111111111111111000000000000000000000000000000000000ec" wide ascii
		$str3 = "\\widctlpar\\wrapdefault\\aspalpha\\aspnum\\" wide ascii
		$str4 = "d0cf11e0a1b11ae10000000000000000000000000000{\\object}" wide ascii
condition:
		$mgic at 0 and all of ($str*)
}

rule TrojanDownloader_X97M_Donoff_2264 
 {
	meta:
		sigid = 2264
		date = "2016-03-01 08:00 AM"
		threatname = "TrojanDownloader_X97M_Donoff"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "Execute"
		$s2 = "Process WriteParameterFiles"
		$s3 = "WScript.Shell"
		$s4 = "STOCKMASTER"
		$s5 = "InsertEmailFax"

	condition:
		all of them

}

rule VBA_Downloader_Macro_116993 
 {
	meta:
		sigid = 116993
		date = "2017-09-05 09:02 AM"
		threatname = "VBA_Downloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		hash = "576b8fff45897ff4997de4f454e95bb8"

	strings:
$s1 = "lpHostName"
$s2 = "URLDownloadToFileW"
$s3 = "ShellExecuteW"
$s4 = "AutoOpen"
$s5 = "WSAAsyncGetHostByName"
$s6 = "Proyecto1"
$s7 = "Documento de Microsoft Office"
$s8 = "????????????"
$s9 = {6D 79 66 69 6C [4-10] 65 78 65 }
condition:
(all of ($s*))
and filesize < 250KB
and filesize > 200KB
and #s8 > 160
}

rule VBS_Worm_ILoveYou_116777 
 {
	meta:
		sigid = 116777
		date = "2017-08-07 05:43 AM"
		threatname = "VBS_Worm_ILoveYou"
		category = "Malware & Botnet"
		risk = 100
		hash = "040dc52b34161d0516b02ee8c67c8fbd"
	strings:
$s1 = "barok -loveletter(vbe) <i hate go to school>"
$s2 = "c.Copy(dirsystem&\"\\LOVE-LETTER-FOR-YOU.TXT.vbs\")"
$s3 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page"
$s4 = "male.Body = vbcrlf&\"kindly check the attached LOVELETTER coming from me.\"\"\") th"
condition:
all of ($s*)
}

rule RTF_Exp_Zeroday_3722 
 {
	meta:
		sigid = 3722
		date = "2017-04-11 17:06 PM"
		threatname = "RTF_Exp_Zeroday"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = "{\\rt"
		$str1 = "504b030414000600080000002100e9de"
		$str2 = "6eafc3acae853a33b7ba11cd1445875ba1b236b1"
		$str3 = "<script language=\"VBScript\">"
		$str4 = "</script>399483c90bd560b0b0263435085"
		$str5 = "d0cf11e0a1b11ae1"
		$str6 = "4d73786d6c322e534158584d4c5265616465722e362e30" //Msxml2.SAXXMLReader.6.0

	condition:
		($magic at 0) and (all of ($str*))

}

rule VBA_TrojanDownloader_Macro_3551 
 {
	meta:
		sigid = 3551
		date = "2017-02-09 12:38 PM"
		threatname = "VBA_TrojanDownloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = { 3D 3D 0D 2D 2D 2D 2D 2D 45 4E 44 20 50 47 50 20 4D 45 53 53 41 47 45 2D 2D 2D 2D 2D 0D 0D 03 0D 0D 04 0D 0D 03 0D 0D 04 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 44 6F 63 75 6D 65 6E 74 20 70 72 6F 74 65 63 74 65 64 20 62 79 20 4D 69 63 72 6F 73 6F 66 74 20 4F 66 66 69 63 65 20 53 65 63 75 72 69 74 79 20 73 79 73 74 65 6D 0D 54 6F 20 64 65 63 72 79 70 74 20 74 68 69 73 20 64 6F 63 75 6D 65 6E 74 2C 20 70 6C 65 61 73 65 20 63 6C 69 63 6B }
		$s2 = "#OLE Aut"
		$s3 = "AutoOpen"
		$s4 = "Project1"
		$s5 = {5F 00 56 00 42 00 41 00 5F 00 50 00 52 00 4F 00 4A 00 45 00 43 00 54}

	condition:
		(all of ($s*))

}

rule CVE_2016_7193_3343 
 {
	meta:
		sigid = 3343
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_7193"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$s1 = "otkloadr.WRLoader.1" ascii wide
		 $s2 = "d0cf11e0a1b11ae1" ascii wide
		 $s3 = "Word.Document." ascii wide

	condition:
		all of ($s*)

}

rule MD_VernalDrop_XLS_3453 
 {
	meta:
		sigid = 3453
		date = "2016-11-23 15:45 PM"
		threatname = "MD_VernalDrop_XLS"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$t1 = "WScript.Shell"
$t2 = "Scripting.FileSystemObject"
$t3 = "Execzy"
$t4 = "WScript.StdOut.Write"
$t5 = "rundll32.exe"
$t6 = "Auto_OpenV"
$h1 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F 4E 61 6D 00 65 }
//Attribut.e VB_Nam.e

	condition:
		all of them

}

rule VBA_TrojanDownloader_Macro_3449 
 {
	meta:
		sigid = 3449
		date = "2016-11-23 15:45 PM"
		threatname = "VBA_TrojanDownloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$doc = { D0 CF 11 E0 }
		$str1 = { 4A 53 63 72 27 00 [10] 4D 53 53 63 72 69 27 00 [8] 72 69 70 74 43 6F 27 00 [8] 6E 74 72 6F 6C 00 [10] 69 70 74 00 27 00 }
		$str2 = { 53 65 74 [13] 43 00 72 65 61 74 65 4F 62 6A [12] 4C 80 61 6E 67 75 61 67 65 [9] 41 64 64 43 00 6F 64 65 [96] 45 6E 64 20 53 75 62 [6] 41 75 74 6F 4F }
		$msg1 = { 45 00 4E 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 20 00 44 00 4F 00 43 00 55 00 4D 00 45 00 4E 00 54 }
		$msg2 = {43 00 4F 00 4E 00 46 00 49 00 44 00 45 00 4E 00 54 00 49 00 41 00 4C}

	condition:
		$doc at 0
		and ($msg1 or $msg2)
		and (all of ($str*))

}

rule W97MDownloader_2479 
 {
	meta:
		sigid = 2479
		date = "2016-12-13 10:56 AM"
		threatname = "W97MDownloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="KogdaGe_3r"
		$a2="Nebeineboysya_2ek"
		$a3={68 6F 6B 75 6B 6D 96 09 33 85 09 45 B6 33 80 0A 82 0C 2E 00 45 6E 76 69 72 6F 6E 6D}
		$a4={50 75 62 44 6F 53 74 6F 70 4A D2 30 00 08 04 55 73 65 72 46 6F 72 6D 4E 04}
		$a5="CheckBins"
		$a6="CheckDatabase"
		$a7="ConnectMaps"

	condition:
		(all of ($a*))

}

rule VBA_Downloader_2658 
 {
	meta:
		sigid = 2658
		date = "2016-12-13 10:54 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={53 65 74 00 20 44 76 6F 72 65 63 47 80 6F 6C 64 65 6E}
		$a2={4B 72 69 70 6F 74 61 97 E5 30}
		$a3="ShishilMishelPernulVishel"
		$a4="LoadTheseAutosaveFiles"
		$a5="purgeOldAutosaveData"
		$a6="notifyCleanShutdown"

	condition:
		(all of them)

}

rule VBA_Downloader_2685 
 {
	meta:
		sigid = 2685
		date = "2016-12-13 10:53 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={54 35 6B 4E 4E 63 4C 51 00 31 69 63 63 56 4D 61 28}
		$a2="C58xniKNitI"
		$a3="SE8wcILPDl08TQrG6u9OuXZbb0Pwm6jYegBkW3NO"
		$a4="QnxCy6dQUPmwO1iqFfgDZRN79QUdWIGR"
		$a5={4D 4B 33 35 53 58 02 49 E7 02 50 6D 37}
		
		$b1={44 51 77 58 5A 48 51 4C 00 75 7A 4C 28}
		$b2={3D 20 22 59 6F 47 78 00 45 37 48 56 57 67 79 55 00 67 33 58 33 58 5A 35 69}
		$b3="HITG7GImYQgR52Q"
		$b4={44 6F 63 75 6D 65 6E 74 5F 4F 70 65 6E C1[11]59 53 37 32 44 71 67 50 43 49 31 48 38 70 4C 6B 63}

	condition:
		(all of ($a*)) or (all of ($b*))

}

rule VBA_Downloader_2828 
 {
	meta:
		sigid = 2828
		date = "2016-12-13 10:52 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={46 75 6E 63 74 69 6F 6E 00 20 45 6A 65 63 75 74 61 00 53 51 4C}
		$a2="EstaLaCuentaBloqueadam"
		$a3="ImpirmirListadoCaja"
		$a4="UsuariosConectados"
		$a5="KwhToJoule"

	condition:
		(all of them)

}

rule VBA_Downloader_3006 
 {
	meta:
		sigid = 3006
		date = "2016-12-13 10:51 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={47 76 7A 6A 00 55 55 6F 53 6B 42 53 4F 14 41 65 03}
		$a2="BTrCszdUssYhws"
		$a3="uKJesOjQdsphJg"
		$a4="mkwMJrOHNmo"
		$a5="RDlzPuPDZbbWNGL"

	condition:
		(all of them)

}

rule VBA_Downloader_3028 
 {
	meta:
		sigid = 3028
		date = "2016-12-13 10:49 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="breachedmesounaerated"
		$a2="condominium"
		$a3="chucklehead"
		$a4="monandrousexpelycosaur"
		$a5="lintatelanaphalis"
		$a6={6D 65 20 4C 49 4B 45 20 27 50 79 74 68 6F 6E 20 25 27}

	condition:
		(all of them)

}

rule VBA_Downloader_3282 
 {
	meta:
		sigid = 3282
		date = "2016-12-13 10:43 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a1="RtlMoveMemory"
		$a2="EnumSystemLanguageGroupsA"
		$a3="GetModuleHandle"
		$a4="RemoveDirectoryA"
		$a5="TlsAlloc"
		$a6="dephlegmationxP"
		$a7="deplorably"

	condition:
		(all of them)

}

rule CVE_2016_7228_3393 
 {
	meta:
		sigid = 3393
		date = "2016-11-09 14:23 PM"
		threatname = "CVE_2016_7228"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$m1 = { 7D 00 0C 00 } // start of COLINFO record; next 4 bytes are colFirst (2) and colLast (2) - these are the interesting ones here which will get tested in the rule below
		$m2 = { 09 08 ?? ?? 00 06 } // BIFF8
		$m3 = { 00 D1 01 00 00 00 00 40 00 0F 00 08 02 10 00 01}
		$m4 = {00 00 BE 00 18 00 01 00 05 00 3A 00 3A 00 3A 00}

	condition:
		all of ($m*) and for any i in (1..#m1) : (uint16(@m1[i] + 4) < uint16(@m1[i] + 6))

}

rule VBA_TrojanDownloader_Macro_Madeba_3387 
 {
	meta:
		sigid = 3387
		date = "2016-11-07 15:46 PM"
		threatname = "VBA_TrojanDownloader_Macro_Madeba"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$docfile = { D0 CF 11 E0 }
		$png = { 89 50 4E 47 [8] 49 48 44 52 [46] 50 68 6F 74 6F 73 68 6F 70 20 49 43 43 20 70 72 6F 66 69 6C 65 }
		$apis = { 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 [80-120] 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 [40-60] 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 }
		$macro = { 57 69 6E 33 32 [12-19] 56 42 41 36 [1] 23 [4] 50 72 6F 6A 65 63 74 31 [28-36] 54 68 69 73 44 6F 63 75 6D 65 6E 74 [80-90] 57 69 6E 36 34 }

	condition:
		$docfile at 0
		
		and (all of them)

}

rule VBA_Downloader_3214 
 {
	meta:
		sigid = 3214
		date = "2016-08-26 11:55 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$api_01 = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }  // VirtualAlloc
		$api_02 = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }  // RtlMoveMemory
		$api_04 = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }  // CallWindowProcAi
		$magic  = { 50 4F 4C 41 }  // POLA
		$magic1={D0 CF 11 E0}

	condition:
		$magic1 and all of ($api_*) and $magic

}

rule VBA_TrojanDownloader_Macro_2990 
 {
	meta:
		sigid = 2990
		date = "2016-10-14 18:10 PM"
		threatname = "VBA_TrojanDownloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$docfile = { D0 CF 11 E0 }
		$str1 = "msinkaut.InkPicture"
		$str2 = "_Painted"
		$str3 = {52 65 63 65 6E 74 46 69 6C 65 73 [4-9] 43 6F 75 6E 74}
		$str4 = { 43 72 65 61 74 65 4F 62 6A 65 63 74 [250-320] 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 [44-55] 53 65 6E 64 [8-18] 53 74 61 74 75 73 [8-18] 52 65 73 70 6F 6E 73 65 54 65 78 74 }
		$msg = { 57 6F 72 64 20 65 78 70 65 72 69 65 6E 63 65 64 20 61 6E 20 65 72 72 6F 72 20 74 72 79 69 6E 67 20 74 6F 20 6F 70 65 6E 20 74 68 65 20 64 6F 63 75 6D 65 6E 74 2E 0D 54 72 79 20 74 68 65 73 65 20 66 69 78 65 73 3A 0D 0D 31 20 45 6E 61 62 6C 65 20 45 64 69 74 69 6E 67 0D 32 20 4D 61 6B 65 20 73 75 72 65 20 43 6F 6E 74 65 6E 74 20 69 73 20 65 6E 61 62 6C 65 64 0D 33 20 4F 70 65 6E 20 74 68 65 20 66 69 6C 65 20 77 69 74 68 20 74 68 65 20 54 65 78 74 20 52 65 63 6F 76 65 72 79 20 63 6F 6E 76 65 72 74 65 72 2E 0D 0D 21 0D 0D 4F 4B 0D 0D 53 68 6F 77 20 48 65 6C 70 20 3E 3E }

	condition:
		$docfile at 0
		and (all of them)

}

rule VBA_TrojanDownloader_Casdet_119112 
 {
	meta:
		sigid = 119112
		date = "2019-02-05 06:00 AM"
		threatname = "VBA_TrojanDownloader_Casdet"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
                $str1 = ".ThisDocument"
                $str2 = "MsgBox (\"cmd.exe /c reg add \"\"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Script Host\\Settings\""
                $str3 = "CreateObject(\"WScript.Shell\")"
                $str4 = "CreateObject(\"\"ADODB.Stream\"\")\""
                $str5 = ".SaveToFile"
                $str6 = ".run \"\"cmd.exe /C schtasks /create"
                $str7 = ".exe\"\", 0, True\""
condition:
               all of them
}

rule CVE_2013_3906_RTF_3181 
 {
	meta:
		sigid = 3181
		date = "2016-08-10 02:32 AM"
		threatname = "CVE_2013_3906_RTF"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = "{\\rtf1"
		$c1 = "\\listoverridecount026b"
		$s31 = "{\\*\\fldinst"
		$s32 = "http://"
		$s33 = ".php?id="
		$c2 = "{\\*\\objclass Word.Document.11}"
		$c3 = "d0cf11e0a1b11ae1000000000000000"

	condition:
		($magic at 0 ) and ((all of ($s3*) and all of ($c*)))

}

rule CVE_2010_3333_2507 
 {
	meta:
		sigid = 2507
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2010_3333"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic="{\\rt"
		$str1="{\\shp"
		$str2="{\\sp"
		$str3="{\\sv"
		$str4="{\\sn0 pf}"
		$str5="{\\sn1 r}"
		$str6="{\\sn2 agm}"
		$str7="{\\sn3 en}"
		$str8="{\\sn4 ts}"
		$str9="909090909090909090909090909090909090eb"
		$str10="687474703a2f2f"
		$str11="2e657865"

	condition:
		($magic at 0) and (all of ($str*))

}

rule VBA_Trojan_Downloader_3018 
 {
	meta:
		sigid = 3018
		date = "2016-07-07 05:40 AM"
		threatname = "VBA_Trojan_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$hex1={28225345002229202B20226C65306374}
		$hex2="N EREHW"
		$hex3={2229202B20226C65306374}
		$hex4="se(\"erocF\""

	condition:
		all of them

}

rule CVE_2016_3234_2955 
 {
	meta:
		sigid = 2955
		date = "2016-06-15 11:45 AM"
		threatname = "CVE_2016_3234"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$sys1="\\mailmerge\\mmreccur\\mmerrors{\\*\\mmodso{\\mmodsoudldata"

	condition:
		$sys1

}

rule VBA_Trojan_Downloader_2694 
 {
	meta:
		sigid = 2694
		date = "2016-05-05 11:51 AM"
		threatname = "VBA_Trojan_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = {D0CF11E0}
		$hex1 = {43785676526A578031394734463861C09700}
		$hex2 = {5952754378656F327A4A70465FBC1000}
		$hex3 = {5175334B004D72786B332842790056616C205243644980354838}
		$hex4 = {4D365856306E474835564A7558AADF1000}
		$hex5 = {43785676526A57313947344638613C1F1000}

	condition:
		$magic at 0 and all of ($hex*)

}

rule VBA_Trojan_Downloader_2672 
 {
	meta:
		sigid = 2672
		date = "2016-05-05 11:49 AM"
		threatname = "VBA_Trojan_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = {D0CF11E0}
		$hex1 = {674D496243426E68614A4C6347}
		$hex2 = {6675626C6963204600756E6374696F6E20006C56534E6F476B5000}
		$hex3 = {4D4B75634F10636374650314496E74C0}
		$hex4 = {6242596A004C7A492E434455710067775A6A446F66}

	condition:
		$magic at 0 and all of ($hex*)

}

rule VBA_Trojan_Downloader_2642 
 {
	meta:
		sigid = 2642
		date = "2016-04-18 16:31 PM"
		threatname = "VBA_Trojan_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = {D0CF11E0}
		$hex1 = {42657A7261626F74086B69}
		$hex2 = {637265617246610063746F727944414F[1]28707470}
		$hex3 = {436F6E6669677572617253697374656D61F8}
		$hex4 = {4F6274656E65724461746F44656C526567697374726F646557696E646F7773}
		$hex5 = {5265656D706C617A617250616C6162726104}

	condition:
		$magic at 0 and all of ($hex*)

}

rule VBA_Downloader_2595 
 {
	meta:
		sigid = 2595
		date = "2016-04-01 07:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a1={42 63 72 61 48 36 4B 57 00 59 32 5A 77}
		$a2="DQUGZp95uHZN"
		$a3={4E 39 73 37 45 73 69 70 6E 50 4D 46 39 B4 4A 10 00[8]4B 69 69 46 72 33 39 38 69 78 48 51}
		$a4="Fxe4nMP9nYnr2"
		$a5="QRLF8Mtea7ihAPzm&"

	condition:
		($magic at 0) and (all of them)

}

rule Win32_Exploit_CVE_2016_3235_127245 
 {
	meta:
		sigid = 127245
		date = "2023-01-27 07:48 AM"
		threatname = "Win32.Exploit.CVE-2016-3235"
		category = "Malware & Botnet"
		risk = 80
		CVE = "CVE-2016-3235"
        Author = "asasi"
        comments = "Microsoft Office OLE DLL Side Loading Vulnerability"
	
    strings:
        $ole_obj = {D0 CF 11 E0 A1 B1 1A E1}
        $clsid = { 06 B8 92 6C 00 B9 92 43 89 F7 2E D4 B4 C2 32 11}
    
    condition:
    all of them

}

rule App_Exploit_CVE_2009_0221_127218 
 {
	meta:
		sigid = 127218
		date = "2023-01-23 12:28 PM"
		threatname = "App.Exploit.CVE-2009-0221"
		category = "Malware & Botnet"
		risk = 0
		Author = "Satakshi Dubey"
         CVE_ID = "CVE-2009-0221"
	strings:
         $magic_bytes = {D0 CF 11 E0 A1 B1 1A E1}
         $ppt_bytes = {50 00 6F 00 77 00 65 00 72 00 50 00 6F 00 69 00 6E 00 74 00 20 00 44 00 6F 00 63 00 75 00 6D 00 65 00 6E 00 74 00}
         $rectype = {e7 2e 08 00 00 00 00 01 00 00 02 00 00 00}
       
         
    condition:
         all of them 
         //and 
         //for 1 i in (1..#rectype):
        // for i in (1..4):
             // (uint32(@rectype[i]+10)>0x200000)
}

rule VBA_Downloader_Emotet_117406 
 {
	meta:
		sigid = 117406
		date = "2017-11-14 06:50 AM"
		threatname = "VBA_Downloader_Emotet"
		category = "Malware & Botnet"
		risk = 100
		hash1 = "20ca01986dd741cb475dd0312a424cebb53f1201067938269f2e746fb90d7c2e"
hash2 = "c7cab605153ac4718af23d87c506e46b8f62ee2bc7e7a3e6140210c0aeb83d48"
	strings:
$signature = {D0 CF 11 E0}
$base = /JAB7\w{100,}={0,2}/
$s1 = "BuiltInDocumentProperties"
$s2 = "CustomDocumentProperties"
$s3 = "Run"
$s4 = "VBA"
$s6 = "Comments"
$s7 = "autoopen"
$s8 = "Module1"
$s9 = "Picture 1" wide
$s10 = "JFIF"

condition:
$signature at 0 and $base in (0x8200..0x9000) and 8 of ($s*)
}

rule VBA_Downloader_Seduploader_117262 
 {
	meta:
		sigid = 117262
		date = "2017-10-24 10:25 AM"
		threatname = "VBA_Downloader_Seduploader"
		category = "Malware & Botnet"
		risk = 100
		hash = "94b288154e3d0225f86bb3c012fa8d63"
	strings:
$doc = {D0 CF 11 E0 A1 B1 1A E1}
$s1 = "[Content_Types].xml"
$s2 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAA"
$s3 = "_jga"
$s4 = "6FKF////tsgAAADoR4X///2zAAAAOg8hf//g8RA/7bQAAAA6C6F////trgAAADoI4X///"
condition:
$doc and all of ($s*) and @s1 < @s2 and #s3 > 11
}

rule VBA_Downloader_Squirrelwaffle_124437 
 {
	meta:
		sigid = 124437
		date = "2021-10-27 13:19 PM"
		threatname = "VBA.Downloader.Squirrelwaffle"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "AutoOpen()"
$str2 = ".vbs"
$str3 = "Output As #"
$str4 = "Close #"
$str5 = "Shell(\"cmd /k cscript.exe C:\\ProgramData\\"
$str6 = "Chr(48)"
$str7 = "MsgBox(\""

condition:
all of them
}

rule VBA_Downloader_Emotet_3005942 
 {
	meta:
		sigid = 3005942
		date = "2022-04-04 08:11 AM"
		threatname = "VBA.Downloader.Emotet"
		category = "Malware & Botnet"
		risk = 99
		
	strings:
$magic = {D0CF11E0A1B11AE1}
$str1="\\urtj.dll"
$str2="SysWow64"
$str3="\"h\"&\"t\"&\"t\"&\"p:/\""
condition:
($magic at 0) and (all of ($str*))
}

rule VBA_Downloader_2607 
 {
	meta:
		sigid = 2607
		date = "2016-04-11 17:02 PM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a1={4D 6F 64 00 75 6C 65 31 22[3]00 75 62 20 79 46 47 48 56 00 4A 42 6B 62 6A 6B}
		$a2={73 62 6F 75 58 41 4E[7]6B 73 4F 4B 58 77 78 4A 78}
		$a3={69 73 53 6D 45 76 47 73 00 2C 20 53 69 6C 48 48}
		$a4="ytdfYUGIB3fs"
		$a5="ruvgeria"

	condition:
		($magic at 0) and (all of them)

}

rule CVE_2014_1761_2410 
 {
	meta:
		sigid = 2410
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2014_1761"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic="{\\rt"
		$str1="listoverridetable"
		$str2="listid1094795585"
		$str3="llllistoverridecount25"
		$str4="listoverridestartat"
		$str5="levelstartat31611"
		$str6="{\\lfolevel"
		$str7="68457869745453FFD2FFD0E8"
		$str8="31C9648B41308B400C8B7014"

	condition:
		(($magic at 0) and (8 of ($str*)))

}

rule CVE_2016_0015_2351 
 {
	meta:
		sigid = 2351
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2016-0015"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a="\\paperw12240\\paperh15840\\margl1440\\margr1440\\margt1440\\margb1440\\gutter0\\ltrsect"
		$b="\\rtlch\\fcs1 \\af31507 \\ltrch\\fcs0 \\insrsid4786370"
		$c="\\themedata 504b03041400060008000000"
		$d="\\lsdlocked0 Intense Emphasis"
		$e="4d73786d6c322e534158584d4c5265616465722e362e"

	condition:
		all of them

}

rule W97M_Bartallex_2060 
 {
	meta:
		sigid = 2060
		date = "2016-03-01 08:00 AM"
		threatname = "W97M_Bartallex"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="Seacop"
		$str2="Vreation"
		$str3=".txt"
		$str4="AutoOpen"
		$str5=".bat"
		$str6="NHdjhasbdhas"
		$str7="Creasqwdqwjdk"
		$str8="qhjwdh qwhgdjhqw jdkhqwdhqwgdhjqw"
		$str9="qwhdjkw qhdjkwhqw dqwgdhjqgdhq"

	condition:
		all of them

}

rule VBA_Downloader_2144 
 {
	meta:
		sigid = 2144
		date = "2016-03-01 08:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str33="pisahKata"
$str34="pisahJarak"
$str35="NilaiKondisi"
$str36={4B 6F 6E 76 65 72 74[171]4B 6F 6C 6F 6D 50 61 6E 6A 61}
$str32={6E 69 6C 61 69 70 6B 6D[11]6B 6F 6C 6F 6D[12]4E 69 6C 61 69 4B 6F 6C 6F 6D 45 4C 30}
$str31="zimbaba"
$str37="\\inp"
$str39="savetofile"
$str333="responseBody"

	condition:
		all of them

}

rule CVE_2015_1642_1923 
 {
	meta:
		sigid = 1923
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_1642"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$S1 = {1C 32 E3 35 76 D6 0F 02 3E DE 65 BE 85 8C A2 F2 9D 9A D0 1B 01 1E 61 DF 3E 3F 35 6A A9 51 2F 59 2A 7A 52 44 B6 13 F0 53 55 72 77 E0 E5 31 3F 94}
		$S2 = {35 7D 6D 93 3E 7E 75 67 AA 7B 1D 0C 17 F3 DB B3 7D 24 FA E1 48 22 C5 2F 51 2E A8 24 D0 E7 31 E4 D5 CB 64 05 BB A9 BD E1 B1 FA A3 8B 79 12 AC B2}
		$S3 = {61 25 0D 56 6F 55 FB 44 D5 5B 45 43 D5 5B 45 43 D5 5B 45 03 D4 DB 47 95 47 72 77 D6 31 E9 BF 76 F7 28 D2 19 A2 C3 9B A9 65 22 CC 04 80 3F DC D4}

	condition:
		all of them

}

rule Microsoft:_CVE_2015_2477_1909 
 {
	meta:
		sigid = 1909
		date = "2016-02-01 08:00 AM"
		threatname = "Microsoft: CVE-2015-2477"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = {92 63 63 70 CF 65 9E 8A 59 65 78}
$a1 = {59 65 50 67 86 4F}
$a2 = {8E D4 9A CA 53 DD 4F 77}
$a3 = {4D 7A 75 69 C3 53}
$a4 = {88 FE 73 FA 51 74 65 D4 9A}
$a5 = {3B 6D D5 52 41 6D}
$a6 = {28 75 CD 6B 9E 8A 39 65 E8 7D}
$a7 = {70 59 42 59 42 70 37 59 42 59 42 70 37}
$a8 = {DC 9C CF 49 D0 DF BD 24}
$a9 = {67 75 79 CE EA F0 58 EB 6B}
$a10 ={18 4C 5A 79 59 D5 A9 AE B5 F5 C9}
$a11 = {AE FA 57 DF A9 CE 77 D9 D4 38}
$a12 = {83 F8 E3 24 57 5D F0 DF C5 F1 4D 33 E9}
$a13 = {D3 6F 26 8E E8 C2 58 33}
$a14 = {16 57 E4 C3 46 9F F3 32}

	condition:
		all of them

}

rule VBA_Downloader_2510 
 {
	meta:
		sigid = 2510
		date = "2016-04-01 07:00 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a1={59 75 73 73 7355 55 55 00 4B 6B 61 68 68 79 79 75 00 69 6F 6F 6F 70 59 5F 31}
		$a2={4B 69 6C 6C 46 69 6C 65 C5[5]59 75 73 73 73 55 55 55 4B 6B 61}
		$a4={44 6F 62 79 2E 00 4D 65 73 73 61 67 65 20[92]63 00 55 6E 64 6F 46 69 6C 65 00 6E 61 6D 65 45}
		$a5={50 61 6C 61 63 65 50 65 70 65 6C 61 63 5F 38 CC[16]73 73 55 55 55 4B 6B 61}

	condition:
		($magic at 0) and (all of ($a*))

}

rule CVE_2015_2415_1828 
 {
	meta:
		sigid = 1828
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_2415"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$s1 = "scRiPTinG.fiLEsysTeMoBjEcT" nocase
		$s2 = "!Auto_Activate" 
		$s3 = "wscript.sleep"
		$s4 = "WshSHell.Run" nocase
		$s5 = ".exe" nocase
		$s6 = "CreateFolder" 
		$s7 = "objFSO.FileExists" nocase

	condition:
		all of them

}

rule CVE_2015_2377_1825 
 {
	meta:
		sigid = 1825
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_2377"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$chartXMLHeader = "<c:chartSpace xmlns:c="
		$chartXMLHeader2 = "<c:chart>"
		$legendStart = "<c:legend>"
		$legendEnd = "</c:legend>"
		$missingEle = "<c:legendPos"

	condition:
		($chartXMLHeader and $chartXMLHeader2 and $legendStart and $legendEnd) and not $missingEle

}

rule CVE_2015_1651_1650 
 {
	meta:
		sigid = 1650
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-1651"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = "{\\rtf1"
		$a2 = "{\\sbys\\par\\pmartabqr\\pmartabqr"
		$a3 = "{\\shp}"
		$a4 = "\\xmlns1{\\protend{\\xmlclose}\\xmlns2{\\xmlclose}\\xmlns3{\\factoidname#}}"

	condition:
		($a1 at 0) and $a2 and $a3 and $a4

}

rule CVE_2013_1325_1529 
 {
	meta:
		sigid = 1529
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2013-1325"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$hex_string1 = { FF 57 50 43 }
		$hex_string2 = { D2 0B 4A 00 01 00 02 00 00 00 43 00 04 5A 00 00 00 00 00 00 00 00 00 00 00 00 00 33 02 09 1C 00 00 00 00 40 40 01 00 02 00 00 00 43 04 5A 00 5A 00 00 00 00 00 00 00 00 00 00 00 00 00 33 02 09 ?? 00 00 00 00 40 40 00 00 4A 00 0B D2 }
		$hex_string3 = { DC 01 1E 00 03 00 00 88 00 00 00 00 00 00 00 00 03 00 00 88 00 00 00 D5 00 00 00 00 00 00 1E 00 01 DC }
		//$hex_string4 = { D5 00 }

	condition:
		all of them

}

rule CVE_2012_1856:_Exploit_string_1524 
 {
	meta:
		sigid = 1524
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2012-1856: Exploit string"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "CONTROL MSComctlLib.Toolbar.2"
$b = "Toolbar1, 0, 0, MSComctlLib, Toolbar"

	condition:
		all of them

}

rule CVE_2018_15982_118935 
 {
	meta:
		sigid = 118935
		date = "2018-12-11 06:26 AM"
		threatname = "SWF.Exploit.CVE-2018-15982"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
    $str1 = "C:\\WINDOWS\\system32\\cmd.exe /c set path=%ProgramFiles(x86)%\\WinRAR;C:\\Program Files\\WinRAR"
    $str2 = "&& cd /d %"
    $str3 = "dp0 & rar.exe e -o+ -r -inul *.rar scan042.jpg & rar.exe e -o+ -r -inul scan042.jpg backup.exe"
    $cont1 = "ByteArrayAsset"
    $cont2 = "flash.utils"
    $cont3 = "isDebugger"
    $cont4 = ".tvsdk"
    
  
  condition: 
    (uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($cont*)) and (all of ($str*))
}

rule CVE_2015_6091_2159 
 {
	meta:
		sigid = 2159
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-6091"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$fileid = {D0 CF 11 E0 A1 B1 1A E1 }
		$s1 = {10 00 4B 48 00 00 4F 4A 03 00 51 4A 03 00 5E 4A 03 00 61 4A 15 00 70 68 00 00 00 00} 
		$s2 = {2D 15 68 35 07 3B 00 16 68 F8 74 CB 00 42 2A 01 43 4B 12 00 4B 48 00 00 4F 4A 03 00} 
		$s3 = {51 4A 03 00 5E 4A 03 00 61 4A 12 00 70 68 00 00 00 00 03 55 08 01 14 15 68 35 07 3B} 
		$s4 = {00 16 68 35 07 3B 00 43 4A 14 00 4B 48 00 00 00 2D 15 68 35 07 3B 00 16 68 35 07 3B} 
		$s5 = {00 42 2A 01 43 4A 12 00 4B 48 00 00 4F 4A 03 00 51 4A 03 00 5E 4A 03 00 61 4A 12 00} 
		$s6 = {70 68 00 00 00 00 29 15 68 35 07 3B 00 16 68 35 07 3B 00 42 2A 01 4B 48 00 00 4F 4A} 
		$s7 = {03 00 51 4A 03 00 5E 4A 03 00 61 4A 15 00 70 68 00 00 00 00 2B 15 68 35 07 3B 00 16} 
		$s8 = {68 35 07 3B 00 35 08 81 42 2A 01 4B 48 00 00 4F 4A 03 00 51 4A 03 00 5C 08 81 5E 4A}

	condition:
		$fileid at 0 and (all of ($s*))

}

rule VBA_Downloader_kimsuky_122175 
 {
	meta:
		sigid = 122175
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Downloader.kimsuky"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1 = "CreateObject(\"Shell.Application\")"
$str2 = {3D2022[4-16]70[4-16]6F[4-16]77[4-16]65[4-16]72[4-16]73[4-16]68[4-16]65[4-16]6C[4-16]6C[4-16]2E[4-16]65[4-16]78[4-16]65}
$str3 = "Replace("
$str4 = {6F626A5368656C6C2E5368656C6C45786563757465 [36-50] 22222C20226F70656E222C2030}
$str5 = {282768[4-16]74[4-16]74[4-16]70[4-16]3A[4-16]2F[4-16]2F}

condition:
all of ($str*)
}

rule RTF_Exploit_CVE_2017_11882_118213 
 {
	meta:
		sigid = 118213
		date = "2018-05-11 09:29 AM"
		threatname = "RTF_Exploit_CVE-2017-11882"
		category = "Malware & Botnet"
		risk = 100
		hash1= "bb8d9cb340598c84e6f02b6e470e8d48"
hash2= "7fce0138105269ef55ab84dad7eb58df"
	strings:
  $magic= "{\\rtf1"
  $Hex1 = "\\pict\\jpegblip\\picw24\\pich24\\bi"
  $Hex2 = {34333361356334393665373436353663356337343631373336623265363236313734}
  $Hex3 = {353036663737363537323533363836353663366332303232323236363735366536333734363936663665}
  $Hex4 = {33623533373436313732373432643530373236663633363537333733323032373235353434353464353032353563}
  $Hex5 = {3638373437343730336132663266}
  
  
  condition:
   $magic at 0 and (all of ($Hex*))
}

rule VBA_Downloader_Valyria_124782 
 {
	meta:
		sigid = 124782
		date = "2021-12-07 06:02 AM"
		threatname = "VBA.Downloader.Valyria"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "DefaultFilePath("
$str2 = "\".bin"
$str3 = "Documents.Open"
$str4 = "fileName:="
$str5 = "PasswordDocument:="
$str6 = "\"htt"
$str7 = ".d\" & \"oc\""

condition:
all of them
}

rule VBA_Downloader_2662 
 {
	meta:
		sigid = 2662
		date = "2016-12-13 10:54 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={53 75 62 20 00 61 75 74 6F 6F 70 65 6E 00 28 29 0D 0A 43 68 65 63 40 6B  54 61 78 61 20 82 63}
		$a2="stopiccot"
		$a3={73 74 72 46 65 75 69 6C 6C 65 E7 8D 30 00}
		$a4="Plantae"
		$a6={70 72 6F 63 65 73 73 45 6E 76 EE A2 30 00 0A 04 74 65 6D 70 46 6F 6C 64 65 72}
		$a7={73 61 76 65 74 00 6F 66 69 6C 65 20}
		$a8={6A 43 6F 75 6E 74 65 72 62 0E[23]73 74 72 50 55 4C A1 36 30}

	condition:
		(all of them)

}

rule VBA_Downloader_Turla_119980 
 {
	meta:
		sigid = 119980
		date = "2019-09-23 07:47 AM"
		threatname = "VBA.Downloader.Turla"
		category = "Malware & Botnet"
		risk = 0
		BLOG= "https://twitter.com/daphiel/status/1174324244127322115"
	strings:
      $str1 = "PayLoadMac"
      $str2 = "enablmacbat.bat"
      $str3 = "WholeStory"
	  $str4= "\\Microsoft\\Nvstemp\\nvshost.exe"
	  $str5= "https://dsme.info/MicrosoftUpdate.exe"

   condition:
	  all of ($str*)
}

rule VBA_Dropper_Lazarus_123295 
 {
	meta:
		sigid = 123295
		date = "2021-06-11 05:05 AM"
		threatname = "VBA.Dropper.Lazarus"
		category = "Malware & Botnet"
		risk = 0
		
	strings:

$str1 = "Lib \"kernel32.dll\""
$str2 = "CreateObject(\"Wscript.Shell\")"
$str3 = ".Run \"cmd /c"
$str4 = "cmd /c copy /b %systemroot%\\system32\\"
$str5 = "& del"
$str6 = "#If Win64 Then"
$str7 = ".WriteLine"

condition:
all of them
}

rule VBA_Downloader_Agent_123146 
 {
	meta:
		sigid = 123146
		date = "2021-05-18 14:58 PM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "\\\\.\\root\\cimv2"
$str2 = "GetObject(\"winmgmts:\\\\localhost\\root\\"
$str3 = ".execquery(\"select * from antivirusproduct"
$str4 = ".ShellExecute"
$str5 = "CreateObject(\"Shell.Application\")"
$str6 = "CreateObject(\"Schedule.Service\")"
$str7 = "wscript.exe"

condition:
all of them
}

rule VBA_Dropper_TransparentTribe_122970 
 {
	meta:
		sigid = 122970
		date = "2021-04-06 05:27 AM"
		threatname = "VBA.Dropper.TransparentTribe"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"Shell.Application\")"
$str2 = "Environ$(\""
$str3 = ".OperatingSystem"
$str4 = "Split(UserForm"
$str5 = "\".zip\""
$str6 = "Binary Access Write As"

condition:
all of them
}

rule VBA_Downloader_Agent_122904 
 {
	meta:
		sigid = 122904
		date = "2021-03-23 12:31 PM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 50
		
	strings:

$str1 = "Alias \"payload\""
$str2 = ".FolderExists("
$str3 = "ThisWorkbook.path & \"\\\" &"
$str4 = ".CreateFolder"
$str5 = ".Name & \".\" & ext"
$str6 = "Environ("

condition:
all of them
}

rule VBA_Downloader_Macro_121680 
 {
	meta:
		sigid = 121680
		date = "2022-03-02 11:58 AM"
		threatname = "VBA.Downloader.Macro"
		category = "Malware & Botnet"
		risk = 0
		
	
    strings:
        $string = "_Open()"
        $string_1 = "68 74 74 70 3A 2F 2F"
		$string_2 = {4372656174654F626A65637428 [2-50] 28223431203434203466203434203432203265203533203734203732203635203631203664}
		$string_3 = "\"S\" & Chr(10) & \"u\" & Chr(10) & \"m\" & Chr(10) & \"r\" & Chr(10) & \"r\" & Chr(10) & \"y\""
		$string_4 = {2E4F70656E20224722202B20224522202B202254222C [2-10] 46616C7365}
    condition:
         all of them

}

rule VBA_TrojanDownloader_Macro_3553 
 {
	meta:
		sigid = 3553
		date = "2017-02-10 17:28 PM"
		threatname = "VBA_TrojanDownloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = { 54 00 68 00 69 00 73 00 20 00 64 00 6F 00 63 00 75 00 6D 00 65 00 6E 00 74 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 64 00 20 00 69 00 6E 00 20 00 61 00 6E 00 20 00 6F 00 6C 00 64 00 65 00 72 00 20 00 76 00 65 00 72 00 73 00 69 00 6F 00 6E 00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 57 00 6F 00 72 00 64 00 0D 00 }
		$s2 = "yellow bar, and after click" wide
		$s3 = "_VBA_PROJECT" wide
		$s4 = "AutoOpen"
		$s5 = "Normal.ThisDocument" wide

	condition:
		(all of ($s*))

}

rule CVE_2015_1641_2914 
 {
	meta:
		sigid = 2914
		date = "2016-06-22 07:37 AM"
		threatname = "CVE_2015_1641"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic="{\\rt"
		$str1="otkloadr.WRAssembly.1"
		$str2="\\object\\objocx"
		$str3={64 0D 0A 30 0D 0A 63 0D 0A 66 0D 0A 31 0D 0A 31 0D 0A 65 0D 0A}
		$str4="panose 020b0604030504040"
		$str5={68 D6 DC AF 82 44 63 D2 2C EA 5D 2F}

	condition:
		($magic at 0) and (all of ($str*))

}

rule CVE_2016_0018_2360 
 {
	meta:
		sigid = 2360
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0018"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$clsid="{42060D27-CA53-41f5-96E4-B1E8169308A6}" wide ascii nocase

	condition:
		all of them

}

rule VBA_Dropper_HiddenCobra_117841 
 {
	meta:
		sigid = 117841
		date = "2018-04-24 06:41 AM"
		threatname = "VBA_Dropper_HiddenCobra"
		category = "Malware & Botnet"
		risk = 100
		hash = "570cf06399fa0f38e10ec9668283f4b6,1aa7277dad2fc8268c79e8295514aa06,f0de84f439006dba11d9fa0c3c79c783"
	strings:
$s1 = "Windows User"
$s2 = "cmd.exe /c start /b "
$s3 = "Adobe Photoshop CS6 (Windows)"
$s4 = "<rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from application/vnd.adobe.photoshop to image/jpeg\"/>"
$s5 = "B2A56FFFFCFFFFFFFBFFFFFF0000FFFF47FFFFFFFFFFFFFFBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
$s6 = "Cdrbqhoshnm-cnb"
condition:
filesize < 1MB and
all of ($s*)
}

rule VBA_Downloader_Emotet_117398 
 {
	meta:
		sigid = 117398
		date = "2017-11-14 06:19 AM"
		threatname = "VBA_Downloader_Emotet"
		category = "Malware & Botnet"
		risk = 100
		Hash = "fcd76de79819813b631d949b18b1e996"
	strings:
$magic={D0CF11}
$Str1 = "nYSSZjjOFL"
$Str2 = "BOMspfZiQHQ"
$Str3 = "NXfKdwcwzsa"
$Str4 = "FzdPnbwdRHB"
$Str5 = "nYSSZjjOFL"
$Str6 = "wvSUfSmAsdY"
$Str7 = "NXfKdwcwzsa"
$Str8 = "CwUQaEWCaMU"
$Str9 = "mBEhzlliTUz"
$Str10 = "BnONzJBKMw"
$Str11 = "jrmOPrjFiS"
$Str12 = "TbSljHcpGHP"

condition:
($magic at 0) and (all of them)
}

rule CVE_2015_2545_2021 
 {
	meta:
		sigid = 2021
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_2545"
		category = "Malware & Botnet"
		risk = 25
		
	strings:
		$a = "%!PS-Adobe-"
		$b = "%%BoundingBox:"
		$c0 = "9090909090909090"
		$c1 = "4141414141414141"
		$d = "%%EOF"

	condition:
		$a at 0 and $b and ($c0 or $c1) and $d

}

rule VBA_Downloader_Kimsuky_122584 
 {
	meta:
		sigid = 122584
		date = "2021-01-18 07:43 AM"
		threatname = "VBA.Downloader.Kimsuky"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CheckAntiVirusScan("
$str2 = ".ExecQuery(\"Select * from Win32_Service WHERE state = \"\"Running\"\"\")"
$str3 = "GetObject(\"winmgmts:{impersonationLevel=Impersonate}!\\\\\" &"
$str4 = "CreateObject(\"Wscript.shell\")"
$str5 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring"
$str6 = "\" avpui.exe\") > 0 Or InStr(AntiVirusName, \" avp.exe\") > 0"
$str7 = "bdagent.exe"
$str8 = ".Open \"GET\""
$str9 = ".Write WinHttpReq.responseBody"

condition:
all of them
}

rule VBA_Macro_Trojan_DLEXE_3021 
 {
	meta:
		sigid = 3021
		date = "2016-07-04 17:39 PM"
		threatname = "VBA_Macro_Trojan_DLEXE"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
$s1 = "\\VBA\\VBA6\\VBE6.DLL"
$s2 = "NewMacros=22, 29, 1248, 480,"
$s3 = "savetofile"
$s4 = "AutoOpen"
$s5 = "CreateObject"
$s6 = {14 A4 A0 00 67 64 14 45 AD 00 12 00 00 12 64 03}
$s7 = {03 79 3D 00 20 43 68 72 57 28 31 30 90 31 29 20}

	condition:
		($magic at 0) and (all of them)

}

rule VBA_TrojanDownloader_Macro_3820 
 {
	meta:
		sigid = 3820
		date = "2017-05-23 01:42 AM"
		threatname = "VBA_TrojanDownloader_Macro"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "powershell"
		$s2 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::From"
		$s3 = "WScript.Shell"
		$s4 = "schtasks"
		$s5 = "tasks /create /F"
		$s6 = ".vbs"
		$s7 = ".ps1"

	condition:
		$s1 and $s2 and $s3 and ($s4 or $s5) and $s6 and $s7

}

rule VBA_Dropper_PythonRAT_123108 
 {
	meta:
		sigid = 123108
		date = "2021-05-11 07:32 AM"
		threatname = "VBA.Dropper.PythonRAT"
		category = "Malware & Botnet"
		risk = 80
		
	strings:

$str1 = "AutoOpen()"
$str2 = "CreateObject(\"Microsoft.XMLHTTP\")"
$str3 = "CreateObject(\"Adodb.Stream\")"
$str4 = ".Open \"GET\", \"http"
$str5 = ".Send"
$str6 = ".write"
$str7 = ".responseBody"
$str8 = "Shell (\"C:\\Users\\Public\\Downloads\\"
$str9 = ".com\")"

condition:

all of them
}

rule VBA_Downloader_CobaltStrike_123107 
 {
	meta:
		sigid = 123107
		date = "2021-05-11 05:35 AM"
		threatname = "VBA.Downloader.CobaltStrike"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "SW_HIDE"
$str2 = "Lib \"kernel32\" Alias \"CreateProcessA\""
$str3 = "CreateToolhelp32Snapshot Lib \"kernel32.dll\""
$str4 = "Process32Next Lib \"kernel32.dll\""
$str5 = "SELECT ProcessID, name FROM Win32_Process"
$str6 = ":\\\\.\\root\\CIMV2"
$str7 = ".ExecQuery("
$str8 = "iex $"
$str9 = "[System.Convert]::FromBase64String("
$str10 = "AutoOpen()"

condition:
all of them
}

rule CVE_2017_0199_3728 
 {
	meta:
		sigid = 3728
		date = "2017-04-13 18:49 PM"
		threatname = "CVE_2017_0199"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = "{\\rt"
$str1 = "\\mdispDef1\\mlMargin0\\mrMargin0\\mdefJc1\\mwrapIndent1440\\mintLim0\\mnaryLim1}{\\info{"
$str2 = "{\\creatim\\yr2014\\mo11\\dy28\\hr4\\min22}{\\revtim\\yr2016\\mo11\\dy27\\hr22\\min42}{\\version12}{\\edmins1}{\\nofpages1}{\\nofwords128}{\\nofchars1408}"
$str3 = "\\object\\objautlink\\rsltpict"
$str4 = "5c010000e0c9ea79f9bace118c8200aa004ba90b44010" 
$str5 = "d0cf11e0a1b11ae10"

	condition:
		($magic at 0) and (all of ($str*))

}

rule RTF_Exploit_CVE_2017_11882_119794 
 {
	meta:
		sigid = 119794
		date = "2019-07-31 12:17 PM"
		threatname = "RTF.Exploit.CVE-2017-11882"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
  $magic= "{\\rtf1"
  $str1 = "Microsoft Equation 3.0"
  $str2 = "Cmd /c powershell.exe -ExecutionPolicy bypass -noprofile -windowstyle hidden (New-Object System.Net.WebClient).DownloadFile('http"
  $str3 = ";Start-Process"
  $str4 = ".exe"
  
  condition:
   $magic at 0 and (all of ($str*))
}

rule VBA_Downloader_Gen_123800 
 {
	meta:
		sigid = 123800
		date = "2021-08-12 10:48 AM"
		threatname = "VBA.Downloader.Gen"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "autoopeN()"  nocase
$str2 = "For Output As #1"
$str3 = "Print #1"
$str4 = "Replace("
$str5 = "Close #1"
$str6 = ".WshShell"
$str7 = ".exec"
$str8 = ".exe "

condition:
all of them
}

rule VBA_Downloader_AggahAPT_123795 
 {
	meta:
		sigid = 123795
		date = "2021-08-12 09:53 AM"
		threatname = "VBA.Downloader.AggahAPT"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "Auto_Close()"
$str2 = "GetObject(\""
$str3 = "\"n\" + \"e\" + \"w\" +"
$str4 = "Microsoft Office not Installed"
$str5 = ".EXEC"
$str6 = "mshta"
$str7 = ".CreateObject(\"Shell.Application\")"

condition:
all of them
}

rule VBA_Downloader_2857 
 {
	meta:
		sigid = 2857
		date = "2016-12-13 10:51 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1={45 6E 76 69 72 00 6F 6E 28[12]26 20 00 22 5C 75 74 32 72 30 4F E0 67 2E 74 6D}
		$a2={4E 31 75 68 64 6B 70 06 3A}
		$a3="Tr5Hlyhp7"
		$a4={73 76 6E 68 6F 73 74 2E 65 78 65}
		$a5={2F 73 79 73 74 65 6D 2F 6C 6F 67 73 2F}

	condition:
		(all of them)

}

rule VBA_Downloader_Gamaredon_123563 
 {
	meta:
		sigid = 123563
		date = "2021-07-12 11:44 AM"
		threatname = "VBA.Downloader.Gamaredon"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "CreateObject(\"Scripting.FileSystemObject\")"
$str2 = "Environ("
$str3 = "PSBDcmVhdGVPYmplY3QoIldTY3JpcHQuU2hlbGwiKS5FeHBhbmRFbnZpcm9"
$str4 = "TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgNi4xOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWt"
$str5 = "Email:"
$str6 = "Password:"

condition:
all of them
}

rule VBA_Downloader_2902 
 {
	meta:
		sigid = 2902
		date = "2016-06-10 06:21 AM"
		threatname = "VBA_Downloader"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={D0 CF 11 E0}
		$a1={75 74 66 00 55 59 47 48 62 61 73 64 40 64 64 63 22}
		$a3="yahsiudgbjnxj"
		$a4="aFOPNSwDivuKNQIc60"

	condition:
		($magic at 0) and (all of them)

}

rule VBA_Dropper_APT40_123613 
 {
	meta:
		sigid = 123613
		date = "2022-03-02 11:59 AM"
		threatname = "VBA.Dropper.APT40"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "_Open()" nocase 
$str2 = "Environ(\"TEMP\")" nocase
$str3 = "Base64ToFile(" nocase
$str4 = ".ShellExecute(" nocase
$str5 = "WriteTextFile(" nocase
$str6 = "CreateObject(\"WScript.Shell\")" nocase
$str7 = ".Run(\"regsvr32" nocase
$str8 = "Shell.Application" nocase
$str9 = ".dll" nocase

condition:
all of them
}

rule VBA_Downloader_Agent_123593 
 {
	meta:
		sigid = 123593
		date = "2021-07-16 05:44 AM"
		threatname = "VBA.Downloader.Agent"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "WorkBook_Open()"
$str2 = "ActiveWorkbook.Sheets(\"Sheet1\")."
$str3 = "CreateObject(\"Scripting.FileSystemObject\")"
$str4 = ".Write"
$str5 = "CreateObject(\"Wscript.Shell\")"
$str6 = ".Exec (\"mshta"
$str7 = "Environ(\"ALLUSERSPROFILE\")"

condition:
all of them
}

