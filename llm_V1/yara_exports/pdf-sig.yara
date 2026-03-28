rule PDF_Exploit_CVE_2020_6116_124657 
 {
	meta:
		sigid = 124657
		date = "2021-11-22 22:22 PM"
		threatname = "PDF.Exploit.CVE-2020-6116"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$header = "%PDF-"
$str1= "/Type /Pages"
$str2= "<</ColorSpace"
$str3= "<</CS1"
$str4= {2F436F6E74656E7473205B??203020525D}
$str5= /\/N [0-9]{6}/
condition:
$header at 0 and all of ($str*)
}

rule CVE_2016_1007_2521 
 {
	meta:
		sigid = 2521
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_1007"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = ".addAnnot("
$a1 = "popupRect:"
$a2 = "popupOpen: true"
$a3 = ".length=0x4FFF00;"
$a4 = ".setTimeOut("
$a5 = ".setProps({style:"

	condition:
		all of them

}

rule CVE_2016_6945_3324 
 {
	meta:
		sigid = 3324
		date = "2016-10-11 23:30 PM"
		threatname = "CVE-2016-6945"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const0 = "/Type /Action"
		$const1 = "/JS" ascii
		$code0 = "this.setAction('WillSave','app.execMenuItem(\"SaveAs\");');" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x312E and uint8(8) == 0x0D) and (all of ($const*)) and (all of ($code*))

}

rule CVE_2016_6970_RecursiveJavaScriptEval_3322 
 {
	meta:
		sigid = 3322
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6970_RecursiveJavaScriptEval"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/JS" ascii
		$code0 = "var q;"
		$code1 = "eval(q=\"try{eval(q)}catch(e){eval(q)}\");"
		//\"try{eval(q)}catch(e){eval(q)}\");"

	condition:
		// 25 50 44 46 2D 31 2E 36 0A
		 (uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x362E and uint8(8) == 0x0A) and (all of ($code*)) and (all of ($const*))

}

rule CVE_2016_6947_XFAFormModelMemCor_3318 
 {
	meta:
		sigid = 3318
		date = "2016-10-11 23:30 PM"
		threatname = "CVE-2016-6947-XFAFormModelMemCor"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const0 = "/AcroForm" ascii
		$const1 = "/OpenAction" ascii
		$const2 = "/JS" ascii
		$code0 = "xfa.isPropertySpecified" ascii
		$code1 = "xfa.resolveNode\\(\"xfa.form.form1.sf.#border[0].#fill[0].#color[0]\"\\).value = \"1\";" ascii
		$code2 = "xfa.form.resolveNode\\(\"xfa.form.form1.#pageSet.page1[0].#subform[0].bc[0].#value[0]\"\\).oneOfChild = xfa.resolveNode\\(\"xfa.template.form1.fld.items.t1\"\\);" ascii
		$code3 = "xfa.layout.relayoutPageArea\\(0\\);" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0D) and (all of ($const*)) and (all of ($code*)) and #code0 == 2

}

rule CVE_2016_6969_XSLSortElemUAF_3321 
 {
	meta:
		sigid = 3321
		date = "2016-10-11 23:30 PM"
		threatname = "CVE-2016-6969-XSLSortElemUAF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:for-each select=\\\"a\\\">\x09\x09\x09<xsl:sort select=\\\"(/)/*[a()]\\\"/>\x09\x09</xsl:for-each>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2016_6951_3338 
 {
	meta:
		sigid = 3338
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6951"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/AcroForm" ascii 
		$const1 = "/JS" ascii		
		
		$code0 = "o = xfa.resolveNode\\(\"xfa.template.outerform.sf1\"\\);" ascii
		$code1 = "o2 = xfa.resolveNode\\(\"xfa.form.outerform.sf2[0].sf3[0]\"\\);" ascii 
		$code2 = "o.nodes.append\\(o2\\);" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0D)
		and (all of ($const*))
		and (all of ($code*))

}

rule CVE_2016_6959_3336 
 {
	meta:
		sigid = 3336
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6959"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
        $xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:number value=\\\"substring-after(.)\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0A)
		and (all of ($const*))
		and (all of ($xsl*))

}

rule CVE_2016_6962_3335 
 {
	meta:
		sigid = 3335
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6962"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		        $xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:choose>\x09\x09\x09<xsl:when test=\\\"(/)/*[a()]\\\">\x09\x09\x09</xsl:when>\x09\x09</xsl:choose>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0A)
		and (all of ($const*))
		and (all of ($xsl*))

}

rule CVE_2016_1055_2749 
 {
	meta:
		sigid = 2749
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1055"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "function(){app.alert(1);app.execMenuItem(\"Close\");"
$a1 = "this.setAction("
$a2 = "initialize: function(dialog)"
$a3 = "commit: function(dialog)"
$a4 = "getNumPets: function (results)"
$a5 = "ok: function(dialog)"
$a6 = "ckbx: function (dialog)"
$a7 = "cancel: function(dialog)"
$a8 = "other: function(dialog)"
$a9 = "app.execDialog(dialog"

	condition:
		all of them

}

rule CVE_2016_1049_2756 
 {
	meta:
		sigid = 2756
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1049"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a1 = "<</AcroForm 33 0 R/Extensions<</ADBE<</BaseVersion/1.7/ExtensionLevel 8>>>>/Metadata 12 0 R/Names 34 0 R/Outlines 16 0 R/Pages 21 0 R/Type/Catalog>>"

	condition:
		all of them

}

rule CVE_2015_4438_1945 
 {
	meta:
		sigid = 1945
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-4438"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a= "this.identity.__defineGetter__("
$b= "app.launchURL("
$c= "this.ANSendForReview("
$d= "getColumn"
$e= "nextRow"
$f = "this.closeDoc("
$g = "new app.doc."
$h = ".next.call"

	condition:
		all of them

}

rule CVE_2015_4435_1944 
 {
	meta:
		sigid = 1944
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-4435"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a= "this.identity.__defineGetter__("
$b= "app.launchURL("
$c= "this.ANStartApproval("
$d= "getColumn"
$e= "nextRow"
$f = "this.closeDoc("
$g = "new app.doc."
$h = ".next.call"

	condition:
		all of them

}

rule CVE_2015_4441_1942 
 {
	meta:
		sigid = 1942
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_4441"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "/Type /Action"
		$str2 = "/S /JavaScript"
		$str3 = "this.identity.__defineGetter__"
		$str4 = "app.launchURL"
		$str5 = "this.CBBBRInvite"

	condition:
		all of them

}

rule CVE_2015_5089_1939 
 {
	meta:
		sigid = 1939
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5089"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "<?xml version=\"1.0\" ?>"
$a1 = "<!DOCTYPE "
$a2 = "[ <!ENTITY "
$a3 = "SYSTEM \"http://"
$a4 = "\">]><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\">"
$a5 = "></xsl:template></xsl:stylesheet>';"
$a6 = "XMLData.parse("
$a7 = ".applyXSL("

	condition:
		all of them

}

rule CVE_2018_4946_118175 
 {
	meta:
		sigid = 118175
		date = "2018-05-14 19:23 PM"
		threatname = "CVE-2018-4946"
		category = "Malware & Botnet"
		risk = 100
		Description = "Rule to detect a crafted JavaScript code in a PDF." 
Date = "03/23/2018" 
Distribution = "Microsoft MAPP Program Only" 
	strings: 
$const0 = /\/Type[\t\n\r\s]*\/Action[\t\n\r\s]*\/S[\t\n\r\s]*\/JavaScript[\t\n\r\s]*\/JS/ 
$js0 = "this.Net.Discovery.queryServices( \"\", {} ); " ascii 

condition: 

(uint16(0) == 0x5025 and uint16(2) == 0x4644) 
and (all of ($const*)) 
and (all of ($js*)) 
}

rule CVE_2018_4983_118119 
 {
	meta:
		sigid = 118119
		date = "2018-05-14 19:25 PM"
		threatname = "CVE-2018-4983"
		category = "Malware & Botnet"
		risk = 40
		Description = "Rule to detect a crafted JavaScript code in a PDF." 
Disclaimer = "This rule is provided for informational purposes only." 
Author = "Adobe PSIRT" Date = "03/26/2018"
 Distribution = "Microsoft MAPP Program Only" Revision = 1 
	strings: 
$const0 = /\/S[\t\n\r\s]*\/JavaScript[\t\n\r\s]*\/JS/ 
$const1 = /\d+ 0 obj <<\/Type \/Catalog \/Pages \d+ 0 R \/AcroForm 4 0 R \/OpenAction \d+ 0 R>>/ 
$const2 = /\d+ 0 obj <<\/FT \/Ch \/T \(\w+\) \/Subtype \/Widget \/Rect \[\d+ \d+ \d+ \d+\] \/AA <<\/Fo \d+ 0 R>> >>/ 
$js0 = /this\.getField\("\w+"\)\.setFocus\(\)/ 
$js1 = /app\.execMenuItem\("GeneralPrefs"\)/ 
condition: 
(all of ($const*)) and (all of ($js*))
}

rule App_Exploit_CVE_2017_10953_126504 
 {
	meta:
		sigid = 126504
		date = "2022-10-14 05:24 AM"
		threatname = "App.Exploit.CVE-2017-10953"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		  $s1 = "%PDF-"
          $s2 = "xfa.host.gotoURL"
          $s3 = /gotoURL\(\x22((http|https|ftp|smb):\x2f\x2f|\x5c\x5c)/i    
    condition: 
          $s1 at 0  and $s2 and not $s3
}

rule PDF_Exploit_CVE_2020_6092_124651 
 {
	meta:
		sigid = 124651
		date = "2022-03-02 11:59 AM"
		threatname = "PDF.Exploit.CVE-2020-6092"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$header = "%PDF-"
$str1= "<< /Type /Pattern"
$str2= /\/BBox \[[0-9]{10}/
$str3= "<< /ColorSpace"
$str4= "<< /Cs12"
$str5= "/DeviceRGB"
condition:
$header at 0 and all of ($str*)
}

rule PDF_Exploit_CVE_2010_1297_124351 
 {
	meta:
		sigid = 124351
		date = "2022-03-02 11:59 AM"
		threatname = "PDF.Exploit.CVE-2010-1297"
		category = "Malware & Botnet"
		risk = 99
		
	strings:
$header = "%PDF-"
$str1 = "/Fl#61teDe#63#6f#64#65/#41#53#43#49IH#65xD#65c#6f#64#65"
$str2 = ".swf)>>"
$str3 = ".s#77f)>>"
$str4 = "/Su#62#74#79#70e/#46#6cash/#49#6esta#6ec#65#73"
$str5 = "/#45#6d#62#65#64#64#65dFile/"
    condition:
        $header at 0 and all of ($str*)
}

rule CVE_2015_5100_1837 
 {
	meta:
		sigid = 1837
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5100"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "app.doc.getAnnots3D"
		$a1 = "MouseEventHandler();"
		$a2 = "onMouseOver"
		$a3 = "onEvent"
		$a4 = "function(){app.doc.closeDoc(true);};"
		$a5 = "runtime"
		$a6 = "addEventHandler"

	condition:
		all of them

}

rule PDF_Exploit_CVE_2010_1297_124309 
 {
	meta:
		sigid = 124309
		date = "2022-03-02 11:59 AM"
		threatname = "PDF.Exploit.CVE-2010-1297"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$header="%PDF-"
$str1="/Type /Filespec"
$str2=".swf) >>"
$str3="/FlashVars () /Settings 16 0 R >>"
$str4="<< /Type /Action /S /JavaScript /JS"
$str5="unescape(\"%u"
$str6="while ("
$str7=".length"
$str8=".substring("
$str9="new Array();"
condition:
$header at 0 and all of ($str*)
}

rule CVE_2015_5101_1851 
 {
	meta:
		sigid = 1851
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5101"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a0 = "app.doc.getAnnots3D(0)[0].activated=true;"
		$a1 = "=app.doc.getAnnots3D(0)[0].context3D;"
		$a2 = ".SelectionEventHandler();"
		$a3 = ".selected=true;"
		$a4 = ".onEvent=function(){app.doc.closeDoc(true);};"
		$a5 = ".runtime;"
		$a6 = ".addEventHandler("

	condition:
		all of them

}

rule CVE_2015_5094_1842 
 {
	meta:
		sigid = 1842
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5094"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$string1 = "app.doc.getAnnots3D(0)[0].activated=true"
		$string2 = ".context3D"
		$string3 = ".ToolEventHandler()"
		$string4 = ".selected=true"
		$string5 = ".onEvent=function(){app.doc.closeDoc(true);}"
		$string6 = ".addEventHandler("

	condition:
		all of them

}

rule CVE_2016_1068_2780 
 {
	meta:
		sigid = 2780
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1068"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = "%PDF-"
$str1 = "/JS (console.show();"
$str2 = "var _text = this.addField(\"t\",\"text\",0,["
$str3 = "_text.setAction(\"Validate\",\"app.execMenuItem('Close')\");"
$str4 = "this.setAction('WillClose','_text.value=1;');)"

	condition:
		($magic at 0) and (all of ($str*))

}

rule CVE_2016_1041_2761 
 {
	meta:
		sigid = 2761
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1041"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "app"
		$string2 = ".execDialog"
		$string3 = ".__defineGetter__"
		$string4 = ".bind"
		$string5 = "proxy"
		$string6 = "ANAuthenticateResource"
		$string7 = "false"
		$string8 = "get"
		$string9 = "return"
		$string10 = "privileged"

	condition:
		all of them

}

rule CVE_2016_1045_2759 
 {
	meta:
		sigid = 2759
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1045"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "app"
		$string2 = "new Array()"
		$string3 = "while"
		$string4 = ".length"
		$string5 = "util."
		$string6 = ".substr"
		$string7 = ".instanceManager.setInstances"
		$string8 = "instanceManager.moveInstance"

	condition:
		all of them

}

rule CVE_2016_1083_2739 
 {
	meta:
		sigid = 2739
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1083"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "app"
		$string2 = "execAVDialog("
		$string3 = "return"
		$string4 = "toString "
		$string5 = "popUpMenuEx"
		$string6 = "ansyc_free"

	condition:
		all of them

}

rule CVE_2016_1088_2738 
 {
	meta:
		sigid = 2738
		date = "2016-05-12 13:41 PM"
		threatname = "CVE-2016-1088"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$string1 = "<</Subtype/Image/Length 19078"
		$string2 = "/Filter[/FlateDecode]/Name/"
		$string3 = "SMask 111"
		$string4 = "R/BitsPerComponent 8/ColorSpace/DeviceRGB/"
		$string5 = "DecodeParms["
		$string6 = "/Type/XObject>>"

	condition:
		all of them

}

rule CVE_2016_1061_2724 
 {
	meta:
		sigid = 2724
		date = "2016-05-12 13:41 PM"
		threatname = "CVE-2016-1061"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s1 = "global.__defineGetter__("
$s2 = "global.setPersistent("
$s3 = "delete global."

	condition:
		all of them and #s3>4

}

rule CVE_2016_1037_2721 
 {
	meta:
		sigid = 2721
		date = "2016-05-12 13:41 PM"
		threatname = "CVE-2016-1037"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s1 = "<</XObject <</"
		$s2 = "/Contents (3D Object \\(model/u3d\\))"
		$s3 = "/AP <</N 40 0 R"
		$s4 = "/NM (animace)"
		$s5 = "/3DD 41 0 R"
		$s6 = "/Subtype /3D"
		$s7 = "<</VA ["
		$s8 = "/AN <</Subtype /Linear"
		$s9 = "/Subtype /U3D"
		$s10 = "/Length 42 0 R"
		$s11 = ">>stream"

	condition:
		all of them

}

rule PDF_Exploit_CVE_2021_21042_122721 
 {
	meta:
		sigid = 122721
		date = "2022-03-02 11:59 AM"
		threatname = "PDF.Exploit.CVE-2021-21042"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1="Collab.documentToStream(this)"
$str2="stream.read("
$str3="String.fromCharCode("
$str4="new RegExp(\"/ID\\\\[<([0-9A-F]+)>\")"
$str5=".match("
$str6=".substring("
condition:
all of ($str*)
}

rule PDF_Exploit_CVE_2020_3747_120556 
 {
	meta:
		sigid = 120556
		date = "2020-02-11 10:06 AM"
		threatname = "PDF.Exploit.CVE-2020-3747"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "xmlDoc ="
$str2 = "XMLData.parse(xmlDoc,"
$str3 = "applyXSL(xslDoc)"
$str4 = "println(oNode)"

condition:
($str1) and ($str2) and ($str3) and ($str4)
}

rule PDF_Exploit_CVE_2019_7024_119206 
 {
	meta:
		sigid = 119206
		date = "2019-02-12 10:35 AM"
		threatname = "PDF.Exploit.CVE-2019-7024"
		category = "Malware & Botnet"
		risk = 93
		
	strings:
$str1="<exclGroup w="
$str2="value  relevant="
$str3="C7cQxqCnvXoXwDXAi61x38cDvM2cLuiRQ1Yn2aEGPrwaF351qDyQiauuZUnTCQhB4"
$str4="hyphenation hyphenate="
$str5="<destination>pdf</destination>"
$str6="</xdp:xdp>"
$str7="/NeedsRendering"

condition:
all of ($str*)
}

rule PDF_Exploit_CVE_2019_7050_119202 
 {
	meta:
		sigid = 119202
		date = "2019-02-12 10:22 AM"
		threatname = "PDF.Exploit.CVE-2019-7050"
		category = "Malware & Botnet"
		risk = 100
		md5= "d049f2f42241daf903aea01251fb8d17"
	strings: 
	$head = "%PDF-"
	$Str1 = "xfa.form.name = 'c'"
	$Str2 = "v8.id = '/12312*123$123$#12312fwfeds/';"
	$Str3 = "v15.id = 'g'"
	$Str4 = "v2.assignNode('e', 'paloalto', 1)"
	$Str5 = "xfa.layout.name = 'a';"
	$Str6 = "v2.id = 'Password';"
	$Str7 = "v2.id = 'guymqwe';"
	$Str8 = "v9.saveXML('pretty');" 
	$Str9 = "v7.id = 'A'*10000000;"
	
condition: 
$head at 0 and all of them
}

rule _CVE_2017_11263_116818 
 {
	meta:
		sigid = 116818
		date = "2017-08-08 11:29 AM"
		threatname = " CVE-2017-11263"
		category = "Malware & Botnet"
		risk = 0
		Description = "Rule to detect encoding definitions that trigger a memory corruption vulnerability in the internal data structure manipulation." 
Disclaimer = "This rule is provided for informational purposes only."
Author = "Adobe PSIRT" 
Date = "07/17/2017" 
Distribution = "Microsoft MAPP Program Only" 
Revision = 1 
	strings:
   $const0 = /\/DR[\t\n\r\s]*<<[\t\n\r\s]*\/Encoding[\t\n\r\s]*<<[\t\n\r\s]*\/PDFDocEncoding[\t\n\r\s]*\d{1,2} 0 R[\t\n\r\s]*>>[\t\n\r\s]*>>/
   $const1 = /\/Type[\t\n\r\s]*\/Encoding[\t\n\r\s]*\/BaseEncoding[\t\n\r\s]*\/WinAnsiEncoding[\t\n\r\s]*\/Differences[\t\n\r\s]*[ -\d{5,10}[\t\n\r\s]*\/a[\t\n\r\s]*]/
   // $code0 = "" ascii

condition: 
   (uint16(0) == 0x5025 and uint16(2) == 0x4644)
   and (all of ($const*))    

}

rule PDF_Phishing_Redirector_116849 
 {
	meta:
		sigid = 116849
		date = "2017-08-09 10:19 AM"
		threatname = "PDF.Phishing.Redirector"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1="/Type /Action"
$str2="/URI (http:"
$str3="/ /ow.ly"
$str4="/Rect ["
$str5="/Subtype /Link"
condition:
all of them
}

rule CVE_2016_6946_3303 
 {
	meta:
		sigid = 3303
		date = "2016-12-13 08:21 AM"
		threatname = "CVE_2016_6946"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/AcroForm" ascii
		$const1 = "/OpenAction" ascii
		$const2 = "/JS" ascii
		
		$code0 = "o1 = xfa.resolveNode\\(\"xfa[0].form[0].Formular1[0].draw\"\\);" ascii
		$code1 = "o2 = xfa.resolveNode\\(\"xfa[0].form[0].Formular1[0].fld3.#items[0].#text[0]\"\\);" ascii
		$code2 = "o3 = xfa.resolveNode\\(\"xfa[0].form[0].Formular1[0].fld2.#validate[0]\"\\);" ascii
		$code3 = "o1.x = 'X';"
		$code4 = "o2.maxChars = '1';"
		$code5 = "s = \"X\";\\nwhile\\(s.length < 32768\\) s+=s;"
		$code6 = "o3.assignNode\\('xfa[0].form[0].Formular1[0].fld.#value[0].#text[0]', s, '0'\\);"
		$code7 = "xfa.layout.relayout\\(\\);"

	condition:
		// 25 50 44 46 2D 31 2E 37 0D 
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0D)
		and (all of ($const*))
		and (all of ($code*))

}

rule CVE_2016_6978_XSLValueOfMemCor_3316 
 {
	meta:
		sigid = 3316
		date = "2016-10-11 23:30 PM"
		threatname = "CVE-2016-6978-XSLValueOfMemCor"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:value-of select=\\\"substring-after(.)\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2016_6965_JPEG2KMemCrash_3314 
 {
	meta:
		sigid = 3314
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6965_JPEG2KMemCrash"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Subtype/Image/" ascii
		$const2 = "/Filter/JPXDecode"
		$stream0 = {6A 50 20 20 0D 0A} 
		$stream1 = {FF 52 00 0C 00 01 00 01 01 0D 04 04 00 00}

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x352E and uint8(8) == 0x0A)
		and (all of ($const*)) and (all of ($stream*))

}

rule CVE_2016_1089_3311 
 {
	meta:
		sigid = 3311
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_1089"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Extends 11516"
		$const1 = "11516 0 obj"
		$const2 = "11716 0 obj"

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0D) and $const0 and not $const1 and $const2

}

rule CVE_2016_6975_XSLCopyOfElemMemCorruption_3309 
 {
	meta:
		sigid = 3309
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6975_XSLCopyOfElemMemCorruption"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:copy-of select=\\\"substring-after(.)\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2016_6952_3294 
 {
	meta:
		sigid = 3294
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6952"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/AcroForm" ascii 
		$const1 = "/JS" ascii
		// \nxfa.host.openList\(o\);\n)
		$code0 = "xfa.layout.relayoutPageArea\\(0\\);" ascii
		$code1 = "xfa.resolveNode\\(\"xfa.form.form1.#pageSet[0].p1.fld1.#ui[0].#choiceList[0]\"\\).textEntry = '0';" ascii
		$code2 = "o = xfa.resolveNode\\(\"xfa.form.form1.#pageSet[0].p1.fld2\"\\);" ascii
		$code3 = "xfa.host.openList\\(o\\);" ascii
		$code4 = "o = xfa.resolveNode\\(\"xfa.form.form1.#pageSet[0].p1.fld0\"\\);" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0D)
		and (all of ($const*))
		and (all of ($code*))
		and #code3 == 2

}

rule CVE_2016_6968_XSLKeyElemUAF_3319 
 {
	meta:
		sigid = 3319
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6968_XSLKeyElemUAF"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:key name=\\\"x\\\" match=\\\"/\\\" use=\\\"(/)/*[a()]\\\"/></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2016_6976_XSLVariableElemMemCor_3296 
 {
	meta:
		sigid = 3296
		date = "2016-10-25 08:28 AM"
		threatname = "CVE_2016_6976_XSLVariableElemMemCor"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:variable name=\\\"x\\\" select=\\\"substring-after(.)\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0A)
		and (all of ($const*))
		and (all of ($xsl*))

}

rule CVE_2016_3319_3180 
 {
	meta:
		sigid = 3180
		date = "2016-08-10 02:32 AM"
		threatname = "CVE_2016_3319"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "/MediaBox[0.0 0.0 400 300]"
$s2 = "/XObject <<"
$s3 = "/ProcSet[/PDF/ImageC]"
$s4 = "Qendstream"
$s5 = "/Filter [ /JPXDecode ]"
$s6 = "/Subtype /Image"
$s7 = {0C 6A 50 20 20 0D 0A 87 0A 00 00 00 1C 66 74 79 70 6A 70 32 20 00 00 00 00 6A}
$s8 = {70 32 20 6A 70 78 62 6A 70 78 20 00 00 00 1E 72 72 65 71 01 F8 F8 00 05 00 01 80 00 05 40 00 0C}
$s9 = {04 07 01 01 07 01 01 07 01 01 07 01 01 FF 52}

	condition:
		all of them

}

rule CVE_2015_3062_1709 
 {
	meta:
		sigid = 1709
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3062"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "script" nocase
		$a1 = "function"
		$a2 = "launchURL"
		$a3 = "eval"
		$a4 = "app.__proto__"
		$a5 = "AFExactMatch"
		$a6 = "ANVerifyComments"

	condition:
		all of them

}

rule CVE_2015_3072_1706 
 {
	meta:
		sigid = 1706
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3072"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = "/JavaScript"
		$a2 = "console.println("
		$a3 = "app.launchURL"
		$a4 = "Collab.__proto__"
		$a5 = "try {"
		$a6 = "ANRunSharedReviewEmailStep("
		$a7 = "app.alert(\"error: \" + e)"
		$a8 = "connect(this.parent.desc,"
		$a9 = ".execute(\"select"
		$a10 = ".nextRow("
		$a11 = "{debugExcept(e)"
		$a12 = ".toString()"
		$a13 = ".call("

	condition:
		all of them

}

rule CVE_2016_4195_3087 
 {
	meta:
		sigid = 3087
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4195"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1="\"<a/> \""
		$s2="<xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" version=\"1.0\">"
		$s3="<xsl:template match=\"/\">"
		$s4="<xsl:choose>"
		$s5="<xsl:when test=\"A[0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9]\">"
		$s6="</xsl:when>"
		$s7="</xsl:choose>"
		$s8="</xsl:template>"
		$s9="</xsl:stylesheet>"

	condition:
		all of them

}

rule CVE_2016_4198_3078 
 {
	meta:
		sigid = 3078
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4198"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "console.println("
		$a1 = "eval("
		$a2 = "xmlDoc = \"<a/> \";"
		$a3 = "xslDoc = \"<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">"
		$a4 = "<xsl:template match=\\\"/\\\">"
		$a5 = "<xsl:value-of select=\\\"A[0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9]\\\"/>"
		$a6 = "</xsl:template></xsl:stylesheet>\";"
		$a7 = "try {"
		$a8 = ".println(xmlDoc)"
		$a9 = ".alert("
		$a10 = "catch(e)"

	condition:
		all of them

}

rule CVE_2015_3058_1703 
 {
	meta:
		sigid = 1703
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3058"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "cript"
		$a1 = "spell.customDictionaryCreate("
		$a2 = "spell.customDictionaryExport(\"\",\"\")"

	condition:
		all of them

}

rule CVE_2016_1056_2788 
 {
	meta:
		sigid = 2788
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1056"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "var c3d=app.doc.getAnnots3D(0)[0].context3D;"
$a1 = "runtime=c3d.runtime;"
$a2 = "var hRenderEventHandler=c3d.RenderEventHandler();"
$a3 = "hRenderEventHandler.onEvent="
$a4 = "function(){app.execMenuItem('Close');};"
$a5 = "runtime.addEventHandler(hRenderEventHandler);"

	condition:
		all of them

}

rule CVE_2016_1079_2770 
 {
	meta:
		sigid = 2770
		date = "2016-05-12 05:19 AM"
		threatname = "CVE_2016_1079"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={25 50 44 46 2D}
		$a1="app.addToolButton({cName:"
		$a2="cExec: \"try{app.alert(1);"
		$a3="catch(e){var addr='';var i = 59; while(e.extMessage[i] != 'm')"
		$a4="app.alert('Leaked Address: 0x'+addr);"
		$a5="cTooltext: \"Push Me!\",cEnable: true,nPos: 0}"

	condition:
		($magic at 0) and (all of them)

}

rule CVE_2016_1042_2769 
 {
	meta:
		sigid = 2769
		date = "2016-05-12 05:19 AM"
		threatname = "CVE_2016_1042"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={25 50 44 46 2D}
		$str0 = "/S /JavaScript"
		$str1 = "/JS (function exploit()"
		$str2 = "proxy = new Proxy(app,"
		$str3 = "return k.bind(app, proxy)"
		$str4 = "ANProxyAuthenticateResource();"
		$str5 = "return exploit.toString() + \"exploit();"

	condition:
		($magic at 0) and (all of them)

}

rule CVE_2016_1092_2786 
 {
	meta:
		sigid = 2786
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1092"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = "/S /JavaScript"
		$a1 = "var gc = new Array(10000);"
		$a2 = "gc[gc.length - 1] = 1;"
		$a3 = "function trigger_gc(amount, length) {"
		$a4 = "for(var i=0; i < amount; i++) gc.push(s.substr(0, length).sup());"
		$a5 = "var targetchar = unescape(\"%u1010\");"
		$a6 = "var spray_arr = allocs(0xc690, 5000, targetchar);"
		$a7 = "for(var x=0; x < 132; x++) { subform_arr1.push(xfa.template.createNode(\"subform\")); }"
		$a8 = "res = \"[!] vtable: 0x\" + vtable.toString(16) + \", AcroForm.api @ 0x\" + (vtable - 0x7ec74c).toString(16)"

	condition:
		all of them

}

rule CVE_2016_1081_2785 
 {
	meta:
		sigid = 2785
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1081"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "/S /JavaScript"
		$a1 = "var obj = app;"
		$a2 = "function toString_0() {"
		$a3 = "obj.exportFiles(true);"
		$a4 = "return \"test\";"
		$a5 = "var ansyc_free = {"
		$a6 = "toString : toString_0"
		$a7 = "obj.popUpMenuEx(ansyc_free);"

	condition:
		all of them

}

rule CVE_2016_1040_2773 
 {
	meta:
		sigid = 2773
		date = "2016-05-12 05:19 AM"
		threatname = "CVE_2016_1040"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={25 50 44 46 2D}
		$str0 = "/S /JavaScript"
		$str1 = "/JS (function exploit()"
		$str2 = "proxy = new Proxy(app,"
		$str3 = "return k.bind(app, proxy)"
		$str4 = "Net.HTTP.runTaskSet({});"
		$str5 = "return exploit.toString() + \"exploit();"

	condition:
		($magic at 0) and (all of them)

}

rule CVE_2016_1054_2772 
 {
	meta:
		sigid = 2772
		date = "2016-05-12 05:19 AM"
		threatname = "CVE_2016_1054"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic="%PDF"
		$str1="JavaScript"
		$str2="JS"
		$str3="this.addWatermarkFromText"
		$str4="this.getOCGs"
		$str5="setAction"
		$str6="app.execMenuItem"
		$str7="WillSave"
		$str8="[0].state=false"

	condition:
		($magic at 0) and (all of ($str*))

}

rule CVE_2016_1069_2798 
 {
	meta:
		sigid = 2798
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1069"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1 = "this.addField("
		$a2 = ".setAction(\"Calculate\",\"app.execMenuItem('Close')\");"
		$a3 = ".editable=true;"
		$a4 = ".setAction('WillClose','combo.value=[[1]];');)"

	condition:
		all of them

}

rule CVE_2016_1050_2797 
 {
	meta:
		sigid = 2797
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1050"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1 = "(this.setPageAction(0,\"Close\",\"app.execMenuItem('Close')\");"

	condition:
		all of them

}

rule CVE_2016_1067_2795 
 {
	meta:
		sigid = 2795
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1067"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "this"
		$string2 = ".addField"
		$string3 = "combobox"
		$string4 = "setAction"
		$string5 = "Format"
		$string6 = "app"
		$string7 = ".execMenuItem"
		$string8 = "Close"
		$string9 = ".editable"
		$string10 = "true"
		$string11 = "WillClose"

	condition:
		all of them

}

rule CVE_2016_1052_2794 
 {
	meta:
		sigid = 2794
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1052"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "this"
		$string2 = ".addField"
		$string3 = "button"
		$string4 = "new Array()"
		$string5 = ".__defineGetter__"
		$string6 = "app"
		$string7 = ".execMenuItem"
		$string8 = "Close"
		$string9 = ".fillColor"
		$string10 = "WillClose"

	condition:
		all of them

}

rule CVE_2016_1043_2792 
 {
	meta:
		sigid = 2792
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1043"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "<template xmlns=\"http://www.xfa.org/schema/xfa-template/3.3/\">"
$a1 = "<script>"
$a2 = "replace("

	condition:
		all of them

}

rule CVE_2016_0933_2369 
 {
	meta:
		sigid = 2369
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0933"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1= "<?xpacket begin="
$str2= "<?adobe-xap-filters"
$str3= "<x:xmpmeta xmlns:"
$str4= "<rdf:RDF xmlns:rdf="
$str5= "/Subtype /U3D"
$str6= "scene.cameras.getByIndex("
$str7= "scene.animations.getByIndex("
$str8= "scene.meshes.getByIndex"
$str9= "runtime.refresh();"
$str10= ".targetPosition.set("
$str11= "runtime.addEventHandler"
$str12= "scene.createLight("
$str13= ".menuItemName.substr"

	condition:
		all of them

}

rule CVE_2015_3053_1697 
 {
	meta:
		sigid = 1697
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3053"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "this.setPageAction(0,\"Close\",\"this.closeDoc(true);\")"

	condition:
		$a

}

rule CVE_2015_4449_1954 
 {
	meta:
		sigid = 1954
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_4449"
		category = "Malware & Botnet"
		risk = 25
		
	strings:
		$a = "/Type /Action"
$b = "/GoToE /F (javascript:"

	condition:
		all of them

}

rule CVE_2015_3076_1702 
 {
	meta:
		sigid = 1702
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3076"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = {47 57 53}
		$a2 = {25 50 44 46}
		$a3 = {43 42 41 75 74 6F 43 6F 6E 66 69 67 43 6F 6D 6D 65 6E 74 52 65 70 6F 73 69 74 6F 72 79 28}

	condition:
		$a1 at 0 and $a2 in (4..1000) and $a3

}

rule CVE_2015_5102_1850 
 {
	meta:
		sigid = 1850
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5102"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a0 = "app.doc.getAnnots3D(0)[0].activated=true;"
		$a1 = "=app.doc.getAnnots3D(0)[0].context3D;"
		$a2 = ".runtime;"
		$a3 = ".ScrollWheelEventHandler();"
		$a4 = ".onEvent=function(){app.doc.closeDoc(true);};"
		$a5 = "addEventHandler("

	condition:
		all of them

}

rule CVE_2015_5111_1849 
 {
	meta:
		sigid = 1849
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5111"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a0 = "/S /JavaScript"
		$a1 = /try{var [a-zA-Z0-9]+ = this.addField('[a-zA-Z0-9]+',"text",0,\[[0-9,]+\]);}catch(e){}/
		$a2 = /try{[a-zA-Z0-9]+.setAction({cTrigger:"Format",cScript:"this.closeDoc(true);"});}catch(e){}/

	condition:
		all of them

}

rule CVE_2015_5086:_Privilege_Escalation_1846 
 {
	meta:
		sigid = 1846
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-5086: Privilege Escalation"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1="his.identity.__defineGetter__"
		$a2="app.launchURL("
		$a3="this.DoIdentityDialog(1,1,1,1,1,1)"
		$a4="app.setTimeOut("
		$a5="this.closeDoc(true)"
		$a6=";new app.doc.ADBCAnnotEnumerator("
		$a7=").next.call({"

	condition:
		all of them

}

rule CVE_2015_5095_1843 
 {
	meta:
		sigid = 1843
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5095"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a = ".RenderEventHandler()"
$b = ".onEvent=function(event){"
$c = ".context3D"
$d = ".runtime"
$e = ".RenderEventHandler()"
$f = ".onEvent=function(event){"
$g = ".context3D"
$i = ".RenderEventHandler()"
$j = ".onEvent=function(event){"
$k = ".context3D"
$m = ".RenderEventHandler()"
$n = ".onEvent=function(event){"
$o = ".context3D"
$q = ".RenderEventHandler()"
$r = ".onEvent=function(event){"
$s = ".context3D"
$p = ".runtime"
$t = "RenderEventHandler()"
$u = ".onEvent=function(event){};"

	condition:
		all of them

}

rule CVE_2015_5104_1839 
 {
	meta:
		sigid = 1839
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5104"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = ".doc.getAnnots3D"
$a1 = "].activated=true;"
$a2 = "].context3D;"
$a3 = ".runtime;"
$a4 = ".RenderEventHandler();"
$a5 = ".onEvent=function(){app.doc.closeDoc(true);};"
$a6 = ".addEventHandler"

	condition:
		all of them

}

rule CVE_2015_5103_1838 
 {
	meta:
		sigid = 1838
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5103"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = ".doc.getAnnots3D"
		$a1 = "activated=true;"
		$a2 = "context3D;"
		$a3 = ".addCustomMenuItem"
		$a4 = ".MenuEventHandler();"
		$a5 = ".onEvent=function(){app.doc.closeDoc(true);}"
		$a6 = ".addEventHandler("

	condition:
		all of them

}

rule PDF_Exploit__CVE_2021_21035_122708 
 {
	meta:
		sigid = 122708
		date = "2022-03-02 11:59 AM"
		threatname = "PDF.Exploit.CVE-2021-21035"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
$a1 = "stream"
$a2 = "this.getAnnots()["
$a3 = "a0.setProps({type:\"Polygon\",page:1,});"
$a4 = "a0.popupOpen=true;"
$a5 = "a0.popupOpen=false;"
$a6 = "a1.setProps({type:\"Polygon\",page:1,"
$a7 = "a1.popupOpen=true;"
$a8 = "a1.popupOpen=true;"

condition:
all of them
}

rule CVE_2015_5099_1835 
 {
	meta:
		sigid = 1835
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5099"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "app.doc.addField"
		$a1 = "app.doc.removeField"
		$a2 = "__defineGetter__"
		$a3 = "setItems"

	condition:
		all of them

}

rule Suspicious_Strings_1519 
 {
	meta:
		sigid = 1519
		date = "2016-02-01 08:00 AM"
		threatname = "Suspicious_Strings"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a = "%u0c0c"
		$b = /%u[0-9a-zA-Z]{4}%u/

	condition:
		all of them

}

rule PDF_Generic_shellcode_II_1518 
 {
	meta:
		sigid = 1518
		date = "2016-02-01 08:00 AM"
		threatname = "PDF_Generic_shellcode_II"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$shell = "4c20600f0517804a3c20600f0f63804aa3eb804a3020824a6e2f804a41414141260000000000000000000000000000001239804a6420600f000400004141414141414141"

	condition:
		all of them

}

rule Fuzzing_Streams_1516 
 {
	meta:
		sigid = 1516
		date = "2016-02-01 08:00 AM"
		threatname = "Fuzzing_Streams"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a = "414141414141414141414141414141414141414141414141"
		$b = "909090909090909090909090909090909090909090909090"
		$c = "0c0c0c0c0c0c0c0c0c0c0c0c"
		$d = "unescape"

	condition:
		($d and $a ) or ($d and $b) or ($d and $c)

}

rule PDF_CVE_2014_0527_1512 
 {
	meta:
		sigid = 1512
		date = "2016-02-01 08:00 AM"
		threatname = "PDF-CVE-2014-0527"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$1 = "function onError"
$2 = "CollectGarbage"
$3 = "wrap_pdf.innerHTML = "
$4 = "setZoom"

	condition:
		all of them

}

rule CVE_2015_3054_1696 
 {
	meta:
		sigid = 1696
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3054"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "this.setAction(\"WillSave\",\"this.closeDoc(true);\")"

	condition:
		$a

}

rule CVE_2015_3056_1694 
 {
	meta:
		sigid = 1694
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3056"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "var annotx = {};"
		$b = "annotx.type = \"Line\";"
		$c = "annotx.points = 0;"
		$d = "this.addAnnot(annotx)"
		$e = "var t2 = app.setTimeOut('app.clearTimeOut(t2); this.closeDoc(true);',1000);"

	condition:
		all of them

}

rule CVE_2015_3057_1693 
 {
	meta:
		sigid = 1693
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3057"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$trigger = "= app.setTimeOut('this.closeDoc(true);app.openDoc(\"/"

	condition:
		$trigger

}

rule PDF_Exploit_CVE_2020_6092_124650 
 {
	meta:
		sigid = 124650
		date = "2022-03-02 11:59 AM"
		threatname = "PDF.Exploit.CVE-2020-6092"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$header = "%PDF-"
$str1= "<< /Type /Pattern"
$str2= /\/BBox \[[0-9]{10}/
$str3= "<< /ColorSpace"
$str4= "<< /Cs12"
$str5= "/DeviceRGB"
condition:
$header at 0 and all of ($str*)
}

rule PDF_Exploit_CVE_2018_5053_118516 
 {
	meta:
		sigid = 118516
		date = "2018-07-12 09:08 AM"
		threatname = "PDF.Exploit.CVE-2018-5053"
		category = "Malware & Botnet"
		risk = 30
		Description = "Rule to detect image data within U3D stream that triggers the vulnerability." 
Disclaimer = "This rule is provided for informational purposes only."
Author = "Adobe PSIRT" 
Date = "06/15/2018" 
Distribution = "Microsoft MAPP Program Only" 
Revision = 1
	strings:
$u3d_tif_record = { 06 01 03 00 01 05 00 00 06 00 00 00 }
condition: 
$u3d_tif_record
}

rule PDF_Exploit_CVE_2018_5041_118515 
 {
	meta:
		sigid = 118515
		date = "2018-07-12 05:26 AM"
		threatname = "PDF_Exploit_CVE_2018_5041"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
	$u3d_data_record={831323238115252586142424001324248112242405142525152525152424162727182B2C192E2F81182D2E811A2E2F13182D2D192E301B32341D35381D3539193235132C2E17323222403F2947482644472343462244462040421E393C1D35391E363B1F373B1F37391F373A8120383C811F37390020383B8220383C8321393D8121393B11203A3B203A3C213B3F20383B1F34341E31301E32321F33352034372134392135391F35371F33351D33341D34361D37381F3A3B1F3C3D811F3D3F81203C3D01213D3D213D3F81213D401B203E40213E40233D41253D41263E42223A3E1A34381C3A3C28484A2D51532A52542951532A4F5127494A234343223F3E243F3F263F41263F42263F44274044263E41253A3C24393924393A263A3B263B3C273B3C85283A3C812A3C3E06293B3D2A3B3D2B3B3E2C3B3E2B3A3D2B3B3D2B3C3D012B3D3D022C3D3E2D3D3F2E3D40812D3C3F042E3D402D3D3F2C3D3E2B3D3D2C3C3E822D3C3F812C3B3E022D3D3D2C3D3D2A3C3D82293B3D0D2A3C3D2638381E30321B2D301D2F33273C3F344C4E3B5354374D4E2E43432338391D3233203334213335}
condition:
	$u3d_data_record
}

rule PDF_Exploit_CVE_2018_12782_118490 
 {
	meta:
		sigid = 118490
		date = "2018-07-10 09:15 AM"
		threatname = "PDF.Exploit.CVE-2018-12782"
		category = "Malware & Botnet"
		risk = 100
		Distribution = "Microsoft MAPP Program Only"
	strings: 
$const0 = /\/Subtype[\t\n\r\s]*\/U3D[\t\n\r\s]*\/Type[\t\n\r\s]*\/3D[\t\n\r\s]*\/VA/ 
$js0 = "c3d0=this.getAnnots3D(0)[0]" ascii 
$js1 = "c3d0.activated=true" ascii 

condition: 
(uint16(0) == 0x5025 and uint16(2) == 0x4644) and (all of ($const*)) and #const0 > 2 and (all of ($js*))
}

rule CVE_2018_0998_118014 
 {
	meta:
		sigid = 118014
		date = "2018-04-10 06:25 AM"
		threatname = "CVE_2018_0998"
		category = "Malware & Botnet"
		risk = 30
		Distribution = "Microsoft MAPP Program Only"

	strings:
	$str1 = "/PageMode /UseAttachments"
	$str2 = "/Kids [3 0 R]"
	$str3 = "/ProcSet [/PDF /Text /ImageB /ImageC /ImageI]"
	$str4 = "/XObject"
	$str5 = "/Subtype /FileAttachment"
	$str6 = ".lnk)"
	$str7 = "/Type /EmbeddedFile"
	$str8 = "/Name /PushPin"
	$str9 = ".rtf)"
	$str10 = "/MediaBox [0 0 595 842]"
		
	condition:
		(all of ($str*))
}

rule CVE_2018_4974_118176 
 {
	meta:
		sigid = 118176
		date = "2018-05-14 19:23 PM"
		threatname = "CVE-2018-4974"
		category = "Malware & Botnet"
		risk = 100
		Description = "Rule to detect XFA specification that triggers the vulnerability." 
Date = "03/26/2018" 
	strings: 
$xmlns_template = /<template[\t\n\r\s]*xmlns/ 
$xfa0 = "<field name=\"name1\">" 
$xfa1 = "var f = xfa.resolveNode(\"xfa.form.form1.name2\");" 
$xfa2 = "f.instanceManager.addInstance();" 
$xfa3 = "f.instanceManager.moveInstance(2,1);" 
$xfa4 = "<subform name=\"name2\">" ascii 
$xfa5 = "f.instanceManager.removeInstance(1);" 

condition: 
(uint16(0) == 0x5025 and uint16(2) == 0x4644) and $xmlns_template and (all of ($xfa*)) and #xfa2 > 1 and @xfa0 <= @xfa1 and @xfa1 <= @xfa2 and @xfa2 <= @xfa3 and @xfa4 <= @xfa5 
}

rule Win32_Trojan_NTLMStealer_118165 
 {
	meta:
		sigid = 118165
		date = "2018-06-05 20:20 PM"
		threatname = "Win32.Trojan.NTMLStealer"
		category = "Malware & Botnet"
		risk = 40
		ref = "https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/"
	strings:
$x0 = /\/Type/
$x1 = /\/Contents/
$a0 = /\/O\s+?\<\</
$a1 = /\/F\s+?\(\\\\\\\\/
$a2 = /\/D\s+?\[\s+?0\s+?\/Fit\s+?\]/
$a3 = /\/S\s+?\/GoToE/
condition:
(uint16(0) == 0x5025 and uint16(2) == 0x4644) and all of them
}

rule CVE_2016_1044_2751 
 {
	meta:
		sigid = 2751
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1044"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "/Type /Action"
		$a1 = "/S /JavaScript"
		$a2 = ".alert("
		$a3 = ".beginPriv();"
		$a4 = "file = '/c/windows/win.ini';"
		$a5 = ".readFileIntoStream("
		$a6 = ".stringFromStream("
		$a7 = "'http://"
		$a8 = "Collab.uriPutData(args);"
		$a9 = ".trustedFunction.bind("
		$a10 = "execDialog"
		$a11 = "CBSharedReviewIfOfflineDialog"
		$a12 = "AFParseDate("

	condition:
		all of them

}

rule PDF_Trojan_NOBELIUM_123248 
 {
	meta:
		sigid = 123248
		date = "2021-06-02 06:54 AM"
		threatname = "PDF.Trojan.NOBELIUM"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = {25 06 8B C4 1C C5 86 66 F3 DC 75 F9 3B DD 8C 44 E3 D3 A4 74 9D 94 4E 2E 0F D9 01 A6 F2 88 6A A8}
$str2 = {6D 6F 79 DB 20 F6 C7 FA E7 EB B9 88 77 DE 1F A1 92 D7 EA 68 A9 B7 89 17 92 E8 B2 BB A5 58 56 B4}
$str3 = {6D AD 2E 6D 72 67 1E B0 A8 EA 42 82 BD 14 9A 86 F0 0D 9A 8B 92 76 B3 B3 7D EF 69 24 2C 9F C2 CA}
$str4 = "%%EOF"
$not1 = "endobj"
$not2 = "endstream"

condition:
all of ($str*) and not 1 of ($not*)
}

rule CVE_2016_6988_XFAmaxCharsUAF_3317 
 {
	meta:
		sigid = 3317
		date = "2016-10-11 23:30 PM"
		threatname = "CVE-2016-6988-XFAmaxCharsUAF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const0 = "/AcroForm" ascii
		$const1 = "/OpenAction" ascii
		$const2 = "/JS" ascii
		
		$code0 = "s = \"X\";\\n\x09while\\(s.length < 100000\\) s+=s;" ascii
		$code1 = "obj = xfa.form.resolveNode\\(\"xfa.form.main_form.tbl.sf1.fld1\"\\);" ascii
		$code2 = "obj.rawValue = s;" ascii
		$code3 = "obj = xfa.form.resolveNode\\(\"xfa.form.main_form.tbl.sf2.fld2\"\\);"
		$code4 = "obj.fontColor='1,2,3';"
		$code5 = "xfa.form.remerge\\(\\);"

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0D) and (all of ($const*)) and (all of ($code*))

}

rule CVE_2016_6944_RadioButtonUAF_3315 
 {
	meta:
		sigid = 3315
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6944_RadioButtonUAF"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/JS" ascii
		$code0 = "console.show();" ascii
		$code1 = "function esc(){"
		$code2 = "search.query(\"A\");"
		$code3 = "esc();"

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x312E and uint8(8) == 0x0D)
		and (all of ($const*)) and (all of ($code*))

}

rule CVE_2016_6939_HeapOverflowCFF_3308 
 {
	meta:
		sigid = 3308
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6939_HeapOverflowCFF"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$const0 = "/BaseFont/YOJZDE+Gotham-Light/Encoding/WinAnsiEncoding/FirstChar 32/FontDescriptor 63 0 R/LastChar 99/Subtype/Type1/ToUnicode 64 0 R"

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x342E and uint8(8) == 0x0D) and $const0

}

rule CVE_2016_6964_3300 
 {
	meta:
		sigid = 3300
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6964"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:for-each select=\\\"(/)/*[a()]\\\">\x09\x09</xsl:for-each>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2016_6966_ForEachElemMemCor_3290 
 {
	meta:
		sigid = 3290
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6966_ForEachElemMemCor"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
  
$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:for-each select=\\\"substring-after(.)\\\">\x09\x09</xsl:for-each>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2016_6953_3302 
 {
	meta:
		sigid = 3302
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6953"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/AcroForm" ascii 
		$const1 = "/JS" ascii
		$code0 = "global.doc = this;" ascii
		$code1 = "xfa.layout.relayout\\(\\);" ascii
		$code2 = "o = xfa.resolveNode\\(\"xfa.form.form1.sf1.draw.#value[0].#arc[0].#edge[0].#color[0]\"\\);" ascii
		$code3 = "o.instanceManager.removeInstance\\(1\\);" ascii 
		$code4 = "o = xfa.resolveNode\\(\"xfa.form.form1.sf1.draw.#ui[0].#defaultUi[0]\"\\);" ascii 
		$code5 = "o = xfa.resolveNode\\(\"xfa.form.form1.sf1.draw.#ui[0].#defaultUi[0]\"\\);" ascii
		$code6 = "o.instanceManager.addInstance\\(1\\);" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0D) and (all of ($const*)) and (all of ($code*))

}

rule CVE_2016_1057_2784 
 {
	meta:
		sigid = 2784
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1057"
		category = "Malware & Botnet"
		risk = 40
		
	strings:
		$a0 = "/S /JavaScript"
$a1 = "var c3d=app.doc.getAnnots3D(0)[0].context3D;"
$a2 = "runtime=c3d.runtime;"
$a3 = "var hScrollWheelEventHandler=c3d.ScrollWheelEventHandler();"
$a4 = "hScrollWheelEventHandler.onEvent="
$a5 = "function(){"
$a6 = "app.execMenuItem('Close');};"
$a7 = "runtime.addEventHandler(hScrollWheelEventHandler);"

	condition:
		all of them

}

rule CVE_2016_1073_2775 
 {
	meta:
		sigid = 2775
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1073"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = "%PDF-"
		$str1 = "/JS (app.alert\\(1\\);"
		$str2 = "xfa.template.createNode\\(\"field\"\\);\\nob.rawValue = xfa;"
		$str3 = "\\napp.alert\\(ob.rawValue\\);"
		$str4 = "\\n\\no = xfa.resolveNode\\(\"xfa.config.acrobat.common.template.base\"\\)"
		$str5 = "#pageSet[0].pageSet2.pageArea1.area1.subform2.area2.subformSet\"\\);\\n\\no1.nodes.append\\(o2\\);"

	condition:
		($magic at 0) and (all of ($str*))

}

rule PDF_Generic_shellcode_I_1517 
 {
	meta:
		sigid = 1517
		date = "2016-02-01 08:00 AM"
		threatname = "PDF_Generic_shellcode_I"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a = "fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d"

	condition:
		any of them

}

rule CVE_2016_6961_3353 
 {
	meta:
		sigid = 3353
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6961"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:copy-of select=\\\"(/)/*[a()]\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
and uint16(6) == 0x372E and uint8(8) == 0x0A)
and (all of ($const*))
and (all of ($xsl*))

}

rule CVE_2016_6972_3352 
 {
	meta:
		sigid = 3352
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6972"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
$xsl1 = "<xsl:key name=\\\"x\\\" match=\\\"/\\\" use=\\\"substring-after(.)\\\"/></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
and uint16(6) == 0x372E and uint8(8) == 0x0A)
and (all of ($const*))
and (all of ($xsl*))

}

rule CVE_2016_6940_3350 
 {
	meta:
		sigid = 3350
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6940"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$const0 = "<< /Length 822 /Type /3D /Subtype /U3D >>\x0Astream\x0APRC"

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x312E and uint8(8) == 0x0A) and $const0

}

rule CVE_2016_6948_3349 
 {
	meta:
		sigid = 3349
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6948"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$const0 = "/Filter/FlateDecode/First 56/Length 892/N 8/Type/ObjStm"
$stream = {68 DE BC 94 DD 6E DB 36 14 C7 9F 60 EF C0 CB 16 43 F6 97 44 7D D0 40 11 C0 76 E3 D6 5B 9C A4 51 BA 6C CB 72 C1 48 B4 25 54 96 54 89 4E 93 3E FD 78 28 CB 76 BC A6 6E 76 31 10 04 29 9E 6F 52 E7}

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x352E and uint8(8) == 0x0D) and (all of ($const*)) and $stream

}

rule CVE_2016_6979_3347 
 {
	meta:
		sigid = 3347
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6979"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS"
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">"
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:if test=\\\"(/)/*[a()]\\\">\x09\x09</xsl:if>\x09</xsl:template></xsl:stylesheet>"

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2016_6977_3346 
 {
	meta:
		sigid = 3346
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6977"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:choose>\x09\x09\x09<xsl:when test=\\\"substring-after(.)\\\"></xsl:when>\x09\x09</xsl:choose>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule PDF_Exploit_CVE_2019_7030_119175 
 {
	meta:
		sigid = 119175
		date = "2019-02-12 06:19 AM"
		threatname = "PDF.Exploit.CVE_2019_7030"
		category = "Malware & Botnet"
		risk = 100
		
	
strings:
$a="/Rect"
$c="trailer"
$b="/Root"
$e="/JavaScript"
$f="/JS("
$h="app.alert("
$i="this.submitForm({"
$j="cURL: \"mailto:"
$k="cSubmitAs: \"XDP\""
$l="aPackets: {length:0xffffffff},bPDF:false})"
condition:
all of them

}

rule PDF_Exploit_CVE_2019_7021_119205 
 {
	meta:
		sigid = 119205
		date = "2019-02-12 10:27 AM"
		threatname = "PDF.Exploit.CVE-2019-7021"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str1="event activity=\"initialize\""
$str2="script contentType=\"application/x-javascript\""
$str3="try{xfa.form.subform4.usehref=\\'\\'}"
$str4="ref=\"xfa.form."
$str5="<destination>pdf</destination>"
$str6="<pdf>"
$str7="/NeedsRendering true"
condition:
all of ($str*)
}

rule CVE_2016_0117_2518 
 {
	meta:
		sigid = 2518
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0117"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "<</FunctionType 4/"
		$a1 = { 73 74 72 65 61 6d 0a 7b 0a 31 30 39 34 37 39 35 35 38 35 0a } //stream.{.1094795585
		$a2 = "dup"

	condition:
		all of them

}

rule PDF_Trojan_Fareit_3782 
 {
	meta:
		sigid = 3782
		date = "2017-05-08 14:49 PM"
		threatname = "PDF_Trojan_Fareit"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$string1="/OpenAction"
		$string2="/Launch"
		$string3="/Win"
		$encoded="powershell.exe -EncodedCommand"
		$decoded1 = "-ExecutionPolicy bypass"
		$decoded2 = "-noprofile"
		$decoded3 = ".DownloadFile("

	condition:
		(all of ($str*)) and ($encoded or all of ($decoded*))

}

rule CVE_2017_3032_3706 
 {
	meta:
		sigid = 3706
		date = "2017-04-11 17:06 PM"
		threatname = "CVE_2017_3032"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/BitsPerComponent 8" ascii
		$const1 = "/ColorSpace /DeviceRGB" ascii
		$const2 = "/Filter [ /JPXDecode ]" ascii
		$const3 = "/Height 4" ascii
		$const4 = "/Length 126" ascii
		$const5 = "/Subtype /Image" ascii
		$const6 = "/Type /XObject" ascii
		$const7 = "/Width 4" ascii
		$malformed_hex = {FF 5C 00 29 62 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF 90 00 0A 0A}

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x352E and uint8(8) == 0x0A)
		and (all of ($const*))
		and $malformed_hex

}

rule CVE_2017_3020_3686 
 {
	meta:
		sigid = 3686
		date = "2017-04-11 17:06 PM"
		threatname = "CVE_2017_3020"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$const0 = "/Type /Annot" ascii
$const1 = "/Subtype /Link" ascii
$const2 = "/A"
$const3 = "/Type /Action" ascii
$const4 = "/Type /Action" ascii
$const5 = "/S /URI"
$code0 = { 2F 55 52 49 20 28 FE FF ?? [2-32] ?? }

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x342E and uint8(8) == 0x0D) and (all of ($const*)) and (all of ($code*))

}

rule CVE_2016_6974_3305 
 {
	meta:
		sigid = 3305
		date = "2016-12-13 08:37 AM"
		threatname = "CVE_2016_6974"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:if test=\\\"substring-after(.)\\\">\x09\x09</xsl:if>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		// 25 50 44 46 2D 31 2E 37 0A 
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0A)
		and (all of ($const*))
		and (all of ($xsl*))

}

rule CVE_2016_1091_3289 
 {
	meta:
		sigid = 3289
		date = "2016-12-15 06:25 AM"
		threatname = "CVE_2016_1091"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$const0 = "/Outlines 9189 0 R" // document outline -- bookmarks
		$const1 = "9189 0 obj" // the object reference in the outline does not exist

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x362E and uint8(8) == 0x0D) and $const0 and not $const1

}

rule CVE_2016_6958_3348 
 {
	meta:
		sigid = 3348
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6958"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$const0 = "/Type /Action"
$const1 = "/S /JavaScript"	
$code0 = "var myApp = {};"
$code1 = "myApp.__proto__ = app;"
$code2 = "return myApp[\"beginPriv\"];"
$code2a = "return myApp.beginPriv;"	
$code3 = "permission.__defineGetter__(\"granted\", function () { d.requestPermission = app.launchURL; return undefined; });"
$code4 = /permission.__defineGetter__\("annot", function \(\) \{ return "\w+.pyw"; \}\);/

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x312E and uint8(8) == 0x0D) and (all of ($const*)) and $code0 and $code1 and ($code2 or $code2a) and $code3 and $code4

}

rule CVE_2016_6973_3337 
 {
	meta:
		sigid = 3337
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6973"
		category = "Adware"
		risk = 50
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
        $xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:for-each select=\\\"a\\\">\x09\x09\x09<xsl:sort select=\\\"substring-after(.)\\\"/>\x09\x09</xsl:for-each>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0A)
		and (all of ($const*))
		and (all of ($xsl*))

}

rule cve_2016_4197_3100 
 {
	meta:
		sigid = 3100
		date = "2016-07-14 14:49 PM"
		threatname = "cve_2016_4197"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "<a/>"
		$s2 = "<xsl:stylesheet xmlns:xsl="
		$s3 = "xsl:template match=\\\"/\\\""
		$s4 = "<xsl:apply-templates"
		$s5 = "select=\\\"A[0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9]"
		$s6 = "XMLData.parse("
		$s7 = ".nodes.item(0);"
		$s8 = ".applyXSL("

	condition:
		all of them

}

rule CVE_2016_6963_3334 
 {
	meta:
		sigid = 3334
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6963"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
        $xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:apply-templates select=\\\"(/)/*[a()]\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0A)
		and (all of ($const*))
		and (all of ($xsl*))

}

rule CVE_2016_6960_XSLApplyTemplatesElemMemCor_3323 
 {
	meta:
		sigid = 3323
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6960_XSLApplyTemplatesElemMemCor"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:apply-templates select=\\\"substring-after(.)\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2016_6957_3320 
 {
	meta:
		sigid = 3320
		date = "2016-10-11 23:30 PM"
		threatname = "CVE-2016-6957"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const0 = "/Type /Action" ascii
		$const1 = "/S /JavaScript" ascii
		$code0 = "var myApp = {};" ascii
		$code1 = "myApp.__proto__ = app;" ascii
		$code2 = "return myApp[\"beginPriv\"];" ascii
		$code2a = "return myApp.beginPriv;" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x312E and uint8(8) == 0x0D) and (all of ($const*)) and $code0 and $code1 and ($code2 or $code2a)

}

rule CVE_2016_1084_2796 
 {
	meta:
		sigid = 2796
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1084"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "app"
$string2 = "DisablePermEnforcement("
$string3 = "return"
$string4 = "toString "
$string5 = "popUpMenuEx"
$string6 = "ansyc_free"

	condition:
		all of them

}

rule CVE_2016_1048_2789 
 {
	meta:
		sigid = 2789
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1048"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "<</AcroForm 36 0 R/Extensions<</ADBE<</BaseVersion/1.7/ExtensionLevel 8>>>>/Metadata 12 0 R/Names 37 0 R/PageLabels 18 0 R/Pages 20 0 R/Type/Catalog>>"

	condition:
		all of them

}

rule CVE_2016_1064_2787 
 {
	meta:
		sigid = 2787
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1064"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "this.submitForm({cURL: \"http://"
$a1 = "#FDF\", cSubmitAs: \"PDF\", cCharset: \"utf-16\" });"

	condition:
		all of them

}

rule CVE_2016_1072_2778 
 {
	meta:
		sigid = 2778
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1072"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = "%PDF-"
$str1 = "/JS (\\nfunction hex2float\\(hex\\)\\n"
$str2 = "var expo_str = hex.substr\\(0,3\\)"
$str3 = "dolog\\(\"[step] rawValue set, now call crash...\"\\)"
$str4 = "dolog\\(\"[crash] done - now crash.\"\\)"
$str5 = "console.println\\(logstr\\)"

	condition:
		($magic at 0) and (all of ($str*))

}

rule CVE_2016_1074_2774 
 {
	meta:
		sigid = 2774
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1074"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic = "%PDF-1.4"
$str1 = "<</Type/3D/Subtype/U3D/VA[3 0 R 2 0 R 19 0 R]/DV 0/Length 17296>>"
$hex1 = {0A 73 74 72 65 61 6D 0A 55 33 44 00 18}

	condition:
		($magic at 0) and ((all of ($str*) and $hex1))

}

rule CVE_2016_1038_2762 
 {
	meta:
		sigid = 2762
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1038"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "app"
		$string2 = ".execDialog"
		$string3 = ".__defineGetter__"
		$string4 = ".bind"
		$string5 = "proxy"
		$string6 = "CBSharedReviewSecurityDialog"
		$string7 = "http:/"
		$string8 = "get"
		$string9 = "return"
		$string10 = "privileged"

	condition:
		all of them

}

rule CVE_2016_1065_2757 
 {
	meta:
		sigid = 2757
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1065"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = ".setAction"
		$string2 = "WillClose"
		$string3 = "new Array"
		$string4 = "defineGetter"
		$string5 = "app"
		$string6 = ".execMenuItem"
		$string7 = "Close"
		$string8 = ".addAnnot"
		$string9 = "{type:\"FileAttachment\""
		$string10 = "point:"

	condition:
		all of them

}

rule CVE_2016_1077_2725 
 {
	meta:
		sigid = 2725
		date = "2016-05-12 13:41 PM"
		threatname = "CVE-2016-1077"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s1 = "Transparency/CS/DeviceRGB>>"
$s2 = "R/Filter/FlateDecode/Length 11325>>"
$s3 = "false/Filter/FlateDecode/Length 10714>>"
$s4 = "<</Type/XObject/Subtype/Image/Width"
$s5 = "661/ColorSpace/DeviceRGB/BitsPerComponent"
$s6 = "8/Filter/DCTDecode/Interpolate"
$s7 = "true/SMask 15 0"
$s8 = "R/Length 38909>>"

	condition:
		all of them

}

rule CVE_2016_1053_2776 
 {
	meta:
		sigid = 2776
		date = "2016-05-12 05:19 AM"
		threatname = "CVE_2016_1053"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={25 50 44 46 2D}
		$str0 = "/OpenAction 7 0 R"
		$str1 = "/Kids [4 0 R]"
		$str2 = "/Parent 3 0 R"
		$str3 = "/MediaBox [0 0 612 792]"
		$str4 = "(JavaScript example)"
		$str5 = "/JS (this.setAction('WillClose'"
		$str6 = "20, 100, 100, 20"

	condition:
		($magic at 0) and (all of them)

}

rule CVE_2016_1062_2771 
 {
	meta:
		sigid = 2771
		date = "2016-05-12 05:19 AM"
		threatname = "CVE_2016_1062"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic="%PDF"
		$str1="app.c=0"
		$str2=".__defineGetter__"
		$str3="cUIName"
		$str4="app.execMenuItem(\"Close\");"
		$str5="app.launchURL"
		$str6="this.setAction"
		$str7="WillClose"
		$str8="Collab.addStateModel"
		$str9="ReviewStates"
		$str10="My Review"
		$str11="oStates"

	condition:
		($magic at 0) and (all of ($str*))

}

rule CVE_2016_1082_2768 
 {
	meta:
		sigid = 2768
		date = "2016-05-12 05:19 AM"
		threatname = "CVE_2016_1082"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$magic={25 50 44 46 2D}
		$a1="var obj = app;"
		$a2="function toString_0() {"
		$a3="obj.createAVView(\"\");"
		$a4="return \"test\";"
		$a5="var ansyc_free = {"
		$a6="toString : toString_0"
		$a7="obj.popUpMenuEx(ansyc_free);"

	condition:
		($magic at 0) and (all of them)

}

rule CVE_2016_1039_2754 
 {
	meta:
		sigid = 2754
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1039"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$o1 = "/Type /Action"
$o2 = "/S /JavaScript"
$a1 = "k = app.execDialog;"
$a2 = "f = app;"
$a3 = "f.__defineGetter__(\"execDialog\", ()=> {"
$a4 = "return k.bind(app, proxy)"
$a6 = "CBSharedReviewCloseDialog({},false,false,false);"
$b1 = "proxy = new Proxy(app, {"
$b2 = "\"get\": function (oTarget, sKey) {"
$b3 = "if (sKey == \"idle\") {"
$b4 = "return privileged.bind(app);"

	condition:
		all of them

}

rule CVE_2016_1051_2750 
 {
	meta:
		sigid = 2750
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1051"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "/Type /Action"
		$a1 = "/S /JavaScript"
		$a2 = "/JS (try{this.setAction(\"WillSave\",\"app.execMenuItem('Close');\");}catch(e){console.println(\"[x]\" + e)})"

	condition:
		all of them

}

rule CVE_2017_16360_117358 
 {
	meta:
		sigid = 117358
		date = "2017-11-14 10:34 AM"
		threatname = "CVE_2017_16360"
		category = "Malware & Botnet"
		risk = 40
		hash = "a6a7bbd98ae08a2fa1aa5980131e494c"
	strings:
$s1 = "/XObject"
$s2 = "/Im0 2878 0 R"
$s3 = "/Im1 2133 0 R"
$s4 = ">>"
$s5 = "/Rotate 0"
$s6 = "/StructParents 728"
$s7 = "/Tabs /S"
$s8 = "/Type /Page"
condition:
all of ($s*)
and @s1 < @s2 and @s2 < @s3 and @s5 < @s6 and @s7 < @s8
}

rule PDF_Exploit_CVE_2010_2883_3006318 
 {
	meta:
		sigid = 3006318
		date = "2022-07-18 06:17 AM"
		threatname = "PDF.Exploit.CVE-2010-2883"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$a = "%PDF-"
$b = "OpenType"
$c = "TrueType"
$d = "SING"
$e = "name"
condition:
$a at 0 and ( (((@d[1] > @b[1]) and (@d[1] < (@b[1]+250))) and ((@e[2] > @b[1]) and (@e[2] < (@b[1]+250))) and (uint32(@d[1]+12)> 0x0 ) and (uint32(@e[2]+12)==0x0))   or  ( ((@d[1] > @c[1]) and (@d[1] < (@c[1]+250))) and ((@e[2] > @c[1]) and (@e[2] < (@c[1]+250))) and (uint32(@d[1]+12)> 0x0 ) and (uint32(@e[2]+12)==0x0)))
}

rule PDF_Exploit_CVE_2010_2883_125967 
 {
	meta:
		sigid = 125967
		date = "2022-07-13 12:45 PM"
		threatname = "PDF.Exploit.CVE-2010-2883"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$h1 = {25 50 44 46 2D 31 2E 34 0A 25 E2 E3 CF D3 0A 31}
$h2 = {3C 78 6D 70 4D 4D 3A 44 6F 63 75 6D 65 6E 74 49 44 3E 75 75 69 64 3A 61 61 61 61 61 61 61 61 2D 61 61 61 61 2D 61 61 61 61 2D 61 61 61 61 2D 61 61 61 61 61 61 61 61 61 61 61 61 3C 2F 78 6D 70 4D 4D 3A 44 6F 63 75 6D 65 6E 74 49 44 3E}
$h3 = {3C 3F 78 70 61 63 6B 65 74 20 62 65 67 69 6E 3D 22 EF BB BF 22 20 69 64 3D 22 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 22 3F 3E}
$h4 = {2F 42 61 73 65 46 6F 6E 74 20 2F 43 6F 6F 6B 69 65 43 75 74 74 65 72 0A 2F 53 75 62 74 79 70 65 20 2F 54 72 75 65 54 79 70 65 0A}
condition:
$h1 at 0 and $h2 and $h3 and $h4
}

rule CVE_2015_4452_1956 
 {
	meta:
		sigid = 1956
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_4452"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a = "/JavaScript"
		$b = "app.doc.app.__proto__="
		$c = "app.alert=function(){"

	condition:
		all of them

}

rule CVE_2016_0937_2374 
 {
	meta:
		sigid = 2374
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0937"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1="this.addWatermarkFromText("
		$s2="app.doc.getOCGs()[0].setAction('app.doc.closeDoc(true);app.doc.getOCGs()[0].setAction(\"this.closeDoc(true)\")')"
		$s3="app.setTimeOut('app.doc.getOCGs()[0].state=false;',100)"

	condition:
		all of them

}

rule CVE_2015_4443_1943 
 {
	meta:
		sigid = 1943
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_4443"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "<exclGroup layout=\"table\">"
		$str2 = "</exclGroup>"

	condition:
		all of them

}

rule CVE_2016_4196_3074 
 {
	meta:
		sigid = 3074
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4196"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a1 = "var xmlDoc = \"<a/> \";"
		$a2 = "var xslDoc = \"<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\"><xsl:template match=\\\"/\\\"><xsl:if test=\\\"A[0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9]\\\"/></xsl:template></xsl:stylesheet>\";"

	condition:
		all of them

}

rule PDF_CVE_2014_0493_1514 
 {
	meta:
		sigid = 1514
		date = "2016-02-01 08:00 AM"
		threatname = "PDF-CVE-2014-0493"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = /\/AP<<\/N(.{0,30})\/Tx\//
		$b = /\/Type\/XObject\/Subtype\/Image(.{0,30})\/SMask\s\d+0\d+\s\d+\sR/
		$c = /\/Type\/XObject\/Subtype\/Image(.{0,30})\/Filter\/DCTDecode/

	condition:
		all of them

}

rule PDF_Exploit_CVE_2019_16464_120264 
 {
	meta:
		sigid = 120264
		date = "2019-12-10 10:05 AM"
		threatname = "PDF.Exploit.CVE.2019.16464"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$header = "%PDF-"
		$str1 = "/OpenAction"
		$str2 = "/S /JavaScript /JS("
		$str3 = "xfa.resolveNode(\"xfa.form[0"
		$str4 = "xfa.resolveNode(\"xfa\").nodes.remove(a"
		$str5 = "a.execInitialize();"
condition:
		$header at 0 and all of ($str*)
}

rule CVE_2016_6942_3341 
 {
	meta:
		sigid = 3341
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6942"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/AcroForm" ascii
		$const1 = "/JS" ascii
		
		$code0 = "var ob = xfa.xdc.resolveNode\\(\"xfa[0].xdc[0].#deviceInfo[0].#font[0].#metrics[0].#charWidths[0].##text[0]\"\\);"
		$code1 = "var o = xfa.form.resolveNode\\(\"xfa.form.outerform.exclGroup.field\"\\);\\nxfa.host.openList\\(o\\);\\nxfa.host.pageUp\\(\\)"

	condition:
		// 25 50 44 46 2D 31 2E 37 0D
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0D)
		and (all of ($const*))
		and (all of ($code*))

}

rule CVE_2016_6950_3339 
 {
	meta:
		sigid = 3339
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6950"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "/AcroForm" ascii 
		$const1 = "/JS" ascii
		
		$code0 = "exclobj = xfa.template.createNode\\(\"exclGroup\"\\);" ascii
		$code1 = "list = xfa.resolveNode\\(\"xfa[0].form[0].outerform[0].#subform[0].subform_16082722[0].sf[24].target_sf.target_area.target_fld\"\\);" ascii
		$code2 = "xfa.host.openList\\(list\\);"
		$code3 = "odef = xfa.resolveNode\\(\"xfa[0].form[0].outerform[0].#subform[0].subform_16082722[0].sf[28].target_sf.target_area\"\\).nodes;"
		$code4 = "odef.append\\(exclobj\\);"
		$code5 = "xfa.resolveNode\\(\"xfa[0].form[0].outerform[0].#subform[0].subform_16082722[0].sf[27].target_sf\"\\).layout = 'position';"

	condition:
		// 25 50 44 46 2D 31 2E 36 0A 
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0D)
		and (all of ($const*))
		and (all of ($code*))

}

rule PDF_Exploit_CVE_2018_5042_118517 
 {
	meta:
		sigid = 118517
		date = "2018-07-12 05:38 AM"
		threatname = "PDF_Exploit_CVE_2018_5042"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
	$u3d_prefix_record = {384250530001000000000000000300000037000000650008000300040000}
condition:
	$u3d_prefix_record
}

rule PDF_Exploit_CVE_2018_5051_118514 
 {
	meta:
		sigid = 118514
		date = "2018-07-12 09:08 AM"
		threatname = "PDF.Exploit.CVE-2018-5051"
		category = "Malware & Botnet"
		risk = 30
		Description = "Rule to detect image data within U3D stream that triggers the vulnerability." 
Disclaimer = "This rule is provided for informational purposes only."
Author = "Adobe PSIRT" 
Date = "06/15/2018" 
Distribution = "Microsoft MAPP Program Only" 
Revision = 1
	strings:
$u3d_bmp_header = { 28 00 00 00 08 00 00 00 FA 01 00 00 01 00 08 00 01 00 00 00 99 02 00 00 12 0B 00 00 12 0B 00 00 10 00 00 00 10 00 10 00 }
condition: 
all of them
}

rule CVE_2018_4911_117806 
 {
	meta:
		sigid = 117806
		date = "2018-02-13 17:14 PM"
		threatname = "CVE_2018_4911"
		category = "Malware & Botnet"
		risk = 80
		Description = "Rule to detect a crafted JavaScript code in a PDF."
Disclaimer = "This rule is provided for informational purposes only."
Author = "Adobe PSIRT"
Date = "01/29/2018"
Distribution = "Microsoft MAPP Program Only"
Revision = 1
hash = "7920dffb838b48dd1c8bd49bb497ebb8"
	strings:
    $js0 = "this.bookmarkRoot.createChild(\"Next Page\", \"\");" ascii
    $js1 = "this.bookmarkRoot.children[0].createChild(\"Next Page\", \"this.bookmarkRoot.children[0].children[0].execute();this.bookmarkRoot.children[0].remove();this.closeDoc();" ascii
    $js2 = "this.bookmarkRoot.children[0].children[0].execute();" ascii
  condition:
    // 25 50 44 46
   (all of ($js*))
}

rule CVE_2016_0943_2367 
 {
	meta:
		sigid = 2367
		date = "2023-07-14 11:14 AM"
		threatname = "CVE-2016-0943"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a="/Type /Action"
$b="/JavaScript"
$c="global.Int32Array=0;"
$d="global.__defineGetter__"
$e="Int32Array"
$f="function(){"
$g="app.launchURL"
$h="global.setPersistent(\"Int32Array\",true);"
$i="endobj"

	condition:
		all of them
}

rule PDF_Exploit_CVE_2010_2883_124359 
 {
	meta:
		sigid = 124359
		date = "2021-10-20 16:44 PM"
		threatname = "PDF.Exploit.CVE-2010-2883"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$header = "%PDF-"
$str1 = "/#4d#61#63#52o#6d#61n#45ncodin#67"
$str2 = "/Fo#6e#74Fil#65"
$str3 = "/F#6c#61#74e#44#65#63#6fde"
$str4 = "/#4a#61#76aSc#72ipt"
$str5 = "/#41#53CI#49#48ex#44#65#63#6f#64#65"
condition:
$header at 0 and all of ($str*)
}

rule CVE_2018_4959_118123 
 {
	meta:
		sigid = 118123
		date = "2018-05-14 19:30 PM"
		threatname = "CVE-2018-4959"
		category = "Malware & Botnet"
		risk = 20
		Description = "Rule to detect a crafted JavaScript code in a PDF." 
    Disclaimer = "This rule is provided for informational purposes only."
    Author = "Adobe PSIRT" 
    Date = "03/26/2018" 
    Distribution = "Microsoft MAPP Program Only" 
    Revision = 1
	strings:
    $const0 = /\/Type[\t\n\r\s]*\/Action[\t\n\r\s]*\/S[\t\n\r\s]*\/JavaScript[\t\n\r\s]*\/JS/
    $js0 = "var Object_1 = this.addAnnot({type: \"Highlight\", name: \"Object_1\", inReplyTo: \"Object_1\"," ascii
        $js1 = "var Object_17 = this.addAnnot({type: \"Circle\", name: \"Object_17\", inReplyTo: \"Object_17\", " ascii
    $js2 = /Object_1.__defineSetter__\("style", function\(newval\)[\t\n\r\s]*\{[\t\n\r\s]*Object_17.setProps\(Object_17.getProps\(\)\)/
  condition: 
    // 25 50 44 46
    (uint16(0) == 0x5025 and uint16(2) == 0x4644)
    and (all of ($const*))
    and (all of ($js*))
}

rule PDF_CVE_2016_6965_XSLNumberElemUAF_3313 
 {
	meta:
		sigid = 3313
		date = "2016-10-11 23:30 PM"
		threatname = "PDF_CVE_2016_6965_XSLNumberElemUAF"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:number value=\\\"(/)/*[a()]\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D and uint16(6) == 0x372E and uint8(8) == 0x0A) and (all of ($const*)) and (all of ($xsl*))

}

rule CVE_2015_4451_1955 
 {
	meta:
		sigid = 1955
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_4451"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a = "ANSendApprovalToAuthorEnabled = app.trustedFunction(function("
		$b = "app.beginPriv();"
		$c = ".requestPermission = app.beginPriv;"
		$d = "permission.__defineGetter__(\"granted\", function () {"
		$e = ".launchURL;"

	condition:
		all of them

}

rule CVE_2015_3069_1711 
 {
	meta:
		sigid = 1711
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3069"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "script" nocase
		$a1 = "function"
		$a2 = "launchURL"
		$a3 = "eval"
		$a4 = "__proto__"
		$a5 = "ANVerifyComments"
		$a6 = "AFSimple_Calculate.call"

	condition:
		all of them

}

rule CVE_2015_3064_1710 
 {
	meta:
		sigid = 1710
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3064"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "script" nocase
		$a1 = "function"
		$a2 = "launchURL"
		$a3 = "eval"
		$a4 = "app.__proto__"
		$a5 = "ANVerifyComments"
		$a6 = "DynamicAnnotStore"
		$a7 = ".complete.call"

	condition:
		all of them

}

rule CVE_2015_3059_1708 
 {
	meta:
		sigid = 1708
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3059"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "script"
		$a1 = { 2e 73 74 61 74 65 [0-4] 3d [0-4] 22 43 61 6e 63 65 6c 6c 65 64 22 3b } // .state = "Cancelled"
		$a2 = { 2e 73 74 61 74 65 4d 6f 64 65 6c [0-4] 3d [0-4] 22 4d 61 72 6b 65 64 22 3b } // .stateModel = "Marked";
		$a3 = { 2e 74 79 70 65 [0-4] 3d [0-4] 22 54 65 78 74 22 3b } // .type = "Text";
		$a4 = "this.addAnnot"
		
		$b0 = { f2 d5 f8 dd a7 eb d3 40 fb a3 79 c4 e8 db 8f c5 }
		$b1 = { bb eb 30 bc 16 4f 9a 1d 3c f7 d3 38 57 8f d1 34 }
		$b3 = { a2 d7 9a 1e 90 08 5f 0b 26 ea 92 55 5c c4 b7 61 }
		$b4 = { 38 7a fd 1b e6 ef 5e dd bd 7c f1 e7 ef 9b 8b ab }

	condition:
		all of ($a*) or all of ($b*)

}

rule CVE_2015_3070_1707 
 {
	meta:
		sigid = 1707
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3070"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = "/MediaBox"
$a2 = "(a pwning u3d model)"
$a3 = ".stream.U3D"
$a4 = "CCCCBox01"
$a5 = "Box01RX"
$a6 = "Scapula"
$a7 = "Humerus"
$a8 = "Radius"
$a9 = "Ulna"

	condition:
		all of them

}

rule CVE_2015_3074_1705 
 {
	meta:
		sigid = 1705
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3074"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = "/JavaScript"
$a2 = "\"/c/windows/system.ini\""
$a3 = "\"trustPropagatorFunction\""
$a4 = ".readFileIntoStream};"
$a5 = ".__proto__"
$a6 = "ANTrustPropagateAll("
$a7 = ".alert(util.stringFromStream("
$a8 = "ScriptBridgeUtils.jsResult2xmlString.call({"
$a9 = "eval"
$a10 = ".toString()"
$a11 = "alert(e)"

	condition:
		all of them

}

rule CVE_2015_3075_1704 
 {
	meta:
		sigid = 1704
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3075"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = "/MediaBox"
		$a2 = "/JavaScript"
		$a3 = "this.removeField("
		$a4 = "this.addField({ cName:"
		$a5 = "cFieldType: \"combobox\","
		$a6 = ".setAction(\"Keystroke\", \"fnFree()\"),"
		$a7 = ".setItems(["

	condition:
		all of them

}

rule PDF_Exploit_CVE_2018_12840_118746 
 {
	meta:
		sigid = 118746
		date = "2018-09-20 07:48 AM"
		threatname = "PDF.Exploit.CVE_2018_12840"
		category = "Malware & Botnet"
		risk = 0
		
	strings: $jbig_segment_huffman_table_data = { FF FF 03 46 09 FF 7F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 18 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 00 00 00 00 37 7E 7E E8 01 61 10 03 78 76 69 B4 96 0F 84 23 FF AC}
condition: $jbig_segment_huffman_table_data
}

rule PDF_Exploit_CVE_2018_12764_118522 
 {
	meta:
		sigid = 118522
		date = "2018-07-18 10:08 AM"
		threatname = "PDF.Exploit.CVE-2018-12764"
		category = "Malware & Botnet"
		risk = 0
		Description = "Rule to detect JBIG data that triggers the vulnerability." 
    Disclaimer = "This rule is provided for informational purposes only."
    Author = "Adobe PSIRT" 
    Date = "06/07/2018" 
    Distribution = "Microsoft MAPP Program Only" 
    Revision = 1
	strings:
    $magic = {25 50 44 46 2D}
	$jbig_segment_data = {00 00 00 04 00 00 00 7F 00 FF 10 FF FF DF F2 47 FF CA 03 00 00 00 00 1F A4 22 FF 00 00 46 FF FF FC 04}
	$Jbig_Decode= {3C3C202F4465636F64655061726D7320203C3C202F4A42494732476C6F62616C73203420302052203E3E}
  condition: 
    $magic at 0 and $jbig_segment_data and $Jbig_Decode
}

rule CVE_2018_4980_118163 
 {
	meta:
		sigid = 118163
		date = "2018-05-14 19:26 PM"
		threatname = "CVE-2018-4980"
		category = "Malware & Botnet"
		risk = 100
		Description = "Rule to detect a crafted JavaScript code in a PDF." 
Disclaimer = "This rule is provided for informational purposes only."
Author = "Adobe PSIRT" 
Date = "03/26/2018" 
Distribution = "Microsoft MAPP Program Only" 
Revision = 1 
	strings:
$const0 = /\/Type[\t\n\r\s]*\/Action[\t\n\r\s]*\/S[\t\n\r\s]*\/JavaScript[\t\n\r\s]*\/JS/
$js0 = "this.identity.__defineGetter__('email',function(){app.launchURL(" ascii
condition: 
(uint16(0) == 0x5025 and uint16(2) == 0x4644) and (all of ($const*)) and (all of ($js*))

}

rule PDF_Exploit_CVE_2018_12767_118460 
 {
	meta:
		sigid = 118460
		date = "2018-07-18 10:08 AM"
		threatname = "PDF.Exploit-CVE-2018-12767"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
$jbig_segment_data = {FD FF 00 8B 00 00 10 E7 FF 00 00 00 00 1F 00 00 00 0A 00 5E 00 00 20 00 D1 00 43 EE 21 02 47 34 00 10}

condition: 
$jbig_segment_data
}

rule Trojan_PDFDoc_3745 
 {
	meta:
		sigid = 3745
		date = "2017-05-30 09:14 AM"
		threatname = "Trojan_PDFDoc"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = {2F 54 79 70 65 2F 45 6D 62 65 64 64 65 64 46 69 6C 65 2F} // /Type/EmbeddedFile/
		$a1 = {2F 46 69 6C 74 65 72 2F 46 6C 61 74 65 44 65 63 6F 64 65} // /Filter/FlateDecode
		$a2 = {2F 54 79 70 65 2F 46 69 6C 65 73 70 65 63 2F 46 28 [1-100] 2E 64 6F 63 6D 29 2F 55 46} // /Type/Filespec/F(675938.docm)/UF
		$a3 = {44 65 73 63 28} // Desc(

	condition:
		all of them

}

rule CVE_2016_6941_3351 
 {
	meta:
		sigid = 3351
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6941"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "<<\x0A/Length\x202\x200\x20R\x0A/Type /XObject\x0A/Subtype /Image"
$const1 = "/JPXDecode"
$data = { 62 70 63 63 04 04 04 00 00 00 00 0F }

	condition:
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
and uint16(6) == 0x352E and uint8(8) == 0x0A)
and (all of ($const*))
and $data

}

rule CVE_2018_4961_118121 
 {
	meta:
		sigid = 118121
		date = "2018-05-14 19:30 PM"
		threatname = "CVE-2018-4961"
		category = "Malware & Botnet"
		risk = 40
		Description = "Rule to detect a crafted JavaScript code in a PDF." 
Disclaimer = "This rule is provided for informational purposes only." 
Author = "Adobe PSIRT" Date = "03/26/2018" Distribution = "Microsoft MAPP Program Only" Revision = 1
	strings: 
$const0 = /\/Type[\t\n\r\s]*\/Action[\t\n\r\s]*\/S[\t\n\r\s]*\/JavaScript[\t\n\r\s]*\/JS/ /* var Object_2 = this.addField("Object_2", "listbox", 0, [168, 1, 32, 37, ]); var Object_7 = this.addField("Object_7", "radiobutton", 0, [5, 22, 16, 93, ]); var Object_16 = this.addAnnot({type: "Polygon", name: "Object_16"}) var Object_17 = this.addAnnot({type: "StrikeOut", name: "Object_17"}); Object_2.setAction("OnBlur", "Object_16.type=0;"); Object_7.setAction("OnBlur", "Object_17.type=0"); var TimeOut_1 = app.setTimeOut("Object_16.popupOpen=-1;", 1); var TimeOut_0 = app.setTimeOut("Object_17.popupOpen=1168303071;", 1); Object_2.setFocus(); Object_7.setFocus(); */ $js0 = /var [\w\d_]+ = this\.addField\("[\w\d_]+",/ 
$js1 = /var [\w\d_]+ = this\.addAnnot\(\{type: "[\w\d_]+", name: "[\w\d_]+"\}\)/ 
$js2 = /O[\w\d_]+\.setAction\("OnBlur", "[\w\d_]+\.type=0/ 
$js3 = /var [\w\d_]+ = app.setTimeOut\("[\w\d_]+\.popupOpen=/ 
$js4 = /O[\w\d_]+.setFocus\(\)/ 
condition: // 25 50 44 46 
(all of ($const*)) and (all of ($js*))
}

rule PDF_Exploit_CVE_2018_4977_118120 
 {
	meta:
		sigid = 118120
		date = "2018-05-14 19:26 PM"
		threatname = "CVE-2018-4977"
		category = "Malware & Botnet"
		risk = 80
		Description = "Rule to detect XFA specification that triggers the vulnerability." 
Disclaimer = "This rule is provided for informational purposes only."
Author = "Adobe PSIRT" 
Date = "03/26/2018" 
Distribution = "Microsoft MAPP Program Only" 
Revision = 1 
	strings:
$xfa0 = "o = xfa.resolveNode\\(\"xfa.form.sf_base.subform_1._subform_2\"\\);" ascii
$xfa1 = "o.count = \"1\"" ascii
$xfa2 = "o.count = \"0\"" ascii
$xfa3 = "xfa.layout.relayout\\(\\)" ascii
condition: 
(all of ($xfa*))
}

rule cve_2016_4199_3101 
 {
	meta:
		sigid = 3101
		date = "2016-07-14 14:49 PM"
		threatname = "cve_2016_4199"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "<a/>"
$s2 = "<xsl:stylesheet xmlns:xsl="
$s3 = "xsl:template match=\\\"/\\\""
$s4 = "<xsl:for-each"
$s5 = "select=\\\"A[0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9][0][1][2][3][4][5][6][7][8][9]"
$s6 = "XMLData.parse("
$s7 = ".nodes.item(0);"
$s8 = ".applyXSL("

	condition:
		all of them

}

rule PDF_Exploit_JS_gen_1614 
 {
	meta:
		sigid = 1614
		date = "2016-02-01 08:00 AM"
		threatname = "PDF.Exploit.JS.gen"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a = "<script"
		$b = "}catch(qq){"
		$c = ".substr("
		$d =  "document.createElement("
		$f = "</script>"

	condition:
		$a and $f and $b and ($c or $d)

}

rule App_Exploit_CVE_2010_3622_126384 
 {
	meta:
		sigid = 126384
		date = "2022-09-29 04:06 AM"
		threatname = "App.Exploit.CVE-2010-3622"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$a = "%PDF-"
$b = {00 00 00 00 6D 6C 75 63}
condition:
$a at 0 and for any i in (1..#b) : (uint32be(@b[i]+12) > 0x15555555)
}

rule CVE_2015_3055_1695 
 {
	meta:
		sigid = 1695
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3055"
		category = "Adware"
		risk = 127
		
	strings:
		$a = "var fieldx = this.addField('A',\"signature\",0,this.getPageBox({cPage:0}));"
$b1 = "try{fieldx.hidden = false;}catch(e){}"
$b2 = "try{fieldx.textSize = 0x7fffffff;}catch(e){}"
$b3 = "try{var x = fieldx.numItems;}catch(e){}"
$b4 = "try{fieldx.textColor = [];}catch(e){}"
$b5 = "try{fieldx.buttonScaleWhen = 0x80000000;}catch(e){}"
$b6 = "try{fieldx.strokeColor = [];}catch(e){}"
$b7 = "try{fieldx.borderStyle = \"beveled\";}catch(e)"
$c = "app.setTimeOut('app.clearTimeOut(t2); this.closeDoc(true);',1500)"

	condition:
		$a and any of ($b*) and $c

}

rule App_Exploit_CVE_2021_34833_126477 
 {
	meta:
		sigid = 126477
		date = "2022-10-12 11:38 AM"
		threatname = "App.Exploit.CVE-2021-34833"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$s = "%PDF-"
$b = "/S /JavaScript"
$c ="/JS"
$d = /annot[^\s]*\.destroy\(\);/
$e = /annot[^\s]*\.author[\s]{0,1}=/
$aa= "this.getAnnots();"
$ab= "this.addAnnot"
condition:
$s at 0 and $b and $c and for any i in (1..#d) : ((@d[i]+100) > (@e[i])) and any of ($a*)
}

rule CVE_2015_5113_1834 
 {
	meta:
		sigid = 1834
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5113"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "JavaScript"
		$a1 = ".addField("
		$a2 = "combobox"
		$a3 = "}catch(e){}"
		$a4 = ".setAction"
		$a5 = "cTrigger:"
		$a6 = "Format"
		$a7 = ".closeDoc(true)"

	condition:
		all of them

}

rule CVE_2016_6967_3301 
 {
	meta:
		sigid = 3301
		date = "2016-12-13 08:35 AM"
		threatname = "CVE_2016_6967"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "/Type/Action/S/JavaScript/JS" ascii
		$xsl0 = "<xsl:stylesheet xmlns:xsl=\\\"http://www.w3.org/1999/XSL/Transform\\\" version=\\\"1.0\\\">" ascii
		$xsl1 = "<xsl:template match=\\\"/\\\">\x09\x09<xsl:variable name=\\\"x\\\" select=\\\"(/)/*[a()]\\\"/>\x09</xsl:template></xsl:stylesheet>" ascii

	condition:
		// 25 50 44 46 2D 31 2E 37 0A 
		(uint16(0) == 0x5025 and uint16(2) == 0x4644 and uint16(4) == 0x312D
		and uint16(6) == 0x372E and uint8(8) == 0x0A)
		and (all of ($const*))
		and (all of ($xsl*))

}

rule CVE_2016_0944_2370 
 {
	meta:
		sigid = 2370
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0944"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1= "<</Pages"
$str2= "/OpenAction"
$str3= "<</MediaBox" 
$str4= "/Resources" 
$str5= "/BaseFont /2PTK675"
$str6= "/FontDescriptor"
$str7= {35 02 75 35 41 35 00 00 02 00 E5 02 29 01 BC 03 20 00 05 00 0B 00 0D 40 06 05 06 0A 02 08 04 2B}
$str8= {3F 3F 3F 30 31 01 11 17 07 27 11 23 11 07 27 37 11 23 07 27 37 21 17 07 02 04 38 35 4D CA 4E 35}

	condition:
		all of them

}

