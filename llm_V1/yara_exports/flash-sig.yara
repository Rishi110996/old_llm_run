

import "pe"
rule CVE_2014_0577:_TypeConfusion_1571 
 {
	meta:
		sigid = 1571
		date = "2016-12-13 07:45 AM"
		threatname = "CVE-2014-0577: TypeConfusion"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = /Lookup\:\d+\s\(\"flash\"\)/
		$b = /Lookup\:\d+\s\(\"Microphone\"\)/
		$c = /Lookup\:\d+\s\(\"get\"\)/
		$d = /Push\sLookup\:\d+\s\(\"ASnative\"\)/
		$e = /Push\sLookup\:\d+\s\(\"call\"\)/
		$g = /Lookup\:\d+\s\(\"flash\"\)/

	condition:
		all of them

}

rule CVE_2016_7862_3409 
 {
	meta:
		sigid = 3409
		date = "2016-11-08 15:28 PM"
		threatname = "CVE_2016_7862"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "getNextHighestDepth" ascii
    $const1 = "createEmptyMovieClip" ascii
    $const2 = "removeMovieClip" ascii
    $const3 = "constructor" ascii
    $const4 = "watch" ascii
    $const5 = "__proto__" ascii

$re1 = /action: Push int:\d+ register:\d+ Lookup:\d+ \("createEmptyMovieClip"\)/
$re2 = /action: Push register:\d+ int:\d+ register:\d+ Lookup:\d+ \("getNextHighestDepth"\)/
$re3 = /action: Push Lookup:\d+ \("removeMovieClip"\)/
$re4 = /action: Push Lookup:\d+ \("constructor"\) int:\d+ Lookup:\d+/
$re5 = /Push Lookup:\d+ \("__proto__"\) Undefined/
$const6 = "action: SetMember"

	condition:
		all of them

}

rule CVE_2016_6985_3332 
 {
	meta:
		sigid = 3332
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6985"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "var <q>[packageinternal]::fl:<q>[public]flash.display::FrameLabel"
		$a1 = "getscopeobject"
		$a2 = "findpropstrict <q>[public]flash.display::FrameLabel"
		$a3 = "pushstring"
		$a4 = "pushbyte"
		$a6 = "constructprop <q>[public]flash.display::FrameLabel, 2 params"
		$a7 = "coerce <q>[public]flash.display::FrameLabel"
		$a8 = "setslot"
		$a9 = "getscopeobject"
		$a10 = "newfunction"
		$a11 = "coerce <q>[public]::Function"
		$a12 = "setslot"
		$a13 = "callproperty <q>[public]::addEventListener, 2 params"
		$a14 = "pop"

	condition:
		all of them

}

rule CVE_2015_8655_2529 
 {
	meta:
		sigid = 2529
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2015_8655"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1="findpropstrict <q>[public]flash.media::AVSegmentedSource"
		$s2="constructprop <q>[public]flash.media::AVSegmentedSource, 0 params"
		$s3="initproperty <q>[private]NULL::source"
		$s4="getproperty <q>[private]NULL::source"
		$s5="getlex <q>[public]flash.events::AVStatusEvent"
		$s6="getproperty <q>[public]::AV_STATUS"
		$s7="getproperty <q>[private]NULL::statusHandler"
		$s8="callpropvoid <q>[public]::addEventListener, 2 params"
		$s9="getproperty <q>[private]NULL::stream"
		$s10="getlex <q>[public]flash.media::AVSegmentedSource"
		$s11="pushstring \"http://\""
		$s12="method <q>[public]::void <q>[private]NULL::statusHandler=(<q>[public]flash.events::AVStatusEvent)(1 params, 0 optional)"
		
		
		$ff1="new AVSegmentedSource()"
		$ff2="new AVStream(this.source)"
		$ff3=".source.addEventListener(AVStatusEvent.AV_STATUS,this.statusHandler)"
		$ff4=".stream.addEventListener(AVStatusEvent.AV_STATUS,this.statusHandler)"
		$ff5=".load(\"http://\""
		$ff6="statusHandler(param1:AVStatusEvent) : void"

	condition:
		(all of ($s*)) or (all of ($ff*))

}

rule CVE_2016_0989_2523 
 {
	meta:
		sigid = 2523
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0989"
		category = "Malware & Botnet"
		risk = 25
		
	strings:
		$a1 = " = new DisplacementMapFilter("
$a2 = " = new BitmapData("
$a3 = " = new Point("
$a4 = " = new TextField("
$a5 = ".mapBitmap ="
$a6 = ".rotationY = 65535;"
$a7 = ".filters = ["

	condition:
		all of them

}

rule CVE_2016_0988_2522 
 {
	meta:
		sigid = 2522
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0988"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "tf.removeTextField();"
		$a1 = "createTextField("
		$a2 = "= intfunc;"
		$a3 = { 73 65 74 49 6e 74 65 72 76 61 6c 28 74 66 2c 22 [1-10] 22 2c 22 2c 7b 76 61 6c 75 65 4f 66 3a } //setInterval(tf,"AAA",",{valueOf:

	condition:
		all of them

}

rule CVE_2015_5574:Memory_Corruption_2065 
 {
	meta:
		sigid = 2065
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_5574:Memory-Corruption"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a=".createTextField("
$b="new Object();"
$c=".valueOf = function()"
$d=".removeTextField();"
$e="return"
$f="new Color("
$g=".setTransform("

	condition:
		all of them

}

rule CVE_2015_5573:Type_Confusion_2064 
 {
	meta:
		sigid = 2064
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-5573:Type-Confusion"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a="requestheader:Array"
$b="super();"
$c="new URLStream()"
$d="new Object()"
$e="toString = function():*"
$f="throw"
$g=".requestHeaders ="
$h=".load("
$i="catch("
$j=".objectEncoding"

	condition:
		all of them

}

rule SWF_Exploit_CVE_2018_15978_118871 
 {
	meta:
		sigid = 118871
		date = "2018-11-13 10:35 AM"
		threatname = "SWF.Exploit.CVE-2018-15978"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
$ffd1="extends Sprite"
$ffd2="super()"
$ffd3=":TextField = new TextField()"
$ffd4=".htmlText = \"<img src=\\\"\\\"></img>\""
$ffd5="wordWrap = true"
$ffd6="new BitmapData(1,1).draw(_loc1_,new Matrix())"

$swfd1="flash.display::Sprite"
$swfd2="findpropstrict <q>[public]flash.text::TextField"
$swfd3="coerce <q>[public]flash.text::TextField"
$swfd4="pushstring \"<img src=\"\"></img>"
$swfd5="setproperty <q>[public]::htmlText"
$swfd6="setproperty <q>[public]::wordWrap"
$swfd7="findpropstrict <q>[public]flash.display::BitmapData"
$swfd8="pushbyte 1"
$swfd9="constructprop <q>[public]flash.display::BitmapData, 2 params"
$swfd10="findpropstrict <q>[public]flash.geom::Matrix"
condition:
all of ($ffd*) or all of ($swfd*)
}

rule CVE_2015_5133_1920 
 {
	meta:
		sigid = 1920
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-5133"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a= ":ContentElement"
$b = "new FontDescription();"
$c = ".scrollRect"
$d = /.fontName\s?=/
$e = /.fontLookup\s?=\s?FontLookup\.EMBEDDED_CFF;/
$f = "new ElementFormat("
$g = "new TextElement("
$h = "new TextBlock();"
$i = /.content\s?=/
$j = ".createTextLine("
$k = "addChild("

	condition:
		all of them

}

rule CVE_2017_2934_3518 
 {
	meta:
		sigid = 3518
		date = "2017-01-09 16:33 PM"
		threatname = "CVE_2017_2934"
		category = "Adware"
		risk = 70
		
	strings:
		$hex1 = {41 54 46 BA B5 00 FF 79 FF 24 00 0D}
		$s1 = "pushstring \"main\""
		$s2 = "setproperty <q>[public]::x"
		$s3 = "pushstring \"left\""
		$s4 = "pushstring \"loading...\""
		$s5 = "callproperty <q>[public]::load, 1 params"
		$s6 = "pushstring \"Got it!\""
		$s7 = "indpropstrict <q>[public]::addChild"

	condition:
		all of them

}

rule CVE_2016_7855_3381 
 {
	meta:
		sigid = 3381
		date = "2016-11-02 14:39 PM"
		threatname = "CVE_2016_7855"
		category = "Malware & Botnet"
		risk = 90
		
	strings:
		$const0 = "IDataOutput" ascii
		$const1 = "IDataInput" ascii
		$const2 = "IExternalizable" ascii
		$const3 = "writeExternal" ascii
		$const4 = "readExternal" ascii
		$const5 = "ByteArray" ascii
		$const6 = "writeObject" ascii
		$const7 = "readObject" ascii
		$const8 = "objectEncoding" ascii
		$re1 = /setproperty <q>[public]::position/
		$re2 = /callpropvoid <q>[public]::writeObject/
		$re3 = /getlex <q>[public]::ArgumentError/
		$re4 = /findpropstrict <q>[public]flash.net::registerClassAlias/

	condition:
		all of them

}

rule SWF_Exploit_CVE_2016_4228_126142 
 {
	meta:
		sigid = 126142
		date = "2023-07-05 07:02 AM"
		threatname = "SWF.Exploit.CVE-2016-4228"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$h1 = "action: DefineFunction getter_free()"
$h2 = "String:\"removeMovieClip\""
$h3 = "String:\"flash\""
$h4 = "String:\"geom\""
$h5 = "String:\"Rectangle\""
$h6 = "String:\"addProperty\""
$h7 = "SetMember"
$h8 = "GetMember"
$s1 = "String:\"createEmptyMovieClip\""
$s2 = "String:\"attachMovie\""
$s3 = "String:\"duplicateMovieClip\""
condition:
all of ($h*) and 1 of ($s*)
}

rule SWF_Exploit_CVE_2016_4228_3005988 
 {
	meta:
		sigid = 3005988
		date = "2023-09-08 09:26 AM"
		threatname = "SWF.Exploit.CVE-2016-4228"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
	$a0 = "String:\"createEmptyMovieClip\""
	$a1 = "String:\"scrollRect\""
	$a2 = "String:\"ASnative\""
	$a3 = "String:\"removeMovieClip\""
	$a4 = "String:\"getter_free\""
	$a5 = "String:\"addProperty\" "
	condition:
	all of them
}

rule CVE_2015_5570:UAF_2063 
 {
	meta:
		sigid = 2063
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-5570:UAF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "flash.media.AVSegmentedSource"
		$b = ":Array"
		$c = "new AVSegmentedSource("
		$d = "new Object("
		$e = ".toString"
		$f = "function():String"
		$g = ".setSubscribedTags("
		$h = ".setCuePointTags("
		$i = ".dispose()"

	condition:
		all of them

}

rule CVE_2015_5552_1915 
 {
	meta:
		sigid = 1915
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5552"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "Error: Unknown tag:"
$a1 = "DEFINEVIDEOSTREAM defines id 0000 (0 frames, 0x0 smoothed codec 0x00)"

	condition:
		all of them

}

rule SWF_Exploit_CVE_2016_1105_124358 
 {
	meta:
		sigid = 124358
		date = "2021-10-20 16:28 PM"
		threatname = "SWF.Exploit.CVE-2016-1105"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "\" String:\"flash\" String:\"display\" String:\"BitmapData\""
$str2 = "Push Lookup:9 (\"BitmapData\")"
$str3 = "String:\"FileReference\" String:\"call\""
$str4 = "Push int:1000 int:1000 int:2 register:2 Undefined"
$str5 = "Push register:1 int:1 int:200 int:2204"
$str6 = "Push Lookup:5 (\"name\") int:1 register:1 Lookup:8 (\"unwatch\")"
$str7 = "String:\"ASnative\" String:\"unwatch\""

condition:
all of them
}

rule CVE_2015_3134_1874 
 {
	meta:
		sigid = 1874
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_3134"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "builtin::split"
$a1 = "flash.net::URLVariables"
$a2 = "flash.events::NetStatusEvent"
$a3 = "flash.net::NetStream"
$a4 = "[packageinternal]::statusChanged"
$a5 = ".flv"
$a6 = "[public]::play"
$a7 = "flash.media::Video"
$a8 = "NetStream.Play.Stop"

	condition:
		all of them

}

rule CVE_2015_3130_1879 
 {
	meta:
		sigid = 1879
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_3130"
		category = "Adware"
		risk = 0
		
	strings:
		$a0 = "return 100000;"
		$a1 = "var s = 1;"
		$a2 = "= new Array();"
		$a3 = "var n = {valueOf:gl};"
		$a4 = ".length = n;"
		$a5 = ".sortOn("
		
		$b0 = "Push int:100000"
		$b1 = "Push Lookup:0 (\"s\") int:1"
		$b2 = "Push Lookup:11 (\"n\") Lookup:12 (\"valueOf\") Lookup:13 (\"gl\")"
		$b3 = "Push Lookup:15 (\"sort"
		$b4 = "Push Lookup:14 (\"length\")"

	condition:
		all of ($a*) or all of ($b*)

}

rule CVE_2015_0340_1645 
 {
	meta:
		sigid = 1645
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-0340"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "flash.net::URLRequestHeader"
		$a1 = "flash.net::URLRequest"
		$a2 = "\\0d\\0aContent-Disposition:form-data; name="
		$a3 = "\\0d\\0aContent-Type: "
		$a4 = "multipart/form-data"
		$a5 = "::requestHeaders"
		$a6 = "flash.net::sendToURL"

	condition:
		all of them

}

rule CVE_2016_1098_2728 
 {
	meta:
		sigid = 2728
		date = "2016-05-12 13:41 PM"
		threatname = "CVE-2016-1098"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s1 = "callproperty <q>[public]::createDefaultContentFactory, 0"
$s2 = "callproperty <q>[namespace]com.adobe.tvsdk.mediacore:ContentFactory::retrieveAdPolicySelector, 1"
$s3 = "getproperty <q>[public]::pSDK"

$f1 = "PSDK.pSDK;"
$f2 = ":ContentFactory"
$f3 = "createDefaultContentFactory();"
$f4 = ".retrieveAdPolicySelector("

	condition:
		all of ($s*) or all of ($f*)

}

rule SWF_Exploit_PurpleFoxEK_122460 
 {
	meta:
		sigid = 122460
		date = "2022-03-02 11:59 AM"
		threatname = "SWF.Exploit.PurpleFoxEK"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$Str1= "public]flash.external::ExternalInterface"
$Str2= "pushstring \"execScript\""
$Str3= "pushstring \"eval(unescape('eval%28function%28p"
$Str4= "35%3FString.fromCharCode%28c"
$Str5= "%7C%7C%7C%7C%7C%7C%7Cvar%7C%7C%7C%7C"
$Str6= "%7C0x7FFE0000%7Cbreak%7Cpush%7Cwhile%7C0"
$Str7= "%7CJScript%7C0x82%7C0xFF000000%7C0xFFFF00%7C"
$Str8= "%7CVirtualProtect%7Cexport%7C"
$Str9= "%27.split%28%27%7C%27%29%2C0%2C%7B%7D%29%29"
$Str10= "pushstring \"JScript.Encode\""

condition:
all of them
}

rule CVE_2016_7875_3533 
 {
	meta:
		sigid = 3533
		date = "2017-01-10 16:14 PM"
		threatname = "CVE-2016-7875"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$str1=/::BitmapData.{10,100}pushint 65535/s
$str2=/::Rectangle.{10,100}pushshort 1940/s
$str3=/::Point.{10,100}pushshort 128/s
$str4=/::Array.{,30}pushnull/s
$str5="findpropstrict <q>[public]flash.filters::GradientGlowFilter"
$str6=":DisplayObjectContainer"
$str7=":InteractiveObject"
$str8="getlex <q>[public]flash.events::EventDispatcher"

	condition:
		all of them

}

rule CVE_2017_3058_3709 
 {
	meta:
		sigid = 3709
		date = "2017-04-11 17:06 PM"
		threatname = "CVE_2017_3058"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$str1 = "flash.media::Sound"
		$str2 = "flash.utils::ByteArray"
		$str3 = "length"
		$str4 = "position"
		$str5 = "loadPCMFromByteArray"
		$str6 = "play"
		$str7 = "loadCompressedDataFromByteArray"
		$str8 = "initproperty <q>[public]::snd"
		$str9 = "getproperty <q>[public]::bytes"

	condition:
		(all of them)

}

rule CVE_2017_2997_3626 
 {
	meta:
		sigid = 3626
		date = "2017-03-14 18:29 PM"
		threatname = "CVE_2017_2997"
		category = "Adware"
		risk = 50
		
	strings:
		$const0 = "AuditudeSettings" ascii
		$const1 = "com.adobe.tvsdk.mediacore.metadata" ascii
		$const2 = "clone" ascii
		$const3 = "customParameters" ascii
		$const4 = "reproduce\\velociraptorReproduce\\src"

	condition:
		(all of them)

}

rule CVE_2017_2995_3574 
 {
	meta:
		sigid = 3574
		date = "2017-03-14 18:29 PM"
		threatname = "CVE_2017_2995"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = "<q>[public]flash.display::Sprite"
$a1 = "<q>[public]flash.utils::ByteArray"
$a2 = "pushbyte 0"
$a3 = "<q>[public]::defaultObjectEncoding"
$a4 = "<q>[public]flash.system::Worker"
$a5 = "<q>[public]::current"
$a6 = "::createMessageChannel, 1 params"
$a7 = "::send, "
$a8 = "}::receive,"
$a9 = "<q>[public]::Array"
$a10 = "<q>[public]flash.events::EventDispatcher"
$a11 = "} // END TRY (HANDLER:"
$a12 = "pushscope"
$a13 = "setslot"
$a14 = "returnvoid"
$a15 = "<q>[public]::Object"
$a17 = "flash.display::DisplayObjectContainer"
$a18 = "initproperty <q>[public]::"

	condition:
		all of them

}

rule CVE_2015_3103_1725 
 {
	meta:
		sigid = 1725
		date = "2016-12-13 06:52 AM"
		threatname = "CVE-2015-3103"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = "system.Worker"
		$a2 = "system.WorkerDomain"
		$a3 = "Worker.current.terminate()"
		$a4 = "WorkerDomain.current.createWorker(loaderInfo.bytes)"
		$a5 = ".start();"
		$a6 = "Worker.current.isPrimordial" //checks for if is a main threat or created thread
		
		$b1 = "<q>[public]flash.system::Worker"
		$b2 = "getproperty <q>[public]::current"
		$b3 = "callpropvoid <q>[public]::terminate"
		$b4 = "<q>[public]flash.system::WorkerDomain"
		$b5 = "getproperty <q>[public]::current"
		$b6 = "getlex <q>[public]::loaderInfo"
		$b7 = "getproperty <q>[public]::bytes"
		$b8 = "callproperty <q>[public]::createWorker"
		$b9 = "callpropvoid <q>[public]::start"
		$b10 = "getproperty <q>[public]::isPrimordial"

	condition:
		all of ($a*) or all of ($b*)

}

rule CVE_2014_0581_1575 
 {
	meta:
		sigid = 1575
		date = "2016-12-13 06:47 AM"
		threatname = "CVE_2014_0581"
		category = "Malware & Botnet"
		risk = 40
		
	strings:
		$a = /\(\(\(+/
		$b = /\)\)+/
		$c = ")?+"
		$d = "::RegExp"

	condition:
		all of them

}

rule CVE_2016_7879_3492 
 {
	meta:
		sigid = 3492
		date = "2016-12-13 22:09 PM"
		threatname = "CVE_2016_7879"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "__proto__" ascii
		$const1 = "__constructor__" ascii
		$const2 = "NetConnection" ascii
		$const3 = "connect" ascii
		$const4 = "call" ascii
		$const5 = "NetStream" ascii
		$instr0 = { 07 02 00 00 00 08 02 1c 96 02 00 08 1e 52 }
		$instr1 = { 08 14 4e 96 04 00 08 15 08 17 1c 4f }
		$instr2 = { 08 17 40 87 01 00 0? 17 96 0c 00 02 04 0? 07 02 00 00 00 04 0? }
		$instr3 = { 96 0c 00 02 04 0? 07 02 00 00 00 04 0? 08 ?? 4e 96 02 00 08 ?? 52 }

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_7868_3491 
 {
	meta:
		sigid = 3491
		date = "2016-12-13 22:09 PM"
		threatname = "CVE_2016_7868"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "(?'HH'" ascii
		$const1 = /\(\[\w{4,}\]/ ascii
		$const2 = "(*THEN:" ascii
		$const4 = "\x01)"
		$const5 = "RegExp" ascii
		$instr0 = { 2c 0b 85 63 0? }
		$instr1 = { 62 0? [0-2] 2c ?? a0 85 63 0? }
		$instr2 = { 2c 0d 85 63 0? }
		$instr3 = { 5d 01 62 0? 62 0? [0-2] a0 62 0? a0 4a 01 01 80 01 63 0? }

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*)) and #instr1 > 4

}

rule CVE_2016_7877_3485 
 {
	meta:
		sigid = 3485
		date = "2016-12-13 22:09 PM"
		threatname = "CVE-2016-7877"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const1 = "flash.net"
		$const2 = "IDynamicPropertyOutput"
		$const3 = "DynamicPropertyWriter"
		$const4 = "IDynamicPropertyWriter"
		$const5 = "writeDynamicProperties"
		$const6 = "writeDynamicProperty"
		$const7 = "flash.net::ObjectEncoding"
		$const8 = "findpropstrict <q>[public]::Object"
		$const9 = "constructprop <q>[public]::Object, 0 params"
		$const10 = "constructprop <q>[public]flash.utils::ByteArray, 0 params"
		$const11 = "getlex <q>[public]::DynamicPropertyWriter"
		$const12 = "pushstring \""
		$const13 = "flash.net:IDynamicPropertyOutput::writeDynamicProperty"
		$const14 = "::position"
		$const15 = "::writeObject"
		$const16 = "::DynamicPropertyWriter extends <q>[public]::Object implements"
		$const17 = "<q>[public]::addFrameScript"
		$const18 = "::dynamicPropertyWriter"
		$const19 = "[staticprotected]flash.display:InteractiveObject"
		$const20 = "<q>[public]flash.display::Sprite"
		$const21 = "<q>[public]flash.display::MovieClip"

	condition:
		all of them

}

rule CVE_2016_7874_3483 
 {
	meta:
		sigid = 3483
		date = "2016-12-13 22:09 PM"
		threatname = "CVE-2016-7874"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		//For ffdec output
		$a0 = "import flash.display.Sprite;"
		$a1 = "import flash.net.NetConnection;"
		$a2 = /new\sNetConnection\(\)\.proxyType\s?=\s/
		
		$b0 = "none"
		$b1 = "HTTP"
		$b2 = "CONNECTOnly"
		$b3 = "CONNECT"
		$b4 = "best"
		
		//For swfdump output
		$c0 = "<q>[public]flash.display::Sprite"
		$c1 = "pushscope"
		$c2 = "findpropstrict <q>[public]flash.net::NetConnection"
		$c3 = "constructprop <q>[public]flash.net::NetConnection, 0 params"
		$c4 = "pushstring \""
		$c5 = "setproperty <q>[public]::proxyType"

	condition:
		not any of ($b*) and (all of ($a*) or all of ($c*))

}

rule CVE_2016_7869_3475 
 {
	meta:
		sigid = 3475
		date = "2016-12-13 22:09 PM"
		threatname = "CVE_2016_7869"
		category = "Malware & Botnet"
		risk = 60
		
	strings:
		$a1="coerce_s "
		$a5="pushstring \"([wagl]"
		$a6="iflt ->54"
		$a7="pushstring \"(*PRUNE:"
		$a8="findpropstrict <q>[public]::RegExp"
		$a9="constructprop <q>[public]::RegExp, 1 params"
		$a10="debugfile \"C:\\Users\\ZDI\\Desktop\\prune\\src"
		$a11="convert_i"
		$a12="DOABC \"poc\", lazy load"

	condition:
		all of them

}

rule CVE_2016_7870_3472 
 {
	meta:
		sigid = 3472
		date = "2016-12-13 22:09 PM"
		threatname = "CVE-2016-7870"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "pushstring \"(?'HH'\""
		$b = "pushstring \"([wagl]\""
		$c = "pushstring \"(*SKIP:\""
		$d = "findpropstrict <q>[public]::RegExp"
		$e = "coerce_s"
		$f = "setlocal"
		$g = "pushstring \")\""
		$h = "add"
		$i = "findpropstrict <q>[public]::RegExp"
		$j = "constructprop <q>[public]::RegExp"
		$k = "coerce <q>[public]::RegExp"

	condition:
		all of them

}

rule CVE_2016_7859_3401 
 {
	meta:
		sigid = 3401
		date = "2016-12-13 09:46 AM"
		threatname = "CVE_2016_7859"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "Push register:0 Lookup:2 (\"prototype\")"
		    $str2 = "Push Lookup:8 (\"getNextHighestDepth\")"
		    $str3 = "Push int:6 Lookup:7 (\"_root\")"
		    $str4 = "Push Lookup:10 (\"createTextField\")"
		    $str5 = "Push Lookup:13 (\"removeTextField\")"
		    $str6 = "Push Lookup:16 (\"__constructor__\") int:3 register:8 Lookup:17 (\"addProperty\")"
		    $str7 = " Push int:1 NULL register:1 int:3 Lookup:18 (\"ASSetPropFlags\")"
		    $const0 = "_root" ascii
		    $const1 = "getNextHighestDepth" ascii
		    $const2 = "createTextField" ascii
		    $const3 = "removeTextField" ascii
		    $const4 = "__constructor__"
		    $const5 = "prototype"
		    $const6 = "addProperty"

	condition:
		all of them

}

rule CVE_2016_7868:_SelectionSetFocusUAF_3420 
 {
	meta:
		sigid = 3420
		date = "2016-12-13 07:55 AM"
		threatname = "CVE-2016-7868: SelectionSetFocusUAF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const0 = "removeMovieClip" ascii
$const1 = "getNextHighestDept" ascii
$const2 = "createEmptyMovieClip" ascii
$const3 = "addProperty" ascii
$const4 = "ASnative" ascii

$const5 = "toString"
$const6 = "DefineFunction"
$const7 = "GetVariable"
$const8 = /Push Lookup:\d+\s\("mmc/
$const9 = "CallFunction"
$const10 = /int\:4\sint\:600\sint\:2\sLookup\:\d+\s\("ASnative"\)/ 
$const11 = /Push Lookup:\d+ \("mmc:d"\)/
$const12 = /Lookup:\d\s\("mc"\)/
$const13 = "NewObject"

	condition:
		all of them

}

rule BinaryDataPayloadDetections_2218 
 {
	meta:
		sigid = 2218
		date = "2016-12-13 07:54 AM"
		threatname = "BinaryDataPayloadDetections"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		// ffdec
$a0 = "flash.system.Capabilities"
$a1 = "flash.utils.Endian"
$a2 = "flash.utils.ByteArray"
$a3 = "Capabilities.version.toLowerCase()"
$a4 = ".length < 4"
$a5 = "!= \"win \""  nocase
$a6 = "as Class)()"
$a7 = "new ByteArray()"
$a8  = "Endian.LITTLE_ENDIAN"
$a9 = "] ^ _"

// swfdump 
$b0 = "flash.system::Capabilities"
$b1 = "flash.utils::Endian"
$b2 = "flash.utils::ByteArray"
$b3 = "::toLowerCase"
$b4 = "[public]::length"
$b5 = "pushbyte 4"
$b6 = "pushstring \"win \"" // nocase
$b7 = "::Class"
$b8 = "::Array"
$b9 = "::LITTLE_ENDIAN"
$b10 = "::endian"
$b11 = "bitxor"

	condition:
		(all of ($a*)) or (all of ($b*))

}

rule CVE_2015_7645:_TypeConfusionInWriteExternal_2182 
 {
	meta:
		sigid = 2182
		date = "2016-12-13 07:52 AM"
		threatname = "CVE-2015-7645: TypeConfusionInWriteExternal"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "<q>[public]::writeExternal:NULL"	
$a1 = "flash.utils::ByteArray"
$a2 = "flash.display::Sprite"
$a3 = "flash.utils::IDataInput"
$a4 = "flash.utils::IDataOutput"
$a5 = "implements <q>[public]flash.utils::IExternalizable"
$a6 = "<q>[public]::writeExternal:NULL"

	condition:
		(all of ($a*))

}

rule CVE_2015_5119:_UseAfterFree_1809 
 {
	meta:
		sigid = 1809
		date = "2016-12-13 07:51 AM"
		threatname = "CVE-2015-5119: UseAfterFree"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = ":getDefinitionByName"
		$a1 = ":getQualifiedClassName"
		$a2 = "::Class"
		$a3 = "::Object"
		$a5 = "__AS3__.vec::Vector"
		$a6 = "flash.utils::Endian"
		$a7 = "::LITTLE_ENDIAN"
		$a8 = "::ToByteArray"
		$a9 = "::position"
		$a10 = "KERNEL32.DLL" nocase
		$a11 = ":readUTFBytes"
		$a12 = "flash.system::Capabilities"
		
		$c4 = "::supports64BitProcesses"
		$c5 = "::supports32BitProcesses"
		
		//ffdec based signature
		//Packed flash signature
		$d11 = "\"B\" + \"y\" + \"te\";" 
		$d0 = "\"po\" + \"si\" + \"tion\";" nocase
		$d1 = "\"l\" + \"en\" + \"gth\";" nocase
		$d2 = "write" nocase
		$d3 = "\"ch\" + \"arC\" + (\"ode\" + \"At\");" 
		$d4 = "\"all\" + \"owD\" + (\"om\" + \"ain\");" 
		$d5 = "\"addEve\" + (\"ntLi\" + \"ste\" + \"ner\");"
		$d6 = "\"ad\" + (\"ded\" + \"ToS\" + \"tage\");"
		$d7 = "\"flash.d\" + (\"is\" + \"pla\" + \"y.L\") + \"oader\";"
		$d8 = "\"load\" + (\"By\" + \"tes\");"
		$d9 = "\"ad\" + (\"dCh\" + \"ild\");"
		$d10 = "\"rem\" + (\"oveE\" + (\"ventLis\" + \"tener\"));"
		
		$e0 = /\^\s+param/
		$e1 = "ByteArray"
		$e2 = "ByteArrayAsset"
		//end of packed sig
		
		//Unpacked flash signature
		$f1 = "ByteArray"
		$f2 = "readByte()"
		$f3 = "writeUnsignedInt("
		$f4 = "new Vector.<uint>"
		$f5 = "isDebugger"
		$f6 = "new Array("
		$f7 = ".length"
		$f8 = /\!=\s0/
		
		$g0 = "winmm.dll" nocase
		$g1 = "kernel32.dll" nocase
		$g2 = "ntdll.dll" nocase
		$g3 = "VirtualProtect" nocase
		$g5 = "VirtualAlloc" nocase
		$g6 = "CreateThread" nocase
		$g7 = "memcpy" nocase
		//end of signature
		
		$h0 = ".valueOf"
		$h1 = "new Array("
		$h2 = "push("
		$h3 = "function TryExpl("
		$h4 = ":Vector.<uint>"
		$h5 = ".length"
		$h8 = "isWin"
		$h6 = ".Exec"
		$h7 = "Capabilities.supports"

	condition:
		(all of ($a*) and (any of ($c*))) or ((7 of ($d*)) and all of ($e*)) or ((all of ($f*)) and (any of ($g*))) or (all of ($h*))

}

rule SWF_Exploit_Broxwet_3425 
 {
	meta:
		sigid = 3425
		date = "2016-11-09 14:23 PM"
		threatname = "SWF_Exploit_Broxwet"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "static function EXP_try() : void"
		$s2 = "static function extLoaded(param1:Event) : void"
		$s3 = "= admin_10.rc4_decrypt(admin_11.option_"
		$s4 = "new LoaderContext(false,ApplicationDomain[§_-q§.vari30]));"
		$s5 = "public class admin_4 extends admin_1"
		$s6 = "= Capabilities.os.toUpperCase().search(\"WINDOWS 10\") >= 0;"
		$s7 = "  static function is64(param1:String) : Boolean"

	condition:
		(all of them)

}

rule CVE_2016_7863_3418 
 {
	meta:
		sigid = 3418
		date = "2016-11-08 15:28 PM"
		threatname = "CVE_2016_7863"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "getNextHighestDepth" ascii
		$const1 = "createEmptyMovieClip" ascii
		$const2 = "createTextField" ascii
		$const3 = "variable" ascii
		$const4 = "removeMovieClip" ascii
		$instr0 = { 08 04 1c 96 02 00 08 0? 52 96 04 00 08 0? [6-20] 08 ?? 52 }
		$instr1 = { 96 28 00 08 ?? 07 ?? 00 00 00 07 ?? 00 00 00 07 ?? 00 00 00 07 ?? 00 00 00 06 00 00 00 00 00 00 00 00 08 ?? 07 06 00 00 00 08 06 1c 96 02 00 08 09 52 }
		$instr2 = { 96 02 00 08 ?? 1c 96 04 00 08 ?? 08 ?? 4f }
		$instr3 = { 96 02 00 08 ?? 52 [16-256] 96 02 00 08 ?? 3e }
		$instr4 = { 96 09 00 08 ?? 07 ?? 00 00 00 08 ?? 1c 96 02 00 08 ?? 52 }

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_6984_3297 
 {
	meta:
		sigid = 3297
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6984"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "com.adobe.tvsdk.mediacore" ascii
		$const1 = "createQOSProvider" ascii
		$const2 = "attachMediaPlayer" ascii
		$const3 = "detachMediaPlayer" ascii
		
		$instr0 = {5d 01 66 0166 02 46 03 00 80 04 d5 }
		
		$instr1 = {d1 5d 05 5d 01 66 01 66 02 46 06 004a 05 01 46 07 01 29 }
		
		$instr2 = {d1 46 08 00 29 }
		
		$instr3 = {d1 46 09 00 29 }

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_7855_3370 
 {
	meta:
		sigid = 3370
		date = "2016-10-25 08:28 AM"
		threatname = "CVE_2016_7855"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "IDataOutput" ascii
$const1 = "IDataInput" ascii
$const2 = "IExternalizable" ascii
$const3 = "writeExternal" ascii
$const4 = "readExternal" ascii
$const5 = "ByteArray" ascii
$const6 = "writeObject" ascii
$const7 = "readObject" ascii
$const8 = "objectEncoding" ascii
$instr0 = { d? 30 60 10 d? 61 1c }
$instr1 = { 5d 1e 4a 1e 00 80 1e d? }
$instr2 = { 5d 12 4a 12 00 80 12 d? }
$instr3 = { 5d 1f 2c ?? 60 12 4f 1f 02 }
$instr4 = { d2 24 00 61 20 }
$instr5 = { d? d? 4f 21 01 }
$instr6 = { d? 4f 22 00 }
$instr7 = { d1 6d 01 }
$instr8 = { 5d 06 4a 06 00 82 6d 02 }
$instr9 = { 6c 02 40 19 61 29 }
$instr10 = { d? 30 57 2a d? 30 }
$instr11 = { 60 10 66 1c 66 28 48 }
$instr12 = { 6c ?? 2d ?? [2-64] 60 2a [2-64] 6c 01 [2-64] 46 29 50 ?? 48 }

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_4285_3260 
 {
	meta:
		sigid = 3260
		date = "2016-09-14 10:20 AM"
		threatname = "CVE_2016_4285"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a1 = "= new DRMDeviceGroup();"
		$a2 = "DRMManager.getDRMManager().addToDeviceGroup("

	condition:
		all of them

}

rule CVE_2016_4283_3258 
 {
	meta:
		sigid = 3258
		date = "2016-09-14 10:20 AM"
		threatname = "CVE-2016-4283"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a= "findproperty <q>[public]::"
		$b="findpropstrict"
		$c= "com.adobe.tvsdk.mediacore.metadata::AuditudeSettings"
		$d="constructprop"
		$e="setproperty"
		$f="[public]com.adobe.tvsdk.mediacore.timeline.resolvers::ShimContentResolver"
		$g="pushbyte 2"
		$h="com.adobe.tvsdk.mediacore.timeline::Placement"
		$i="getproperty <q>[public]::prototype"
		$j="findpropstrict <q>[packageinternal]::valueOf_0"
		$k="setproperty <q>[public]::scaleZ"
		$l="findpropstrict <q>[public]com.adobe.tvsdk.mediacore.timeline::Opportunity"
		$m="pushstring"
		$n="TextBlock"
		$o="::resolve"
		$p="pushshort 4660"

	condition:
		all of them

}

rule CVE_2016_4272_3255 
 {
	meta:
		sigid = 3255
		date = "2016-09-13 17:48 PM"
		threatname = "CVE_2016_4272"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$f1 = ".BitmapData(100,100);"
$f2 = ".BitmapData(10,10);"
$f3 = ".filters.DisplacementMapFilter("
$f4 = ".mapBitmap"
$f5 = ".setPixel("
$f6 = ".createTextField("
$f7 = ".removeMovieClip.call("
$f8 = "new NetConnection();"

$s1 = "Push int:100 int:100 int:2 Lookup:2 (\"flash"
$s2 = "Push Lookup:3 (\"display\")"
$s3 = "\"BitmapData\")"
$s4 = "Push int:10 int:10 int:2 Lookup:2 (\"flash\")"
$s5 = "Push Lookup:5 (\"filters\")"
$s6 = "Push Lookup:6 (\"DisplacementMapFilter\")"
$s7 = "(\"mapBitmap\")"
$s8 = "int:1073741823"
$s9 = "Push Lookup:11 (\"createTextField\")"
$s10 = "CallMethod"
$s11 = "Push Lookup:17 (\"removeMovieClip\")"
$s12 = "Push Lookup:18 (\"call\")"
$s13 = "Push int:0 Lookup:19 (\"NetConnection\")"

	condition:
		(all of ($f*)) or (all of ($s*))

}

rule CVE_2016_4280_3252 
 {
	meta:
		sigid = 3252
		date = "2016-09-13 17:48 PM"
		threatname = "CVE_2016_4280"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="Push Lookup:8 (\"NetStream\")"
		$str2="Push Lookup:9 (\"TextSnapshot\")"
		$str3="Push Lookup:1 (\"_global\")"
		$str4="Push int:0 Lookup:10 (\"NetConnection\")"
		$str5="Push NULL int:1 register:3 Lookup:11 (\"connect\")"
		$str6="Push Lookup:13 (\"getCount\")"

	condition:
		all of them

}

rule CVE_2016_4271_3248 
 {
	meta:
		sigid = 3248
		date = "2016-09-13 17:48 PM"
		threatname = "CVE_2016_4271"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "<q>[packageinternal]::pobj:<q>[public]::Object"
		$s2 = "<q>[packageinternal]::darubare:<q>[public]::Object"
		$s3 = "<q>[packageinternal]::attackernameobj:<q>[public]::Object"
		$s4 = "<q>[public]flash.net::URLLoader"
		$s5 = "<q>[public]flash.net::navigateToURL"

	condition:
		all of them

}

rule EITest_Gate_3125 
 {
	meta:
		sigid = 3125
		date = "2016-08-10 21:54 PM"
		threatname = "EITest_Gate"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = "getproperty <q>[public]::ADDED_TO_STAGE"
		$a1 = "pushstring \"f"
		$a2 = "pushstring \"o"
		$a3 = "add"
		$a4 = "pushstring \"C"
		$a5 = "findpropstrict <q>[public]::String"
		$a6 = "charCodeAt"
		$a7 = "getlex <q>[public]flash.external::ExternalInterface"
		$a8 = "getproperty <q>[public]::loaderInfo"
		$a9 = "getproperty <q>[public]::url"
		$a10 = "gourl"
		$a11 = "addChild"
		$a12 = "decode"
		$a13 = "split"
		$a14 = "[public]::decodeToByteArray="

	condition:
		((all of ($a*)) and filesize < 60000)

}

rule CVE_2016_4249_3102 
 {
	meta:
		sigid = 3102
		date = "2016-07-14 14:49 PM"
		threatname = "CVE_2016_4249"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1 = ".arrByteArrays = new Array(99840 * 2)" 
		$a2 = "ByteArray()"
		$a3 = "addEventListener(Event.ADDED_TO_STAGE"
		$a4 = ".length = 256"
		$a5 = ".arrByteArrays[_loc3_].clear()"
		$a6 = "\"valueOf\":"
		$a10 = "writeUnsignedInt(this.cur + 1016);"
		$a7 = ".writeUnsignedInt(this.cur + 1016 * 2)"
		$a8 = "removeEventListener(Event.ADDED_TO_STAGE"
		$a9 = ".writeUnsignedInt(2.290649224E9);"

	condition:
		all of ($a*)

}

rule CVE_2016_4224_3098 
 {
	meta:
		sigid = 3098
		date = "2016-07-14 14:49 PM"
		threatname = "CVE_2016_4224"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a1 = "extends"
		$a2 = "[public]com.adobe.tvsdk.mediacore.timeline.operations::DeleteRangeTimelineOperation{"
		$a3 = "staticconstructor * =()"
		$a4 = "getlocal_0"
		$a5 = "pushscope"
		$a6 = "findpropstrict <multi>{[public]\"\"}::"
		$a7 = "getlex <q>[public]::Object"
		$a8 = "getlex <q>[public]com.adobe.tvsdk.mediacore.timeline.operations::DeleteRangeTimelineOperation"
		$a9 = "newclass [classinfo 00000000 <q>[public]::MyDeleteRangeTimelineOperation]"
		$a10 = "popscope"
		$a11 = "returnvoid"

	condition:
		all of them

}

rule CVE_2016_4182_3070 
 {
	meta:
		sigid = 3070
		date = "2016-07-14 14:49 PM"
		threatname = "CVE_2016_4182"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "E:\\fuzzing\\flash22\\poc\\src\\poc.as="
		$str2 = "E:\\fuzzing\\flash22\\poc\\src;;poc.as"
		$str3 = "com.adobe.tvsdk.mediacore::MediaPlayerItemLoader"
		$str4 = "constructsuper 0 params"
		$str5 = "flash.events::EventDispatcher"
		$str6 = "flash.display::DisplayObjectContainer"

	condition:
		all of them

}

rule CVE_2016_4226_3097 
 {
	meta:
		sigid = 3097
		date = "2016-07-13 07:45 AM"
		threatname = "CVE_2016_4226"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a1 = "this.createEmptyMovieClip("
$a2 = ".func = ASnative(666, 4);"
$a3 = ".removeMovieClip();"

	condition:
		all of them

}

rule CVE_2016_4225_3089 
 {
	meta:
		sigid = 3089
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4225"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$p1 = "extends AdBreakPlacement"
$p2 = "super();"
$p3 = "Event.ADDED_TO_STAGE"
$p4 = "addEventListener("

$s1 = "extends <q>[public]com.adobe.tvsdk.mediacore.timeline.operations::AdBreakPlacement"
$s2 = "constructsuper 0 params"
$s3 = "iffalse ->9"
$s4 = "getlex <q>[public]flash.events::EventDispatcher"
$s5 = "findpropstrict <q>[public]::removeEventListener"
$s6 = "getlex <q>[public]flash.events::Event"

	condition:
		all of ($p*) or all of ($s*)

}

rule CVE_2016_4232_3075 
 {
	meta:
		sigid = 3075
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4232"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "createEmptyMovieClip"
		$a1 = "(\"ColorTransform\")"
		$a2 = "(\"colorTransform\") Lookup:"
		$a3 = /Push Lookup:\d+ \(\"ColorTransform\"\) int:\d+ Lookup:\d+ \(\"/

	condition:
		all of them

}

rule CVE_2016_4185_3072 
 {
	meta:
		sigid = 3072
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4185"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="go=(<q>[public]flash.events::Event = null)(1"
		$str2="<q>[public]::Evil, 0 params"
		$str3="<q>[public]::Main=()(0 params, 0 optional"
		$str4="00000000 <q>[public]::Evil]"
		$str5="0000 as \"Main\""

	condition:
		all of them

}

rule CVE_2016_4142_2938 
 {
	meta:
		sigid = 2938
		date = "2016-06-15 11:45 AM"
		threatname = "CVE_2016_4142"
		category = "Malware & Botnet"
		risk = 70
		
	strings:
		$str1 = "root.removeMovieClip.call(_global.c[i])"
		$str2 = "_root.removeMovieClip.call(_global.l3)"
		$str3 = "tf.tabStops = l3"
		$str4 = "__Packages.Testi"

	condition:
		all of them

}

rule CVE_2016_4154_2941 
 {
	meta:
		sigid = 2941
		date = "2016-06-15 11:45 AM"
		threatname = "CVE_2016_4154"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="poc()"
		$str2="ShimContentResolver"
		$str3="pushbyte 0"
		$str4="Placement"
		$str5="Metadata"
		$str6="Opportunity"
		$str7="obj"
		$str8="pm"
		$str9="mt"

	condition:
		all of them

}

rule CVE_2016_4174_3067 
 {
	meta:
		sigid = 3067
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4174"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "TextField()"
		$str2 = "StyleSheet()"
		$str3 = "htmlText="
		$str4 = "nc:NetConnection = new NetConnection()"
		$str5 = "addEventListener(\"exitFrame\",handler2)"
		$str6 = "addEventListener(\"added\",handler4)"
		$str7 = "handler_index4 = handler_index4 + 1"

	condition:
		all of them

}

rule CVE_2016_4188_3061 
 {
	meta:
		sigid = 3061
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4188"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a = "findpropstrict"
		$b = "com.adobe.tvsdk.mediacore.events::TimedEvent"
		$c = "pushbyte 0"
		$d = "constructprop"
		$e = "coerce"
		$f = "setlocal_1"
		$g = "getlocal_1"
		$h = "getproperty"
		$i = "::description"

	condition:
		all of them

}

rule KaixinGenericDetector_2976 
 {
	meta:
		sigid = 2976
		date = "2016-06-16 18:35 PM"
		threatname = "KaixinGenericDetector"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = "flash.system::Security"
		$a1 = "::allowDomain"
		$a2 = "flash.system::LoaderContext"
		$a3 = "::currentDomain"
		$a4 = "allowLoadBytesCodeExecution"
		$a5 = "::readUnsignedInt"
		$a6 = "flash.utils::Endian"
		$a7= "::LITTLE_ENDIAN"
		$a8 = "::position"
		$a9 = "::getQualifiedClassName"
		$a10 = "systemmanager"
		$a11 = "bitxor"
		$a12 = "::addEventListener"

	condition:
		all of them

}

rule CVE_2016_4146_2973 
 {
	meta:
		sigid = 2973
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4146"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "action: Push int:0 Lookup:13 (\"Sound\")"
$a1 = "action: Push register:4 Lookup:11 (\"onLoadStart\")"
$a2 = "action: Push Lookup:14 (\"removeMovieClip\")"
$a3 = "action: Push Lookup:15 (\"call\")"

	condition:
		all of them

}

rule CVE_2016_4154_2972 
 {
	meta:
		sigid = 2972
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4154"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "findpropstrict <q>[public]com.adobe.tvsdk.mediacore.timeline.resolvers::ShimContentResolver"
$a1 = "pushbyte 0"
$a2 = "callproperty <q>[public]::resolve, 1 params"

	condition:
		all of them

}

rule CVE_2016_4149_2970 
 {
	meta:
		sigid = 2970
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4149"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "flash.display::Sprite"
		$a1 = "::addEventListener"
		$a2 = "com.adobe.tvsdk.mediacore.timeline.operations::AdBreakPlacement"
		$a3 = "::removeEventListener"
		$a4 = "::adBreak"
		$a6 = "::adBreak:<q>[public]::Object = true"

	condition:
		all of them

}

rule CVE_2016_4133_2952 
 {
	meta:
		sigid = 2952
		date = "2016-06-15 11:45 AM"
		threatname = "CVE_2016_4133"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$Str = "function test()"
		  $str1 = "\\\\g6553\\\\g65536!@"
		  $str2 = "this.textArea.text = pat;"
		  $str3 = "new RegExp(pat);"
		  $str4 = "this.textArea.text +"
		  $str5 = "RegExp Finished!!!!!!!!!!!"

	condition:
		all of them

}

rule CVE_2016_4121_2950 
 {
	meta:
		sigid = 2950
		date = "2016-06-15 11:45 AM"
		threatname = "CVE_2016_4121"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="(?>(?&t)c|(?&t))(?(DEFINE)(?<t>a|b(*PRUNE)c))(a|)\\\\1{2,3}b\\\\g{36}"
		$str2="(?>(?&t)c|(?&t))(?(DEFINE)(?<t>a|b"
		$str3=".exec("

	condition:
		all of them

}

rule CVE_2016_1108_2758 
 {
	meta:
		sigid = 2758
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1108"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="Push Lookup:1 (\"_global\")"
		$str2="Push Lookup:2 (\"MySound\")"
		$str3="Push Lookup:3 (\"TextField\") register:2"
		$str4="Push int:10 int:10 int:0 int:0 int:1320 Lookup:4 (\"tf\") int:6 Lookup:5 (\"_root\")"
		$str5="Push Lookup:6 (\"createTextField\")"
		$str6="Push Lookup:7 (\"l3\") register:3"
		$str7="Push int:0 Lookup:8 (\"Sound\")"
		$str8="Push Lookup:11 (\"addProperty\")"
		$str9="Push Lookup:12 (\"ahah\") register:3 int:2 register:4 Lookup:13 (\"loadSound\")"
		$str10="Push Lookup:14 (\"call\")"
		$str11="Push Lookup:16 (\"removeMovieClip\")"

	condition:
		all of them

}

rule CVE_2016_1101_2748 
 {
	meta:
		sigid = 2748
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1101"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "[public]::LoadImage extends <q>[public]flash.display::Sprite"
$a1 = "[public]flash.text::TextField"
$a2 = "LoadImage::loader:<q>[public]flash.display::Loader"
$a3 = "[public]flash.display::Bitmap"
$a4 = "findpropstrict <q>[public]::addChild"

	condition:
		all of them

}

rule CVE_2016_1106_2741 
 {
	meta:
		sigid = 2741
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1106"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "Push Lookup:0 (\"in func\")"
		$str2 = "Push Lookup:1 (\"t\") int:1 Lookup:1 (\"t\") int:2 Lookup:3 (\"this\")"
		$str3 = "Push Lookup:5 (\"func\")"
		$str4 = "Push Lookup:6 (\"a\") int:2 Lookup:1 (\"t\")"
		$str5 = "Push Lookup:8 (\"a,b\") int:106"

	condition:
		all of them

}

rule ContainerDetect_2813 
 {
	meta:
		sigid = 2813
		date = "2016-05-16 17:02 PM"
		threatname = "ContainerDetect"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$l0 = "flash.display.Sprite"  // binaryData can be accessed if class inherits from Sprite
		$l1 = "flash.system.Capabilities"// check for installed fp version
		$l2 = "flash.utils.Endian"// here, used for making shellcode in litle-endian fromat
		$l3 = "flash.display.Loader"// Loader to load the shellcode in mem
		
		$a0 = "super()"
		$a1 = "if(stage)"
		$a2 = "addEventListener("
		$a3 = ".indexOf("
		$a4 = "uint(_"
		$a5 = "while("
		$a6  = "^ _loc"
		$a7 = "& 255"
		$a8 = ".readUnsignedInt("
		$a9 = "break"
		$a10 = ".position"
		$a11 = "&& _loc"
		$a12= ".loadBytes"
		$a13 = "addChild"
		$a14 = "extends ByteArrayAsset"

	condition:
		(all of ($a*)) and (3 of ($l*))

}

rule CVE_2016_1097_2790 
 {
	meta:
		sigid = 2790
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1097"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a1 = "var ps:PSDK = PSDK.pSDK;"
		$a2 = "ps.release();"
		$a3 = "ps.createAuditudeSettings();"

	condition:
		all of them

}

rule CVE_2016_1018_2620 
 {
	meta:
		sigid = 2620
		date = "2016-04-19 14:04 PM"
		threatname = "CVE_2016_1018"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="<q>[public]::MyShellCode=MyShellCode"
		$a2="exports 0000 as "//poc\"
		$a3="<q>[public]::poc=poc"
		$a4="<q>[public]::m_Obj:<q>[public]::MyShellCode"
		$a5="<q>[public]::m5981:<q>[public]::uint"
		$a6="<q>[public]::m5967:<q>[public]::uint"
		$a7="<q>[public]::m24:<q>[public]::uint = 7105636"
		$a8="<q>[private]NULL::UrlLoaderComplete=(<q>[public]flash.events::"
		$a9="<q>[private]NULL::LoaderCount64kbForWrite"
		$a10="pushstring "//HoHo!"

	condition:
		all of them

}

rule CVE_2016_1017_2610 
 {
	meta:
		sigid = 2610
		date = "2016-04-19 14:04 PM"
		threatname = "CVE_2016_1017"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "arrMovieClips"
		$string2 = "new LoadVars()"
		$string3 = ".watch"
		$string4 = ".removeMovieClip()"
		$string5 = ".decode.call"
		$swf1 = /(\"arrMovieClips\")/
		$swf2 = /(\"LoadVars\")/
		$swf3 = /(\"removeMovieClip\")/
		$swf4 = /(\"watch\")/
		$swf5 = /(\"decode\")/
		$swf6 = /(\"call\")/

	condition:
		all of ($string*) or all of ($swf*)

}

rule CVE_2016_0993_2540 
 {
	meta:
		sigid = 2540
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0993"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$val1 = "0x80000010;"
$a1 = "= new ByteArray();"
$a2 = ".length = "
$a3 = "ApplicationDomain.currentDomain.domainMemory = "
$a4 = ":uint = "
$a5 = "si32("
$a6 = "- 0x7FFFFFF0)"

	condition:
		all of them

}

rule CVE_2016_0963_2511 
 {
	meta:
		sigid = 2511
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0963"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1 = "obj =new BitmapData(16383,16383,true);"
$a2 = "p2.y = 0xffffffff;"
$a3 = "obj.hitTest(p1,0xFC000000,obj,p2,0xFC000000);"

	condition:
		all of them

}

rule CVE_2016_0961_2509 
 {
	meta:
		sigid = 2509
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0961"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$swft1="GlowFilter"
		$swft2="coerce_a"
		$swft3="setproperty"
		$swft4="[staticprotected]flash.events:EventDispatcher}::quality"
		$swft5="[staticprotected]flash.events:EventDispatcher}::blurY"
		$swft6="findpropstrict"
		$swft7="[staticprotected]flash.events:EventDispatcher}::BitmapData"
		$swft8="pushshort 200"
		$swft9="pushdouble"
		$swft10="1797693134862309900000000"
		$swft11="[staticprotected]flash.events:EventDispatcher}::y"
		$swft12="pushshort 32767"
		$swft13="[staticprotected]flash.events:EventDispatcher}::applyFilter, 4 params"
		$ff1="GlowFilter"
		$ff2=".quality = 32767"
		$ff3=".blurY = 51"
		$ff4="BitmapData(200,200)"
		$ff5=".y = 1.79769313486231e+308"
		$ff6=".width = 32767"
		$ff7=".applyFilter("

	condition:
		(all of ($swft*)) or (all of ($ff*))

}

rule SWF_AnglerEK_L_2503 
 {
	meta:
		sigid = 2503
		date = "2016-04-01 07:00 AM"
		threatname = "SWF_AnglerEK_L"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="flash.utils.ByteArray"
		$a2="\"a\" + \"ddEv\" + \"e"
		$a3="+ \"Listene\" + \"r"
		$a4="= \"writeByte"
		$a5="\"c\" + \"urrentDomain"
		$a6="\"gotoAndPlay"
		$a7="\"a\" + \"llowDomain"
		$a8="\"flash.display.Loader"
		$a9="\"load\" + this.ert2fgfny6563trgtry"

	condition:
		all of them

}

rule CVE_2016_0979_2462 
 {
	meta:
		sigid = 2462
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0979"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$sd1 = "constructprop <multi>{[private]NULL,[private]NULL,[public]\"\",[packageinternal]\"\",[public]flash.display,[public]flash.geom,[protected]poc,[staticprotected]poc,[staticprotected]flash.display:Sprite,[staticprotected]flash.display:DisplayObjectContainer,[staticprotected]flash.display:InteractiveObject,[staticprotected]flash.display:DisplayObject,[staticprotected]flash.events:EventDispatcher}::Point, 0 params"
		$sd2 = "pushbyte 3"
		$sd3 = "pushint 2147483647"
		$sd4 = "callpropvoid <multi>{[private]NULL,[private]NULL,[public]\"\",[packageinternal]\"\",[public]flash.display,[public]flash.geom,[protected]poc,[staticprotected]poc,[staticprotected]flash.display:Sprite,[staticprotected]flash.display:DisplayObjectContainer,[staticprotected]flash.display:InteractiveObject,[staticprotected]flash.display:DisplayObject,[staticprotected]flash.events:EventDispatcher}::setTo, 2 params"
		$sd5 = "callpropvoid <multi>{[private]NULL,[private]NULL,[public]\"\",[packageinternal]\"\",[public]flash.display,[public]flash.geom,[protected]poc,[staticprotected]poc,[staticprotected]flash.display:Sprite,[staticprotected]flash.display:DisplayObjectContainer,[staticprotected]flash.display:InteractiveObject,[staticprotected]flash.display:DisplayObject,[staticprotected]flash.events:EventDispatcher}::hitTest, 5 params"

	condition:
		all of them

}

rule CVE_2016_0984_2461 
 {
	meta:
		sigid = 2461
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0984"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "[public]::soundPCM=soundPCM("
$a1 = "findpropstrict <q>[public]flash.media::Sound"
$a2 = "callproperty <multi>{[private]soundPCM"
$a3 = "::writeByte"
$a4 = "[private]FilePrivateNS:soundPCM"
$a5 = "}::loadPCMFromByteArray,"
$a6 = "CATCH(<q>[public]::Error <q>[packageinternal"

	condition:
		all of them

}

rule CVE_2016_0982_2441 
 {
	meta:
		sigid = 2441
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0982"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "global.ASnative(900,1).call("
		$a1 = "swfRoot.createTextField("
		$a2 = { 2e 61 64 64 50 72 6f 70 65 72 74 79 28 [4-10] 66 75 6e 63 74 69 6f 6e 28 29 } // .addProperty(xxxxxxfunction()
		$a3 = ".removeTextField();"
		
		$b0 = "String:\"removeTextField\""
		$b1 = "String:\"createTextField\""
		$b2 = "String:\"ASnative\""
		$b3 = "String:\"addProperty\""
		$b4 = "int:1 int:900 int:2 Lookup:1 (\"_global\")"

	condition:
		all of ($a*) or all of ($b*)

}

rule CVE_2016_0974_2438 
 {
	meta:
		sigid = 2438
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2016-0974"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$string1 = ".removeTextField()"
		$string2 = "new LoadVars()"
		$string3 = ".decode"
		$string4 = ".createTextField"
		$string5 = ".watch"
		$swf1 = /Push Lookup:\d+ (\"removeTextField\")/
		$swf2 = /Push Lookup:\d+ (\"decode\")/
		$swf3 = /Push Lookup:\d+ (\"createTextField\")/
		$swf4 = /Lookup:\d+ \(\"LoadVars\"\)/
		$swf5 = /Lookup:\d+ \(\"watch\"\)/

	condition:
		all of ($string*) or all of ($swf*)

}

rule CVE_2015_8636_2324 
 {
	meta:
		sigid = 2324
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-8636"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1="var _loc2_:Number = this.camH * scaleY;"
		$a2="var _loc3_:Number = this.camW * scaleX;"
		$a3="var _loc4_:Number = this.sH / _loc2_;"
		$a4="var _loc5_:Number = this.sW / _loc3_;"
		$a5="this.x2 = _loc3_ / 2 * _loc5_;"
		$a6="this.y2 = _loc2_ / 2 * _loc4_;"
		$a7="this.scaleX2 = _loc5_;"
		$q0="[public]::parent"
		$q1="[public]::visible"
		$q2="[public]::camH"
		$q3="[public]::scaleY"
		$q4="[public]::myBitmapData"
		$q5="[public]::lock"
		$q6="[public]::fillRect"
		$q7="[public]::unlock>[public]::stage"
		$q8="[public]::draw"
		$q9="[public]::filters"
		$q10="[public]::transform"
		$q11="[public]::colorTransform"
		$q12="[public]::REMOVED_FROM_STAGE"
		$q13="[public]::removeChild"
		$q14="[public]::dispose"

	condition:
		all of ($a*) or all of ($q*)

}

rule CVE_2015_8648_2320 
 {
	meta:
		sigid = 2320
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8648"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="getNextHighestDepth"
		$str2="createEmptyMovieClip"
		$str3="YUKI"
		$str4="fromCharCode"
		$str5="substr"
		$str6="swfRoot"
		$str7="addProperty"
		$str8="removeMovieClip"
		$str9="setMask"
		$str10="flash"
		$str11="external"
		$str12="ExternalInterface"

	condition:
		all of them

}

rule CVE_2015_8449_2297 
 {
	meta:
		sigid = 2297
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8449"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = /"Push Lookup:\d+ \(\"createTextField\"\)/
		$a1 = /"Push Lookup:\d+ \(\"crateEmptyMovieClip\"\)/
		$a2 = /"Push Lookup:\d+ \(\"removeTextField\"\)/
		$a3 = "GetVariable"
		$a4 = "GetMember"
		$a5 = "RemoveSprite"
		$a6 = "int:136849448"

	condition:
		all of them

}

rule CVE_2015_8414_2294 
 {
	meta:
		sigid = 2294
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8414"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$s1 = /Push Lookup:\d+ \("createTextField"\)/
		$s2 = /Lookup:\d+ \("valueOf"\)/
		$s6 = /Lookup:\d+ \("func"\)/
		$s3 = /Push Lookup:\d+ \("removeMovieClip"\)/
		$s4 = /Push Lookup:\d+ \("createEmptyMovieClip"\)/
		$s5 = /Push Lookup:\d+ \("thiz"\)/
		
		$f1 = ".createTextField("
		$f2 = ".createEmptyMovieClip"
		$f3 = ".valueOf = function()"
		$f4 = ".removeMovieClip"

	condition:
		(all of ($s*)) or (all of ($f*))

}

rule CVE_2015_8418_2292 
 {
	meta:
		sigid = 2292
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8418"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1="pushstring \"\\((?&abc))(?P<abc)\""
		$s2="pushstring \"|\""
		$s3="findpropstrict"
		$s4="[public]::RegExp"
		$s5="constructprop"

	condition:
		all of them

}

rule CVE_2015_8439:_Type_Confusion_2290 
 {
	meta:
		sigid = 2290
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-8439: Type Confusion"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s1 = ".connect("
		$s2 = "SharedObject.getRemote("
		$s3 = "ASSetPropFlags("
		$s4 = ".watch("
		$s5 = ".send("
		$s6 = "2261634.509803921;"

	condition:
		all of them

}

rule CVE_2015_8407_2289 
 {
	meta:
		sigid = 2289
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8407"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$s1 = "flash.net.SharedObject"
		$s2 = "SharedObject.getLocal("
		$s5 = ":Array;"
		$s3 = ".length = 16777215;"
		$s4 = ".send.apply(null,this."

	condition:
		all of them

}

rule CVE_2015_8438:_Flash_Heap_Overflow_2287 
 {
	meta:
		sigid = 2287
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-8438: Flash Heap Overflow"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s1 = "flash.external.ExternalInterface.call("
$s2 = "new XML("
$s3 = ".length < 536870912)"
$s4 = ".length < 1073741824)"
$s5 = ".firstChild.attributes."
$s6 = ".toString();"

	condition:
		all of them

}

rule CVE_2015_8437:_Flash_UAF_2286 
 {
	meta:
		sigid = 2286
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-8437: Flash UAF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s1 = "new Array(8192);"
		$s2 = ".length)"
		$s3 = ".createEmptyMovieClip("
		$s4 = ".getNextHighestDepth("
		$s5 = ".addProperty(\"focusEnabled\""
		$s6 = ".removeMovieClip("
		$s7 = "Selection.setFocus("

	condition:
		all of them

}

rule CVE_2015_8457_2284 
 {
	meta:
		sigid = 2284
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8457"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "[public]::ADDED_TO_STAGE"
		$a1 = "[public]flash.media::AVSegmentedSource"
		$a2 = "flash.media::StageVideo"
		$a3 = "[public]::getServerName"
		$a4 = "[public]::DASH"
		$a5 = "pushstring \".m3u8\""
		$a6 = "[public]::HLS"
		$a7 = "pushstring \"http://\""
		$a8 = "[public]::getServerName="
		$a9 = "[public]::getPort="

	condition:
		all of ($a*)

}

rule CVE_2015_7660_2184 
 {
	meta:
		sigid = 2184
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_7660"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="createTextField("
		$str2=".toString()"
		$str3="this.createEmptyMovieClip(\"l3\",2,1,1,10,10)"
		$str4="_global.Number = MyMovieClip"
		$str5="class MyMovieClip extends MovieClip"
		$str6="_global.l3.removeMovieClip()"
		$str7=".removeTextField()"
		
		$swf1="(\"createTextField\")"
		$swf2="(\"toString\")"
		$swf3="(\"_global\")"
		$swf4="(\"createEmptyMovieClip\")"
		$swf5="(\"l3\")"
		$swf6="Number"
		$swf7="coolNumber"
		$swf8="removeMovieClip"
		$swf9="removeTextField"

	condition:
		(all of ($str*)) or (all of ($swf*))

}

rule CVE_2015_7652:_UAF_2179 
 {
	meta:
		sigid = 2179
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-7652: UAF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s0 = ".toString = function()"
$s1 = "this.createTextField("
$s2 = "_global.mc.createTextField("
$s3 = "return \"pixel\";"
$s4 = "= new TextFormat();"
$s5 = ".tabStops ="
$s6 = ".gridFitType"

$p1 = "(\"createTextField\")"
$p2 = "(\"_global\")"
$p3 = "(\"toString\")"
$p4 = "(\"pixel\")"
$p5 = "(\"TextFormat\")"
$p6 = "(\"gridFitType\")"

	condition:
		all of ($s*) or all of ($p*)

}

rule CVE_2015_7655_2176 
 {
	meta:
		sigid = 2176
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_7655"
		category = "Malware & Botnet"
		risk = 25
		
	strings:
		$a0 = "_global.Number = MyNumber;"
$a1 = "extends"
$a2 = "createTextField(\"tf\""
$a3 = "_global.oldNumber = _global.Number;"
$a4 = "_global.aTextFields = aTextFields;"

$b0 = "class MyNumber extends"
$b1 = { 5f 67 6c 6f 62 61 6c 2e [0-15] 72 65 6d 6f 76 65 54 65 78 74 46 69 65 6c 64 28 29 3b } // _global.????removeTextField();

$c0 = { 50 75 73 68 20 72 65 67 69 73 74 65 72 3a [1-3] 20 4c 6f 6f 6b 75 70 3a [1-3] 20 28 22 4e 75 6d 62 65 72 22 29 20 4c 6f 6f 6b 75 70 3a [1-3] 20 28 22 4d 79 4e 75 6d 62 65 72 22 29 } // Push register:1 Lookup:0 (\"Number\") Lookup:1 (\"MyNumber\")
$c1 = { 50 75 73 68 20 69 6e 74 3a [1-3] 20 4c 6f 6f 6b 75 70 3a [1-3] 20 28 22 63 72 65 61 74 65 54 65 78 74 46 69 65 6c 64 22 29 } // Push int:6 Lookup:12 (\"createTextField\")
$c2 = { 50 75 73 68 20 4c 6f 6f 6b 75 70 3a [1-3] 20 28 22 6f 6c 64 4e 75 6d 62 65 72 22 29 20 4c 6f 6f 6b 75 70 3a [1-3] 20 28 22 5f 67 6c 6f 62 61 6c 22 29 } // Push Lookup:14 (\"oldNumber\") Lookup:13 (\"_global\")
$c3 = { 50 75 73 68 20 4c 6f 6f 6b 75 70 3a [1-3] 20 28 22 72 65 6d 6f 76 65 54 65 78 74 46 69 65 6c 64 22 29 } //Push Lookup:5 (\"removeTextField\")
$c4 = "extend"

	condition:
		(all of ($a*) and all of ($b*)) or all of ($c*)

}

rule Win32_Zurgop_2146 
 {
	meta:
		sigid = 2146
		date = "2016-03-01 08:00 AM"
		threatname = "Win32_Zurgop"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1={BA 83 EB 00 00 49 41 49 41 49[4]46 66 8B C9 4E 46 E6 01 8A F6 4E 46 57 5F[12]64 8F 02 83 C4 04}
$str2={BB 6C 00 00 00 89 5D E4 B8 09 9A 00 00}
$str3={B9 BF 85 00 00 B8 16 00 00 00 89 45 C4 BB E0 C6 00 00}

	condition:
		all of them

}

rule CVE_2015_7645_2123 
 {
	meta:
		sigid = 2123
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_7645"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "extends <q>[public]flash.display::Sprite"
		$a1 = {22 74 5c 78 7b 31 30 30 7d 7b 33 2c 7d 21 22}
		$a2 = "findpropstrict <q>[public]::RegExp"
		$a3 = "constructprop <q>[public]::RegExp, 2 params"
		$a4 = "getlex <q>[public]flash.display::InteractiveObject"
		
		$b0 = "flash.display.Sprite;"
		$b1 = ":String = null;"
		$b2 = {22 74 5c 78 7b 31 30 30 7d 7b 33 2c 7d 21 22}

	condition:
		all of ($a*) or all of ($b*)

}

rule CVE_2015_7645_2122 
 {
	meta:
		sigid = 2122
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_7645"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "_SafeStr_10 extends <q>[public]flash.utils::ByteArray"
		$a1 = "::MainTimeline extends <q>[public]flash.display::MovieClip"
		$a2 = "setproperty <q>[public]::allowCodeImport"
		$a3 = "coerce <q>[public]flash.net::URLRequest"
		$a4 = "::configureListeners=(<q>[public]flash.events::IEventDispatcher"
		$a5 = "pushstring \"MyExt2\""
		
		$b0 = ".addEventListener(MouseEvent.CLICK,this.clickHandler);"
		$b1 = ":URLRequest = new URLRequest(\"MyExt.bin\");"
		$b2 = "configureListeners(param1:IEventDispatcher) : void"
		$b3 = "param1:IOErrorEvent) : void"
		$b4 = "bytesLoaded=\" + param1.bytesLoaded + \" bytesTotal=\" + param1.bytesTotal);"
		$b5 = "writeExternal"
		$b6 = ".writeByte(0);"
		$b7 = "catch(e:Error)"

	condition:
		all of ($a*) or all of ($b*)

}

rule CVE_2015_7631_2111 
 {
	meta:
		sigid = 2111
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_7631"
		category = "Malware & Botnet"
		risk = 25
		
	strings:
		$a0 = "new GroupElement("
$a1 = "new TextBlock();"
$a2 = ".content =" 
$a3 = ".createTextLine"
$a4 = "addEventListener(Event.REMOVED,"
$a5 = ".validity = \"static\""
$a6 = ".recreateTextLine("

$b0 = "constructprop <q>[public]flash.text.engine::GroupElement"
$b1 = "constructprop <q>[public]flash.text.engine::TextBlock"
$b2 = "setproperty <q>[public]::content"
$b3 = "callproperty <q>[public]::createTextLine"
$b4 = "getproperty <q>[public]::REMOVED"
$b5 = "callpropvoid <q>[public]::addEventListener"
$b6 = "pushstring \"static\""
$b7 = "setproperty <q>[public]::validity"
$b8 = "callpropvoid <q>[public]::recreateTextLine"

	condition:
		all of ($a*) or all of ($b*)

}

rule CVE_2015_7645_2110 
 {
	meta:
		sigid = 2110
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_7645"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a1 = "<q>[public]flash.display::Sprite"
		$a2 = "<q>[public]flash.utils::ByteArray"
		$a3 = "callproperty <multi>{[private]externalizable"
		$a4 = "<q>[public]flash.utils::IExternalizable"
		$a5 = "writeExternal(<q>[public]flash.utils::IDataOutput"
		$a6 = "var <q>[public]::writeExternal:"
		
		$b1 = "flash.utils.IExternalizable;"
		$b2 = "function writeExternal("
		$b3 = ":IDataOutput"
		$b4 = "var writeExternal"
		$b5 = "extends Sprite"
		$b6 = "new ByteArray()"
		$b7 = ".writeObject("

	condition:
		(all of ($a*)) or (all of ($b*))

}

rule CVE_2015_5567:_memory_corruption_2078 
 {
	meta:
		sigid = 2078
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-5567: memory_corruption"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1 = "::Object"
$a2 = "::dispose"
$a3 = "aAVSS"
$a4 = "length"
$x = "::setSubscribedTags"
$y = "setCueTags"
$z = "SetSubscribedTagsForBackgroundManifest"

	condition:
		(all of ($a*) and $x) or (all of ($a*)  and $y) or (all of ($a*)  and $z)

}

rule CVE_2015_5563_1963 
 {
	meta:
		sigid = 1963
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5563"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$ff1 =  "external.ExternalInterface.call"
		$ff2 = "new Array"
		$ff3 = "1094861636"
		$ff4 = "1094795587"
		$ff5 = "1094795520"
		$ff6 = "new lash.filters.GlowFilter"
		$ff7 = "0:"
		$ff8 = "2:"
		
		$swfd1 = "ExternalInterface"
		$swfd2 = "Array"
		$swfd3 = "1094861636"
		$swfd4 = "1094795587"
		$swfd5 = "1094795520"
		$swfd6 = "GlowFilter"
		$swfd7 = "(\"0\")"
		$swfd8 = "(\"2\")"

	condition:
		(all of ($ff*)) or (all of ($swfd*))

}

rule CVE_2015_3107_1922 
 {
	meta:
		sigid = 1922
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_3107"
		category = "Malware & Botnet"
		risk = 40
		
	strings:
		$a="SharedObject.getLocal"
		$b="ASSetPropFlags"
		$c="new NetConnection("
		$d=".flush("
		$e=".connect.call("
		$f="flash.display.BitmapData"
		$g="flash.filters.DisplacementMapFilter("
		$h="setInterval("

	condition:
		all of them

}

rule CVE_2015_5124_1921 
 {
	meta:
		sigid = 1921
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5124"
		category = "Malware & Botnet"
		risk = 40
		
	strings:
		$a=".trackAsMenu"
$b=".current.createWorker"
$c=".createMessageChannel"
$d=".addEventListener"
$e=".setSharedProperty"
$f=".start("
$g="new NetMonitor("
$h=".gotoAndStop"
$i="System.gc("

	condition:
		all of them

}

rule CVE_2015_5550_1916 
 {
	meta:
		sigid = 1916
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5550"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "action:     Push Lookup:1 (\"removeMovieClip\")"
$a1 = "action: Push Lookup:5 (\"createEmptyMovieClip\")"
$a2 = "action: Push Lookup:10 (\"swapDepths\")"

	condition:
		all of them

}

rule CVE_2015_3122_1877 
 {
	meta:
		sigid = 1877
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_3122"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a="NetConnection("
$b=".__proto__"
$c=".connect.call("
$d="SharedObject.getLocal("
$e="flash.display.BitmapData("
$f="ASSetPropFlags("
$g=".data"

	condition:
		all of them

}

rule CVE_2015_3104_1731 
 {
	meta:
		sigid = 1731
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3104"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "constructprop <q>[public]flash.utils::ByteArray"
$a1 = "pushint 1094795585"
$a2 = "callpropvoid <q>[public]::writeUnsignedInt"
$a3 = "constructprop <q>[public]flash.display::ShaderJob"
$a4 = "constructprop <q>[public]flash.display::Shader"
$a5 = "setproperty <q>[public]::byteCode"
$a6 = "setproperty <q>[public]::shader"

$b0 = ":ByteArray = new ByteArray();"
$b1 = ".writeUnsignedInt(1094795585);"
$b2 = ":ShaderJob = new ShaderJob();"
$b3 = ":Shader = new Shader();"
$b4 = ".byteCode ="

	condition:
		all of ($a*) or all of ($b*)

}

rule CVE_2015_3108_1730 
 {
	meta:
		sigid = 1730
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3108"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "coerce <q>[public]flash.utils::ByteArray"
$a1 = "callpropvoid <q>[public]::writeByte,"
$a2 = "callpropvoid <q>[public]::writeUnsignedInt,"
$a3 = "findpropstrict <q>[public]flash.display::Shader"
$a4 = "setproperty <q>[public]::byteCode"
$a5 = "findpropstrict <q>[public]flash.display::BitmapData"
$a6 = "pushbyte 0"
$a7 = "multiply"
$a8 = "callpropvoid <q>[public]::setPixel,"
$a9 = "getlex <q>[public]flash.events::EventDispatcher"

	condition:
		all of them

}

rule Xss_due_to_UTF_conversion_1536 
 {
	meta:
		sigid = 1536
		date = "2016-02-01 08:00 AM"
		threatname = "Xss_due_to_UTF_conversion"
		category = "Adware"
		risk = 50
		
	strings:
		$a = "UnicodeUtils"
		$b = "utf8ToUtf16"

	condition:
		$a and $b

}

rule CVE_2015_3092_1699 
 {
	meta:
		sigid = 1699
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3092"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$str1= "FRAMELABEL \"ShaderRegisters\""
$str2= "callpropvoid <q>[public]::writeByte,"
$str3= "constructprop <q>[public]flash.display::ShaderJob"
$str4= "[staticprotected]ShaderRegisters"
$str5= "staticprotected]flash.display:DisplayObjectContainer"
$str6= "<q>[public]::ShaderRegisters]"
$str7= "exports 0000 as \"ShaderRegisters\""

	condition:
		all of them

}

rule CVE_2015_3038_1659 
 {
	meta:
		sigid = 1659
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3038"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "findpropstrict <q>[public]flash.utils::ByteArray"
	$a1 = "constructprop <q>[public]flash.utils::ByteArray"
	$a2 = "setproperty <q>[public]::shareable"
	$a3 = "callproperty <q>[public]::createWorker"
	$a4 = "callpropvoid <q>[public]::setSharedProperty"
	$b = "callpropvoid <q>[public]::start"

	condition:
		all of ($a*) and not $b

}

rule CVE_2015_0346_1655 
 {
	meta:
		sigid = 1655
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-0346"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "getlocal_"
		$a1 = "<q>[public]::Lso extends <q>[public]flash.display::Sprite{"
		$a2 = ":LSO_PATH:<q>[public]::String"
		$a3 = "::void <q>[public]::openManager="
		$a4 = "getproperty <q>[public]::SETTINGS_MANAGER"
		$a5 = "findpropstrict <q>[public]::Lso"
		$a6 = "flash.system::Security"
		$a7 = "::writeLSO="
		$a8 = "astype <q>[public]flash.net::SharedObject"
		$a9 = "getlex <q>[public]flash.external::ExternalInterface"

	condition:
		all of them

}

rule CVE_2016_7867_3479 
 {
	meta:
		sigid = 3479
		date = "2016-12-13 22:09 PM"
		threatname = "CVE_2016_7867"
		category = "Malware & Botnet"
		risk = 70
		
	strings:
		$const2 = "debug [register 00="
		$const3 = "debug [register 01="
		$const4 = "debug [register 05="
		$const5 = "1:1 constructsuper 0 params"
		$const6 = "pushstring \"([jack]"
		$const7 = "pushstring \"(*MARK:"
		$const8 = "setlocal r6"
		$const9 = "inclocal_i r9"
		$const10 = "findpropstrict <q>[public]::RegExp"
		$const11 = "constructprop <q>[public]::RegExp, 1 params"
		$const12 = "coerce <q>[public]::RegExp"
		$const13 = "getlex <q>[public]flash.events::EventDispatcher"
		$const14 = "getlex <q>[public]flash.display::DisplayObjectContainer"
		$const15 = "iflt ->49"
		$const16 = "pushstring \"(?'HH'"

	condition:
		all of them

}

rule SWF_Exploit_CVE_2018_5007_118502 
 {
	meta:
		sigid = 118502
		date = "2018-07-18 10:07 AM"
		threatname = "SWF.Exploit.CVE-2018-5007"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
$ff1="= new NetConnection();"
$ff2="= undefined;"
$ff3="this.watch("
$ff4="this.func);"
$ff5="this.__proto__"
$ff6=".connect.call(this,null)"
$ff7="new String("
$ff8=".__proto__ = {}"
$ff9=".__proto__.__constructor__ = String"
$ff10="super()"

$swfd1="(\"NetConnection\")"
$swfd2="Push Undefined"
$swfd3="uri"
$swfd4="watch"
$swfd5="CallMethod"
$swfd6="__proto__"
$swfd7="connect"
$swfd8="call"
$swfd9="String"
$swfd10="NewObject"
$swfd11="StoreRegister"
$swfd12="prototype"
$swfd13="__constructor__"
$swfd14="in func"
$swfd15="watchts"

condition:
all of ($ff*) or all of ($swfd*)
}

rule SWF_Exploit_CVE_2018_12825_118659 
 {
	meta:
		sigid = 118659
		date = "2018-08-14 10:18 AM"
		threatname = "SWF.Exploit.CVE-2018-12825"
		category = "Malware & Botnet"
		risk = 0
		Description = "Rule to detect https:// protocol in an ActiveX bin (presumably embedding SWF content)." 
Disclaimer = "This rule is provided for informational purposes only."
Author = "Adobe PSIRT" 
Date = "27/03/2018" 
Distribution = "Microsoft MAPP Program Only" 
Revision = 1
	strings:
$https_access = { 68 00 74 00 74 00 70 00 73 00 3A 00 2F 00 2F 00 }
condition:
(uint32be(0) == 0x6EDB7CD2 and uint32be(4) == 0x6DAECF11) and $https_access
}

rule CVE_2018_12824_118635 
 {
	meta:
		sigid = 118635
		date = "2018-08-10 21:38 PM"
		threatname = "CVE_2018_12824"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
$comm_data_hex = {43 4F 4D 4D 00 00 00 0F 00 80 00 00 00 08 78 9C 63 74 84 00 00 07 2C 01 C9}
    
condition:
$comm_data_hex
}

rule CVE_2018_4878_117768 
 {
	meta:
		sigid = 117768
		date = "2018-02-05 08:14 AM"
		threatname = "CVE_2018_4878"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$header = "rdf:RDF" ascii wide
$title = "Adobe Flex" ascii wide
$pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" ascii wide
$s1 = "URLRequest" ascii wide
$s2 = "URLLoader" ascii wide
$s3 = "myUrlLoader" ascii wide
$s4 = "loadswf" ascii wide
condition:
($header) and ($title) and ($pdb) and ( 3 of ($s*))
}

rule CVE_2016_4152_2947 
 {
	meta:
		sigid = 2947
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4152"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str0="var obj:ShimContentResolver = new ShimContentResolver(0);"
		$str1="var mi:MediaPlayerItem;"
		$str2="var cl:ContentResolverClient;"
		$str3="obj.configure(mi,cl)"

	condition:
		all of them

}

rule CVE_2016_1107_2753 
 {
	meta:
		sigid = 2753
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1107"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$re1 = /var \w+ = new \w+\(\);/
$s1 = "_global."
$s2 = ".valueOf = "
$s3 = "= _root.createEmptyMovieClip("
$s4 = "_global."
$s5 = "._rotation = _global"
$s6 = "removeMovieClip()"

	condition:
		all of them

}

rule SWF_Exploit_CVE_2016_4228_123411 
 {
	meta:
		sigid = 123411
		date = "2022-03-02 11:59 AM"
		threatname = "SWF.Exploit.CVE-2016-4228"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str0 = "this.createEmptyMovieClip"
$str1 = ".scrollRect"
$str2 = "flash.geom.Rectangle"
$str3 = "flash.geom"
$str4 = ".addProperty(\"Rectangle\""
$str5 = "ASnative(900,405)"

condition : (all of them)
}

rule SWF_Exploit_CVE_2016_4227_123413 
 {
	meta:
		sigid = 123413
		date = "2021-06-25 11:07 AM"
		threatname = "SWF.Exploit.CVE-2016-4227"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str0 = "this.createEmptyMovieClip"
$str1 = "Selection.setFocus"
$str2 = "({toString:"
$str3 = "new TextFormat()"

condition : (all of them) and  filesize < 1KB
}

rule CVE_2014_0588_1576 
 {
	meta:
		sigid = 1576
		date = "2016-12-13 07:51 AM"
		threatname = "CVE-2014-0588"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "flash.utils::ByteArray"
		$b = /setproperty\s\<q\>\[public\]\:\:shareable/
		$c = /callpropvoid\s\<q\>\[public\]\:\:setSharedProperty/
		$d = /pushstring\s\"(lzma|zlib)\"/
		$e = /callpropvoid\s\<q\>\[public\]\:\:uncompress/

	condition:
		all of them

}

rule CVE_2014_0569:_IntegerOverflowInCasi32_1544 
 {
	meta:
		sigid = 1544
		date = "2016-12-13 07:45 AM"
		threatname = "CVE-2014-0569: IntegerOverflowInCasi32"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a = "flash.system::ApplicationDomain"
		$b = "flash.utils::ByteArray"
		$c = "getproperty <q>[public]::currentDomain"
		$d = "setproperty <q>[public]::domainMemory"
		$e = "::atomicCompareAndSwapLength"
		$f = /avm2\.intrinsics\.memory::casi32,\s\d\sparams/

	condition:
		all of them

}

rule CVE_2015_7645_2208 
 {
	meta:
		sigid = 2208
		date = "2016-12-13 06:45 AM"
		threatname = "CVE_2015_7645"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		// swfdump based signature
		$a0 = "<q>[private]NULL::"
		$a1= "flash.utils::ByteArray"
		$a2 = "::VERSION"
		$a3 = "init=()"
		$a4 = "newclass [classinfo"
		$a5 = "::ByteArrayAsset"
		$a6 = "flash.utils"
		$a7 = "TRY {"
		$a8 = "CATCH(<q>[public]::Error"
		$a9 = "<q>[public]::RegExp"
		$a10 = "pushstring \"pl\""
		$a11 = "pushstring \"a\""
		$a12 = "pushstring \"ce\""
		$a13 = "pushstring \"re\""
		$a14 = "bitxor"
		
		// ffed based signature
		$b0 = "getDefinitionByName" // runtime class registeration
		$b1 = "\"push\""
		$b2 = "new RegExp(para" // regex based modification to properties
		$b3 = "\"pl\",\"a\",\"ce\",\"re\""
		$b4 = "extends ByteArrayAsset" // handle to binary data
		$b5 = "flash.system.Capabilities"
		$b6 = "flash.utils.ByteArray"
		$b7 = "Capabilities.version.toLowerCase()"
		$b8 = ".length < 4"
		$b9 = "\"win "
		$b10 = "as Class)()"
		$b11 = /param\d\s(\+|\^)\sparam\d/

	condition:
		(all of ($a*)) or (all of ($b*))

}

rule SWF_CVE_2016_6987_AccessibilitySendEventUAF_3312 
 {
	meta:
		sigid = 3312
		date = "2016-10-11 23:30 PM"
		threatname = "SWF_CVE_2016_6987_AccessibilitySendEventUAF"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "arrMovieClips" ascii
		$const1 = "valueOf" ascii
		$const2 = "Accessibility" ascii
		$const3 = "sendEvent" ascii
		$instr0 = {8e 0c 00 66 75 6e 63 00 00 00 04 2a 00 ff 00}
		$instr1 = {1c 96 02 00 04 02 4e 96 02 00 08 02 52 17 }
		$instr2 = {96 0E 00 08 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 08 06 40}
		$instr3 = {96 04 00 08 0A 08 00 1C 96 02 00 08 00 1C 96 02 00 08 01 ?? ?? ??}
		$instr4 = {96 06 00 08 0C 08 0D 08 0E 1C 96 05 00 07 01 0000 00 43 3C}
		$instr5 = {96 02 00 08 0A 1C 96 04 00 08 0F 08 10 1C 96 0200 08 11 4E 4F}

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_6982_PSDKEventDispatchMemCor_3299 
 {
	meta:
		sigid = 3299
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6982_PSDKEventDispatchMemCor"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "PSDK\x19com.adobe.tvsdk.mediacore" ascii
		$const1 = "PSDKEventDispatcher"
		$const2 = "pSDK\x10createDispatcher"
		
		// var i0:PSDK = PSDK.pSDK;
		$instr0 = {5d 01 66 01 66 02 80 01 d5}
		$instr1 = {d1 46 03 00 80 04 d6}
		$instr3 = {d1 d2 46 05 01 80 06 d7}
		$instr4 = {d3 46 07 00 29}

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) // FWS
		and (all of ($const*)) 
		and (all of ($instr*))

}

rule CVE_2016_4227_3076 
 {
	meta:
		sigid = 3076
		date = "2016-10-05 06:51 AM"
		threatname = "CVE_2016_4227"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = /Push Lookup:1 \(\".{,10}\"\) int:\d+ Lookup:\d+ \(\".{,10}\"\) int:\d+ Lookup:\d+ \(\"this\"\)/
		$a1 = /Push Lookup:\d+ \(\"createEmptyMovieClip\"\)/
		$a2 = /Push Lookup:\d+ \(\".{,10}\"\) Lookup:\d+ \(\"Selection\"\)/
		$a3 = /Push Lookup:\d+ \(\"setFocus\"\)/
		$a4 = /Push Lookup:\d+ \(\"toString\"\) Lookup:\d+ \(\".{,10}\"\)/

	condition:
		all of them

}

rule CVE_2015_7654:_UAF_2186 
 {
	meta:
		sigid = 2186
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-7654: UAF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$s1 = "new flash.filters.ConvolutionFilter();"
$s2 = "new Array();"
$s3 = ".createEmptyMovieClip("
$s4 = "new Sound("
$s5 = ".toString = function()"
$s6 = ".removeMovieClip();"
$s7 = "new flash.display.BitmapData("
$s8 = ".attachSound("

$p1 = "ConvolutionFilter"
$p2 = "createEmptyMovieClip"
$p3 = "aConvoMatrix"
$p4 = "Sound"
$p5 = "toString"
$p6 = "_global"
$p7 = "my_sound"
$p8 = "removeMovieClip"
$p9 = "BitmapData"
$p10 = "attachSound"

	condition:
		all of ($s*) or all of ($p*)

}

rule CVE_2015_7663_2173 
 {
	meta:
		sigid = 2173
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-7663"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "[staticprotected]spark.components:SkinnableContainer,[staticprotected]spark.components.supportClasses:SkinnableContainerBase,[staticprotected]spark.components.supportClasses:SkinnableComponent,[staticprotected]mx.core:UIComponent,[staticprotected]mx.core:FlexSprite,[staticprotected]flash.display:Sprite,[staticprotected]flash.display:DisplayObjectContainer,[staticprotected]flash.display:InteractiveObject,[staticprotected]flash.display:DisplayObject,[staticprotected]flash.events:EventDispatcher,[public]mx.charts,[public]mx.controls,[public]mx.core,[public]spark.core}::progressBar"

	condition:
		#a0 > 4

}

rule CVE_2015_6682_2072 
 {
	meta:
		sigid = 2072
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_6682"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = ":Main=Main/Main()"
		$a1 = "flash.text::TextField"
		$a2 = "flash.media::Video"
		$a3 = "flash.net::NetConnection"
		$a4 = "flash.events::NetStatusEvent"
		$a5 = "Main::getMeta"
		$a6 = "[public]::onSeekPoint"
		$a7 = "flash.net::URLStream"
		$a8 = ".flv"
		$a9 = "flash.media::Video"
		$a10 = "[public]::writeUnsignedInt,"

	condition:
		all of them

}

rule CVE_2015_3127:UAF_1820 
 {
	meta:
		sigid = 1820
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3127:UAF"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a="SharedObject.getLocal"
		$b="ASSetPropFlags"
		$c=".data.length"
		$d="flush("
		$e=".push.call("
		$f="new flash.display.BitmapData("

	condition:
		all of them

}

rule SWF_Exploit_CVE_2016_1105_123408 
 {
	meta:
		sigid = 123408
		date = "2022-03-02 11:59 AM"
		threatname = "SWF.Exploit.CVE-2016-1105"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$str0 = {74 68 69 73 2E 77 61 74 63 68 [0-2] 28 [0-2] 22 6E 61 6D 65}
$str1 = {5F 67 6C 6F 62 61 6C 2E 41 53 6E 61 74 69 76 65 [0-2] 28 32 32 30 34 [0-2] 2C 32 30 30 [0-2] 29 [0-2] 28 74 68 69 73 29}
$str2 = {74 68 69 73 2E 75 6E 77 61 74 63 68 [0-2] 28}
$str3 = "flash.display.BitmapData"
condition: (all of them)
}

rule SWF_Exploit_CVE_2019_8070_119938 
 {
	meta:
		sigid = 119938
		date = "2019-09-10 09:23 AM"
		threatname = "SWF.Exploit.CVE_2019_8070"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "import flash.display.Sprite;"
		$str2 = "import flash.media.StageVideo;"
		$str3 = "= new TextField();"
		$str4 = ".x = 100;"
		$str5 = ".y = 100;"
		$str6 = ":Sprite = new Sprite();"
		$str7 = "= PSDK.pSDK;"
		$str8 = ".createDefaultMediaPlayerItemConfig();"
		$str9 = ".addEventListener(-4096,"
		$str10 = "= new StageVideo();"
		$str11 = "= new MediaPlayerView("
		$str12 = "String.fromCharCode("
		$str13 = ".indexOf(\"undefined\",0);"
		$str14 = ".charAt(Infinity);"
		$str15 = ".replace(undefined,undefined);"
		$str16 = ".setObject(\"NFKC\","
condition:
		(all of them)
}

rule Exploit_CVE_2015_5119_2189 
 {
	meta:
		sigid = 2189
		date = "2016-03-01 08:00 AM"
		threatname = "Exploit_CVE_2015_5119"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = "extends ByteArrayAsset" 
		$a1 = "flash.utils.ByteArray"
		$a2 = "new ByteArray();"
		$a3 = "] + param" 
		$a4 = "flash.utils.Endian" 
		$a5 = "new Array()"
		$a6 = ".readInt()"
		$a7 = ".readUTFBytes("
		$a8 = ".valueOf = function():int" 
		$a9 = "new Vector.<Object>"
		$a10 = "Capabilities.version.toLowerCase"

	condition:
		all of them

}

rule SWF_Exploit_CVE_2017_3082_116511 
 {
	meta:
		sigid = 116511
		date = "2017-06-13 10:11 AM"
		threatname = "SWF_Exploit_CVE_2017_3082"
		category = "Malware & Botnet"
		risk = 100
		sigsweb_link = "http://signatures.corp.zscaler.com/tickets/116493"
z_intel_link = "http://z-intel.corp.zscaler.com/threat-ticket-info/1227842"
	strings:
$s1 = "getlex <q>[public]flash.globalization::LocaleID"
$s2 = "getlocal_1"
$s3 = "pushstring \"i-default\""
$s4 = "callpropvoid <q>[public]::determinePreferredLocales, 3 params"
condition:
all of them
and @s1 < @s2 and @s2 < @s3 and @s3 < @s4
and $s4 in (@s1 .. @s1 + 200)
}

rule CVE_2017_3079_116509 
 {
	meta:
		sigid = 116509
		date = "2017-06-13 10:12 AM"
		threatname = "CVE_2017_3079"
		category = "Malware & Botnet"
		risk = 40
		
	strings:
$str1= "BitmapData"
$str2="Sprite"
$str3="beginBitmapFill"
$str4="graphics"
$str5="drawTriangles"
$str6="pushbyte 3"
$str7="pushbyte -61"
$str8="pushdouble 0.300000"
$str9="pushdouble 0.100000"
condition:
(all of them)
}

rule CVE_2017_3079_116508 
 {
	meta:
		sigid = 116508
		date = "2017-06-13 05:13 AM"
		threatname = "CVE_2017_3079"
		category = "Malware & Botnet"
		risk = 40
		
	strings:
$str1 = "Bitmap"
$str2 = "Shape"
$str3="Matrix"
$str4="ColorTransform"
$str5="shader"
$str6="8x8linear"
$str7="BitmapData"
$str8="transform"
$str9="drawWithQuality"
$str10="pushdouble 0.600000"
$str11="pushdouble 1.200000"
$str12="pushdouble -0.300000"
$str13="pushdouble -0.700000"
$str14="pushdouble 0.500000"
condition:
(all of them)
}

rule CVE_2017_3070_3778 
 {
	meta:
		sigid = 3778
		date = "2017-05-09 19:38 PM"
		threatname = "CVE_2017_3070"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "flash"
		$const1 = "display"
		$const2 = "ConvolutionFilter"
		$const3 = "Rectangle"
		$const4 = "filters"
		$const5 = "Filter"
		
		$sprite = "Sprite"
		$movie_clip = "MovieClip"
		
		$si1 = "findpropstrict <q>[public]flash.filters::ConvolutionFilter"
		$si2 = "pushbyte 3"
		$si3 = "pushbyte -87"
		$si4 = "pushbyte 64"
		$si5 = "pushbyte -10"
		$si6 = "pushbyte 70"
		$si7 = "pushbyte -79"
		$si8 = "pushbyte 29"
		$si9 = "pushbyte -113"
		$si10 = "pushbyte 110"
		$si11 = "pushbyte -76"
		$si12 = "newarray 9"
		$si13 = "pushfalse"
		$si14 = "pushint"
		$si15 = "pushdouble"
		$si16 = "constructprop <q>[public]flash.filters::ConvolutionFilter, 9 params"
		$si17 = "newarray"
		$si18 = "initproperty <q>[public]::filters"
		$si19 = "getlocal_"
		$si20 = "findpropstrict <q>[public]flash.geom::Rectangle"
		$si21 = "pushshort -254"
		$si22 = "pushbyte -62"
		$si23 = "pushbyte 1"
		$si24 = "pushshort 200"
		$si25 = "constructprop <q>[public]flash.geom::Rectangle, 4 params"
		$si26 = "initproperty <q>[public]::scrollRect"
		$si27 = "returnvoid"
		$mi1 = "Push Lookup:11 (\"filters\") double:"
		$mi2 = "int:-43 int:16 int:78 int:55 int:68 int:-84 int:3 int:115 int:-125 int:9"
		$mi3 = "InitArray"
		$mi4 = "Push int:3 int:3 int:9 Lookup:4 (\"flash\")"
		$mi5 = "GetVariable"
		$mi6 = "GetMember"
		$mi7 = "Push Lookup:12 (\"ConvolutionFilter\")"
		$mi8 = "NewMethod"
		$mi9 = "Push int:1"
		$mi10 = "InitArray"
		$mi11 = "SetMember"

	condition:
		(all of ($const*))
		and ($sprite or $movie_clip)
		and ( ((all of ($mi*)) and $movie_clip)
		  or ((all of ($si*)) and $sprite) )

}

rule CVE_2017_3059_3714 
 {
	meta:
		sigid = 3714
		date = "2017-04-11 17:06 PM"
		threatname = "CVE-2017-3059"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$const0 = "createEmptyMovieClip" ascii
		    $const1 = "push" ascii
		    $const2 = "getNextHighestDepth" ascii
		    $const3 = "createEmptyMovieClip" ascii
		    $const4 = "removeMovieClip" ascii
		
		    $str1 = /Push Lookup:\d+ \(\"arrMovieClips\"\)/
		    $str2 = /Push register:\d+ int:\d+ Lookup:\d+ \(\"Array\"\)/
		    $str3 = "NewObject"
		    $str4 = "SetMember"
		
		    $str5 = "GetVariable"
		    $str6 = /Push Lookup:\d+ \(\"createEmptyMovieClip\"\)/
		    $str7 = "CallMethod"
		    $str8  = "NewObject"
		
		    $str9 = /Push Lookup:\d+ \(\"toString\"\)/
		    $str10 = /Push Lookup:\d+ \(\"removeMovieClip\"\)/
		    $str11 = "SetTarget2"
		    $str12 = "NewObject"

	condition:
		all of them

}

rule CVE_2016_7858_3421 
 {
	meta:
		sigid = 3421
		date = "2016-12-13 07:55 AM"
		threatname = "CVE-2016-7858"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "length"
		$a1 = "removeMovieClip"
		$a2 = "getNextHighestDepth"
		$a3 = "createEmptyMovieClip"
		$a4 = "toString"
		
		$b0 = "GetVariable"
		$b1 = "CallMethod"
		$b2 = "NewObject"
		
		$c0 = /Push Lookup\:\d+ \("external"\)/
		$c1 = /Push Lookup\:\d+ \("ExternalInterface"\)/
		$c2 = /Push Lookup\:\d+ \("addCallback"\)/
		 
		$c3 = "DefineFunction"
		$c4 = /Push int\:3 Lookup\:\d+ \("mc"\)/
		$c5 = /Push Lookup\:\d+ \("AS2Go"\) int\:1 Lookup:\d+ \("flash"\)/
		$c6 = /Push Lookup\:\d+ \("call"\)/

	condition:
		all of them

}

rule CVE_2015_5123:_UseAfterFree_1815 
 {
	meta:
		sigid = 1815
		date = "2016-12-13 07:52 AM"
		threatname = "CVE-2015-5123: UseAfterFree"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1="<q>[public]flash.display::"
		$a2="::DisplayObjectContainer"
		$a3="getlex <q>[public]flash.system::Capabilities"
		$a4="<q>[public]__AS3__.vec::Vector"
		$a5="::valueOf"
		$a6="findpropstrict <q>[public]flash.utils::ByteArray"
		$a7="flash.filters::ConvolutionFilter"
		$a8="callproperty <q>[public]::readUTFBytes"
		$a9="KERNEL32.DLL"
		
		$b1 = "::supports64BitProcesses"
		$b2 = "::supports32BitProcesses"
		
		
		$h0 = "ConvolutionFilter"
		$h1 = ":Vector.<uint>"
		$h3 = "new Array("
		$h4 = ".matrix"
		$h5 = ".length"
		$h6 = ".Exec"
		$h7 = "isWin"
		$h8 = "Capabilities.supports"
		$h9 = ".Init()"
		$h10 = "function TryExpl()"

	condition:
		(all of ($a*) and any of ($b*)) or (all of ($h*))

}

rule BinaryDataPayloadDetections_2214 
 {
	meta:
		sigid = 2214
		date = "2016-12-13 07:53 AM"
		threatname = "BinaryDataPayloadDetections"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = "flash.utils.ByteArray" // byteArray import ( used to deal with binary data )
$a1 = "addedToStage" // if not on stage then no execution
$a2 = "uncompress" // if the data is compressed using traditional compression technique
$a3 = "length" 
$a4 = "getDefinition" // runtime register
$a5 = "flash.display.Loader" // used to load files
$a6 = "loadBytes"
$a7 = "addChild" // adding child on stage 
$a8 = "charCodeAt" // runtime generation of payload
$a9 = "position" // to go back and forth in payload creation
$a10 = "as Class)()" // getDefinititionByName and then trating string as a class
$b0 = /param\d\[_loc\d_\]\s\^\s_loc\d_\[/
$b1 = /param\d\[_loc\d_\]\s\%\s_loc\d_\[/

// swfdump 
$x0 = "flash.system"
$x1 = "extends <q>[public]flash.utils::ByteArray"
$x2 = "bitand"
$x3 = "bitxor"
$x4 = "pushstring \"uncompress\""
$x5 = "pushstring \"length\""
$x6 = "pushstring \"getDefinition\""
$x7 = "pushstring \"flash.display.Loader\""
$x8 = "pushstring \"stage\""
$x9 = "pushstring \"loadBytes\""
$x10 = "pushstring \"charCodeAt\""
$x11 = "pushstring \"position\""

	condition:
		((all of ($a*)) and (any of ($b*))) or (all of ($x*))

}

rule CVE_2016_7855_3380 
 {
	meta:
		sigid = 3380
		date = "2016-11-02 14:39 PM"
		threatname = "CVE_2016_7855"
		category = "Malware & Botnet"
		risk = 90
		
	strings:
		$const0 = "IDataOutput" ascii
		$const1 = "IDataInput" ascii
		$const2 = "IExternalizable" ascii
		$const3 = "writeExternal" ascii
		$const4 = "readExternal" ascii
		$const5 = "ByteArray" ascii
		$const6 = "writeObject" ascii
		$const7 = "readObject" ascii
		$const8 = "objectEncoding" ascii
		$params = "80 params"
		
		$re1 = /setproperty \<q\>\[public\]::position/
		$re2 = /callpropvoid \<q\>\[public\]::writeObject/
		$re3 = /getlex \<q\>\[public\]::ArgumentError/
		$re4 = /findpropstrict \<q\>\[public\]flash.net::registerClassAlias/

	condition:
		all of them

}

rule CVE_2016_7873_3493 
 {
	meta:
		sigid = 3493
		date = "2016-12-13 22:09 PM"
		threatname = "CVE_2016_7873"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$s1 = "<q>[public]com.adobe.tvsdk.mediacore::PSDK"
$s2 = "<q>[public]::createDefaultMediaPlayerItemConfig"
$s3 = "callproperty <q>[public]::createDefaultContentFactory"
$s4 = "setproperty <q>[public]::advertisingFactory"
$s5 = ":ContentFactory::retrieveAdPolicySelector"
$s6 = "::DisplayObjectContainer"
$s7 = "::InteractiveObject"

	condition:
		all of them

}

rule CVE_2016_7871_3487 
 {
	meta:
		sigid = 3487
		date = "2016-12-13 22:09 PM"
		threatname = "CVE_2016_7871"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "<q>[public]flash.system::WorkerDomain"
$a1 = "callproperty <q>[public]::createWorker, 2 params"
$a2 = "coerce <q>[public]flash.system::Worker"
$a3 = "callpropvoid <q>[public]::start, 0 params"

	condition:
		all of them

}

rule CVE_2016_7873_3482 
 {
	meta:
		sigid = 3482
		date = "2016-12-13 22:09 PM"
		threatname = "CVE_2016_7873"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0= "PSDK" ascii
		$const1= "com.adobe.tvsdk.mediacore" ascii
		$const2= "pSDK\"createDefaultMediaPlayerItemConfig" ascii
		$const3= "MediaPlayerItemConfig" ascii
		$const4= "createDefaultContentFactory" ascii
		$const5= "advertisingFactory" ascii
		$const6= "retrieveAdPolicySelector" ascii
		$instr0 = { 5d 0? 66 0? 66 0? 46 03 0? 80 0? d? }
		$instr1 = { d? 5d 0? 66 0? 66 0? 46 05 0? 61 0? }
		$instr2 = { d? 66 0? 20 46 07 0? }

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and #const1 > 1 and #const3 > 1 and (all of ($instr*))

}

rule CVE_2016_7878_3474 
 {
	meta:
		sigid = 3474
		date = "2016-12-13 22:09 PM"
		threatname = "CVE_2016_7878"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$ffdec1 = "com.adobe.tvsdk.mediacore"
		$ffdec2 = "PSDK.pSDK"
		$ffdec3 = "createDispatcher()"
		$ffdec4 = "createQOSProvider()"
		$ffdec5 = "new MediaPlayerItemLoader("
		$ffdec6 = "attachMediaPlayerItemLoader"
		$swfdump1 = "com.adobe.tvsdk.mediacore::PSDK"
		$swfdump2 = "[public]::pSDK"
		$swfdump3 = "::createDispatcher, 0 params"
		$swfdump4 = "::createQOSProvider, 0 params"
		$swfdump5 = "com.adobe.tvsdk.mediacore::MediaPlayerItemLoader"
		$swfdump6 = "com.adobe.tvsdk.mediacore::MediaPlayerItemLoader, 1 params"
		$swfdump7 = "::attachMediaPlayerItemLoader, 1 params"

	condition:
		(all of ($ffdec*) or all of ($swfdump*))
		and (@ffdec1 < @ffdec2 and @ffdec2 < @ffdec3 and @ffdec3 < @ffdec4 and @ffdec4 < @ffdec5 and @ffdec5 < @ffdec6) or (@swfdump1 < @swfdump2 and @swfdump2 < @swfdump3 and @swfdump3 < @swfdump4 and @swfdump4 < @swfdump5 and @swfdump5 < @swfdump6 and @swfdump6 < @swfdump7)

}

rule Exploit_SWF_Broxwek_3388 
 {
	meta:
		sigid = 3388
		date = "2016-12-13 07:49 AM"
		threatname = "Exploit_SWF_Broxwek"
		category = "Adware"
		risk = 100
		
	strings:
		$str1 = "_loc3_.endian = Endian.LITTLE_ENDIAN;"
		$str2 = "if(!_loc5_ || (_loc3_[0] ^ _loc5_) != 70)"
		$str3 = "loc3_[_loc6_] = _loc3_[_loc6_] ^ _loc5_"
		$str4 = "9090909090909090909090909090909090909090909090909090909090909090909090EB"
		$str5 = ".loadBytes(_loc3_,new LoaderContext(false,ApplicationDomain.currentDomain));"

	condition:
		(all of them)

}

rule CVE_2016_7857_3419 
 {
	meta:
		sigid = 3419
		date = "2016-12-13 06:52 AM"
		threatname = "CVE-2016-7857"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "flash.display::Sprite"
		$a1 = "pushstring \"AVSegmentedSource"
		$a2 = "::addChild"
		$a3 = "flash.media::AVSegmentedSource"
		$a4 = "constructprop <q>[public]flash.media::AVSegmentedSource, 0 params"
		$a5 = "flash.media::AVStream"
		$a6 = "callpropvoid <q>[public]::dispose"
		$a7 = /\:loadWithBackgroundManifest,\s\d+ params/
		$a8 = "pushshort"
		$a9 = "::Object"
		$10 = "flash.events::EventDispatcher"
		$a11 = "::InteractiveObject"
		$a12 = "flash.display::Sprite"

	condition:
		all of them

}

rule CVE_2014_0536_1533 
 {
	meta:
		sigid = 1533
		date = "2016-12-13 06:46 AM"
		threatname = "CVE_2014_0536"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a = "::RegExp"
		$b = "(?=(?=(?=(?="

	condition:
		$a and $b

}

rule CVE_2016_7860_3408 
 {
	meta:
		sigid = 3408
		date = "2016-11-08 15:28 PM"
		threatname = "CVE_2016_7860"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$const0 = "AdvertisingMetadata\"com.adobe.tvsdk.mediacore.metadata"
		$const1 = "setObject"
		$instr0 = {5d 03 4a 03 ?? 80 03 (d4 | d5 | d6 |d7)}
		$instr1 = {2c 07 85 (d4 | d5 | d6 | d7) (d0 | d1 | d2 | d3) (d0 | d1 | d2 | d3) 2f 01 4f 04 ??}

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_7865_3400 
 {
	meta:
		sigid = 3400
		date = "2016-11-08 15:28 PM"
		threatname = "CVE_2016_7865"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "getNextHighestDepth" ascii
		$const1 = "createEmptyMovieClip" ascii
		$const2 = "__proto__" ascii
		$const3 = "__constructor__" ascii
		$const4 = "LocalConnection" ascii    
		$const5 = "registerClass" ascii
		$const6 = "removeMovieClip" ascii
		$instr0={960d0008??06000000000000000008??1c96020008025296090008??070200000008??1c9602000803}
		$instr1={8e0800000000????00??00[16-256]08??4e960400080508061c4f}
		$instr2={96020008??1c96090008??070200000008??1c96020008??52}
		$instr3={96020008001c96070008??07??0000004f}
		$instr4={96020008??1c96090008??070200000008??1c96020008??52}
		$instr5={96020008011c96020008??4e960900070100000004??08??4e960200080452}

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_7861_3394 
 {
	meta:
		sigid = 3394
		date = "2016-11-08 15:28 PM"
		threatname = "CVE_2016_7861"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "Metadata\"com.adobe.tvsdk.mediacore.metadata" ascii
$const1 = "setObject" ascii
$instr0 = { 5d 03 4a 03 ?? 80 03 (d4 | d5 | d6 |d7) }
$instr1 = { 2c 07 85 (d4 | d5 | d6 | d7) (d0 | d1 | d2 | d3) (d0 | d1 | d2 | d3) 2f 01 4f 04 ?? }

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_6981_3354 
 {
	meta:
		sigid = 3354
		date = "2016-10-11 23:30 PM"
		threatname = "CVE_2016_6981"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "NetConnection" ascii
		$const1 = "flash.net\x07connect\x09NetStream"
		$instr0 = { 5d 03 4a 03 00 80 03 d6 }
		$instr1 = { d2 21 20 4f 04 02 }
		$instr2 = { 5d 05 d2 2c 09 4a 05 02 80 05 d5 }
		$instr3 = { d1 20 4f 06 01 }
		$instr4 = { d1 24 00 4f 07 01 }

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53)
		and (all of ($const*)) 
		and (all of ($instr*))

}

rule CVE_2016_4230_3071 
 {
	meta:
		sigid = 3071
		date = "2016-07-14 14:49 PM"
		threatname = "CVE_2016_4230"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = /Push Lookup:\d+ \(\"removeMovieClip\"\)/
$str2 = /Push Lookup:\d+ \(\"createEmptyMovieClip\"\)/
$str3 = /Lookup:\d+ \(\"flash\"\)/
$str5 = /Push Lookup:\d+ \(\"geom\"\)/
$str6 = /Push Lookup:\d+ \(\"Transform\"\)/
$str7 = /Push Lookup:\d+ \(\"addProperty\"\)/
$str8 = /Lookup:\d+ \(\"ASnative\"\)/
$ptr1 = "createEmptyMovieClip("
$ptr2 = "flash.geom.Transform"
$ptr3 = ".addProperty"
$ptr4 = "Transform"
$ptr5 = "ASnative"
$ptr6 = "removeMovieClip()"

	condition:
		all of ($str*) or all of ($ptr*)

}

rule CVE_2016_4248_3062 
 {
	meta:
		sigid = 3062
		date = "2016-07-14 14:49 PM"
		threatname = "CVE_2016_4248"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "E:\\fuzzing\\flash22\\poc\\src\\poc.as="
		$str2 = "E:\\fuzzing\\flash22\\poc\\src;;poc.as"
		$str3 = "com.adobe.tvsdk.mediacore::PSDK"
		$str4 = "constructsuper 0 params"
		$str5 = "flash.events::EventDispatcher"
		$str6 = "flash.display::DisplayObjectContainer"

	condition:
		all of them

}

rule EITest_Gate_3188 
 {
	meta:
		sigid = 3188
		date = "2016-08-11 13:38 PM"
		threatname = "EITest_Gate"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = /File size: \d{4}\r\n/
		$a1 = "addEventListener"
		$a2 = "ADDED_TO_STAGE"
		$a3 = "charCodeAt"
		$a4 = "gourl"
		$a5 = "asdasdasdasdasdasdasd"

	condition:
		((uint32(@a0+11) <= 0x37303030) and (all of ($a*)))

}

rule CVE_2016_3327_3177 
 {
	meta:
		sigid = 3177
		date = "2016-08-10 02:32 AM"
		threatname = "CVE_2016_3327"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1 = "FWS" ascii wide nocase
		$s2 = "navigateToURL(" ascii wide nocase
		$s3 = "\\\\?\\UNC\\\\\\" ascii wide nocase

	condition:
		($s1 at 0) and ($s2 and $s3)

}

rule CVE_2016_4279_3259 
 {
	meta:
		sigid = 3259
		date = "2016-09-14 10:20 AM"
		threatname = "CVE-2016-4279"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a="GetVariable"
$b="Push Lookup:2 (\"getNextHighestDepth\")"
$c="this"
$d="createEmptyMovieClip"
$e="CallMethod"
$f="__proto__"
$g="SetMember"
$h="GetMember"
$i="__constructor__"
$j="TextFormat"
$k="register"
$l="removeMovieClip"
$m="call"
$n="font"
$o="watch"

	condition:
		all of them

}

rule CVE_2016_4281_3250 
 {
	meta:
		sigid = 3250
		date = "2016-09-13 17:48 PM"
		threatname = "CVE-2016-4281"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$f1 = "extends Sprite"
$f2 = "super();"
$f3 = "new ShimContentResolver(1);"
$f4 = ".resolve(null);"

$s1 = "getproperty <q>[public]flash.display::Sprite"
$s2 = "constructprop <q>.resolvers::ShimContentResolver, 1 params"
$s3 = "::resolve, 1 params"

	condition:
		all of ($f*) or all of ($s*)

}

rule CVE_2016_0983_2464 
 {
	meta:
		sigid = 2464
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0983"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$f0 = "swfRoot.createEmptyMovieClip"
		$f2 = ".addProperty("
		$f4 = ".removeMovieClip();"
		$f5 = "_global.ASnative"
		$f6 = ".call("
		
		$s1 = "(\"createEmptyMovieClip\")"
		$s2 = "(\"removeMovieClip\")"
		$s3 = "(\"addProperty\")"
		$s5 = "(\"ASnative\")"
		$s6 = "(\"call\")"
		$s7 = "(\"_global\")"

	condition:
		(all of ($f*)) or (all of ($s*))

}

rule CVE_2016_4147_2931 
 {
	meta:
		sigid = 2931
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4147"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a1 = "function func()"
		$a2 = "var _loc4_ = new Sound();"
		$a3 = "tf.onID3 = function()"
		$a4 = "func();"
		$a5 = "snd.loadSound.call(tf,"
		$a6 = "snd.attachSound.call(tf,"

	condition:
		all of them

}

rule CVE_2016_4151_2974 
 {
	meta:
		sigid = 2974
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4151"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a1 = "var obj:ShimContentFactory = new ShimContentFactory();"
		$a2 = "var mi:MediaPlayerItem;"
		$a3 = "obj.retrieveResolvers(mi);"

	condition:
		all of them

}

rule CVE_2016_4153_2971 
 {
	meta:
		sigid = 2971
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4153"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "findpropstrict <q>[public]com.adobe.tvsdk.mediacore.timeline.generators::ShimOpportunityGenerator"
		$a1 = "coerce <q>[public]com.adobe.tvsdk.mediacore.timeline.generators::ShimOpportunityGenerator"
		$a2 = "callproperty <q>[public]::configure, 5 params"

	condition:
		all of them

}

rule CVE_2016_4156_2968 
 {
	meta:
		sigid = 2968
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4156"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "flash.display::Sprite"
$a1 = "adobe.tvsdk.mediacore.timeline.resolvers::ShimContentResolver"
$a2 = "com.adobe.tvsdk.mediacore.timeline::Placement"
$a3 = "adobe.tvsdk.mediacore.metadata::Metadata"
$a4 = "com.adobe.tvsdk.mediacore.timeline::Opportunity"
$a5 = "::resolve, 1 params"

	condition:
		all of them

}

rule CVE_2016_4171_2964 
 {
	meta:
		sigid = 2964
		date = "2016-06-15 19:46 PM"
		threatname = "CVE_2016_4171"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$s1="frame1"
		$s2={45 78 65 63 50 6F 6C 69 63 79 03 4F 53 52 01 41 01 41 01 41 01 41 01 41 01 41 01 41 01 41 01 41}
		$s3={01 41 03 16 01 18 02 00 03 07 01 02 07 01 03 03}
		$s4={FF 10 05 FF 10 05 FF 10 05 FF 10 05 FF 10 05 FF}

	condition:
		all of them

}

rule CVE_2016_4146_2949 
 {
	meta:
		sigid = 2949
		date = "2016-06-15 11:45 AM"
		threatname = "CVE_2016_4146"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="MovieClipLoader"
		$str2="getTimer()"
		$str3="new Sound()"
		$str4="_root.removeMovieClip.call(_global.l1)"

	condition:
		all of them

}

rule SWF_Axpergle_BM_2927 
 {
	meta:
		sigid = 2927
		date = "2016-06-15 11:45 AM"
		threatname = "SWF_Axpergle_BM"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="\"f\" + \"lash.utils.B\" + \"y\" + \"t\" +"
		$a2="ret + \"B\" + \"yt"
		$a3="\"ll\" + \"o\" + \"w\" + \"Do\" + ma + \"in"
		$a4="\"l\" + \"oadBytes\";"
		$a5="\"rCodeAt\";"
		$a6="\"a\" + dd + \"Chi\" + ld;"

	condition:
		all of them

}

rule GenericContainerDetect_2617 
 {
	meta:
		sigid = 2617
		date = "2016-04-19 14:04 PM"
		threatname = "GenericContainerDetect"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		// common in container files
		//swfdump
		$p0 = "flash.utils::ByteArray"
		$p1 = "mx.core::ByteArrayAsset"
		// any one of these 
		
		$q0 = "constructsuper 0 params"
		$q1 = "flash.display::MovieClip"
		
		$r0 = "flash.system::ApplicationDomain"
		$r1 = "flash.utils::getDefinitionByName" // runtime class registration
		$r2 = "flash.system::Capabilities" // get to know about environment such as fp version
		// any one of these would be good 
		
		$s0 = "::split"
		$s1 = "pushstring \"win \""
		$s2 = "::length"
		
		$t0 = "lshift"
		$t1 = "bitand"
		$t2 = "bitxor"
		$t3 = "::position"
		
		$u0 = "::stage"
		$u1 = "::writeByte"
		
		//ffdec
		$a0 = "import flash.utils.ByteArray" // container 
		$a1 = "import mx.core.ByteArrayAsset" // for getting handler to bindata
		// any one of these two
		
		$b0 = "super()" // making handler to bindata
		$b1 = "import flash.display.MovieClip" // main class
		
		$c0 = "import flash.system.ApplicationDomain" // get to know the app domain and allow things to execute
		$c1 = "import flash.utils.getDefinitionByName" // runtime class registration
		$c2 = "import flash.system.Capabilities" // get to know about environment such as fp version
		// any one of these would be good 
		
		$d0 = ".split(" // get fp/windows version
		$d1 = "!= \"win"
		$d2 = "new ByteArray()"
		$d3 = ".length"
		$d4 = "while"
		
		$e0 = "<<"
		$e1 = "&&"
		$e3 = "position"
		
		$g0 = "this.stage"
		$g1 = ".writeByte" // write data to memory

	condition:
		($p0 or $p1) and (all of ($q*)) and (any of ($r*)) and (all of ($s*)) and (all of ($t*)) and (all of ($u*)) or ($a0 or $a1) and (all of ($b*)) and (any of ($c*)) and (all of ($d*)) and (all of ($e*)) and (all of ($g*))

}

rule CVE_2016_1110_2793 
 {
	meta:
		sigid = 2793
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_1110"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1 = "var _loc2_ = _root.createTextField(\"tf1\",132,0,0,10,10);"
		$a2 = "_loc2_.variable ="
		$a3 = "var _loc3_ = new Date();"
		$a4 = "var _loc4_ = _root.createTextField(\"tf\",1320,0,0,10,10);"
		$a5 = "_global.l3 = _loc4_;"
		$a6 = "_root.addProperty("
		$a7 = "this.func,this.func);"
		$a8 = "var _loc5_ = new Sound();"
		$a9 = "_global.ASSetNativeAccessor(_loc4_,101,"

	condition:
		all of them

}

rule CVE_2016_1100_2760 
 {
	meta:
		sigid = 2760
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1100"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1="getlex <q>[public]com.adobe.tvsdk.mediacore::PSDK"
		$str2="getproperty <q>[public]::pSDK"
		$str3="pushbyte 0"
		$str4="callproperty <q>[public]::createOpportunityGenerator, 1 params"
		$str5="callproperty <q>[namespace]com.adobe.tvsdk.mediacore.timeline.generators:OpportunityGenerator::update, 2 params"
		$str6="returnvoid"

	condition:
		all of them

}

rule CVE_2016_1019_2625 
 {
	meta:
		sigid = 2625
		date = "2016-04-19 14:04 PM"
		threatname = "CVE_2016_1019"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "pushstring \"LocalConnection.send() succeeded\""
		$str2 = "pushstring \"LocalConnection.send() failed\""
		$str3 = "pushstring \"status\""
		$str4 = "pushstring \"error\""
		$str5 = "pushstring \"toAS2\""
		$str6 = "<q>[public]flash.net::LocalConnection"
		$str7 = "<q>[public]flash.events::StatusEvent"
		$str8 = "<q>[public]::onSendStatus"
		$str9 = "<q>[public]::timestr"
		$str10 = "pushstring \"start\""
		$str11 = "callpropvoid <q>[public]::send, 2 params"
		
		$ff1 = "lc:LocalConnection;"
		$ff2 = "onSendStatus(param1:StatusEvent)"
		$ff3 = "LocalConnection.send() succeeded\";"
		$ff4 = "LocalConnection.send() failed\";"
		$ff5 = "this.timestr = \"\" + this.d.hours + this.d.minutes + + (this.d.seconds >>> 2);"
		$ff6 = "\"toAS2\" + this.timestr;"
		$ff7 = "this.lc.send(\"toAS2\" + this.timestr,\"start\");"

	condition:
		all of ($str*) or all of ($ff*)

}

rule CVE_2016_0985_2460 
 {
	meta:
		sigid = 2460
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0985"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "DEFINEMORPHSHAPE2"
$a1 = "[public]flash.display::MovieClip{"
$a2 = "[public]::addFrameScript"
$a3 = "[public]flash.text::TextField"
$a4 = "[public]::message"
$a5 = "flash.text::TextField, 0 params"
$a6 = "[staticprotected]flash.events:EventDispatcher}::gridFitType"
$a7 = "flash.display::DisplayObjectContainer"

	condition:
		all of them

}

rule CVE_2016_0987_2536 
 {
	meta:
		sigid = 2536
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0987"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a = ".createEmptyMovieClip"
		$b = "new Sound("
		$c = ".attachSound("
		$d = "_global.Number = ff;"
		$e = ".setTransform(7);"
		$f = ".start();"
		$g = ".removeMovieClip();"
		$h = ".lr = 9999;"
		$i = ".ll = 9999;"
		$j = ".rl = 9999;"
		$k = ".rr = 9999;"

	condition:
		all of them

}

rule CVE_2016_0990_2524 
 {
	meta:
		sigid = 2524
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0990"
		category = "Malware & Botnet"
		risk = 25
		
	strings:
		$a0 = { 2e 63 72 65 61 74 65 54 65 78 74 46 69 65 6c 64 28 22 74 66 22 20 2b 20 [1-10] 2c 73 77 66 52 6f 6f 74 2e 67 65 74 } // .createTextField("tf" + AAAA,swfRoot.get
$a1 = "swfRoot.addProperty("
$a2 = ".removeTextField();"

	condition:
		all of them

}

rule SWF_Exploit_CVE_2016_4227_125486 
 {
	meta:
		sigid = 125486
		date = "2022-08-11 05:20 AM"
		threatname = "SWF.Exploit.CVE-2016-4227"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
	$a1 = "String:\"createTextField\""
	$a2 = "String:\"Selection\" String:\"setFocus\" "
	$a3 = "String:\"removeTextField\""
	condition:
	all of them and filesize < 1KB
}

rule SWF_Exploit_CVE_2015_5558_1927 
 {
	meta:
		sigid = 1927
		date = "2022-03-02 11:58 AM"
		threatname = "SWF_Exploit_CVE_2015_5558"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "Constantpool"
		$a1 = "(\"FileReference\")"
		$a2 = "String:\"TextFormat"
		$a3 = "String:\"flash\" String:\"net\""
		$a4 = "(\"ASSetPropFlags\")"

	condition:
		all of them
}

rule CVE_2015_5565_1964 
 {
	meta:
		sigid = 1964
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_5565"
		category = "Malware & Botnet"
		risk = 40
		
	strings:
		$a="SharedObject.getLocal"
$b="ASSetPropFlags("
$c="new NetConnection("
$d="__proto__"
$e=".fpadInfo"
$f=".data"
$g=".connect.call("
$h="while"
$i="new flash.display.BitmapData("
$j="new flash.filters.DisplacementMapFilter("
$k="setInterval("

	condition:
		all of them

}

rule CVE_2016_0981_2440 
 {
	meta:
		sigid = 2440
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0981"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "global.ASnative(101,10).call("
		
		$b0 = "String:\"ASnative\""
		$b1 = "int:10 int:101 int:2 Lookup:1 (\"_global\")"
		$b2 = { 50 75 73 68 20 4c 6f 6f 6b 75 70 3a [1-4] 20 28 22 41 53 6e 61 74 69 76 65 22 29 } //Push Lookup:??? ("ASnative")
		$b3 = "CallMethod"

	condition:
		$a0 or all of ($b*)

}

rule CVE_2015_8640:_UAF_2322 
 {
	meta:
		sigid = 2322
		date = "2017-01-03 17:34 PM"
		threatname = "CVE_2015_8640: UAF"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$s1 = "new Array("
		$s2 = ".length"
		$s3 = "createEmptyMovieClip"
		$s4 = "getNextHighestDepth"
		$s5 = "new Object();"
		$s6 = ".removeMovieClip();"
		$s7 = ".substr("
		$s8 = ".addProperty("
		$s9 = "ExternalInterface.call("
		$s10 = "(12288);"
		$r1 = /Lookup:\d+ \(\"Array\"\)/
		$r2 = /Push Lookup:\d+ \(\"length\"\)/
		$r3 = /Lookup:\d+ \(\"createEmptyMovieClip\"\)/
		$r4 = /Lookup:\d+ \(\"getNextHighestDepth\"\)/
		$r7 = /Push Lookup:\d+ \(\"removeMovieClip\"\)/
		$r8 = /Push Lookup:\d+ \(\"substr\"\)/
		$r9 = /Lookup:\d+ \(\"addProperty\"\)/
		$r10 = /Push Lookup:\d+ \(\"ExternalInterface\"\)/
		$r11 = "int:12288"

	condition:
		all of ($s*) or all of ($r*)

}

rule CVE_2015_3040_1660 
 {
	meta:
		sigid = 1660
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3040"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "vertexbuffer"
		$a1 = "uploadFromVector"
		$a2 = "AGALMiniAssembler"
		$a3 = "vertex"
		$a4 = "m44 op, va0 vc0\\nife vc0.x, vc0.y\\nmov v0, va1\\neif"
		$a5 = "fragment"
		$a6 = "mov oc, v0"
		$a7 = "context3D"
		$a8 = "createProgram"
		$a9 = "agalcode"

	condition:
		all of them

}

rule CVE_2015_8642_2329 
 {
	meta:
		sigid = 2329
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8642"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "String:\"getNextHighestDepth\""
		$a1 = "String:\"createEmptyMovieClip\""
		$a2 = "String:\"removeMovieClip\""
		$a3 = "String:\"ExternalInterface\""
		$a4 = "String:\"unwatch\""
		$a5 = "String:\"ASSetPropFlags\""
		$a6 = "(\"arrMovieClips\")"
		$a7 = "(\"getNextHighestDepth\")"
		$a8 = "(\"ASSetPropFlags\")"

	condition:
		all of them

}

rule CVE_2015_8650_2318 
 {
	meta:
		sigid = 2318
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8650"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "String:\"createEmptyMovieClip\""
$a1 = "String:\"removeMovieClip\""
$a2 = "String:\"http://127.0.0.1\""
$a3 = "String:\"LoadVars\""
$a4 = "getNextHighestDepth"
$a5 = "arrMovieClips"
$a6 = "toString"

	condition:
		all of them

}

rule CVE_2015_8447_2299 
 {
	meta:
		sigid = 2299
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8447"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = /"Push Lookup:d+ ("createTextField")/
$a1 = /"Push Lookup:d+ ("valueOf")/
$a2 = /"Push Lookup:d+ ("removeTextField")/
$a3 = /"Push Lookup:d+ ("setTransform")/
$a4 = /"Push int:\d+ Lookup:d+ ("Color")/
$a5 = "CallMethod"

	condition:
		all of them

}

rule CVE_2015_7627:_Memory_Corruption_2120 
 {
	meta:
		sigid = 2120
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-7627: Memory Corruption"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$f1 = "extends Sprite"
$f2 = ".graphics.beginFill(bgColor);"
$f3 = ".graphics.lineStyle(4,6710886);"
$f4 = ".graphics.drawRect(0,"
$f5 = ".graphics.endFill();"
$f6 = "addChild("
$f7 = "new BitmapData("
$f8 = "new Rectangle("
$f9 = ".fillRect("
$f10 = "new BlurFilter();"
$f11 = "new Shape();"
$f12 = "InteractiveObject("
$f13 = "focusOut"

	condition:
		all of them

}

rule CVE_2015_6679_2073 
 {
	meta:
		sigid = 2073
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_6679"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "flash.display::Loader"
		$a1 = "flash.system::LoaderContext"
		$a2 = "flash.net::URLRequest"
		$a3 = "CATCH(NULL"
		$a4 = "flash.utils::setTimeout"
		$a5 = "console.log(unescape(x"
		$a6 = "::target"
		$a7 = "::data"
		$a8 = "::applicationDomain"
		$a9 = "::getDefinition"
		$a10 = "flash.display::InteractiveObject"
		$a11 = "flash.display::MovieClip"

	condition:
		all of them

}

rule CVE_2015_6678_2071 
 {
	meta:
		sigid = 2071
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_6678"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "DEFINEFONT2"
$a1 = "Object}::CreateSpray"
$a2 = "::textSnapshot"
$a3 = "::getSelected"
$a4 = "::spray_size"
$a5 = "::float_hig"
$a6 = "::float_low"
$a7 = "::hole_end:<q>[public]::uint"
$a8 = "flash.events::EventDispatcher"
$a9 = "flash.display::InteractiveObject"

	condition:
		all of them

}


rule CVE_2015_5572_Security_Bypass_2066 
 {
	meta:
		sigid = 2066
		date = "2016-03-01 08:00 AM"
		threatname = "CVE-2015-5572-Security-Bypass"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a=":TextField"
		$b="new TextField()"
		$c=".autoSize"
		$d="TextFieldAutoSize.LEFT"
		$e=".displayAsPassword"
		$f="true"
		$g=".type"
		$h="TextFieldType.INPUT"
		$i="addChild("
		$j="Event.ADDED_TO_STAGE"

	condition:
		all of them

}

rule CVE_2016_0962_2513 
 {
	meta:
		sigid = 2513
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0962"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$swft1="[staticprotected]flash.events:EventDispatcher}::BitmapData"
		$swft2="pushshort 11000"
		$swft3="[staticprotected]flash.events:EventDispatcher}::Point"
		$swft4="pushint 2147483632"
		$swft5="[staticprotected]flash.events:EventDispatcher}::height"
		$swft6="pushbyte 4"
		$swft7="[staticprotected]flash.events:EventDispatcher}::right"
		$swft8="pushbyte 100"
		$swft9="pushbyte 50"
		$swft10="callpropvoid"
		$swft11="[staticprotected]flash.events:EventDispatcher}::setTo"
		$swft12="[staticprotected]flash.events:EventDispatcher}::paletteMap"
		$ff1="BitmapData(11000,11000)"
		$ff2=".height = 0x7ffffff0"
		$ff3=".right = 4"
		$ff4=".setTo(100,50)"
		$ff5=".paletteMap("

	condition:
		(all of ($swft*)) or (all of ($ff*))

}

rule CVE_2015_3124_1985 
 {
	meta:
		sigid = 1985
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_3124"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a1 = "as DisplayObjectContainer;"
		$a2 = ".addChild(new Bitmap());"
		$a3 = ".addChild(new TextField());"
		$a4 = { 67 65 74 5f 61 6c 6c 28 [1-4] 29 20 61 73 20 42 69 74 6d 61 70 3b } // get_all(AA) as Bitmap;
		$a5 = ".bitmapData = new BitmapData("
		$a6 = { 67 65 74 5f 61 6c 6c 28 [1-4] 29 2e 6d 61 73 6b } // get_all(AA).mask
		$a7 = "new Vector.<DisplayObject>();"
		$a8 = ".push(this);"
		$a9 = "= all[param1];"
		$a10 = "all = null"

	condition:
		all of them

}

rule CVE_2015_0347_1654 
 {
	meta:
		sigid = 1654
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-0347"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "<q>[public]flash.events::Event = null"
		$a1 = "flash.media::AVSegmentedSource"
		$a2 = "flash.media::AVResult"
		$a3 = "findpropstrict <q>[public]::removeEventListener"
		$a4 = "getlex <q>[public]flash.events::Event"
		$a5 = "callpropvoid <q>[public]::removeEventListener"
		$a6 = "findpropstrict <q>[public]flash.system::AuthorizedFeaturesLoader"
		$a7 = "constructprop <q>[public]flash.system::AuthorizedFeaturesLoader"
		$a8 = "callpropvoid <q>[public]::loadAuthorizedFeatures"

	condition:
		all of them

}

rule CVE_2015_5122:_Use_After_Free_1814 
 {
	meta:
		sigid = 1814
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-5122: Use After Free"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a1="<q>[public]flash.display::"
$a2="::DisplayObjectContainer"
$a3="getlex <q>[public]flash.system::Capabilities"
$a4="<q>[public]__AS3__.vec::Vector"
$a5="<q>[public]flash.text.engine::TextBlock"
$a6="::valueOf"
$a7="findpropstrict <q>[public]flash.utils::ByteArray"
$a8="setproperty <q>[public]::opaqueBackground"
$a9="callproperty <q>[public]::readUTFBytes"
$a10="KERNEL32.DLL"

$b1 = "::supports64BitProcesses"
$b2 = "::supports32BitProcesses"

	condition:
		all of ($a*) and any of ($b*)

}

rule CVE_2016_1010_2528 
 {
	meta:
		sigid = 2528
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_1010"
		category = "Adware"
		risk = 100
		
	strings:
		$s1="findpropstrict <q>[public]flash.display::BitmapData"
		$s2="pushint -16777215"
		$s3="coerce <q>[public]flash.display::BitmapData"
		$s4="findpropstrict <q>[public]flash.geom::Rectangle"
		$s5="pushshort -880"
		$s6="pushbyte -2"
		$s7="pushint 1073741838"
		$s8="constructprop <q>[public]flash.geom::Rectangle, 4 params"
		$s9="constructprop <q>[public]flash.geom::Point, 2 params"
		$s10="constructprop <q>[public]flash.text::TextFormat, 0 params"
		$s11="callpropvoid <q>[public]::copyPixels, 3 params"
		
		$ff1="new BitmapData(1,1,true,-16777215)"
		$ff2="new Rectangle(-880,-2,1073741838,8)"
		$ff3="new Point(0,0)"
		$ff4="copyPixels("

	condition:
		(all of ($s*)) or (all of ($ff*))

}

rule CVE_2016_7892_3496 
 {
	meta:
		sigid = 3496
		date = "2016-12-21 14:34 PM"
		threatname = "CVE_2016_7892"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "loadBytes"
$const1 = "Loader"
$const2 = "ExternalInterface"
$const3 = "addCallback"
$const4 = "SharedObject"
$const5 = "URLRequest"
$const6 = "URLLoader"
$const7 = "addEventListener"
$const8 = "FireInHole.php"
$const9 = "TrigeUp.gif"
$const10 = "TrigeDown.gif"
$const11 = "BpGo.gif"
$const12 = "LOG.dat"
$const13 = "KERNEL32.DLL"
$const14 = "readUTFBytes"
$const15 = ":loadas"
$const16 = "loadas:Ewt"
$const17 = "loadas.as$0"
$const18 = "loadas:do_use"
$const19 = "loadas:timeout"
$const20 = "loadas:do_go"
$const21 = "loadas/private:TrigTest"
$const22 = "loadas/private:MstePlay"
$const23 = ":loadas/loadas"
$const24 = "LetterPool"
$const25 = "Q1A2Z3W4S5XEDCRFVTG.BYHNUJMIKOLP67890d_ogesupshfwat"
$const26 = "fromCharCode"
$const27 = "toUpperCase"
$const28 = "Capabilities"
$const29 = "isDebugger"
$const30 = "flash.system"
$const31 = "flash.net"
$const32 = "Bp_poolalloc"
$const33 = "Bp_GetPhome"
$const34 = "Bp_GetMhome"

	condition:
		all of them

}

rule CVE_2015_3132_1878 
 {
	meta:
		sigid = 1878
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_3132"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "ASnative("
		$str2 = "SharedObject.getLocal("
		$str3 = ".data[0]"
		$str4 = "unshift.call"

	condition:
		all of them

}

rule CVE_2018_4920_117924 
 {
	meta:
		sigid = 117924
		date = "2018-03-13 09:12 AM"
		threatname = "CVE_2018_4920"
		category = "Malware & Botnet"
		risk = 40
		
	strings:
$str1="tvsdk.mediacore.timeline.advertising"
$str2="AdBannerAsset"
$str3="staticUrl"
$str4="pushstring \"id\""
$str5="jump ->27"
$str6="findpropstrict <multi>{[public]\"\"}::MyClass"
condition:
(all of them)
}

rule CVE_2018_4878_117758 
 {
	meta:
		sigid = 117758
		date = "2018-02-02 23:42 PM"
		threatname = "CVE_2018_4878"
		category = "Malware & Botnet"
		risk = 0
		
	strings:  
$a0 = "new URLLoader("
$a1 = "flash.utils.ByteArray;"
$a2 = "!Capabilities.isDebugger?\"-D\":\"\""
$a3 = ".writeBytes(this."
$a4 = ".url + (\"?id=\" +"
$a5 = ".url + (\"&fp_vs="
$a6 = ".url + (\"&os_vs=" 
$a7 = "].toString(16).toUpperCase();"
$a8 = "URLLoader(event.target);"
$a9 = "= new ByteArray();"
$a10 = ".length;"
$a11 = ".writeByte(uint(\"0x\" +"
$a12 = ".readUnsignedInt();"
$a13 = ".position = 0;" 
$a14 = "] ^ " 
$a15 = "new Loader();"
$a16 = ".loadBytes("
$a17 = "addChild("
condition:
all of them

}

rule FlashContainerDetect_2183 
 {
	meta:
		sigid = 2183
		date = "2016-12-13 07:53 AM"
		threatname = "FlashContainerDetect"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a0 = "flash.display::MovieClip"
$a1 = "flash.utils::ByteArray"
$a2 = "flash.utils::Endian"
$a3 = "<q>[public]::LITTLE_ENDIAN"
$a4 = "<q>[public]::endian"
$a5 = "flash.utils::getDefinitionByName"
$a6 = "<q>[public]::Class"
$a7 = "TRY {"
$a8 = "CATCH(<q>[public]::Error"
$a9 = "flash.system::Capabilities" // find out os name & verion of flashPlayer installed
$a10 = "getproperty <q>[public]::version"
$a11 = "pushbyte 4" // this is the index of the os name
$a12 = "pushstring \"win " // test for os match
$a13 = "bitxor" 	// used for generating payload at runtime

$b0 = /pushshort\s\d+/		//combined together gives the endpayload byteArray, number of count of occurance of thie should be veryHigh
$b1 = /pushint\s\d+/

	condition:
		(all of ($a*)) and #b0 > 8000 and #b1 > 5000

}

rule CVE_2015_8644_2328 
 {
	meta:
		sigid = 2328
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8644"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "[public]::myfont extends <q>[public]flash.text::Font"
$a1 = "[public]button_fla::MainTimeline extends <q>[public]flash.display::MovieClip{"
$a2 = "[public]button_fla::MainTimeline=()"
$a3 = "findpropstrict <q>[public]::addFrameScript"
$a4 = "getproperty <q>[packageinternal]button_fla::frame"
$a5 = "callpropvoid <q>[public]::addFrameScript"
$a6 = "[public]flash.display::SimpleButton"
$a7 = "<multi>{[public]\"\"}::myfont"
$a8 = "getlex <q>[public]flash.display::InteractiveObject"
$a9 = "getlex <q>[public]flash.display::MovieClip"

	condition:
		all of them

}

rule CVE_2015_5588_2075 
 {
	meta:
		sigid = 2075
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_5588"
		category = "Malware & Botnet"
		risk = 25
		
	strings:
		$a1 = "<q>[packageinternal]flash.utils::ObjectOutput"
		$a2 = { 63 6c 61 73 73 20 3c 71 3e 5b 70 75 62 6c 69 63 5d 66 6c 61 73 68 2e 75 74 69 6c 73 3a 3a [2-10] 20 65 78 74 65 6e 64 73 20 3c 71 3e 5b 70 75 62 6c 69 63 5d 66 6c 61 73 68 } // class <q>[public]flash.utils::AAAA extends <q>[public]flash
		$a3 = "callproperty <q>[public]::writeDouble, 1 params"

	condition:
		all of them

}

rule CVE_2016_0991_2538 
 {
	meta:
		sigid = 2538
		date = "2016-04-01 07:00 AM"
		threatname = "CVE_2016_0991"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a = ".toString = function () {"
		$b = ".removeTextField()"
		$c = "_root.createTextField("
		$d = "_global.ASnative("

	condition:
		all of them

}

rule CVE_2018_15982_118942 
 {
	meta:
		sigid = 118942
		date = "2018-12-13 10:31 AM"
		threatname = "SWF.Exploit.CVE-2018-15982"
		category = "Malware & Botnet"
		risk = 60
		
	strings:
$ffd1 =  "flash.utils.ByteArray"
$ffd2 = ".tvsdk.mediacore"
$ffd3 = "Capabilities.isDebugger"
$ffd10 = "LocalConnection().connect"
$ffd4 = " removeEventListener(Event.ADDED_TO_STAGE,this."
$ffd5 = ".LITTLE_ENDIAN;"
$ffd6 = ".keySet;"
$ffd7 = ".charCodeAt("
$ffd8 = ".toString()"
$ffd9 = "AddEventListener(Event.ADDED_TO_STAGE,this."

condition: 
all of ($ffd*)
}

rule CVE_2016_2937_3524 
 {
	meta:
		sigid = 3524
		date = "2017-01-10 16:14 PM"
		threatname = "CVE_2016_2937"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$const0 = "_global" ascii
		    $const1 = "FileReference" ascii
		    $const2 = "__proto__" ascii
		    $const3 = "constructor" ascii
		    $const4 = "watch" ascii
		    $const5 = "prototype" ascii
		    $const6 = "ASSetPropFlags" ascii
		    $const7 = "Subfr" ascii
		     
		$a1 = /Push Lookup:\d+ \(\"_global\"\)/
		$a2 = "action: GetVariable"
		$a3 = /action: Push Lookup:\d+ \(\"backup\"\) Lookup:\d+ \(\"_global\"\)/
		$a4 = /Push Lookup:\d+ \(\"flash\"\)/
		$a5 = /Push Lookup:\d+ \(\"net\"\)/
		$a6 = /action: Push Lookup:\d+ \(\"FileReference\"\)/
		$a7 = /action: Push register:\d+ Lookup:\d+ \(\"__proto__\"\) int:\d+/
		$a8 = /Push Lookup:\d+ \(\"__constructor__\"\) Lookup:\d+ \(\"Array\"\)/

	condition:
		all of them

}

rule CVE_2017_2999_3615 
 {
	meta:
		sigid = 3615
		date = "2017-03-14 18:29 PM"
		threatname = "CVE-2017-2999"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "com.adobe.tvsdk.mediacore"
$a1 = "::MediaPlayerView"
$a2 = "::focusRect"
$a3 = "::stage"
$a4 = "::addChild"
$a5 = "::Object"
$a6 = "flash.events::EventDispatcher"
$a7 = "flash.display::Sprite"
$b8 = "pushnull"
$a9 = "coerce <q>[public]com.adobe.tvsdk"
$a10 = "<q>[public]::addChild, 1 params"
$a11 = "pop"
$a12 = "returnvoid"

	condition:
		all of ($a*) and #b8 > 1

}

rule CVE_2016_4223_3063 
 {
	meta:
		sigid = 3063
		date = "2016-07-13 02:31 AM"
		threatname = "CVE_2016_4223"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="<q>[public]::MyAdTimelineItem"
		$a2="<q>[public]::MyAdTimelineItem, 0 params"
		$a3="<q>[public]::MyAdTimelineItem=()(0 params, 0 optional)"
		$a4="newclass [classinfo 00000000 <q>[public]::MyAdTimelineItem]"
		$a5="initmethod * init=()(0 params, 0 optional)"
		$a6="constructsuper 0 params"

	condition:
		(all of them)

}

rule CVE_2015_3118_1827 
 {
	meta:
		sigid = 1827
		date = "2016-02-01 08:00 AM"
		threatname = "CVE_2015_3118"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
		$a0 = "createTextField"
		$a1 = "filters"
		$a2 = "int:4 int:3 int:2 int:1 int:1"
		
		$b0 = "createTextField(\"tf\",1,1,2,3,4);"
		$b1 = ".filters"

	condition:
		(#a0 > 1 and #a2 > 1 and $a1) or (#b0 > 1 and $b1)

}

rule Exploit_SWF_Broxwek_3389 
 {
	meta:
		sigid = 3389
		date = "2016-12-13 09:44 AM"
		threatname = "Exploit_SWF_Broxwek"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "constructprop <q>[private]"
		$str2 = "0coerce <q>[public]flash.utils::ByteArray"
		$str3 = "callpropvoid <q>[public]::uncompress, 0 params"
		$str4 = "getproperty <q>[public]::length"
		$str5 = "convert_i"
		$str6 = "jump ->"
		$str7 = "getproperty"
		$str8 = "<l,multi>{[private]"
		$str9 = "pushbyte 64"
		$str10 = "pushbyte 8"
		$str11 = "modulo"
		$str12 = "pushbyte 4"
		$str13 = "multiply"
		$str14 = "add"
		$str15 = "setproperty"
		$str16 = "<l,multi>{[private]"
		$str17 = "pushbyte 32"
		$str18 = "pushbyte 0"
		$str19 = "greaterequals"
		$str20 = "subtract"
		$str21 = "dup"
		$str22 = "iftrue ->33"
		$str23 = "findpropstrict <q>[public]flash.display::Loader"
		$str24 = "constructprop <q>[public]flash.display::Loader, 0 param"
		$str25 = "findpropstrict <q>[public]flash.system::LoaderContex"
		$str26 = "constructprop <q>[public]flash.system::LoaderContext, 2 params"
		$str27 = "callpropvoid <q>[public]::loadBytes, 2 params"

	condition:
		@str26 > @str25 and
		@str27 > @str26 and
		@str25 > @str24 and
		@str24 > @str23 and
		@str23 > @str22 and
		@str22 > @str21 and
		@str21 > @str20 and
		@str20 > @str19 and
		@str19 > @str18 and
		@str17 > @str16 and
		@str15 > @str14 and
		@str14 > @str13 and
		@str13 > @str12 and
		@str12 > @str11 and
		@str11 > @str10 and
		@str10 > @str9 and
		@str9 > @str8 and
		@str8 > @str7 and
		@str6 > @str5 and
		@str5 > @str4 and
		@str4 > @str3 and
		@str3 > @str2 and
		@str2 > @str1 and
		  (all of them)

}

rule CVE_2016_1019_2624 
 {
	meta:
		sigid = 2624
		date = "2016-04-19 14:04 PM"
		threatname = "CVE_2016_1019"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$swf1="pushstring \"ad\""
		$swf2="pushstring \"d\""
		$swf3="pushstring \"Ev\""
		$swf4="pushstring \"ent\""
		$swf5="pushstring \"Li\""
		$swf6="pushstring \"sten\""
		$swf7="pushstring \"er\""
		$swf8="pushstring \"r\""
		$swf9="pushstring \"emov\""
		$swf10="pushstring \"eEve\""
		$swf11="pushstring \"ntLi\""
		$swf12="pushstring \"sten\""
		$swf13="pushstring \"er\""
		$swf14="pushstring \"lo\""
		$swf15="pushstring \"ad\""
		$swf16="pushstring \"By\""
		$swf17="pushstring \"tes\""
		$swf18="pushstring \"join\""
		$swf19="pushstring \"win \""
		$swf20="flash.utils::ByteArray"
		$swf21="pushstring \"charCodeAt\""
		$swf22="writeByte, 1 params"
		
		$ff1="[\"ad\",\"\",\"d\",\"\",\"Ev\",\"\",\"ent\",\"\",\"Li\",\"\",\"sten\",\"\",\"er\"]"
		$ff2="[\"r\",\"\",\"emov\",\"\",\"eEve\",\"\",\"ntLi\",\"\",\"sten\",\"\",\"er\"]"
		$ff3="[\"fl\",\"\",\"as\",\"\",\"h.dis\",\"\",\"pla\",\"\",\"y.\",\"\",\"Lo\",\"\",\"ade\",\"\",\"r\"]"
		$ff4="[\"lo\",\"\",\"ad\",\"\",\"By\",\"\",\"tes\"]"
		$ff5="\"join\"]"
		$ff6="\"win \""
		$ff7="getDefinitionByName(\"flash.utils.ByteArray\")"
		$ff8="charCodeAt"
		$ff9="writeByte"

	condition:
		all of ($swf*) or all of ($ff*)

}

rule GenericPackerDetect_2394 
 {
	meta:
		sigid = 2394
		date = "2016-03-01 08:00 AM"
		threatname = "GenericPackerDetect"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		// swfdump
$a0 = "flash.system::Security" // looks for accessing system level
$a1 = "flash.system::ApplicationDomain"
$a2 = "flash.utils::ByteArray"
$a3 = "flash.display.Loader"
$a4 = "public]::Class" // telling that the variable is of class type
$a5 = " add" // adding to the raw byte array to transform full fledged code for other function
$a6 = "bitxor" // Generate code for decryption
$a7 = " subtract"
$a8 = "inclocal_i" // integer increment
$a9 = "multiply"
$a10 = "bitand" // Get decrypted 2nd file
$a11 = "\"writeByte\""
$a12 = "addEvent\""

// ffdec
$b0 = "flash.utils.ByteArray"
$b1 = "flash.display.Loader\""
$b2 = "extends ByteArray" // get control of binary data attached
$b3 = "flash.system.Security" // system level access
$b4 = ":Class;" // define var as a class type
$b5 = "as Class;" // runtime class registration
$b6 = /_loc\d_ \+ _loc\d_/
$b7 = /_loc\d_ < _loc\d_/
$b8 = "] ^ _loc"
$b9 = /param\d & param\d/
$b10 = /param\d \* param\d/
$b11 = "\"writeByte\""
$b12 ="addEvent\""

	condition:
		(all of ($a*)) or ( all of ($b*))

}

rule CVE_2017_11225_117355 
 {
	meta:
		sigid = 117355
		date = "2017-11-14 10:32 AM"
		threatname = "CVE_2017_11225"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
$str1 = "PSDK"
$str2 = "createMetadata"
$str3 = "createQOSProvider"
$str4 = "metadata"
$str5 = "getObject"
$str6 = "com.adobe.tvsdk.mediacore::PSDK"
$str7 = "pushstring \"aaaaaaaaaaaa"
condition:
(all of them)
}

rule CVE_2015_3098_1729 
 {
	meta:
		sigid = 1729
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3098"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$a0 = "MovieClipLoader"
		$a1 = "onLoadInit"
		$a2 = "javascript:void(confirm("
		$a3 = "getURL"
		$a4 = "createEmptyMovieClip"
		$a5 = "Pop"
		$a6 = "MovieClipLoader"
		$a7 = "addListener"

	condition:
		all of them

}

rule CVE_2015_3042_1661 
 {
	meta:
		sigid = 1661
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2015-3042"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$b0 = "findpropstrict <q>[public]::RegExp"
		$c0 = "constructprop <q>[public]::RegExp"
		$d0 = "callproperty <q>[namespace]http://adobe.com/AS3/2006/builtin::exec, 1 params"
		$a0 = { 70 75 73 68 73 74 72 69 6e 67 20 22 28 3f 28 3f 3c [1-6] 3e 29 3f 29 22 } // decodes to 'pushstring "(?(?<[1-6]>)?)"'

	condition:
		all of them

}

rule CVE_2015_8634_2331 
 {
	meta:
		sigid = 2331
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8634"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$a0 = "constructsuper 0 params"
		$a1 = "findpropstrict <q>[public]::addFrameScript"
		$a2 = "pushbyte 0"
		$a3 = "callpropvoid <q>[public]::addFrameScript, 2 params"
		$a4 = "findproperty <q>[private]NULL::main"
		$a5 = "getlocal_0"
		$a6 = "initproperty <q>[private]NULL::main"
		$a7 = "getlex <q>[private]NULL::main"
		$a8 = "getproperty <q>[public]::parent"
		$a9 = "getlocal_0"
		$a10 = "getproperty <q>[public]::loaderInfo"
		$a11 = "callpropvoid <q>[public]::addEventListener, 2 params"

	condition:
		all of them

}

rule CVE_2015_8638_2330 
 {
	meta:
		sigid = 2330
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8638"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "String:\"arrMovieClips\""
$a1 = "String:\"getNextHighestDepth\""
$a2 = "String:\"createEmptyMovieClip\""
$a3 = "String:\"removeMovieClip\""
$a4 = "String:\"addProperty\""
$a5 = "String:\"ASSetPropFlags\""
$a6 = "\"arrMovieClips\") int"
$a7 = "\"createEmptyMovieClip\")"
$a8 = "Jump -80"
$a9 = "(\"mc_2\")"

	condition:
		all of them

}

rule CVE_2015_8651_2317 
 {
	meta:
		sigid = 2317
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8651"
		category = "Malware & Botnet"
		risk = 20
		
	strings:
		$a0 = "extends <q>[public]flash.display::Sprite{"
$a1 = "pushdouble 2148663340"
$a2 = "pushint 2147483644"
$a3 = "li32"
$a4 = "pushint 2146303960"
$a5 = "pushint 305419896"
$a6 = "getlex <q>[public]flash.events::EventDispatcher"
$a7 = "getlex <q>[public]flash.display::DisplayObject"
$a8 = "getlex <q>[public]flash.display::InteractiveObject"
$a9 = "getlex <q>[public]flash.display::DisplayObjectContainer"

	condition:
		all of them

}

rule CVE_2015_8460_2327 
 {
	meta:
		sigid = 2327
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2015_8460"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$string1 = "[public]::tjfuzz1686 extends <q>[public]flash.display::Sprite"
		$string2 = "kill r3"
		$string3 = "pushstring \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		$string4 = "[public]flash"
		$string5 = "[public]::tjfuzz1686=tjfuzz1686"
		$string6 = "[public]::listener"

	condition:
		all of them

}

rule CVE_2016_4173_3096 
 {
	meta:
		sigid = 3096
		date = "2016-07-13 07:45 AM"
		threatname = "CVE_2016_4173"
		category = "Malware & Botnet"
		risk = 30
		
	strings:
		$a1 = ".removeTextField()"
$a2 = ".createTextField("
$a3 = ":Transform = new Transform("
$a4 = ".colorTransform = new ColorTransform("
$a5 = "= flash.geom"
$a6 = ".addProperty(\"ColorTransform\","

	condition:
		all of them

}

rule CVE_2016_1109_2746 
 {
	meta:
		sigid = 2746
		date = "2016-05-10 19:37 PM"
		threatname = "CVE_2016_1109"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "String:\"removeMovieClip\" String:\"call\""
		$a1 = "createEmptyMovieClip"
		$a2 = "focusEnabled"
		$a3 = "addProperty"
		$a4 = "setFocus"

	condition:
		all of them

}

rule CVE_2016_4117_2783 
 {
	meta:
		sigid = 2783
		date = "2016-05-12 13:41 PM"
		threatname = "CVE_2016_4117"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "[public]com.adobe.tvsdk.mediacore.timeline.operations::DeleteRangeTimelineOperation"
$a1 = "findpropstrict <q>[public]::removeEventListener"
$a2 = "[public]::ADDED_TO_STAGE"
$a3 = "[private]NULL::init"
$a4 = "callpropvoid <q>[public]::removeEventListener"
$a5 = "[private]NULL,[public]\"\",[private]NULL,[packageinternal]\"\""
$a6 = "[public]com.adobe.tvsdk.mediacore.timeline.operations::DeleteRangeTimelineOperation"
$a7 = "getproperty <q>[public]::placement"
$a8 = "[public]::placement:<q>[public]::Object = true"

	condition:
		all of them

}

rule CVE_2017_3003_3631 
 {
	meta:
		sigid = 3631
		date = "2017-03-14 18:29 PM"
		threatname = "CVE_2017_3003"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$const0 = "display" ascii
$const1 = "Camera" ascii
$const2 = "attachMovie" ascii
$const3 = "video" ascii
$const4 = "getNextHighestDepth" ascii
$const5 = "createEmptyMovieClip" ascii
$const7 = "ASnative" ascii
$const8 = "attachVideo" ascii
$const9 = "valueOf" ascii
$constA = "removeMovieClip" ascii
$instr0 = "Push Lookup:19 (\"my_cam\") int:0 Lookup:20 (\"Camera\")"
$instr01 = "Push Lookup:21 (\"get\")"
$instr02 = "CallMethod"
$instr03 = "DefineLocal"
$instr1 = "Push register:1 Lookup:4 (\"display\")"
$instr11 = "GetMember"
$instr12 = "Push register:1 Lookup:4 (\"display\")"
$instr13 = "Push Lookup:11 (\"video\")"
$instr2 = "Push Lookup:23 (\"mc\") int:0 Lookup:7 (\"_root\")"
$instr21 = "Push Lookup:24 (\"getNextHighestDepth\")"
$instr22 = "Push Lookup:23 (\"mc\") int:2 Lookup:7 (\"_root\")"
$instr23 = "Push Lookup:25 (\"createEmptyMovieClip\")"
$instr24 = "CallMethod"
$instr25 = "DefineLocal"
$instr3 = "Push Lookup:23 (\"mc\")"
$instr31 = "Push Lookup:26 (\"func\") int:0 int:2107 int:2 Lookup:1 (\"_global\")"
$instr32 = "GetVariable"
$instr33 = "Push Lookup:27 (\"ASnative\")"
$instr34 = "CallMethod"
$instr4 = "Push Lookup:19 (\"my_cam\")"
$instr41 = "GetVariable"
$instr42 = "Push int:1 register:3 Lookup:28 (\"attachVideo\")"
$instr43 = "CallMethod"
$instr5 = "Push Lookup:19 (\"my_cam\")"
$instr51 = "Push Lookup:29 (\"onStatus\")"
$instr52 = "(remainder of 17 bytes:\"\\0\\1\\0\\4)\\0\\2infoObj\\0\\\\0\")"
$instr53 = "Push Lookup:30 (\"muted\")"
$instr54 = "Push Lookup:31 (\"valueOf\")"
$instr55 = "(remainder of 8 bytes:\"\\0\\0\\0\\2)\\0\\27\\0\")"
$instr56 = "Push int:0 Lookup:23 (\"mc\")"
$instr57 = "Push Lookup:32 (\"removeMovieClip\")"
$instr58 = "Push int:1 Lookup:23 (\"mc\")"
$instr59 = "Push Lookup:26 (\"func\")"
$instr510 = "StoreRegister"
$instr511 = "SetMember"

	condition:
		(uint16(0) == 0x5746 and uint8(2) == 0x53) and (all of ($const*)) and (all of ($instr*))

}

rule CVE_2016_4282_3244 
 {
	meta:
		sigid = 3244
		date = "2016-09-13 17:48 PM"
		threatname = "CVE_2016_4282"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$a1="var ins1:ShimContentResolver = new ShimContentResolver(2);"
		$a2="ins1.configure(null,null);"
		$a3="Main extends Sprite"

	condition:
		(all of them)

}

rule CVE_2016_4143_2969 
 {
	meta:
		sigid = 2969
		date = "2016-06-16 18:35 PM"
		threatname = "CVE_2016_4143"
		category = "Malware & Botnet"
		risk = 10
		
	strings:
		$a0 = "String:\"_global\" String:\"_root\" String:\"Sound\" String:\"prototype\" String:\"ASSetPropFlag\""
		$a1 = "(\"tf\")"
		$a2 = "createTextField"
		$a3 = "(\"id"
		$a4 = "removeMovieClip"
		$a5 = "\\0\\1\\0\\3)\\0\\2mc\\0\\20\\0"

	condition:
		all of them

}

rule CVE_2016_0959_2465 
 {
	meta:
		sigid = 2465
		date = "2016-03-01 08:00 AM"
		threatname = "CVE_2016_0959"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$ff1=".removeTextField()"
		$ff2="_root.createTextField("
		$ff3=".removeTextField()"
		$ff4="_global.ASnative(1,2).call("
		$ff5="_root."
		
		$swf1="(\"removeTextField\")"
		$swf2="(\"createTextField\")"
		$swf3="(\"ASnative\")"
		$swf4="(\"call\")"
		$swf5="StoreRegister 0"
		$swf6="SetMember"
		$swf7="(\"prototype\")"
		$swf8="GetMember"
		$swf9="StoreRegister 1"

	condition:
		(all of ($ff*)) or (all of ($swf*))

}

