rule Java_Backboor_VersaMem_133274 
 {
	meta:
		sigid = 133274
		date = "2024-08-28 08:39 AM"
		modified_date = "2024-08-27 21:28 PM"
		threatname = "Java.Backdoor.VersaMem"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
$s1 = "com.versa.vnms.ui.config.Config"
$s2 = "com.versa.vnms.ui.transformer.CoreClassFileTransformer"
$s3 = "/usr/bin/pgrep"
$s4 = "org.apache.catalina.startup.Bootstrap"
$s5 = "Runtime.getRuntime().exec("
$s6 = "VirtualMachine.attach("
$s7 = "/tmp/.java_pid"
$s8 = "org.apache.catalina.core.ApplicationFilterChain"
$s9 = "doFilter"
$s10 = "javax.crypto.spec.SecretKeySpec"
$s11 = "setUserPassword"
$s12 = "com/versa/vnms/ui/services/impl/VersaAuthenticationServiceImpl"
$s13 = "getInsertCode()"
$s14 = "insertShell("
$s15 = ".toBytecode()"

condition:
filesize < 5MB and all of them
}

rule Java_Exploit_CVE_2013_0431_126724 
 {
	meta:
		sigid = 126724
		date = "2023-03-16 18:41 PM"
		threatname = "Java.Exploit.CVE-2013-0431"
		category = "Malware & Botnet"
		risk = 80
		
	strings:
        $a1 = "localJmxMBeanServer.getMBeanInstantiator"
        $a2 = "com.sun.jmx.mbeanserver.Introspector"
        $a3 = "com.sun.jmx.mbeanserver.MBeanInstantiator"
        $a4 = "extends Applet"
        $a5 = "Introspector.elementFromComplex"
    condition:
        all of them
}

rule Apache_Exploit_CVE_2022_42889_126589 
 {
	meta:
		sigid = 126589
		date = "2022-10-18 19:15 PM"
		threatname = "Apache.Exploit.CVE-2022-42889"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
$str1="StringSubstitutor.createInterpolator();"
$str2=".replace("
$str3=".println("
condition:
all of ($str*)
}

rule JAVA_Exploit_CVE_2020_1464_124616 
 {
	meta:
		sigid = 124616
		date = "2021-11-17 10:14 AM"
		threatname = "Java.Exploit.CVE-2020-1464"
		category = "Malware & Botnet"
		risk = 0
		
	strings:
$str1 = "Installation Database"
$str2 = "Intel;1033"
$str3 = "{4A87FF31-A0CA-4FAD-A846-A4257FB0F7D3}"
$str4 = "Windows Installer XML Toolset (3.8.1128.0)"
$str5 = "META-INF/"
$str6 = "META-INF/MANIFEST.MFPK"
condition:
(all of them)
}

rule Java_Backdoor_CobaltStrike_124379 
 {
	meta:
		sigid = 124379
		date = "2021-10-21 11:27 AM"
		threatname = "Java.Backdoor.CobaltStrike"
		category = "Malware & Botnet"
		risk = 50
		hash = "222b8f27dbdfba8ddd559eeca27ea648"
	strings:
		$meta = "META-INF/MANIFEST.MF"
		$Jar = {504B}
		$str1 = "beacon/BeaconHTTP.class" wide ascii nocase
		$str2 = "beacon/BeaconExploits.class" wide ascii nocase
		$str3 = "beacon/BeaconPayload.class" wide ascii nocase
		$str4 = "beacon/BeaconDNS.class" wide ascii nocase
		$str5 = "beacon/BeaconCommands.class" wide ascii nocase
		$str6 = "beacon/exploits/PK" wide ascii nocase
		$str7 = "beacon/remoteexploits/PK" wide ascii nocase
		$str8 = "beacon/bof/PsExecCommand.class" wide ascii nocase
		$str9 = "beacon/c2setup/BeaconSetupC2.classmR" wide ascii nocase
	condition:
		$Jar at 0 and $meta and all of ($str*)
}

rule Java_Trojan_Log4j_124855 
 {
	meta:
		sigid = 124855
		date = "2021-12-22 17:45 PM"
		threatname = "Java.Trojan.Log4j"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "rm -rf"
$str2 = "Exploit"
$str3 = "PrintStream;"
$str4 = "exec"
$str5 = "Process;"

condition:
all of them
}

rule CVE_2013_2471_jar_1505 
 {
	meta:
		sigid = 1505
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2013-2471-jar"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$api1 = "CreateWritableRaster"  
$api2 = "getNumDataElements"  
$api3 = "AlphaCompositeClass.compose"  
$api4 = "AccessControllerContext"  
$api5 = "IntegerComponentRaster"

	condition:
		all of ($api*)

}

rule CVE_2013_2423_jar_1501 
 {
	meta:
		sigid = 1501
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2013-2423-jar"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$str1="findStaticSetter"  
$str2="Double.class"  
$str3="Integer.class"  
$str4="invokeExact"  
$str5="getSecurityManager"  
$str6="getDeclaredField"

	condition:
		all of ($str*)

}

rule Apache_Exploit_CVE_2021_44228_124803 
 {
	meta:
		sigid = 124803
		date = "2021-12-11 00:49 AM"
		threatname = "Apache.Exploit.CVE-2021-44228"
		category = "Malware & Botnet"
		risk = 80
		
	strings:
$str1="${jndi:ldap://"
$str2="${jndi:rmi://"
$str3="${jndi:dns://"
$str4="LogManager.getLogger()"
condition:
$str4 and ($str1 or $str2 or $str3)
}

rule Apache_Exploit_CVE_2021_44228_124850 
 {
	meta:
		sigid = 124850
		date = "2021-12-21 13:58 PM"
		threatname = "Apache.Exploit.CVE-2021-44228"
		category = "Malware & Botnet"
		risk = 100
		
	strings:

$str1 = "/fuck"
$str2 = ".hta"
$str3 = "http://"
$str4 = "cmd.exe"
$str5 = "mshta"
$str6 = "curl"
$str7 = "python"

condition:
all of them
}

rule AlienSpy_RAT_1649 
 {
	meta:
		sigid = 1649
		date = "2016-02-01 08:00 AM"
		threatname = "AlienSpy_RAT"
		category = "Malware & Botnet"
		risk = 50
		
	strings:
		$sa_1 = "METAINF/MANIFEST.MF"
		          $sa_2 = "Main.classPK"
		          $sa_3 = "plugins/Server.classPK"
		          $sa_4 = "IDPK"
		          $sb_1 = "config.iniPK"
		          $sb_2 = "password.iniPK"
		          $sb_3 = "plugins/Server.classPK"
		          $sb_4 = "LoadStub.classPK"
		          $sb_5 = "LoadStubDecrypted.classPK"
		          $sb_7 = "LoadPassword.classPK"
		          $sb_8 = "DecryptStub.classPK"
		          $sb_9 = "ClassLoaders.classPK"
		          $sc_1 = "config.xml"
		          $sc_2 = "options"
		          $sc_3 = "plugins"
		          $sc_4 = "util"
		          $sc_5 = "util/OSHelper"
		          $sc_6 = "Start.class"
		          $sc_7 = "AlienSpy"
		          $sc_8 = "PK"

	condition:
		(all of ($sa_*)) or (all of ($sb_*)) or (all of ($sc_*))

}

rule Java_Backdoor_GoldBrute_120609 
 {
	meta:
		sigid = 120609
		date = "2020-02-21 07:12 AM"
		threatname = "Java.Backdoor.GoldBrute"
		category = "Malware & Botnet"
		risk = 100
		
	strings:
		$str1 = "BRUTEENCRYPTSYNC"
		$str2 = "INITVENCRYPTSYNC"
		$str3 = "\"3389\""
		$str4 = "PROTOCOL_RDP"
		$str5 = "\"scan\""
		$str6 = "\"brute\""
		$str7 = "Cipher.getInstance(\"RC4\")"
		$str8 = "Cipher.getInstance(\"AES/CBC/PKCS5Padding\")"
condition:
		all of ($str*)
}

rule Java_Backdoor_CobaltStrike_125475 
 {
	meta:
		sigid = 125475
		date = "2022-04-26 06:40 AM"
		threatname = "Java.Backdoor.CobaltStrike"
		category = "Malware & Botnet"
		risk = 100
		zipfile= "43ea9eb42b0d4d53177432fd21e4ef2f"
	strings:
		$meta = "META-INF/MANIFEST.MF"
		$Jar = {504B}
		$str1 = "resources/cobaltstrike.auth" wide ascii nocase
		$str2 = "beacon/BeaconExploits.class" wide ascii nocase
		$str3 = "beacon/BeaconPayload.class" wide ascii nocase
		$str4 = "beacon/BeaconData.class" wide ascii nocase
		$str5 = "beacon/BeaconHTTP.class" wide ascii nocase
condition:
		$Jar at 0 and $meta and all of ($str*)
}

rule CVE_2013_2460_jar_1502 
 {
	meta:
		sigid = 1502
		date = "2016-02-01 08:00 AM"
		threatname = "CVE-2013-2460-jar"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$str1="InvocationHandler"
$str2="ProviderFactory" 
$str3="forName" 
$str4="Invoke" nocase
$str5="MethodHandles" 
$str6="lookup" 
$str7="findStatic" 
$str8="findVirtual" 
$pattern1= "sun.tracing.Provider" 
$pattern2= "extends Provider"

	condition:
		$pattern1 and $pattern2 and 4 of ($str*)

}

rule CVE_2013_0422_jar_1499 
 {
	meta:
		sigid = 1499
		date = "2016-01-01 08:00 AM"
		threatname = "CVE-2013-0422-jar"
		category = "Malware & Botnet"
		risk = 127
		
	strings:
		$api1= "java.lang.reflect"  
		$api2= "getMBeanInstantiator"  
		$api3= "JmxMBeanServer"  
		$str3="forName"  
		$str4="Invoke" nocase
		$str5="MethodHandles"  
		$str6="lookup"  
		$str7="findStatic"  
		$str8="findVirtual"
	condition:
		all of ($api*) and (4 of ($str*))

}

rule Java_Backdoor_CrossRat_117720 
 {
	meta:
		sigid = 117720
		date = "2018-01-29 05:49 AM"
		threatname = "Java.Backdoor.CrossRat"
		category = "Malware & Botnet"
		risk = 0
		
	strings: 
$s1 = "crossrat" ascii wide
$s2 = "getHostName" ascii wide
$s3 = "java.io.tmpdir" ascii wide
$s4 = "mediamgrs.jar" ascii wide
$s5 = "userRoot" ascii wide
condition:
all of ($s*)
}

rule Java_Backdoor_CrossRat_117722 
 {
	meta:
		sigid = 117722
		date = "2018-01-29 06:36 AM"
		threatname = "Java.Backdoor.CrossRat"
		category = "Malware & Botnet"
		risk = 100
		
	strings: 
$s1 = "crossrat" ascii wide
$s2 = "getHostName" ascii wide
$s3 = "getNetworkInterfaces" ascii wide
$s4 = "kali" ascii wide
$s5 = "writeBytes" ascii wide
condition:
all of ($s*)
}

