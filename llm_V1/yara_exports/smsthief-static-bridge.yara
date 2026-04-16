rule Android_Trojan_SMSThief_StaticBridge_122513 : knownmalware
{
    meta:
        source_rule = "Android_Trojan_SmsThief_122513"
        note = "Adapted for the current static APK dump format"

    strings:
        $s1 = "http://uaioey.ga/otp.php"
        $s2 = "/Camera/?e=1351855869&pay=pasargad"
        $s3 = "android.permission.RECEIVE_SMS"
        $s4 = "android.permission.READ_SMS"

    condition:
        all of them
}


rule Android_Trojan_SMSThief_StaticBridge_122510 : knownmalware
{
    meta:
        source_rule = "Android_Trojan_SmsThief_122510"
        note = "Adapted for the current static APK dump format"

    strings:
        $s1 = "AMStrings:smsq"
        $s2 = "AMStrings:Email"
        $s3 = "AMStrings:Password"
        $s4 = "AMStrings:123+123"
        $s5 = "Hakistan"
        $s6 = "AMStrings:Giving up on delivering"
        $s7 = "keylogger"
        $perm1 = "android.permission.READ_SMS"
        $perm2 = "android.permission.SEND_SMS"
        $perm3 = "android.permission.RECEIVE_SMS"

    condition:
        all of ($s*) and 2 of ($perm*)
}


rule Android_Trojan_SMSThief_StaticBridge_124562 : knownmalware
{
    meta:
        source_rule = "Android_Trojan_SmsThief_124562"
        note = "Adapted for the current static APK dump format"

    strings:
        $perm1 = "android.permission.READ_SMS"
        $perm2 = "android.permission.RECEIVE_SMS"
        $perm3 = "android.permission.SEND_SMS"
        $svc1 = "ir.a.testfirebase.SmsReceiver"
        $svc2 = "ir.a.testfirebase.SmsProcessService"
        $c21 = "AMStrings:GetLink.php"
        $c22 = "mytestprojects.xyz"

    condition:
        all of ($perm*) and all of ($svc*) and all of ($c2*)
}


rule Android_Trojan_SMSThief_StaticBridge_123343 : knownmalware
{
    meta:
        source_rule = "Android_Trojan_SmsThief_123343"
        note = "Adapted for the current static APK dump format"

    strings:
        $s1 = "content://sms/inbox"
        $s2 = ".component.As1"
        $s3 = ".component.As2"
        $s4 = ".component.DaS"
        $s5 = ".notification.NoRsS"

    condition:
        all of them
}


rule Android_Trojan_SMSThief_StaticBridge_121958 : knownmalware
{
    meta:
        source_rule = "Android_Trojan_SMSThief_121958"
        note = "Adapted for the current static APK dump format"

    strings:
        $s1 = "AMStrings:tel_stu"
        $s2 = "AMStrings:ban_ben"
        $s3 = "AMStrings:xing_hao"
        $s4 = "AMStrings:xi_tong"
        $s5 = "PASSWORD_ENC_SECRET"
        $s6 = "AcpManager"

    condition:
        5 of them
}