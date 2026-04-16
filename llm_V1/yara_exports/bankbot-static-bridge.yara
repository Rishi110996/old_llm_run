rule Android_Banker_Bankbot_StaticBridge_121895 : knownmalware
{
    meta:
        source_rule = "Android_Banker_Bankbot_121895"
        note = "Adapted for the current static APK dump format"

    strings:
        $s1 = "AMStrings:sendernumber"
        $s2 = "AMStrings:receivenumber"
        $s3 = "AMStrings:message"
        $s4 = "AMStrings:statusreceiver"
        $s5 = "AMStrings:statushide"
        $s6 = "AMStrings:statusread"
        $s7 = "CREATE TABLE smsbase"
        $s8 = "CREATE TABLE injects"

    condition:
        all of them
}


rule Android_Banker_Bankbot_StaticBridge_121893 : knownmalware
{
    meta:
        source_rule = "Android_Banker_Bankbot_121893"
        note = "Adapted for the current static APK dump format"

    strings:
        $s1 = "/decryptstringmanager/DecryptString.smali"
        $s2 = "/res/layout/adm_perm.xml"
        $s3 = "PBKDF2WithHmacSHA1"
        $s4 = "AMStrings:AES/ECB/PKCS5Padding"
        $s5 = "obfuscation:label=\"SMS_S\""

    condition:
        all of them
}


rule Android_Banker_Bankbot_StaticBridge_122572 : knownmalware
{
    meta:
        source_rule = "Android_Banker_Bankbot_122572"
        note = "Adapted for the current static APK dump format"

    strings:
        $am1 = "AMStrings:hookcalls"
        $am2 = "AMStrings:hooksms"
        $am3 = "AMStrings:http.connection.timeout"
        $am4 = "AMStrings:isadmin"
        $am5 = "AMStrings:ru.sberbankmobile"
        $am6 = "AMStrings:sentsms"
        $am7 = "AMStrings:usedinj"
        $am8 = "AMStrings:botpwd"
        $perm1 = "android.permission.READ_SMS"
        $perm2 = "android.permission.RECEIVE_SMS"
        $perm3 = "android.permission.SEND_SMS"

    condition:
        all of ($am*) and 2 of ($perm*)
}


rule Android_Banker_Bankbot_StaticBridge_122139 : knownmalware
{
    meta:
        source_rule = "Android_Banker_Bankbot_122139"
        note = "Adapted for the current static APK dump format"

    strings:
        $sms1 = "Sms Is Deleted !" nocase
        $sms2 = "SMS is NOT DELETED" nocase
        $c2_1 = "/set/log_add.php" nocase
        $c2_2 = "/set/receiver_data.php" nocase
        $c2_3 = "/set/set.php" nocase
        $c2_4 = "/set/tsp_tsp.php" nocase
        $cmd1 = "/proc/%d/cmdline" nocase
        $cmd2 = "/proc/%d/cgroup" nocase
        $perm = "android.permission.RECEIVE_SMS"

    condition:
        1 of ($sms*) and 2 of ($c2_*) and 1 of ($cmd*) and $perm
}


rule Android_Banker_Bankbot_StaticBridge_121894 : knownmalware
{
    meta:
        source_rule = "Android_Banker_Bankbot_121894"
        note = "Adapted for the current static APK dump format"

    strings:
        $s1 = "cdn1e699bdc.com"
        $s2 = "android.app.action.ADD_DEVICE_ADMIN"
        $s3 = "AMStrings:clean,.kms.,.drweb,.eset"
        $s4 = "AMStrings:tor.zip"
        $s5 = "enabled_accessibility_services"

    condition:
        all of them
}


rule Android_Banker_Bankbot_StaticBridge_118284 : knownmalware
{
    meta:
        source_rule = "Android_Banker_Bankbot_118284"
        note = "Adapted for the current static APK dump format"

    strings:
        $req1 = "activity_inj"
        $req2 = "activity_go_adm"
        $req3 = "activity_activ_location"
        $opt1 = "android.intent.action.NEW_OUTGOING_CALL"
        $opt2 = "android.intent.action.QUICKBOOT_POWERON"
        $opt3 = "android.permission.QUICKBOOT_POWERON"
        $opt4 = "res/layout/activity_inj.xml"
        $opt5 = "res/layout/activity_go_adm.xml"
        $opt6 = "res/layout/r_l.xml"
        $opt7 = "encrypted-storage"
        $opt8 = "android.app.action.DEVICE_ADMIN_DISABLED"

    condition:
        all of ($req*) and 2 of ($opt*)
}


rule Android_Banker_Bankbot_StaticBridge_121714 : knownmalware
{
    meta:
        source_rule = "Android_Banker_Bankbot_121714"
        note = "Adapted for the current static APK dump format"

    strings:
        $perm1 = "fvqxs.fqtivf.mbfm"
        $perm2 = "gorupn.wgtiroe.yetphemo"
        $perm3 = "pefhf.qjurwu.wqsk"
        $perm4 = "ujjir.elyx.iise"
        $perm5 = "ushnyla.vssrds.nvocjhxm"
        $rec1 = "gyykjd.LoReceiver"
        $rec2 = "gyykjd.OxgReceiver"
        $rec3 = "gyykjd.PdsReceiver"
        $svc1 = "gyykjd.MdService"

    condition:
        3 of ($perm*) and 2 of ($rec*) and $svc1
}


rule Android_Banker_Bankbot_StaticBridge_122574 : knownmalware
{
    meta:
        source_rule = "Android_Banker_Bankbot_122574"
        note = "Adapted for the current static APK dump format"

    strings:
        $req1 = "encodedPassword == null"
        $req2 = "encodedUsername == null"
        $req3 = "android.accessibilityservice.AccessibilityService"
        $req4 = "ru.secretion.adviser.Financial"
        $perm1 = "android.permission.READ_SMS"
        $perm2 = "android.permission.SEND_SMS"
        $perm3 = "android.permission.WAKE_LOCK"

    condition:
        all of ($req*) and 2 of ($perm*)
}