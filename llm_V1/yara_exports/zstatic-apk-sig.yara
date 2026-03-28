rule Android_Spyware_LunaSpy_139617 : knownmalware 
 {
	meta:
		sigid = 139617
		date = "2025-08-26 06:39 AM"
		modified_date = "2025-08-26 12:55 PM"
		threatname = "Android.Spyware.LunaSpy"
		category = "Spyware"
		risk = 127
		
	strings:
        $str_1 = "readSMSBox"
        $str_2 = "executeShell"
        $str_3 = "checkAdminRights"
        $str_4 = "GET_CONTACTS"
        $str_5 = "GET_CALL_LOGS"
        $str_6 = "GET_DEVICE_INFO"
        $str_7 = "startListeningForCommands"
        $str_8 = "sendCustomMessageToServer"

    condition:
        all of ($str_*)
}

rule Android_Banker_Gen_139601 : knownmalware 
 {
	meta:
		sigid = 139601
		date = "2025-08-22 14:12 PM"
		modified_date = "2025-08-25 16:12 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
	$a1 = "\",\"sms\":\""
	$a2 = "{\"uid\":\""
	$a3 = "HeadlessSmsSendService"
	$a4 = "incoming_number"
	$a5 = "phone_numbers="
	$a6 = "branch="
	$a7 = "RegInfo(uid="
	$a8 = "worker"
	$a9 = "sender="
	$a10 = "SmsInfo(uid="
	$a11 = "Номер:"
condition:
	all of them
}

rule Android_Trojan_SpyAgent_139562 : knownmalware 
 {
	meta:
		sigid = 139562
		date = "2025-08-18 12:45 PM"
		modified_date = "2025-08-19 10:14 AM"
		threatname = "Android.Trojan.SpyAgent"
		category = "Trojan"
		risk = 127
		
	strings:
        $s1 = "Call is hooked !!!" ascii wide
        $s2 = "CALL_END Number =" ascii wide
        $s3 = "rc1.mp3" ascii wide
        $s4 = "This is Emulator!!" ascii wide
        $s5 = "서비스 실행됨" wide   // Korean string
        $s6 = "click-phone" ascii wide
        $s7 = "click-sound" ascii wide
        $s8 = "KEY_P3_NUMBER" ascii wide
        $s9 = "KEY_P2_NUMBER" ascii wide
        $s10 = "callStatus = " ascii wide
        $s11 = "phoneState=" ascii wide
        $s12 = ".uploadNumber =" ascii wide
        $s13 = "number=? and type=?" ascii wide
        $s14 = "persist.txt" ascii wide

    condition:
        5 of them
}

rule Android_Banker_NGate_139546 : knownmalware 
 {
	meta:
		sigid = 139546
		date = "2025-08-18 06:01 AM"
		modified_date = "2025-08-18 12:32 PM"
		threatname = "Android.Banker.NGate"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "/baxi/b"
        $str_2 = "/smartcard_list.txt"
        $str_3 = "/model/CardInfo;"
        $str_4 = "/CurrencyLookup;"
        $str_5 = "android.hardware.nfc\" android:required=\"true"
        $str_6 = "android.nfc.cardemulation.category.PAYMENT"

    condition:
        all of ($str_*)
}

rule Android_RAT_XNotice_139302 : knownmalware 
 {
	meta:
		sigid = 139302
		date = "2025-08-08 10:05 AM"
		modified_date = "2025-08-08 12:46 PM"
		threatname = "Android.RAT.XNotice"
		category = "RAT"
		risk = 127
		
	strings:
        $str_1 = "xproject-"
        $str_2 = "com.xnotice.app"
        $str_3 = "xnotice.themainx"
        $str_4 = "XLoader"
        $str_5 = ".handlingservice"
        $str_6 = "ApplicationHook"
        $str_7 = "assets/url.txt"

    condition:
        6 of ($str_*)
}

rule Android_Banker_SoumniBot_139414 : knownmalware 
 {
	meta:
		sigid = 139414
		date = "2025-08-05 16:30 PM"
		modified_date = "2025-08-06 11:59 AM"
		threatname = "Android.Banker.SoumniBot"
		category = "Banker"
		risk = 127
		
	strings:
        // Core class names
        $class1 = "TelePhoneRecSJKV"
        $class2 = "PhoneCallServiceSKV"

        // Obfuscated function names
        $obf1 = "phon eCallAc tivity"
        $obf2 = "isForwa rdingHan dUp"

        // Command & Control commands
        $c2_1 = "streaming_mic"
        $c2_2 = "execute_command_recording"
        $c2_3 = "send_call_started_msg_to_server"

        // Data Exfiltration and Actions
        $exfil1 = "saveAlbumDB"
        $exfil2 = "upload_recording_file"
        $exfil3 = "delete_command_recording_by_id"
        $exfil4 = "deleteSMS"
        $exfil5 = "uploadInfoContact"
        $exfil6 = "uploadInfoSmsAll"

        // Command Beans and APK Actions
        $bean1 = "CommandDeleteSMSBean"
        $bean2 = "commandLoadInfoBean"
        $apk_upload = "ACTION_APP3_UPLOAD_APK"

        // Audio/Camera Streaming Hijack
        $rtmp = "RTMP_CAMERA"

    condition:
        (4 of ($class*,$obf*,$c2*,$exfil*,$bean*,$apk_upload,$rtmp))
}

rule Android_RAT_SpyNote_139384 : knownmalware 
 {
	meta:
		sigid = 139384
		date = "2025-08-04 06:43 AM"
		modified_date = "2025-08-04 12:40 PM"
		threatname = "Android.RAT.SpyNote"
		category = "RAT"
		risk = 127
		
	strings:
        $str_1 = "/app/saveCardPwd"
        $str_2 = "/app/saveSms"
        $str_3 = "/app/uploadImageBase64"
        $str_4 = "/app/saveUnlockInfo"
        $str_5 = ":1935/live/"
        $str_6 = "searchPackageName"
        $str_7 = "current_domain_index"
        $str_8 = "com.shell.dynamic."

    condition:
        7 of ($str_*)
}

rule Android_Spyware_DCHSpy_139381 : knownmalware 
 {
	meta:
		sigid = 139381
		date = "2025-08-04 04:28 AM"
		modified_date = "2025-08-04 12:39 PM"
		threatname = "Android.Spyware.DCHSpy"
		category = "Spyware"
		risk = 127
		
	strings:
        // SFTP and file exfiltration
        $s1 = "sendFiles" ascii
        $s2 = "SFTPUploaderService" ascii
        $s3 = "Putting file :" ascii
        $s4 = "target file :" ascii
        $s5 = /^sftp:\/\/(\w+):(\w+)@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)(\/.+)?/ nocase ascii

        // Surveillance / Command & control
        $c1 = "New Call Started" ascii
        $c2 = "cmdId =" ascii
        $c3 = "installServerUpdate: destFile" ascii
        $c4 = "installApk:" ascii
        $c5 = "downloadFile:" ascii
        $c6 = "catalog.apk" ascii

        // VPN abuse
        $v1 = ".api.PauseVPN" ascii
        $v2 = ".api.DisconnectVPN" ascii
        $v3 = ".api.ConnectVPN" ascii
        $v4 = ".api.ResumeVPN" ascii

    condition:
        (3 of ($s*) and 2 of ($c*) and 2 of ($v*))
}

rule Android_Banker_Redhook_139361 : knownmalware 
 {
	meta:
		sigid = 139361
		date = "2025-07-30 08:32 AM"
		modified_date = "2025-07-30 12:04 PM"
		threatname = "Android.Banker.Redhook"
		category = "Banker"
		risk = 127
		
	strings:
        // Group 1: Communication/Identifiers
        $pg1_1 = "deviceId=" ascii
        $pg1_2 = "wss://" ascii
        $pg1_3 = "/ws/device?menberId=" ascii
        $pg1_4 = "_video_connection" ascii
        $pg1_5 = "connecting server..." ascii

        // Group 2: Functions/APIs
        $g2_1 = "WebsocketVideoUtil" ascii
        $g2_2 = "MediaProjectionManager" ascii
        $g2_3 = "stopCapture" ascii
        $g2_4 = "startCapture" ascii
        $g2_5 = "checkIsScreenShareDoing" ascii
        $g2_6 = "screenshot.jpg" ascii
        $g2_7 = "sendFrameToServer" ascii
        $g2_8 = "ScreenCapture" ascii

        // Group 3: Chinese Log/Debug Strings (wide for UTF-16 support)
        $g3_1 = "创建虚拟视图，开始录屏" wide
        $g3_2 = "mediaProjection为空" wide
        $g3_3 = "sc是否连接" wide
        $g3_4 = "视频流发送b图片大小" wide
        $g3_5 = "视频socket未发送----->ping" wide
        $g3_6 = "视频sc处于断连状态：isConnect=" wide
        $g3_7 = "当前视频连接的webSocket链接地址" wide

    condition:
        (4 of ($pg*)) or
        (
            10 of ($g*)
        )
}

rule Android_Banker_Mamont_139205 : knownmalware 
 {
	meta:
		sigid = 139205
		date = "2025-07-18 10:13 AM"
		modified_date = "2025-07-18 11:31 AM"
		threatname = "Android.Banker.Mamont"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "/send-card"
        $str_2 = "/open-app"
        $str_3 = "/send-contact"
        $str_4 = "hideAppIcon"
        $str_5 = "sendSmsOverWebSocket"
        $str_6 = "/WebSocketService$sendFileToServer"
        $str_7 = "/activities/CardActivity"

    condition:
        all of ($str_*)
}

rule Android_Banker_NGate_139204 : knownmalware 
 {
	meta:
		sigid = 139204
		date = "2025-07-18 09:30 AM"
		modified_date = "2025-07-18 11:31 AM"
		threatname = "Android.Banker.NGate"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "/EmulatorActivity;"
        $str_2 = "/MyHostApduService;"
        $str_3 = "processCommandApdu"
        $str_4 = "apdu_command"
        $str_5 = "android_asset/pincode.html?pin="
        $str_6 = "android.permission.BIND_NFC_SERVICE"
        $str_7 = "android.permission.NFC"

    condition:
        all of ($str_*)
}

rule Android_Banker_Gen_139142 : knownmalware 
 {
	meta:
		sigid = 139142
		date = "2025-07-11 12:07 PM"
		modified_date = "2025-07-16 11:41 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
        // Encoded Intents and Admin Actions
        $s1  = "ZH_TTO_\x08ZVK\x08ZEOOTH\x15g\x7fbdb~pre~yzbvou"
        $s2  = "\x07c\x02\x7f\td\x02#\x07}\x16#\x03u\x12\x7f\x07#\\H0D%H9L\\@/C"
        $s3  = "ZH_TTO_\x08ZVK\x08^^OTZ\x08zb\x7fy~~kjzhzrriu"

        // Encoded Identifiers / Keys
        $s4  = "_CMOXCdVTJREB"
        $s5  = "6B5Y"
        $s6  = "X2KK5"

        // Other Obfuscated Strings
        $s7  = "\x00C\x02C\x18P\x11R/U\x07U" //perehvat_sws - russian meaning- interception
        $s8  = "\x1eG\x1dC"
        $s9  = "H\x15R\x07I\x02M"
        $s10 = "\x03G\x06C/O\x1eL"
        $s11 = "B\x15J/U\x07U"
        $s12 = "#k#y#c>r"
        $s13 = "uvudt~e~omc\x7f"
        $s14 = "@\x11J\x03C"
        $s15 = "u=u/b5j9p5t5b"

        //  malicious page
        $s16 = "lensfor"
        $s17 = "add_log.php"

    condition:
        4 of ($s*)
}

rule Android_Trojan_Dropper_139043 : knownmalware 
 {
	meta:
		sigid = 139043
		date = "2025-07-08 12:38 PM"
		modified_date = "2025-07-09 11:30 AM"
		threatname = "Android.Trojan.Dropper"
		category = "Trojan"
		risk = 127
		
	strings:
        $str_1 = ".InstallingActivity"
        $str_2 = ".InstallReceiver"
        $str_3 = "android.intent.action.BOOT_COMPLETED"
        $str_4 = "android.permission.REQUEST_INSTALL_PACKAGES"
        $pack_5 = "com.example.fcmexpr"
        $pack_6 = "com.example.fcmexpr2"

    condition:
        all of ($str_*) and 1 of ($pack_*)
}

rule Android_Ransom_Gen_138892 : knownmalware 
 {
	meta:
		sigid = 138892
		date = "2025-07-03 06:35 AM"
		modified_date = "2025-07-03 13:11 PM"
		threatname = "Android.Ransom.Gen"
		category = "Ransom"
		risk = 127
		
	strings:
        $str_1 = ".MainActivity$NotiService"
        $str_2 = ".MainActivity$BackgroundService"
        $str_3 = "/adrt/ADRTLogCatReader;"
        $str_4 = "Lcom/beingyi/encrypt/"
        $str_5 = "android.permission.WAKE_LOCK"
        $str_6 = "android.permission.FOREGROUND_SERVICE"
        $str_7 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"

    condition:
        6 of ($str_*)
}

rule Android_Trojan_FakeWallet_137441 : knownmalware 
 {
	meta:
		sigid = 137441
		date = "2025-06-24 10:55 AM"
		modified_date = "2025-06-24 13:41 PM"
		threatname = "Android.Trojan.FakeWallet.A"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "io.gonative.android.MainActivity.Extra.BROADCAST_RECEIVER_ACTION_WEBVIEW_LIMIT_REACHED"
	$str_2 = "file:///android_asset/offline.html"
	$str_3 = "pancakefentfloyd.cz/api.php"
	$str_4 = "appConfig.json"

condition:
	3 of ($str*)
}

rule Android_Trojan_SparkKitty_137437 : knownmalware 
 {
	meta:
		sigid = 137437
		date = "2025-06-24 10:09 AM"
		modified_date = "2025-06-24 13:40 PM"
		threatname = "Android.Trojan.SparkKitty"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.ACCESS_BACKGROUND_LOCATION"
	$str_2 = "android.intent.category.MULTIWINDOW_LAUNCHER"
	$str_3 = "joigvwfrkppvorabnxtgvcey"
	$str_5 = "oaoksnejbhtzpskdemwkajhs"

condition:
	all of ($str*)
}

rule Android_Trojan_REA_131365 : knownmalware 
 {
	meta:
		sigid = 131365
		date = "2024-03-20 13:01 PM"
		threatname = "Android.Trojan.REA"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "AndroidManifest.xml/"
	$str_2 = "resources.arsc/"
	$str_3 = "classes.dex/"

condition:
	all of ($str_*)
}

rule Android_Spyware_Mandrake_137362 : knownmalware 
 {
	meta:
		sigid = 137362
		date = "2025-06-20 06:38 AM"
		modified_date = "2025-06-20 06:59 AM"
		threatname = "Android.Spyware.Mandrake"
		category = "Spyware"
		risk = 127
		
	strings:
	$str1_1 = "RICINUS_DEX"
	$str1_2 = "dex_load_hidden"
	$str1_3 = "ServiceJob"
	$str1_4 = {61 73 73 65 74 73 2F 72 61 77 2F ?? ?? ?? ?? 2E 72 61 77}
	$str1_5 = "libopencv_java"
	$str2_1 = "service.ServiceWvw"
	$str2_2 = "service.ServiceJobScheduler"
	$str2_3 = "receiver.ReceiverBootDevice"
	$str2_4 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str2_5 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str2_6 = "android.permission.WAKE_LOCK"
condition:
	3 of ($str1*) and 3 of ($str2*)
}

rule Android_Spyware_SmsSpy_137354 : knownmalware 
 {
	meta:
		sigid = 137354
		date = "2025-06-19 11:12 AM"
		modified_date = "2025-06-19 12:56 PM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
        $str_1 = "/sendMessage?parse_mode=markdown&chat_id="
        $str_2 = "com.google.myandroi"
        $str_3 = "Berhasil Kirim SMS dari Jauh"
        $str_4 = "/SendSMS;"
        $str_5 = "android.permission.RECEIVE_SMS"

    condition:
        5 of ($str_*)
}

rule Android_Banker_Asacub_137346 : knownmalware 
 {
	meta:
		sigid = 137346
		date = "2025-06-19 05:19 AM"
		modified_date = "2025-06-19 06:33 AM"
		threatname = "Android.Banker.Asacub"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "anu_bispro.app.admky"
        $str_2 = "anu_bispro.app.actinj"
        $str_3 = ".GdOd_As"
        $str_4 = ".GsdfO_Acsad"
        $str_5 = "android.permission.RECEIVE_SMS"

    condition:
        4 of ($str_*)
}

rule Android_Spyware_SmsSpy_137265 : knownmalware 
 {
	meta:
		sigid = 137265
		date = "2025-06-12 11:48 AM"
		modified_date = "2025-06-12 12:11 PM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
        $str_0 = "/api/upload_sms.php"
        $str_1 = "/api/upload_call_log.php"
        $str_2 = "/api/get_bot_commands.php"
        $str_3 = "BotHeartbeatService"
        $str_4 = "BotSmsExporter"
        $str_5 = "InstalledAppsSender"

    condition:
        5 of ($str_*)
}

rule Android_Banker_Zanubis_137174 : knownmalware 
 {
	meta:
		sigid = 137174
		date = "2025-06-06 19:26 PM"
		modified_date = "2025-06-09 12:30 PM"
		threatname = "Android.Banker.Zanubis"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "activity_main"
        $str_1 = "btnActualizar"
        $str_2 = ".apkPK"
        $perm_1 = "android.permission."

    condition:
        all of ($str_*) and #perm_1 == 0
}

rule Android_Banker_SoumniBot_137083 : knownmalware 
 {
	meta:
		sigid = 137083
		date = "2025-05-30 04:33 AM"
		modified_date = "2025-06-02 17:13 PM"
		threatname = "Android.Banker.SoumniBot"
		category = "Banker"
		risk = 127
		
	strings:
        $str1 = "kqkticwjgzy.dat"
        $str2 = "Virbox"
        $str3 = "I0f326f12"
        $str4 = "androidx.core.content.FileProvider"
	$perm_1 = "android.permission.READ_CONTACT"
	$perm_2 = "android.permission.READ_SMS"
	$perm_3 = "android.permission.SEND_SMS"
	$perm_4 = "android.permission.SYSTEM_ALERT_WINDOW"
	$perm_5 = "android.permission.GET_ACCOUNTS"
    condition:
        3 of ($str*) and all of ($perm*)
}

rule Android_Dropper_TsarBot_136882 : knownmalware 
 {
	meta:
		sigid = 136882
		date = "2025-05-16 11:40 AM"
		modified_date = "2025-05-16 12:57 PM"
		threatname = "Android.Banker.TsarBot"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = ".afterINSTALL"
        $str_2 = "DONE_INSTALL_IMPLANT"
        $str_3 = "APKSTORE_DROPPER"
        $str_4 = "res/raw/implant.apk"
        $str_5 = "android.permission.REQUEST_INSTALL_PACKAGES"

    condition:
        all of ($str_*)
}

rule Android_Banker_TsarBot_136881 : knownmalware 
 {
	meta:
		sigid = 136881
		date = "2025-05-16 11:31 AM"
		modified_date = "2025-05-16 12:57 PM"
		threatname = "Android.Banker.TsarBot"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "ScreenCaptureService"
        $str_2 = "TAP_COORDINATES"
        $str_3 = "CLICK_NEAR_TEXT"
        $str_4 = "injects/ServiceName.txt"
        $str_5 = "injects/htmlPIN/android"
        $str_6 = "autoAllowPermissionsDialog"
        $str_7 = "pin_inject"
        $str_8 = "showBlackOverlay"

    condition:
        6 of ($str_*)
}

rule Android_Banker_Coper_136812 : knownmalware 
 {
	meta:
		sigid = 136812
		date = "2025-05-09 18:12 PM"
		modified_date = "2025-05-12 16:46 PM"
		threatname = "Android.Banker.Coper"
		category = "Banker"
		risk = 127
		
	strings:
        $str1_1 = "EXC_SMSRCV"
        $str1_2 = "EXC_BOOTRCV"
        $str1_3 = "EXC_PINGRCV"
        $str2_1 = "GOOGLE_AUTH: auth code"
        $str2_2 = "GOOGLE_AUTH: current user"
        $str3_1  = "short_sms"
        $str3_2  = "disable_gp"
        $str3_3  = "vnc_screen"
        $str3_4  = "VNCINJ"
        $str3_5  = "push_admin"
        $str3_6  = "devadmin_confirm"
        $str3_7  = "keylogger_delay"
        $str3_8  = "smart_inject"
        $str3_9  = "kill_bot"
        $str3_10 = "TEAMVIEWER"
        $str3_11 = "Do you want to wipe all data?"

    condition:
		((any of ($str1_*)) and (any of ($str2_*)) and (3 of ($str3_*))) or
		((any of ($str1_*)) and (4 of ($str3_*))) or
		((any of ($str2_*)) and (4 of ($str3_*))) or
		(5 of ($str3_*))
}

rule Android_Banker_Mamont_136790 : knownmalware 
 {
	meta:
		sigid = 136790
		date = "2025-05-08 06:28 AM"
		modified_date = "2025-05-08 14:01 PM"
		threatname = "Android.Banker.Mamont"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "ru.putisha.gay.SmsService"
        $str_2 = "ru.putisha.gay.WebSocketService"
        $str_3 = "android.permission.READ_CALL_LOG"
        $str_4 = "android.permission.RECEIVE_SMS"
        $str_5 = "android.permission.PROCESS_OUTGOING_CALLS"

    condition:
        all of ($str_*)
}

rule Android_Banker_Mamont_136789 : knownmalware 
 {
	meta:
		sigid = 136789
		date = "2025-05-08 06:11 AM"
		modified_date = "2025-05-08 14:01 PM"
		threatname = "Android.Banker.Mamont"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "Lcom/example/skynet/govno1;"
        $str_2 = "/SMS/SmsReciver;"
        $str_3 = "/CLIENT/GetApps;"
        $str_4 = "/CLIENT/PostCall;"
        $str_5 = "isDefaultSmsApp"

    condition:
        all of ($str_*)
}

rule Android_Trojan_FakeApp_136785 : knownmalware 
 {
	meta:
		sigid = 136785
		date = "2025-05-07 12:42 PM"
		modified_date = "2025-05-07 16:30 PM"
		threatname = "Android.Trojan.FakeApp"
		category = "Trojan"
		risk = 127
		
	strings:
        $str_1 = "android.permission.READ_CONTACTS"
        $str_2 = "android.permission.READ_SMS"
	$str_3 = "microsoft_maui_essentials_fileprovider_file_paths"
        $count_4 = "android:name=\"android.permission."
        $count_5 = "uses-permission android:name="
        $count_6 = "filename:lib/arm64-v8a/"

    condition:
        all of ($str_*) and #count_4 > 1000 and #count_5 > 2000 and #count_6 > 2000
}

rule Android_Banker_FakeCalls_136782 : knownmalware 
 {
	meta:
		sigid = 136782
		date = "2025-05-07 09:01 AM"
		modified_date = "2025-05-07 09:43 AM"
		threatname = "Android.Banker.FakeCalls"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "android.permission.ANSWER_PHONE_CALLS"
        $str_2 = "android.permission.SYSTEM_ALERT_WINDOW"
        $str_3 = "android.permission.MANAGE_OWN_CALLS"
        $str_4 = "android.permission.WRITE_CALL_LOG"
        $str_5 = "sn2c4hg6fprb8.com"

    condition:
        all of ($str_*)
}

rule Android_Banker_Creduz_136767 : knownmalware 
 {
	meta:
		sigid = 136767
		date = "2025-05-06 09:24 AM"
		modified_date = "2025-05-06 13:51 PM"
		threatname = "Android.Banker.Creduz"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "com.android.desync.HiddenAlias"
        $str_2 = "phone_numbers_prefs"
        $str_3 = "/api/logs"
        $str_4 = "SmsDataWorker"
        $str_5 = "SmsServiceChannel"

    condition:
        all of ($str_*)
}

rule Android_Banker_Rewardsteal_136748 : knownmalware 
 {
	meta:
		sigid = 136748
		date = "2025-05-05 08:46 AM"
		modified_date = "2025-05-05 14:43 PM"
		threatname = "Android.Banker.Rewardsteal"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "bm.kisan.app.bwkdswgdjwdjwkd"
        $str_2 = "getLaunchIntentForPackage"
        $str_3 = "openSession"
        $str_4 = "getAssets"
        $str_5 = "android.permission.REQUEST_INSTALL_PACKAGES"

    condition:
        all of ($str_*)
}

rule Android_PUA_FakeApp_136716 : knownmalware 
 {
	meta:
		sigid = 136716
		date = "2025-05-02 12:10 PM"
		modified_date = "2025-05-02 12:37 PM"
		threatname = "Android.PUA.FakeApp"
		category = "PUA"
		risk = 127
		
	strings:
        $str_1 = "app.webproject.MainActivity"
        $str_2 = ".app.backgroundService"
        $str_3 = "/h5?plat=android"
        $str_4 = "addJavascriptInterface"
        $str_5 = "openNewWindow"
        $str_6 = "synCookies"
        $str_7 = "downloadBySystem"

    condition:
        all of ($str_*)
}

rule Android_Banker_Crocodilus_136658 : knownmalware 
 {
	meta:
		sigid = 136658
		date = "2025-04-28 04:16 AM"
		modified_date = "2025-04-28 12:14 PM"
		threatname = "Android.Banker.Crocodilus"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "/Pragmatical"
        $str_1 = "KingGetDears"
        $str_2 = "KingRecep0203"
        $str_3 = "AP76431F58C369"
        $str_4 = "TR2XAQSWDEFRGT"
        $str_5 = "PCROC9F9PCROC"
        $str_6 = "TRS9X8A6D8JBKS"
        $str_7 = "PR0mv2ks6lm7k6m4z2"

    condition:
        6 of ($str_*)
}

rule Android_Banker_Rewards_136635 : knownmalware 
 {
	meta:
		sigid = 136635
		date = "2025-04-25 08:20 AM"
		modified_date = "2025-04-25 10:54 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
        $pkg = "com.pjuddgsg.axisrewards"
        $str_1 = "android.permission.REQUEST_INSTALL_PACKAGES"
        $str_2 = "/axis/axis.apk"
        $str_3 = "/store_sms.php"
        $str_4 = "android.permission.RECEIVE_SMS"

    condition:
        $pkg and 2 of ($str_*)
}

rule Android_Trojan_CardNSuper_136606 : knownmalware 
 {
	meta:
		sigid = 136606
		date = "2025-04-22 07:25 AM"
		modified_date = "2025-04-23 07:46 AM"
		threatname = "Android.Trojan.CardNSuper"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE" 
	$str_2 = "android.nfc.cardemulation.action.HOST_APDU_SERVICE" 
	$str_3 = "android.permission.REQUEST_INSTALL_PACKAGES" 
	$str_4 = "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION"	
	$str_5 = "android.permission.CHANGE_NFC_STATE" 
	$str_6 = "android.permission.NFC"
	$str_7 = "c2c.proto" 
	$str_8 = "c2s.proto"
	$str_9 = "eyJhbGciOiJ"
	$str_10 = "https://api."

condition:
	all of ($str_*)
}

rule Android_Banker_Rewardsteal_136282 : knownmalware 
 {
	meta:
		sigid = 136282
		date = "2025-04-11 08:51 AM"
		modified_date = "2025-04-11 10:53 AM"
		threatname = "Android.Banker.Rewardsteal"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "Customer support INSTALL"
        $str_1 = "Click Proceed to Install"
        $str_2 = "addApkToInstallSession"
        $str_3 = "/Ujjivantreimaka;"

    condition:
        all of ($str_*)
}

rule Android_Banker_SoumniBot_136175 : knownmalware 
 {
	meta:
		sigid = 136175
		date = "2025-04-01 08:58 AM"
		modified_date = "2025-04-01 12:01 PM"
		threatname = "Android.Banker.SoumniBot"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "com.captain.CaptainAccessibilityService"
        $str_1 = ".keepalive.service.RemoteService"
        $str_2 = ".kee.adfadgf.fghdghwefw"
        $str_3 = "android.permission.call_phone"
        $str_4 = "android.permission.FOREGROUND_SERVICE"

    condition:
        all of ($str_*)
}

rule Android_Banker_SoumniBot_136174 : knownmalware 
 {
	meta:
		sigid = 136174
		date = "2025-04-01 08:28 AM"
		modified_date = "2025-04-01 12:00 PM"
		threatname = "Android.Banker.SoumniBot"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "com.kero.ilogisticsko"
        $str_1 = "getSmsInPhone"
        $str_2 = "getAllAppAndUploading"
        $str_3 = "LAST_SMS_NUM"
        $str_4 = "LAST_CONTACT_NUM"

    condition:
        all of ($str_*)
}

rule Android_Spyware_PJobRat_136159 : knownmalware 
 {
	meta:
		sigid = 136159
		date = "2025-03-28 12:03 PM"
		modified_date = "2025-03-28 12:47 PM"
		threatname = "Android.Spyware.PJobRat"
		category = "Spyware"
		risk = 127
		
	strings:
        $str_0 = "/m_chowa_srv/main.php"
        $str_1 = "_ace_am_ace_"
        $str_2 = "__start__scan__"
        $str_3 = "_kansell_"
        $str_4 = "_kontak_"
        $str_5 = "_my_ace_am_ace.txt"
        $str_6 = "_my_foil_struck.txt"

    condition:
        6 of ($str_*)
}

rule Android_Spyware_GhostSpy_136104 : knownmalware 
 {
	meta:
		sigid = 136104
		date = "2025-03-25 09:44 AM"
		modified_date = "2025-03-25 11:15 AM"
		threatname = "Android.Spyware.GhostSpy"
		category = "Spyware"
		risk = 127
		
	strings:
        $str_0 = "mb-call-history-monitor-"
        $str_1 = "mb-location-monitor-"
        $str_2 = "mb-all-gallery-monitor-"
        $str_3 = "SendAllGallery"
        $str_4 = "getCallDetails"
        $str_5 = "getInstalledAppList"
        $str_6 = "setStopUninstall"
        $str_7 = "getAutoStartBackgroundPermission"

    condition:
        6 of ($str_*)
}

rule Android_Banker_Ngate_136098 : knownmalware 
 {
	meta:
		sigid = 136098
		date = "2025-03-25 06:05 AM"
		modified_date = "2025-03-25 11:10 AM"
		threatname = "Android.Banker.NGate"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "assets/xposed_init"
        $str_1 = "assets/android-devices.db"
        $str_2 = "assets/html/desfire-info.en.html"
        $str_3 = "android.permission.NFC"
        $str_4 = "android:minSdkVersion=\"19\""
        $str_5 = "android.nfc.cardemulation.action.HOST_APDU_SERVICE"
        $str_6 = "Password must be exactly 4 digits."
condition:
		all of ($str_*)
}

rule Android_Trojan_FinStealer_136062 : knownmalware 
 {
	meta:
		sigid = 136062
		date = "2025-03-19 12:01 PM"
		modified_date = "2025-03-19 12:01 PM"
		threatname = "Android.Trojan.FinStealer"
		category = "Trojan"
		risk = 127
		
	strings:
        $str_0 = "/SMSForwarder;"
        $str_1 = "/KeepAliveJobService;"
        $str_2 = "fetchForwardingNumber"
        $str_3 = "initializeSMSForwarder"
        $str_4 = "sendMessageToTelegramBots"
        $str_5 = "formatInstallationMessage"
        $str_6 = "requestAutoStartPermission"

    condition:
        6 of ($str_*)
}

rule Android_Banker_TangleBot_136027 : knownmalware 
 {
	meta:
		sigid = 136027
		date = "2025-03-13 08:12 AM"
		modified_date = "2025-03-13 08:12 AM"
		threatname = "Android.Banker.TangleBot"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = "Click Proceed to Install Indusind Bank"
        $str_2 = "addApkToInstallSession"
        $str_3 = "Lcom/verify/weird/InstallDropSession"
        $str_4 = "SESSION_API_PACKAGE_INSTALLED"

	condition:
		all of ($str_*)
}

rule Android_Trojan_Malformed_136020 : knownmalware 
 {
	meta:
		sigid = 136020
		date = "2025-03-12 12:24 PM"
		modified_date = "2025-03-12 12:24 PM"
		threatname = "Android.Trojan.Malformed"
		category = "Trojan"
		risk = 127
		
	strings:
		$mal_1 = "Malformed:filename:"
		$str_1 = "AndroidManifest.xml/"
		$str_2 = "resources.arsc/"
		$str_3 = "classes.dex/"

	condition:
		$mal_1 and any of ($str_*)
}

rule Android_Trojan_Gen_135990 : knownmalware 
 {
	meta:
		sigid = 135990
		date = "2025-03-11 08:42 AM"
		modified_date = "2025-03-11 08:42 AM"
		threatname = "Android.Trojan.Gen"
		category = "Trojan"
		risk = 127
		
	strings:
		$perm = "<uses-permission android"

		$str_0 = "assets/base.apk"
		$str_1 = ".SketchApplication"
		$str_2 = "installApk"
		$str_3 = "application/vnd.android.package-archive"
		$str_4 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$str_5 = "Installing Update"

	condition:
		5 of ($str_*) and #perm == 1
}

rule Android_Banker_FakeCalls_135988 : knownmalware 
 {
	meta:
		sigid = 135988
		date = "2025-03-11 07:01 AM"
		modified_date = "2025-03-11 07:01 AM"
		threatname = "Android.Banker.FakeCalls"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = ".NotificationReServ"
		$str_1 = ".cast.CallMyListener"
		$str_2 = ".jist.LSServ\""
		$str_3 = ".jist.AudioServ\""
		$str_4 = "android.permission.ACCESS_BACKGROUND_LOCATION"
		$str_5 = "android.permission.BIND_INCALL_SERVICE"
		$str_6 = "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION"

	condition:
		all of ($str_*)
}

rule Android_Banker_Mamont_135986 : knownmalware 
 {
	meta:
		sigid = 135986
		date = "2025-03-11 06:08 AM"
		modified_date = "2025-03-11 06:08 AM"
		threatname = "Android.Banker.Mamont"
		category = "Banker"
		risk = 127
		
	strings:
        $cls_1 = "com/example/photo33/core/telephony/sms"
        $str_1 = "/SmsActivity;"
        $str_2 = "/SmsService;"
        $str_3 = "SmsArchiveWorker"
        $str_4 = "permission_granted_report_sent"
        $str_5 = "getMessagesFromIntent"

    condition:
        $cls_1 and 3 of ($str_*)
}

rule Android_Banker_Mamont_135968 : knownmalware 
 {
	meta:
		sigid = 135968
		date = "2025-03-07 10:32 AM"
		modified_date = "2025-03-07 10:32 AM"
		threatname = "Android.Banker.Mamont"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "com.harry.loader.afterINSTALL"
        $str_1 = "com.harry.loader.INSTALL_"
        $str_2 = "loc_sessINSTALL"
        $str_3 = "android.permission.REQUEST_INSTALL_PACKAGES"
        $str_4 = "android.permission.POST_NOTIFICATIONS"
        $str_5 = "android.permission.QUERY_ALL_PACKAGES"

    condition:
        5 of ($str_*)
}

rule Android_Banker_Mamont_135964 : knownmalware 
 {
	meta:
		sigid = 135964
		date = "2025-03-07 08:44 AM"
		modified_date = "2025-03-07 08:44 AM"
		threatname = "Android.Banker.Mamont"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "com.example.yandexdirect"
        $str_1 = "android.permission.READ_SMS"
        $str_2 = "CLIENT_RESTART"
        $str_3 = "android.permission.SEND_SMS"
	condition:
		all of ($str_*)
}

rule Android_Banker_FakeCalls_135836 : knownmalware 
 {
	meta:
		sigid = 135836
		date = "2025-02-25 12:17 PM"
		modified_date = "2025-02-25 12:17 PM"
		threatname = "Android.Banker.FakeCalls"
		category = "Banker"
		risk = 127
		
	strings:
        $str_1 = ".AutoServ\" android:permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE"
        $str_2 = "android.permission.QUERY_ALL_PACKAGES"
        $str_3 = "android.permission.REQUEST_INSTALL_PACKAGES"
        $str_4 = "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
        $str_5 = "res/layout/noti_ffss.xml"

    condition:
        all of ($str_*)
}

rule Android_Banker_Sharkbot_126824 : knownmalware 
 {
	meta:
		sigid = 126824
		date = "2025-02-25 10:22 AM"
		modified_date = "2025-02-25 10:22 AM"
		threatname = "Android.Banker.SharkBot"
		category = "Banker"
		risk = 127
		
	strings:				
		$str_1 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$str_2 = "android.permission.READ_EXTERNAL_STORAGE"
		$str_3 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$str_4 = "android.permission.REQUEST_DELETE_PACKAGES"
		$str_5 = "android.permission.PACKAGE_USAGE_STATS"
		$str_6 = "android.permission.QUERY_ALL_PACKAGES"
		$str_7 = "application/vnd.android.package-archive"
		$str_8 = "android.settings.MANAGE_UNKNOWN_APP_SOURCES"
		$str_9 = "android.intent.action.VIEW"
		$str_10 = "adRC4().rc4Decrypt(APP_STRING)"
		
	condition:
		all of them
}

rule Android_Ransom_SLocker_127132 : knownmalware 
 {
	meta:
		sigid = 127132
		date = "2025-02-25 10:22 AM"
		modified_date = "2025-02-25 10:22 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_2 = "android.permission.USE_FULL_SCREEN_INTENT"
	$str_3 = "android.permission.RECORD_AUDIO"
	$str_4 = "android.intent.action.BOOT_COMPLETED"
	$str_5 = "android.media.SCO_AUDIO_STATE_CHANGED"
	$str_6 = "android:windowSoftInputMode=\"adjustNothing\""
	$str_7 = "android:screenOrientation=\"portrait\""
	$str_8 = "android:showOnLockScreen=\"true\""
	$str_9 = "android:autoRemoveFromRecents=\"true\""
	$str_10 = "android:resizeableActivity=\"false\""
	$str_11 = "android:showWhenLocked=\"true\""
	$str_12 = "android:stopWithTask=\"false\""
	$ktr_13 = "<receiver"

condition:
	all of ($str_*) and #ktr_13 == 1
}

rule Android_Banker_Rewards_128099 : knownmalware 
 {
	meta:
		sigid = 128099
		date = "2025-02-25 10:22 AM"
		modified_date = "2025-02-25 10:22 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.SEND_SMS"
	$str_2 = "android.permission.RECEIVE_SMS"
	$str_3 = "androidx.profileinstaller.action.SKIP_FILE"
	$str_4 = "com.miui.permcenter.autostart.AutoStartManagementActivity"
	$str_5 = "/save_sms0.php?phone="
	
condition:
	all of ($str_*)
}

rule Android_Banker_Rewards_135773 : knownmalware 
 {
	meta:
		sigid = 135773
		date = "2025-02-19 07:43 AM"
		modified_date = "2025-02-19 07:43 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "cardpin"
        $str_1 = "cardnum"
        $str_2 = ".axis_page."
        $str_3 = ".pnb_two_page"
        $str_4 = ".sbi_two_page"
        $str_5 = ".gasbiil."
        $str_6 = ".activity_card"
        $str_7 = "pmkisan_layout.xml"
        $str_8 = "android.provider.Telephony.SMS_RECEIVED"

    condition:
        7 of ($str_*)
}

rule Android_Banker_Mamont_135706 : knownmalware 
 {
	meta:
		sigid = 135706
		date = "2025-02-14 07:00 AM"
		modified_date = "2025-02-14 07:00 AM"
		threatname = "Android.Banker.Mamont"
		category = "Banker"
		risk = 127
		
	strings:
        $str_0 = "sendRequestToServer"
        $str_1 = "/banks/types/Card;"
        $str_2 = "/banks/SmsBank;"
        $str_3 = "push/PushListenerService;"
        $str_4 = "banks/SimOperatorBank;"
        $str_5 = "getAmountFromKoronaPayTransfer"
        $str_6 = "/sms/rat/SmsRat;"
        $str_7 = "sms/rat/SendingSMS;"
        $str_8 = "handleSmsInterception"

    condition:
        6 of ($str_*)
}

rule Android_Trojan_Joker_135677 : knownmalware 
 {
	meta:
		sigid = 135677
		date = "2025-02-11 18:52 PM"
		modified_date = "2025-02-11 18:52 PM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" 
	$str_2 = "duin"  
	$str_3 = "sycu"  
	$str_4 = "suim"
	$str_5 = "sinly"
	$str_6 = "brargh"
	$str_7 = "acc7de"
condition:
	all of ($str_*)
}

rule Android_Trojan_SpyNote_134663 : knownmalware 
 {
	meta:
		sigid = 134663
		date = "2025-02-07 04:23 AM"
		modified_date = "2025-02-07 04:23 AM"
		threatname = "Android.RAT.SpyNote"
		category = "RAT"
		risk = 127
		
	strings:
        $str_1 = "/Config/sys/apps/tch"
        $str_2 = "/Config/sys/apps/loge/pwd"
        $str_3 = "/Config/sys/apps/pay/pay"
        $str_4 = "/Config/sys/apps/rc"
        $str_5 = "/Config/sys/apps/Data"
        $str_6 = "okex.gp:id/amount"
        $str_7 = ":id/etVerificationCode"
        $str_8 = ":id/etSmsVerificationCode"
        $str_9 = "gatei0:id/sms_code_input"
        $str_10 = "gatei0:id/email_code_input"
        $str_11 = "crypto.trustapp:id/input_general_amount"
        $str_12 = "com.android.settings:id/permission_allow_button"

	condition:
		6 of ($str_*)
}

rule Android_Trojan_Spysolr_135546 : knownmalware 
 {
	meta:
		sigid = 135546
		date = "2025-02-04 11:49 AM"
		modified_date = "2025-02-04 11:49 AM"
		threatname = "Android.Trojan.Spysolr"
		category = "Trojan"
		risk = 127
		
	strings:
        $str_0 = "/Startme;"
        $str_1 = "/LockActivity;"
        $str_2 = "/AlertActivity;"
        $str_3 = "/ProxyService;"
        $str_4 = "/ResetServices;"
        $str_5 = "/Splasher;"
        $str_6 = "/RequestDataUsage"
        $str_7 = "android.permission.QUERY_ALL_PACKAGES"
        $str_8 = "android.permission.BIND_ACCESSIBILITY_SERVICE"

    condition:
        7 of ($str_*)
}

rule Android_Trojan_TriaStealer_135492 : knownmalware 
 {
	meta:
		sigid = 135492
		date = "2025-01-31 05:21 AM"
		modified_date = "2025-01-31 05:21 AM"
		threatname = "Android.Trojan.TriaStealer"
		category = "Trojan"
		risk = 127
		
	strings:
        $str_0 = "Mr_tria"
        $str_1 = "/SMSMonitor;"
        $str_2 = "/CallMonitor;"
        $str_3 = "/SendIntro;"
        $str_4 = "/SendData;"
        $str_5 = "/sendMessage"
        $str_6 = "telegram.org/bot"

    condition:
        6 of ($str_*)
}

rule Android_Trojan_Skygofree_130650 : knownmalware 
 {
	meta:
		sigid = 130650
		date = "2025-01-22 09:14 AM"
		modified_date = "2025-01-22 09:14 AM"
		threatname = "Android.Trojan.Skygofree"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "executeCommands"
		$str_1 = "/costanti/Costanti;"
		$str_2 = "upload_history.php"
		$str_3 = "upload_filesystem.php"
		$str_4 = "upload_whatsapp_msg.php"
		$str_5 = "upload_documents.php"
		$str_6 = "upload_listapp.php"
		$str_7 = "upload_sms.php"

	condition:
		7 of them
}

rule Android_Clean_App_135266 : knownclean 
 {
	meta:
		sigid = 135266
		date = "2025-01-17 10:34 AM"
		modified_date = "2025-01-17 10:34 AM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
	$str_1 = "SHA1:6b1ab4824ff7d40d171ddc06376e6df2ad3af033"
	$str_2 = "com.jch_hitachi.aircloudglobal"

condition:
	all of ($str_*)
}

rule Android_Clean_App_135223 : knownclean 
 {
	meta:
		sigid = 135223
		date = "2025-01-13 09:55 AM"
		modified_date = "2025-01-13 09:55 AM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
	$str_1 = "/mnt/vendor/persist/data/c2c/c2c_forwarder.json" 
	$str_2 = "package=\"com.qualcomm.qti.alert\""
	$str_3 = "tcp://localhost" 
condition:
	all of ($str_*)
}

rule Android_Spyware_Gen_135128 : knownmalware 
 {
	meta:
		sigid = 135128
		date = "2024-12-31 09:53 AM"
		modified_date = "2024-12-31 09:53 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "MainActivity$postDataToApi"
		$str_1 = "ScreenRecorderService"
		$str_2 = "ReceiveSms"
		$str_3 = "MyAccessibilityService"
		$str_4 = "/recorded_video.mp4"
		$str_5 = "android.permission.QUERY_ALL_PACKAGES"

	condition:
		all of ($str_*)
}

rule Android_Banker_DroidBot_135011 : knownmalware 
 {
	meta:
		sigid = 135011
		date = "2024-12-18 06:25 AM"
		modified_date = "2024-12-18 06:25 AM"
		threatname = "Android.Banker.DroidBot"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = ".faknotiactivity"
		$str_1 = ".httputils2service"
		$str_2 = ".service1sms$service1sms_B"
		$str_3 = ".trackeractivity"
		$str_4 = ".uploadservice"
		$str_5 = ".a11yforce"
		$str_6 = ".perm_ignorebatperm"
		$str_7 = "android.permission.BIND_ACCESSIBILITY_SERVICE"

	condition:
		7 of ($str_*)
}

rule Android_Spyware_NoviSpy_135010 : knownmalware 
 {
	meta:
		sigid = 135010
		date = "2024-12-18 05:56 AM"
		modified_date = "2024-12-18 05:56 AM"
		threatname = "Android.Spyware.NoviSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "ambient recording command"
		$str_1 = "call recording=%b"
		$str_2 = "video recording=%b"
		$str_3 = "getSmsList"
		$str_4 = "getCallList"
		$str_5 = "getBrowserHistory"
		$str_6 = "startRootShell"

	condition:
		all of ($str_*)
}

rule Android_Spyware_BoneSpy_134993 : knownmalware 
 {
	meta:
		sigid = 134993
		date = "2024-12-17 06:46 AM"
		modified_date = "2024-12-17 06:46 AM"
		threatname = "Android.Spyware.BoneSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "/api/sms/bot/"
		$str_1 = "/api/calllog/bot/"
		$str_2 = "/api/file/upload"
		$str_3 = "/api/recordedcall/bot/"
		$str_4 = "CallRecordService"
		$str_5 = "ScreenCaptureService"
		$str_6 = "android.settings.ACCESSIBILITY_SETTINGS"

	condition:
		6 of ($str_*)
}

rule Android_Spyware_DroidWatcher_134992 : knownmalware 
 {
	meta:
		sigid = 134992
		date = "2024-12-17 06:42 AM"
		modified_date = "2024-12-17 06:42 AM"
		threatname = "Android.Spyware.DroidWatcher"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "NOTIFY_SMS"
		$str_1 = "SCREENSHOT_INTERVAL"
		$str_2 = "SEND_ALLOG_FIRST_RUN"
		$str_3 = "Shotternonroot"
		$str_4 = "recordCalls"
		$str_5 = "RootTools"
		$str_6 = "CommandsModule"
		$str_7 = "sendMessageServer"

	condition:
		all of ($str_*)
}

rule Android_Trojan_Monokle_134968 : knownmalware 
 {
	meta:
		sigid = 134968
		date = "2024-12-12 07:38 AM"
		modified_date = "2024-12-12 07:38 AM"
		threatname = "Android.Trojan.Monokle"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "E+0zbLbnQepatuNrgu4Oj+AZgzQCIiST9aMSBCx867M="
	$str_2 = "lib/arm64-v8a/library.so"

condition:
	all of ($str_*)
}

rule Android_Spyware_EagleMsgSpy_134967 : knownmalware 
 {
	meta:
		sigid = 134967
		date = "2024-12-12 07:20 AM"
		modified_date = "2024-12-12 07:20 AM"
		threatname = "Android.Spyware.EagleMsgSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "SUBJECT: /C=-/ST=-/L=-/O=-/OU=-/CN=-"
		$str_1 = "SUBJECT: /C=(-)/ST=(-)/L=(-)/O=(-)/OU=(-)/CN=(-)"
		$str_2 = "accessibility_service_config.xml"
		$str_3 = "permission_white_external_hint"
		$str_4 = "permission_recode_audio_hint"
		$str_5 = {e6 b2 a1 e6 9c 89 e6 ad a4 e6 9d 83 e9 99 90 ef bc 8c e6 97 a0 e6 b3 95 e5 bc 80 e5 90 af e8 bf 99 e4 b8 aa e5 8a 9f e8 83 bd ef bc 8c e8 af b7 e5 bc 80 e5 90 af e6 9d 83 e9 99 90}

	condition:
		5 of ($str_*)
}

rule Android_Backdoor_DarkNimbus_134916 : knownmalware 
 {
	meta:
		sigid = 134916
		date = "2024-12-09 11:07 AM"
		modified_date = "2024-12-09 11:07 AM"
		threatname = "Android.Backdoor.DarkNimbus"
		category = "Backdoor"
		risk = 127
		
	strings:
		$str_0 = "cmd_10001"
		$str_1 = "cmd_10022"
		$str_2 = "cmd_code=?"
		$str_3 = "ansec_server_config"
		$str_4 = "%s_Crontab_WakeLock"
		$str_5 = "/CrontabService;"
		$str_6 = "/interface/sendfile"
		$str_7 = "/EventMonitorService;"
		$str_8 = "/ChatRecordService;"
		$str_9 = "/ForceStopPackageCmd;"

	condition:
		6 of ($str_*)
}

rule Android_Banker_PixStealer_134900 : knownmalware 
 {
	meta:
		sigid = 134900
		date = "2024-12-05 09:54 AM"
		modified_date = "2024-12-05 09:54 AM"
		threatname = "Android.Banker.PixStealer"
		category = "Banker"
		risk = 127
		
	strings:
		$act_1 = "com.ticket.action.Service"
		$act_2 = "com.ticket.stage.Service"
		$act_3 = "com.sell.allday.Service"
		$str_1 = "getUUID"
		$str_2 = "getInstalled"
		$str_3 = "getHasPermission"
		$str_4 = "/InstallActivity;"
		$str_5 = "setJavaScriptEnabled"
		$str_6 = "android.permission.REQUEST_INSTALL_PACKAGES"

	condition:
		1 of ($act_*) and all of ($str_*)
}

rule Android_Spyware_Loan_134894 : knownmalware 
 {
	meta:
		sigid = 134894
		date = "2024-12-05 06:55 AM"
		modified_date = "2024-12-05 06:55 AM"
		threatname = "Android.Spyware.Loan"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_CALL_LOG"
	$str_2 = "android.permission.READ_SMS"
	$str_3 = "android.permission.CAMERA"
	$str_4 = "tv_detail_loan_duration"
	$str_5 = "tv_detail_payment_date"
	$str_6 = "tv_interest_title"
condition:
	all of ($str_*)
}

rule Android_Banker_Godfather_134657 : knownmalware 
 {
	meta:
		sigid = 134657
		date = "2024-11-14 05:08 AM"
		modified_date = "2024-11-14 05:08 AM"
		threatname = "Android.Banker.GodFather"
		category = "Banker"
		risk = 127
		
	strings:
$str_1 = "cGFja2FnZXN0cA=="
$str_2 = "cGFja2FnZQ=="
$str_3 = "ZHJvcA=="
condition:
	all of them
}

rule Android_Banker_TrickMo_134573 : knownmalware 
 {
	meta:
		sigid = 134573
		date = "2024-11-08 05:41 AM"
		modified_date = "2024-11-08 05:41 AM"
		threatname = "Android.Banker.TrickMo"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "name=\"com.mem.installdropsession.InstallDropSession"
		$str_2 = "name=\"android.permission.REQUEST_INSTALL_PACKAGES"
		$str_3 = "com.example.android.apis.content.SESSION_API_PACKAGE_INSTALLED"
		$str_4 = "filename:assets/base.apk"

	condition:
		all of ($str_*)
}

rule Android_Banker_ToxicPanda_134572 : knownmalware 
 {
	meta:
		sigid = 134572
		date = "2024-11-08 04:16 AM"
		modified_date = "2024-11-08 04:16 AM"
		threatname = "Android.Banker.ToxicPanda"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "updateApk"
		$str_2 = "walletList"
		$str_3 = "stopHereTest"
		$str_4 = "hideShortcuts"
		$str_5 = "restartApp"
		$str_6 = "cancelWakeup"
		$str_7 = "antiDeleteOn"
		$str_8 = "ask_relay"
		$str_9 = "readAlbumList"
		$str_10 = "closeProtect"
		$str_11 = "releaseScreenCapture"
		$str_12 = "reqScreenPermission"
		$str_13 = "takeScreen"
		$str_14 = "capturePic"
		$str_15 = "readContactList"
		$str_16 = "callAppSetting"
		$str_17 = "swipePwdScreenOn"
		$str_18 = "installApk"
		$str_19 = "autoRequestPerm"
		$str_20 = "installPermission"

	condition:
		16 of ($str_*)
}

rule Android_RAT_Gossrat_134558 : knownmalware 
 {
	meta:
		sigid = 134558
		date = "2024-11-07 05:45 AM"
		modified_date = "2024-11-07 05:45 AM"
		threatname = "Android.RAT.Goss"
		category = "RAT"
		risk = 127
		
	strings:
		$str_1 = "getServerLink"
		$str_2 = "enableInternetAndWifi"
		$str_3 = "getPhoneNumber"
		$str_4 = "getLocation"
		$str_5 = "setSilentMode"
		$str_6 = "getContacts"
		$str_7 = "getMessages"
		$str_8 = "getIPAddress"
		$str_9 = "getNetworkType"
		$str_10 = "getBluetoothStatus"
		$str_11 = "getCallLogs"
		$str_12 = "sendSMS"
		$str_13 = "getInstalledApps"
		$str_14 = "getSimOperatorName"

	condition:
		12 of ($str_*)
}

rule Android_Backdoor_Vo1d_134231 : knownmalware 
 {
	meta:
		sigid = 134231
		date = "2024-10-18 10:09 AM"
		modified_date = "2024-10-18 10:09 AM"
		threatname = "Android.Backdoor.Vo1d"
		category = "Backdoor"
		risk = 127
		
	strings:
$str_1 = "chmod 0755 /data/system/installd"
$str_2 = "/data/system/installd > /dev/null 2>&1 &"
$str_3 = "cp -rf "
$recv = "<receiver"
$serv = "<service"
condition:
	2 of ($str*) and #recv==1 and #serv==1
}

rule Android_Banker_Rewards_134180 : knownmalware 
 {
	meta:
		sigid = 134180
		date = "2024-10-15 12:03 PM"
		modified_date = "2024-10-15 12:03 PM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "/rewards/"
		$str_1 = "/CardActivity;"
		$str_2 = "/PinActivity;"
		$str_3 = "/Thank"
		$str_4 = "Enter Valid Card No"
		$str_5 = "Card PIN is Required"
		$str_6 = "Card CVV"
		$str_7 = "/api/user/sms"
		$str_8 = "CallForwardingNotificationListener"

	condition:
		6 of ($str_*)
}

rule Android_Banker_Rewards_134152 : knownmalware 
 {
	meta:
		sigid = 134152
		date = "2024-10-14 11:32 AM"
		modified_date = "2024-10-14 11:32 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "is_online"
	$str_2 = "change_mode" 
	$str_3 = "are_you_online"
	$str_4 = "card_user"
	$str_5 = "user_send"
	$str_6 = "android.permission.RECEIVE_SMS"
	$str_7 = "android.permission.READ_SMS"	
condition:
	all of ($str_*)
}

rule Android_Spyware_Gen_134082 : knownmalware 
 {
	meta:
		sigid = 134082
		date = "2024-10-10 08:23 AM"
		modified_date = "2024-10-10 08:23 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "/phone/bean/ReadSmsBean;"
		$str_1 = "/uit/ContactUtils;"
		$str_2 = "/upload/AwsUploadImpl;"
		$str_3 = "startUpload"
		$str_4 = "getAllContacts"
		$str_5 = "getImageList"

	condition:
		5 of ($str_*)
}

rule Android_Banker_Rewards_133872 : knownmalware 
 {
	meta:
		sigid = 133872
		date = "2024-10-03 07:39 AM"
		modified_date = "2024-10-03 07:39 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
		$perm = "<uses-permission android"

		$rew_0 = "Bank" nocase
		$rew_1 = "Rewards" nocase
		$rew_2 = "card no" nocase
		$rew_3 = " cvv" nocase
		$rew_4 = "card.png"
		$rew_5 = "SMS.json"
		$rew_6 = "Thank.html"
		$rew_7 = "Redeem Points"

		$str_1 = "MessageBody"
		$str_2 = "android.permission.INTERNET"
		$str_3 = "android.permission.RECEIVE_SMS"
		$str_4 = "default-rtdb.firebaseio.com"

	condition:
		2 of ($rew_*) and all of ($str_*) and #perm <= 5
}

rule Android_Trojan_FakeWallet_133708 : knownmalware 
 {
	meta:
		sigid = 133708
		date = "2024-09-27 12:22 PM"
		modified_date = "2024-09-27 10:09 AM"
		threatname = "Android.Trojan.FakeWallet.A"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "SHA1:baf686ff99111f3b7e95e71eb861ff2c91547ae7"
		$str_2 = "package=\"co.median.android.rxqnqb"
		$str_3 = "M0A9i59OR9OexIX3F+d2xchis5TvTjRQAnwrcB2KCG4="
		$str_4 = "assets/appConfig.json"

	condition:
		all of ($str_*)
}

rule Android_Dropper_Necro_133634 : knownmalware 
 {
	meta:
		sigid = 133634
		date = "2024-09-25 05:04 AM"
		modified_date = "2024-09-25 07:24 AM"
		threatname = "Android.Dropper.Necro"
		category = "Dropper"
		risk = 127
		
	strings:
	$str_1 = "com.coral.CoralSdk"
	$str_2 = "libcoral.so"
	$str_3 = "com.coral.vmout.BrigAct"
	
condition:
	all of ($str_*)
}

rule Android_Banker_Ajina_133504 : knownmalware 
 {
	meta:
		sigid = 133504
		date = "2024-09-13 11:30 AM"
		modified_date = "2024-09-13 11:30 AM"
		threatname = "Android.Banker.Ajina"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "BANK_DATA"
		$str_1 = "EXPORT_HISTORY"
		$str_2 = "USSD_REQUEST"
		$str_3 = "/core/SmsReceiver;"
		$str_4 = "HuetaZalupa"
		$str_5 = "originating_address"
		$str_6 = "sim_country_iso"
		$str_7 = "uz.paynet."
		$str_8 = "*111*0887#"
		$str_9 = "expressbank.wallet."

	condition:
		8 of ($str_*)
}

rule Android_Banker_Rewards_133476 : knownmalware 
 {
	meta:
		sigid = 133476
		date = "2024-09-12 10:37 AM"
		modified_date = "2024-09-12 10:37 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "Card No:"
		$str_2 = "mywebClient"
		$str_3 = "MsgDbRef"
		$str_4 = "getMessageBody"
		$str_5 = "getPhoneNo"
		$str_6 = "insertMsgData"
		$str_7 = "SmsBroadcastReceiver"
		$str_8 = "getMsg"
		$str_9 = "android.permission.RECEIVE_SMS"
		$str_10 = "/User;"

	condition:
		9 of ($str_*)
}

rule Android_Clean_OlamDigital_133473 : knownclean 
 {
	meta:
		sigid = 133473
		date = "2024-09-12 10:13 AM"
		modified_date = "2024-09-12 10:13 AM"
		threatname = ""
		category = ""
		risk = -127
		
	strings: 
$str_1 = "com.olam.digital.ofis.HomeActivity" 
$str_2 = "com.olam.digital.ofis.FindFarmerActivity" 
$str_3 = "https://www.olamagri.com/privacy.html"
$type = "staticgen:filetype:apk" 

condition: all of them
}

rule Android_Banker_TrickMo_133455 : knownmalware 
 {
	meta:
		sigid = 133455
		date = "2024-09-11 08:03 AM"
		modified_date = "2024-09-11 08:03 AM"
		threatname = "Android.Banker.TrickMo"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "clicker.json"
		$str_2 = "www/inject.js"
		$str_3 = "appMustBeSmsApp"
		$str_4 = "uninstallProtect"
		$str_5 = "executeCommands"
		$str_6 = "SetClickerConfig"
		$str_7 = "Commands$SendUssd"
		$str_8 = "Commands$ReadSms"
		$str_9 = "Commands$ScreenRecord"
		$str_10 = "Commands$GetAllPhotos"

	condition:
		6 of ($str_*)
}

rule Android_Trojan_SpyAgent_133412 : knownmalware 
 {
	meta:
		sigid = 133412
		date = "2024-09-09 10:30 AM"
		modified_date = "2024-09-09 10:30 AM"
		threatname = "Android.Trojan.SpyAgent"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "access$fetchAllMessages"
		$str_1 = "access$fetchGalleryImages"
		$str_2 = "access$sendSms"
		$str_3 = "access$getWebSocketClient$cp"
		$str_4 = "access$startWebSocketService"
		$str_5 = "android.permission.RECEIVE_SMS"
		$str_6 = "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"

	condition:
		6 of ($str_*)
}

rule Android_Trojan_SpyAgent_133411 : knownmalware 
 {
	meta:
		sigid = 133411
		date = "2024-09-09 10:28 AM"
		modified_date = "2024-09-09 10:28 AM"
		threatname = "Android.Trojan.SpyAgent"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "sendsmsprogress"
		$str_1 = "requestimage"
		$str_2 = "name='uploaded_file';filename="
		$str_3 = "/SendPhotoAlarmBroadcastReceiver;"
		$str_4 = "/SendImageAlarmBroadcastReceiver;"
		$str_5 = "/SendInfoAlarmBroadcastReceiver;"
		$str_6 = "/SendPhoneInformationAlarmBroadcastReceiver;"
		$str_7 = "AlreadySetAlarm"
		$str_8 = "android.permission.USE_EXACT_ALRAM"
		$str_9 = "android.permission.SCHEDULE_EXACT_ALARM"

	condition:
		7 of ($str_*)
}

rule Android_Clean_App_133353 : knownclean 
 {
	meta:
		sigid = 133353
		date = "2024-09-03 06:58 AM"
		modified_date = "2024-09-03 06:58 AM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
	$str_1 = "jp.co.quadsystem.skyphone"
	$str_2 = "SHA1:f014a2645cd3aa80cad7388ac97f168c12804da6" nocase
	
condition:
	all of ($str_*)
}

rule Android_Banker_Rocinante_133316 : knownmalware 
 {
	meta:
		sigid = 133316
		date = "2024-08-30 09:20 AM"
		modified_date = "2024-08-30 09:20 AM"
		threatname = "Android.Banker.Rocinante"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "SecurityProtector"
		$str_1 = "/HttpEnvio$Enviar"
		$str_2 = "/HttpEnvio$GravarToken"
		$str_3 = "/HttpEnvio$ComandoReceber"
		$str_4 = "/MyAccessibilityService$takeScreen"
		$str_5 = "/MyAccessibilityService$telegramApi"
		$str_6 = "RecursividadeText"

	condition:
		5 of ($str_*)
}

rule Android_Banker_Fakecalls_133312 : knownmalware 
 {
	meta:
		sigid = 133312
		date = "2024-08-30 07:25 AM"
		modified_date = "2024-08-30 07:25 AM"
		threatname = "Android.Banker.FakeCalls"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
		$str_1 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$str_2 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$str_3 = "KEY_RUN_MAIN"
		$str_4 = "performAction"
		$str_5 = "installer_error_aborted"
		$str_6 = "KEY_RUN_CALL"

	condition:
		all of ($str_*)
}

rule Android_Banker_Eventbot_133296 : knownmalware 
 {
	meta:
		sigid = 133296
		date = "2024-08-29 08:18 AM"
		modified_date = "2024-08-29 08:18 AM"
		threatname = "Android.Banker.Eventbot"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "eventBot"
		$str_1 = "setA11yService"
		$str_2 = "getInjectEventClass"
		$str_3 = "getRecvUsertFilter"
		$str_4 = "makeA11yServiceInfo"
		$str_5 = "putInjectEventQueue"
		$str_6 = "BlockHardwareButtons"
		$str_7 = "doAutorun"
		$str_8 = "/libInterface$injectEvent;"

	condition:
		7 of ($str_*)
}

rule Android_Clean_App_133285 : knownclean 
 {
	meta:
		sigid = 133285
		date = "2024-08-28 07:55 AM"
		modified_date = "2024-08-28 07:55 AM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
	$str_1 = "com.gpsmapcamera.geotagginglocationonphoto"
	$str_2 = "SHA1:8df36d835a33667c3631ad08534dec244c8ed3d2" nocase
	
condition:
	all of ($str_*)
}

rule Android_Banker_NGate_133248 : knownmalware 
 {
	meta:
		sigid = 133248
		date = "2024-08-23 12:11 PM"
		modified_date = "2024-08-23 12:11 PM"
		threatname = "Android.Banker.NGate"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "SHA1:0c799950ec157bb775637fb3a033a502f211e62e"
		$str_1 = "android.permission.NFC\" android:required=\"true"
		$str_2 = "detectNativeHookEnabled"
		$str_3 = "detectNfcEnabled"
		$str_4 = "sendUPDU"
		$str_5 = "alertWarning"
		$str_6 = "javascript:eventResponse("
		$str_7 = "setJavaScriptCanOpenWindowsAutomatically"

	condition:
		all of them
}

rule Android_Clean_App_133198 : knownclean 
 {
	meta:
		sigid = 133198
		date = "2024-08-19 09:56 AM"
		modified_date = "2024-08-19 09:56 AM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
	$str_1 = "SHA1:2750F001D6C58244D2B7A2CBF981D0EAA3A82FDF" nocase
	$str_2 = "com.panasonic"

condition:
	all of ($str_*)
}

rule Android_Trojan_SMSStealer_133076 : knownmalware 
 {
	meta:
		sigid = 133076
		date = "2024-08-09 07:35 AM"
		modified_date = "2024-08-09 07:35 AM"
		threatname = "Android.Trojan.SMSStealer"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "QWxsb3cgcGVybWlzc2lvbiB0byBjb250aW51ZQ=="
		$str_1 = "c2ltX2NvdW50cnk="
		$str_2 = "SElERQ=="
		$str_3 = "Y29tLmFuZHJvaWQuY2hyb21l"
		$str_4 = "c21zX2JvZHk="
		$str_5 = "Y2FsbF9udW1iZXI="
		$str_6 = "getMessageBody"

	condition:
		6 of ($str_*)
}

rule Android_Banker_Rewards_133053 : knownmalware 
 {
	meta:
		sigid = 133053
		date = "2024-08-07 05:53 AM"
		modified_date = "2024-08-07 05:53 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = "android.permission.READ_SMS"
	$str_3 = "Phone number data does not exist in the database."
	$str_4 = "default-rtdb.firebaseio.com"

condition:
	all of ($str_*)
}

rule Android_Clean_App_133008 : knownclean 
 {
	meta:
		sigid = 133008
		date = "2024-08-02 18:38 PM"
		modified_date = "2024-08-02 18:38 PM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
		
		$str_1 = "SHA1:1a07a65a04a3f8a41e12f09cfcd3f16350110de2" nocase
		$str_2 = "com.qrcreator.meteorrain"
		$str_3 = "android.permission.CAMERA"

	condition:		
	all of ($str_*)
}

rule Android_RAT_BingoMod_133002 : knownmalware 
 {
	meta:
		sigid = 133002
		date = "2024-08-01 09:02 AM"
		modified_date = "2024-08-01 09:02 AM"
		threatname = "Android.RAT.BingoMod"
		category = "RAT"
		risk = 127
		
	strings:
		$str_0 = "BingoMod"
		$str_1 = "findAndClickSecondNode"
		$str_2 = "sendFakeSms"
		$str_3 = "checkFor2FACode"
		$str_4 = "permissioncontroller:id/permission_allow_button"
		$str_5 = "<FAKESMS>"
		$str_6 = "<CLICKNODE>"
		$str_7 = "<SUPRESSMS>"

	condition:
		6 of ($str_*)
}

rule Android_Spyware_Mandrake_132975 : knownmalware 
 {
	meta:
		sigid = 132975
		date = "2024-07-30 05:37 AM"
		modified_date = "2024-07-30 05:37 AM"
		threatname = "Android.Spyware.Mandrake"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "opencv_dnn"
		$str_2 = "assets/raw/asdf.raw"
		$str_3 = "assets/raw/yves.raw"
		$str_4 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$str_5 = ".receiver.ReceiverBootDevice"
		$str_6 = ".service.ServiceJobScheduler"
		$str_7 = ".gui.ActivityOverParent"

	condition:
		6 of them
}

rule Android_Banker_Copybara_131111 : knownmalware 
 {
	meta:
		sigid = 131111
		date = "2024-07-26 11:52 AM"
		modified_date = "2024-07-26 03:51 AM"
		threatname = "Android.Banker.Copybara"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "api.pawan.krd/gtranslate?from=en&to="
	$str_2 = "check_sm_app"
	$str_3 = "ClearHistory"
	$str_4 = "close_systemnotis"
	$str_5 = "CreateNotificationFak"
	$str_6 = "getkeylo_send"
	$str_7 = "send_inj_lst"
	$str_8 = "Send_hvncimage_ToPC"
	$str_9 = "/injectionsupload/"
	$str_10 = "/imageupload/"
	$str_11 = "Send_SMS_To_Admin_From_Android"
	$str_12 = "ws_Get_Device_CallLogs"
	$str_13 = "ws_Hide_AppData_Info"
	$str_14 = "ws_Send_Block_Certain_App"
	$str_15 = "ws_Send_blocknoti_CertainApp"
	$str_16 = "ws_Send_CallPhoneNumber"
	$str_17 = "ws_Send_DeviceScreenShot_Permission"
	$str_18 = "ws_Send_KeyLo_Views"
	$str_19 = "ws_Send_LockScreen_Overlay_CO"
	$str_20 = "ws_Send_Open_CertainApp"
	$str_21 = "ws_Send_Show_Pattren_Buttons"
	$str_22 = "ws_Send_SMSMessage_ToNumber"
condition:
	5 of them
}

rule Android_Ransom_PornLocker_132943 : knownmalware 
 {
	meta:
		sigid = 132943
		date = "2024-07-25 10:39 AM"
		modified_date = "2024-07-25 10:39 AM"
		threatname = "Android.Ransom.PornLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_2 = "android.app.action.DEVICE_ADMIN_ENABLED"
	$str_3 = "libtoolChecker.so"
	$str_4 = "HNL5lDKLTbutwSDHm0r8NDRJwHMOgdwS"

condition:
	all of ($str_*)
}

rule Android_Rat_Rafel_132654 : knownmalware 
 {
	meta:
		sigid = 132654
		date = "2024-07-25 11:32 AM"
		modified_date = "2024-07-25 05:04 AM"
		threatname = "Android.RAT.Rafel"
		category = "RAT"
		risk = 127
		
	strings:
		$str_1 = "Rafel-Rat-"
		$str_2 = "Java-DiscordWebhook-BY-Gelox_"
		$str_3 = "LockTheScreen"
		$str_4 = "checkCommandRequests"
		$str_5 = "rehber_oku"
		$str_6 = "sms_oku"
		$str_7 = "add_victim_device"
		$str_8 = "checkCmdFromServer"
		$str_9 = "/commands.php"

	condition:
		6 of them
}

rule Android_Spyware_Gen_132938 : knownmalware 
 {
	meta:
		sigid = 132938
		date = "2024-07-24 13:03 PM"
		modified_date = "2024-07-24 13:03 PM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
    $data1 = "e62a40378901101db737ac9f374dda3e3addde5d5afc384d134a4fa789a69338e64aef5a937e0e1991ff6e62d92958cc16f9f01b8d44f8da30db24f5d0931a54ba39fe81e5f34472d98aebd4b83cd354"
    $pass1 = "f889b6fe6399a864"
    $data2 = "ef3f8cfec799900b6c76db4394d96390d82c43f2195f4eb47c1bf823e24a8b35ac88c521bddb658aae2af45beb092374"
    $pass2 = "556f5c03eb81ab6d"
    $data3 = "6b73f37a1c32c94ff476443e29874ed2866b1e3f7c3513c6195be511d1781d57"
    $data4 = "995899cbb9b9a4f78530392f1cce2eaec7e03cdcafd03487e825c5256a69f116"
    $pass3 = "53216361b711ba85"
    $data5 = "2a2e33bc489ceb73511c500b8b911ccf"
    $data6 = "b033c6dc2d9cb4ea58a76022a31784cd"
    $data7 = "ef2d209c2e82c47c3712f547a6a6011c251df4135670fcd0489748ac1125d29d"
    $pass4 = "8a16a9764135c0cd"
  condition:
    2 of ($data*) and 2 of ($pass*)
}

rule Android_Spyware_Gen_132932 : knownmalware 
 {
	meta:
		sigid = 132932
		date = "2024-07-24 06:41 AM"
		modified_date = "2024-07-24 06:41 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:

	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = "com.example.application"
	$str_3 = "SHA1:927ca44949d7788aa86f9d7f04d7fdacecd1dfb9" nocase

condition:
	all of ($str_*)
}

rule Android_Spyware_Ratel_132931 : knownmalware 
 {
	meta:
		sigid = 132931
		date = "2024-07-24 06:39 AM"
		modified_date = "2024-07-24 06:39 AM"
		threatname = "Android.Spyware.Ratel"
		category = "Spyware"
		risk = 127
		
	strings:

	$str_1 = "action android:name=\"CLIENT_RESTART\""
	$str_2 = "android:name=\"SMS_DELIVERED\""
	$str_3 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVIC"
	$str_4 = "ScKit-"
condition:
	all of ($str_*)
}

rule Android_Banker_Rewards_132892 : knownmalware 
 {
	meta:
		sigid = 132892
		date = "2024-07-18 05:09 AM"
		modified_date = "2024-07-18 05:09 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = "android.permission.FOREGROUND_SERVICE"
	$str_3 = "SHA1:26b02d233509f4aecf56980032343456ceab722a" nocase

condition:
	all of ($str_*)
}

rule Android_Ransom_SLocker_132852 : knownmalware 
 {
	meta:
		sigid = 132852
		date = "2024-07-10 07:54 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android:minSdkVersion=\"14\""
	$str_2 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_3 = "android.permission.SYSTEM_OVERLAY_WINDOW"
	$str_4 = "android.permission.INTERNAL_SYSTEM_WINDOW"
	$str_5 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_6 = "android.permission.WRITE_SETTINGS"
	$str_7 = "android.permission.EXPAND_STATUS_BAR"
	$str_8 = "android:name=\"android.accessibilityservice.category.FEEDBACK_AUDIBLE\""
	$str_9 = "android:name=\"android.max_aspect\" android:value=\"4\""
	$str_10 = "FAKE_CAMERA_SELECT_CAMERA_PICTURE"
	$str_11 = "FAKE_CAMERA_ROTATE_CLOCKWISE"
	
condition:
	all of ($str_*)
}

rule Android_Banker_Medusa_132697 : knownmalware 
 {
	meta:
		sigid = 132697
		date = "2024-06-26 13:11 PM"
		threatname = "Android.Banker.Medusa"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "app_alias_name\">YouTube"
		$str_1 = "from Settings->Accessibility->Installed Services or Downloaded Services"
		$str_2 = "force_notification_message"
		$str_3 = ".Service.AccessibilityControllerService"
		$str_4 = ".VNCActivity"
		$str_5 = ".Receiver.ScreenReceiver"
		$str_6 = ".Receiver.PhoneStateReceiver"
		$str_7 = ".Service.InstallerRestarterService"
		$str_8 = "android.permission.QUERY_ALL_PACKAGES"

	condition:
		7 of them
}

rule Android_Clean_App_132653 : knownclean 
 {
	meta:
		sigid = 132653
		date = "2024-06-21 09:03 AM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
		$str_1 = "package=\"com.amazon.tv.quicksettings\""
		$str_2 = ".amazon.com"
		$str_3 = "com.amazon.tv.AIRPLAY_LAUNCH"
		
	condition:
		all of them
}

rule Android_Trojan_AridViper_132638 : knownmalware 
 {
	meta:
		sigid = 132638
		date = "2024-06-20 07:41 AM"
		threatname = "Android.Trojan.AridViper"
		category = "Trojan"
		risk = 127
		
	strings:
		//{'d', 'u', 'm', 'm', 'y', '.', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.', 'M', 'a', 'i', 'n', 'A', 'c', 't', 'i', 'v', 'i', 't', 'y'}
		$str_1 = {64 00 75 00 6D 00 6D 00 79 00 2E 00 61 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 2E 00 4D 00 61 00 69 00 6E 00 41 00 63 00 74 00 69 00 76 00 69 00 74 00 79}
		//{'.', 'd', 'u', 'm', 'm', 'y', '.', 'k', 'e', 'e', 'p', '.', 's', 'e', 'r', 'v', 'i', 'c', 'e', '.', 'M', 'y', 'A', 'c', 'c', 'e', 's', 's', 'i', 'b', 'i', 'l', 'i', 't', 'y', 'S', 'e', 'r', 'v', 'i', 'c', 'e'}
		$str_2 = {2E 00 64 00 75 00 6D 00 6D 00 79 00 2E 00 6B 00 65 00 65 00 70 00 2E 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 2E 00 4D 00 79 00 41 00 63 00 63 00 65 00 73 00 73 00 69 00 62 00 69 00 6C 00 69 00 74 00 79 00 53 00 65 00 72 00 76 00 69 00 63 00 65}
		//{'g', 'e', 't', 'm', 'e', '.', 'p', 'h', 'p'}
		$str_3 = {67 00 65 00 74 00 6D 00 65 00 2E 00 70 00 68 00 70}
		//{'i', 'n', 'd', 'x', '.', 'p', 'h', 'p'}
		$str_4 = {69 00 6E 00 64 00 78 00 2E 00 70 00 68 00 70}
		// '/', 'a', 'p', 'p', 's', '/'
		$str_5 = {2F 00 61 00 70 00 70 00 73 00 2F}
		//{'u', 'p', 'd', 'a', 't', 'e', '.', 'a', 'p', 'k'}
		$str_6 = {75 00 70 00 64 00 61 00 74 00 65 00 2E 00 61 00 70 00 6B}

	condition:
		5 of them
}

rule Android_Trojan_AridViper_132639 : knownmalware 
 {
	meta:
		sigid = 132639
		date = "2024-06-20 07:43 AM"
		threatname = "Android.Trojan.AridViper"
		category = "Trojan"
		risk = 127
		
	strings:
		// ':', '/', '/', 'w', 'w', 'w', '.', 'a', 'n', 'd', 'r', 'o', 'i', 'd', 'd', '.', 'c', 'o', 'm'
		$str_1 = {00 3A 00 2F 00 2F 00 77 00 77 00 77 00 2E 00 61 00 6E 00 64 00 72 00 6F 00 69 00 64 00 64 00 2E 00 63 00 6F 00 6D}
		//{'S', 'U', 'P', 'E', 'R', 'S', 'U'}
		$str_2 = {00 53 00 55 00 50 00 45 00 52 00 53 00 55}
		//{'-', '-', 'm', 'o', 'u', 'n', 't', '-', 'm', 'a', 's', 't', 'e', 'r'}
		$str_3 = {2D 00 2D 00 6D 00 6F 00 75 00 6E 00 74 00 2D 00 6D 00 61 00 73 00 74 00 65 00 72}
		//{'/', 's', 'y', 's', '/', 'f', 's', '/', 's', 'e', 'l', 'i', 'n', 'u', 'x', '/', 'e', 'n', 'f', 'o', 'r', 'c', 'e'}
		$str_4 = {00 2F 00 73 00 79 00 73 00 2F 00 66 00 73 00 2F 00 73 00 65 00 6C 00 69 00 6E 00 75 00 78 00 2F 00 65 00 6E 00 66 00 6F 00 72 00 63 00 65 00}
		// {'/', 'b', 'a', 'c', 'k', 'e', 'n', 'd', 'N', 'e', 'w', '/', 'p', 'u', 'b', 'l', 'i', 'c', '/', 'a', 'p', 'i', '/'}
		$str_5 = {62 00 61 00 63 00 6B 00 65 00 6E 00 64 00 4E 00 65 00 77 00 2F 00 70 00 75 00 62 00 6C 00 69 00 63 00 2F 00 61 00 70 00 69 00}
		//'c', 'o', 'm', '.', 'b', 'i', 't', 'd', 'e', 'f', 'e', 'n', 'd', 'e', 'r', '.'
		$str_6 = {63 00 6F 00 6D 00 2E 00 62 00 69 00 74 00 64 00 65 00 66 00 65 00 6E 00 64 00 65 00 72 00 2E 00}
		//'c', 'o', 'm', '.', 'e', 's', 'e', 't', '.'
		$str_7 = {63 00 6F 00 6D 00 2E 00 65 00 73 00 65 00 74 00 2E 00}
		//{'c', 'o', 'm', '.', 'a', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's'}
		$str_8 = {63 00 6F 00 6D 00 2E 00 61 00 6E 00 74 00 69 00 76 00 69 00 72 00 75 00 73}

	condition:
		6 of them
}

rule Android_Clean_App_132613 : knownclean 
 {
	meta:
		sigid = 132613
		date = "2024-06-18 13:06 PM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
		$str_1 = "SHA1:4f48c4ceef4cf22e715183b67362c3f6b7104f2b"
		$str_2 = "com.inductiveautomation.perspectiveapp"
		$str_3 = "android.permission.BLUETOOTH_ADMIN"
		
	condition:
		all of them
}

rule Android_Banker_Gen_132270 : knownmalware 
 {
	meta:
		sigid = 132270
		date = "2024-05-22 09:46 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "com.dhruv.smsrecevier.ReceiveSms"
		$str_2 = "roxma.org.sms_forward.SmsListener"
		$str_3 = ".startupOnBootUpReceiver"
		$str_4 = ".service.RemoteService"
		$str_5 = ".classes.PersistentAppService"

	condition:
		4 of them
}

rule Android_Spyware_DonotAPT_132250 : knownmalware 
 {
	meta:
		sigid = 132250
		date = "2024-05-21 07:50 AM"
		threatname = "Android.Spyware.DonotAPT"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "com.system.myapplication.resource"
		$str_1 = ".TempServ"
		$str_2 = "LoadApk"
		$str_3 = "Resource1.apk"
		$str_4 = "/.thumb"
		$str_5 = "/DexLoad"
		$str_6 = "/Olay_app"
		$str_7 = "raw/fakechat.png "

	condition:
		6 of ($str_*)
}

rule Android_Banker_Gen_132234 : knownmalware 
 {
	meta:
		sigid = 132234
		date = "2024-05-20 10:30 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		//short s = (short) (j2 & 65535);
		//short s2 = (short) ((j2 >>> 16) & 65535);
		//short s3 = (short) (s + s2);
		//short s4 = (short) (s2 ^ s);
		//return ((((short) ((s4 >>> 22) | (s4 << 10))) | (((short) (((short) ((s3 >>> 23) | (s3 << 9))) + s)) << 16)) << 16) | ((short) (((short) (((short) ((s << 13) | (s >>> 19))) ^ s4)) ^ (s4 << 5)));
		$cod_1 = {17 00 ff ff 00 00 a0 02 04 00 84 22 8f 22 13 03 10 00 c5 34 c0 04 84 44 8f 44 90 05 02 04 8f 55 e0 00 05 09 e2 05 05 17 b6 05 8f 55 b0 25 8f 55 b7 24 8f 44 e0 00 02 0d e2 01 02 13 b6 10 8f 00 b7 40 8f 00 e0 01 04 05 b7 10 8f 00 e0 01 04 0a e2 04 04 16 b6 14 8f 44 81 51 c3 31 81 44 c1 14 c3 34 81 00 c1 04 10 04}

		$perm_0 = "label=\"New Version"
		$perm_1 = "android.permission.RECEIVE_SMS"
		$perm_2 = "android.permission.QUERY_ALL_PACKAGES"
		$perm_3 = "android.permission.BIND_AUTOFILL_SERVICE"
		$perm_4 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
		$perm_5 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"

	condition:
		all of ($cod_*) and all of ($perm_*)
}

rule Android_Trojan_Proxy_132195 : knownmalware 
 {
	meta:
		sigid = 132195
		date = "2024-05-17 08:40 AM"
		threatname = "Android.Trojan.Proxy"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.intent.action.BOOT_COMPLETED"
	$str_2 = "Dialer{}"
	$str_3 = "Dialer{}"
	$str_4 = "Listener{}"
	$str_5 = "lib/armeabi-v7a/libgojni.so"
	$str_6 = "Request{Version:"
	
condition:
	5 of ($str_*)
}

rule Android_Downloader_Anatsa_132147 : knownmalware 
 {
	meta:
		sigid = 132147
		date = "2024-05-15 09:31 AM"
		threatname = "Android.Banker.Anatsa"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$str_2 = "com.ultimatefilesviewer.filemanagerwithpdfsupport.DocumentService"
		$str_3 = "com.appandutilitytools.fileqrutility.FileManagerService"
		$str_4 = "android.permission.BIND_JOB_SERVICE"
		$str_5 = "java/lang/reflect/Method"

	condition:
		4 of them
}

rule Android_Banker_Gen_132143 : knownmalware 
 {
	meta:
		sigid = 132143
		date = "2024-05-14 10:24 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "com.smsreceiver."
		$str_1 = "forwarding.live/api"
		$str_2 = "/site/number?site="
		$str_3 = "/sms-reader/add"
		$str_4 = "showPermissionDeniedDialog"
		$str_5 = "sendData"
		$str_6 = "debit.html"
		$str_7 = "NetBanking.html"

	condition:
		6 of them
}

rule Android_Spyware_Gen_132067 : knownmalware 
 {
	meta:
		sigid = 132067
		date = "2024-05-09 09:28 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
    $str_1 = "setJavaScriptEnabled"
    $str_2 = "AllContact"
    $str_3 = "AllCall"
    $str_4 = "Location"
    $str_5 = "inject"
    $str_6 = "Activation"
    $str_7 = "getOriginatingAddress"
    $str_8 = "findAccessibilityNodeInfosByText"	
    $str_9 = "ScKit-"
  condition:
    all of them
}

rule Android_Banker_Gen_132007 : knownmalware 
 {
	meta:
		sigid = 132007
		date = "2024-05-06 11:48 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "getOtpData"
		$str_2 = "getOtpLink"
		$str_3 = "getCardLink"
		$str_4 = "closeKeyboard"
		$str_5 = "getNationalCodeData"
		$str_6 = "socket/message/CardModel;"
		$str_7 = "socket/message/OtpModel;"
		$str_8 = "socket/message/SmsModel;"

	condition:
		7 of them
}

rule Android_Trojan_SMSThief_132004 : knownmalware 
 {
	meta:
		sigid = 132004
		date = "2024-05-06 09:57 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "saveMsgIntoFireBase"
		$str_1 = "sendReceiveSms"
		$str_2 = "forwardViaSMS"
		$str_3 = "handleReceivedSms"
		$str_4 = "getUserSmsList"
		$str_5 = "CardDataActivity"
		$str_6 = "ActivityCardDataBinding"

	condition:
		6 of them
}

rule Android_Clean_App_131976 : knownclean 
 {
	meta:
		sigid = 131976
		date = "2024-05-03 10:10 AM"
		threatname = ""
		category = ""
		risk = -127
		
	strings:
	$str_1 = "com.amazon.tv.settings.v2"
	$str_2 = "SHA1:b60b177956b81c1d635333e4688f02771cd9ebb3"

condition:
	all of ($str_*)
}

rule Android_Banker_FakeCalls_131920 : knownmalware 
 {
	meta:
		sigid = 131920
		date = "2024-04-30 07:34 AM"
		threatname = "Android.Banker.FakeCalls"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "kill-classes.dex"
		$str_1 = ".CommandActivity"
		$str_2 = ".service.LAutoService"
		$str_3 = ".receiver.LOutReceiver"
		$str_4 = ".receiver.LBootReceiver"
		$str_5 = ".service.LHoldService"
		$str_6 = ".service.LCallService"
		$str_7 = ".service.MIDService"
		$str_8 = ".ComPoseActivity"
		$str_9 = ".CallsLogActivity"

	condition:
		8 of them
}

rule Android_Banker_Rewards_131851 : knownmalware 
 {
	meta:
		sigid = 131851
		date = "2024-04-29 06:17 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "assets/flutter_assets/assets/credit_card.png"
	$str_2 = "assets/flutter_assets/assets/login.png"
	$str_3 = "assets/flutter_assets/assets/logo.png"
	$str_4 = "android.permission.RECEIVE_SMS"

condition:
	all of ($str_*)
}

rule Android_Banker_Brokewell_131826 : knownmalware 
 {
	meta:
		sigid = 131826
		date = "2024-04-26 10:58 AM"
		threatname = "Android.Banker.Brokewell"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "com.brkwl.upstracking.AccSrvc"
		$str_1 = ".askLOCKPIN"
		$str_2 = ".AskerPermit"
		$str_3 = ".WebvInject"
		$str_4 = ".SMSBroadcastReceiver"
		$str_5 = "android.settings.action.MANAGE_OVERLAY_PERMISSION"
		$str_6 = "android.permission.ACCESS_BACKGROUND_LOCATION"
		$str_7 = "android.permission.RECORD_AUDIO"

	condition:
		7 of ($str_*)
}

rule Android_Spyware_Spymax_125386 : knownmalware 
 {
	meta:
		sigid = 125386
		date = "2024-04-23 08:16 AM"
		threatname = "Android.Spyware.SpyMax"
		category = "Spyware"
		risk = 127
		
	strings:
		$mani_1 = "android.permission.CALL_PHONE"
		$mani_2 = "android.permission.READ_CONTACTS"
		$mani_3 = "android.permission.READ_SMS"
		$mani_4 = "android.permission.RECORD_AUDIO"
		$mani_5 = "android.permission.WRITE_CONTACTS"
		$mani_6 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$str1_1 = "U3RhcnROZXdTY2Fu"  //base64encoded - startnewscan
		$str1_2 = "aHR0cHM6KiptLmZhY2Vib29rLmNvbSpyLnBocA=="  //base64encoded - facebook php page
		$str1_3 = "I#C#O#N#S#C#A#N#E#R"
		$str1_4 = "setComponentEnabledSetting"
		$str2_1 = "/Config/sys/apps/log"
		$str2_2 = "_callr_lsnr_"

	condition:
		5 of ($mani_*) and all of ($str1*) and 1 of ($str2*)
}

rule Android_Spyware_IRATA_131744 : knownmalware 
 {
	meta:
		sigid = 131744
		date = "2024-04-18 12:32 PM"
		threatname = "Android.Spyware.IRATA"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "_comand"
	$str_2 = "DiviceInfo"
	$str_3 = "_findcontactsbyphone"
	$str_4 = "_parsesmsintent"
	$str_5 = "_sendlargesms"
	$str_6 = "httputils2service"
	$str_7 = "hideAppIcon"
	$str_8 = "runHook"

condition:
	all of ($str_*)
}

rule Android_Zscaler_Unsigned_131742 : knownmalware 
 {
	meta:
		sigid = 131742
		date = "2024-04-18 12:31 PM"
		threatname = "Android.PUA.Modded"
		category = "PUA"
		risk = 127
		
	strings:
	$str_1 = "package=\"zscaler.com.zscaler\""
	$cert_1 = "SHA1:64d5af33ef2c8335b0a016d71b6c31d0f5ef6cfe"	nocase
condition:
	$str_1 and #cert_1 == 0
}

rule Android_Clean_Default_131741 : knownclean 
 {
	meta:
		sigid = 131741
		date = "2024-04-18 12:30 PM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "zscaler.com.zscaler"
	$str_2 = "org.zscaler.player.podcasts.Fieldcast"
	$cert_1 = "SHA1:64d5af33ef2c8335b0a016d71b6c31d0f5ef6cfe"
	
condition:
	1 of ($str_*) and $cert_1
}

rule Android_Ransom_SLocker_131716 : knownmalware 
 {
	meta:
		sigid = 131716
		date = "2024-04-16 05:40 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_2 = "android.intent.action.BOOT_COMPLETED"
	$str_3 = "android.app.action.DEVICE_ADMIN_ENABLED"
	$str_4 = "android.permission.RECEIVE_BOOT_COMPLETED"
	$str_5 = "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
	$str_6 = "instrPixelURL"
	$str_7 = "com.android.systemui"
	
condition:
	all of ($str_*)
}

rule Android_Trojan_SMSThief_131713 : knownmalware 
 {
	meta:
		sigid = 131713
		date = "2024-04-15 12:19 PM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "apply-new-cards.online"
		$str_1 = "submit_sms.php"
		$str_2 = "otp_verify.php"
		$str_3 = "insertMsgdata: massage"
		$str_4 = "android.provider.Telephony.SMS_RECEIVED"
		$str_5 = "getMessageBody"

	condition:
		all of them
}

rule Android_Clean_ShingAC_131686 : knownclean 
 {
	meta:
		sigid = 131686
		date = "2024-04-12 18:48 PM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.qinglianyun.airconditioner"
	$str_2 = "com.qinglianyun.airconditioner.view.LoginActivity" 
	$str_3 = "https://www.qinglianyun.com"	
condition:
	all of ($str_*)
}

rule Android_Spyware_Tispy_131618 : knownmalware 
 {
	meta:
		sigid = 131618
		date = "2024-04-05 12:09 PM"
		threatname = "Android.Spyware.Tispy"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "dal>vi>k>.>sy>st>em>.D>ex>Cl>a>ss>Lo>ad>er"
	$str_2 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$ntr_1 = "android.hardware"
	$ntr_2 = "android.permission"
	condition:
	(all of ($str_*)) and (#ntr_1 > 7) and (#ntr_2  > 15)
}

rule Android_Spyware_MobileSpy_131609 : knownmalware 
 {
	meta:
		sigid = 131609
		date = "2024-04-05 12:09 PM"
		threatname = "Android.Spyware.MobileSpy"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "com.mobilespy.io"
	$str_2 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
	$str_3 = "android.permission.BIND_DEVICE_ADMIN"
	$str_4 = "com.google.firebase.components:com.google.firebase.firestore.FirestoreRegistrar"

	condition:
	all of them
}

rule Android_RAT_Vultur_131589 : knownmalware 
 {
	meta:
		sigid = 131589
		date = "2024-04-04 11:26 AM"
		threatname = "Android.RAT.Vultur"
		category = "RAT"
		risk = 127
		
	strings:
	$str1p1_1 = "application.register"
	$str1p1_2 = "/ejr/"
	$str2p1_1 = "9bd25f13-c3f8-4503-ab34-4bbd63004b6e"
	$str2p1_2 = "f9078181-3126-4ff5-906e-a38051505098"
	$str2p1_3 = "78a01b34-2439-41c2-8ab7-d97f3ec158c6"
	$str2p1_4 = "530be150-f0fe-4dd3-8baf-cb7dd11ec204"
	$str3p1_1 = "installer.config"
	$str3p1_2 = "UpdateActivity"
	$str3p1_3 = "Start install"
	$str3p1_4 = "handleIntent: Install succeeded!"
	$str3p1_5 = "native-lib"
	$str1p2_1 = "filename:assets/a.int"
	$str2p2_1 = "49a7bf5f-cd28-4196-849a-05f3c5315fa8"
condition:
	(1 of ($str1p1*) and 2 of ($str2p1*) and 3 of ($str3p1*)) or ($str1p2_1 and 2 of ($str2*))
}

rule Android_Clean_PitneyBowesInc_131456 : knownclean 
 {
	meta:
		sigid = 131456
		date = "2024-03-28 12:55 PM"
		threatname = "Android.Clean.PitneyBowesInc"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "pitneybowes.pbonetracking.MainActivity"
	$str_2 = "pitneybowes.pbonetracking"
	$str_3 = "android.permission.CAMERA"
	$str_4 = "android.permission.FLASHLIGHT"

condition:
	all of ($str_*)
}

rule Android_Trojan_Thamera_131432 : knownmalware 
 {
	meta:
		sigid = 131432
		date = "2024-03-26 13:36 PM"
		threatname = "Android.Trojan.Thamera"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "SElERQ=="
	$str_2 = "QWxsb3cgcGVybWlzc2lvbiB0byBjb250aW51ZQ=="
	$str_3 = "Y29tLmFuZHJvaWQuY2hyb21l"
	$str_4 = "cankl2k.php?key="
condition:
	all of them
}

rule Android_Spyware_SmsSpy_130750 : knownmalware 
 {
	meta:
		sigid = 130750
		date = "2024-03-26 13:34 PM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "@CafeToseeh"
        $str_2 = "setJavaScriptEnabled"
        $str_3 = "removeObserver"
        $str_4 = "getNumbersendTextMessage"
        $str_5 = "AllContact"
        $str_6 = "AllCall"
        $str_7 = "AllApp"
        $str_8 = "Location"
        $str_9 = "inject"
        $str_10 = "Activation"
        $str_11 = "LogRequest"
        $str_12 = "getOriginatingAddress"
        $str_13 = "findAccessibilityNodeInfosByText"
        $str2_1 = "setComponentEnabledSetting"
	$str2_2 = "hideAppIcon"
	$str2_3 = "/UploadFile"
	$str2_4 = "port.txt"
	$str2_5 = "sms.txt"
condition:
	12 of ($str_*) or (11 of ($str_*) and all of ($str2*))
}

rule Android_Trojan_SMSThief_131408 : knownmalware 
 {
	meta:
		sigid = 131408
		date = "2024-03-22 12:17 PM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "Lshd/ske/NnnActivity;"
		$str_1 = "/sendDocument"
		$str_2 = "filename=\"Contacts.txt"
		$str_3 = "/sendMessage?chat_id="
		$str_4 = "getDefaultSmsPackage"
		$str_5 = "getMessageBody"
		$str_6 = "abortBroadcast"
		$str_7 = "VAHAN PARIVAHAN"

	condition:
		7 of ($str_*)
}

rule Android_Trojan_MalformedManifest_131366 : knownmalware 
 {
	meta:
		sigid = 131366
		date = "2024-03-20 13:01 PM"
		threatname = "Android.Trojan.MalformedManifest"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "filename:AndroidManifest.xml Malformed Binary"
	$str_2 = "Bearbeitung"
	$str_3 = "aktiviert"

condition:
	all of ($str_*)
}

rule Android_Trojan_WipeLocker_131340 : knownmalware 
 {
	meta:
		sigid = 131340
		date = "2024-03-18 12:47 PM"
		threatname = "Android.Trojan.WipeLocker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "wipeMemoryCard"
		$str_2 = "deleteMatchingFile"
		$str_3 = "wipeDirectory"
		$str_4 = "/LockScreen;"
		$str_5 = "showAdminSetting"
		$str_6 = "HideAppFromLauncher"
		$str_7 = "Elite has hacked you"

	condition:
		6 of them
}

rule Android_Spyware_SmsSpy_131322 : knownmalware 
 {
	meta:
		sigid = 131322
		date = "2024-03-15 06:34 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
	$mani_1 = "android.permission.READ_CONTACTS"
	$mani_2 = "android.permission.RECEIVE_SMS"
	$mani_3 = "android.permission.SEND_SMS"
	$mani_4 = "android.permission.INTERNET"
	$str_1 = "/createForumTopic?chat_id="
	$str_2 = "/sendDocument"
	$str_3 = "6502278451:AAFJR8PQRusdj9iBuAeaSt0LDwKthQgw40U"
condition:
	all of ($mani*) and all of ($str*)
}

rule Android_Clean_PaxEngine_131319 : knownclean 
 {
	meta:
		sigid = 131319
		date = "2024-03-14 11:50 AM"
		threatname = "Android.Clean.PaxEngine"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.fiserv.pax."
	$str_2 = "fiserv.com/en/about-fiserv"
	$str_3 = "com.pax.fpac."
	$str_4 = "com.pax.pay.FirstDataPaymentActivity"

condition:
	2 of ($str_*)
}

rule Android_Spyware_Spymax_128261 : knownmalware 
 {
	meta:
		sigid = 128261
		date = "2024-03-14 11:49 AM"
		threatname = "Android.Spyware.Spymax"
		category = "Spyware"
		risk = 127
		
	strings:
		$mani_1 = "android.permission.READ_CALL_LOG"
		$mani_2 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$mani_3 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
		$mani_4 = "android.permission.READ_CONTACTS"
		$mani_5 = "android.permission.CALL_PHONE"
		$mani_6 = "android.permission.READ_SMS"
		$mani_7 = "android.permission.RECORD_AUDIO"
		$mani_8 = "android.permission.CAMERA"
		$mani_9 = "android:label=\"Play Store\""
		$mani_10 = "package android:name=\"null\""
		$str_1 = "U3RhcnROZXdTY2Fu"
		$str_2 = "Config/sys/apps/rc"
		$str_3 = "/Config/sys/apps/log"
		$str_4 = "application/vnd.android.package-archive"
		$str_5 = "setComponentEnabledSetting"
	condition:
		5 of ($mani*) and 4 of ($str*)
}

rule Android_Spyware_SpyLoan_131277 : knownmalware 
 {
	meta:
		sigid = 131277
		date = "2024-03-11 11:28 AM"
		threatname = "Android.Spyware.SpyLoan"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = ".India_Bank_Card_Activity"
		$str_2 = ".IndiaConfirm_LoanActivity"
		$str_3 = ".India_MyBank_Info_Activity"
		$str_4 = "User/sms_list"
		$str_5 = "User/call_log"
		$str_6 = "User/BankInfo"
		$str_7 = "loan/loanList"

	condition:
		5 of ($str_*)
}

rule Android_Clean_Ireactor_131258 : knownclean 
 {
	meta:
		sigid = 131258
		date = "2024-03-08 11:25 AM"
		threatname = "Android.Clean.Ireactor"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.ireactor.iexpectation"
	$str_2 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_3 = "updateConfiguration"
	$str_4 = "com.ireactor.iexpectation.main.MainActivity.Retainer"
	$str_5 = "persistAcrossReboots"


condition:
	all of ($str_*)
}

rule Android_Ransom_SLocker_131225 : knownmalware 
 {
	meta:
		sigid = 131225
		date = "2024-03-06 11:21 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_2 = "android.permission.SYSTEM_OVERLAY_WINDOW"
	$str_3 = "android.permission.INTERNAL_SYSTEM_WINDOW"
	$str_4 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_5 = "android.permission.WRITE_SETTINGS"
	$str_6 = "android.accessibilityservice.category.FEEDBACK_AUDIBLE"
	$str_7 = "com.aide.ui"
	$str_8 = "logcat -v threadtime"

condition:
	all of ($str_*)
}

rule Android_Spyware_SmsSpy_131217 : knownmalware 
 {
	meta:
		sigid = 131217
		date = "2024-03-05 10:03 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "android.permission.READ_CONTACTS"
	$str_3 = "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
	$str_4 = "All contact logs from target"
	$str_5 = "All sms logs from target"
	$str_6 = "offline_mode_phone"
condition:
	all of ($str_*)
}

rule Android_Trojan_MoonSDK_131132 : knownmalware 
 {
	meta:
		sigid = 131132
		date = "2024-03-04 11:12 AM"
		threatname = "Android.Trojan.MoonSDK"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_2 = "com.hack.opensdk"
	$str_5 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_6 = "libpl.so"
	$str_7 = "libl.so"
condition:
	all of ($str_*)
}

rule Android_Trojan_FjordPhantom_131130 : knownmalware 
 {
	meta:
		sigid = 131130
		date = "2024-03-04 11:12 AM"
		threatname = "Android.Trojan.FjordPhantom"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "androidx.loader.app"
	$str_2 = "com.hack.opensdk"
	$str_3 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_4 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
	$str_5 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_6 = "libpl.so"
	$str_7 = "libl.so"
condition:
	all of ($str_*)
}

rule Android_Clean_HybridCast_131198 : knownclean 
 {
	meta:
		sigid = 131198
		date = "2024-03-04 11:11 AM"
		threatname = "Android.Clean.HybridCast"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.access_company.android.hybridcast_connect"
	$str_2 = "https://hybridcast.access-company.com"

condition:
	all of ($str_*)
}

rule Android_Spyware_Facestealer_131133 : knownmalware 
 {
	meta:
		sigid = 131133
		date = "2024-02-26 10:39 AM"
		threatname = "Android.Spyware.Facestealer"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "com.pichillilorenzo.flutter_inappwebview"
	$str_2 = "libapp.so"
	$str_3 = "libflutter.so"
	$str_4 = "assets/flutter_assets/imgs/bg.jpeg"
	$str_5 = "assets/flutter_assets/imgs/f.png"
	$str_6 = "com.pichillilorenzo.flutter_inappwebview"
condition:
	all of ($str_*)
}

rule Android_Trojan_Sdwipe_131116 : knownmalware 
 {
	meta:
		sigid = 131116
		date = "2024-02-22 12:37 PM"
		threatname = "Android.Trojan.Sdwipe"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "deleteInCHunks"
		$str_2 = "/exampleone/MainActivity;"
		$str_3 = "/libexampleone.so"
		$str_4 = "android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION"
		$str_5 = "android.permission.MANAGE_EXTERNAL_STORAGE"

	condition:
		all of them
}

rule Android_Clean_Nova_131115 : knownclean 
 {
	meta:
		sigid = 131115
		date = "2024-02-22 12:37 PM"
		threatname = "Android.Clean.Nova"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.teslacoilsw.launcher"
	$str_2 = "SHA1:DA42AC3031F5E7AAB90EC77C93B9BD79BF0BBD16" nocase
	
condition:
	all of ($str_*)
}

rule Android_Banker_Teabot_131093 : knownmalware 
 {
	meta:
		sigid = 131093
		date = "2024-02-21 05:18 AM"
		threatname = "Android.Banker.Teabot"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android:targetSdkVersion=\"34\""
	$str_2 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_3 = "android.permission.READ_EXTERNAL_STORAGE"
	$str_4 = "android.permission.MANAGE_EXTERNAL_STORAGE"
	$str_5 = "DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
	$str_6 = "android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION"
	$str_7 = "android.intent.category.DEFAULT"
	$str_8 = "android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION"
	$str_9 = "package:%s"
	$numberofperm = "uses-permission android:name"
	
condition:
	all of ($str_*) and #numberofperm == 7
}

rule Android_Banker_Gen_131053 : knownmalware 
 {
	meta:
		sigid = 131053
		date = "2024-02-16 11:56 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "received sms; index:"
		$str_2 = "dateMessage.after(forAnHour) ="
		$str_3 = "t_sms_messages"
		$str_4 = "sms are cleaned up"
		$str_5 = "messages/?id="
	condition:
		all of them
}

rule Android_Spyware_SaveStealer_131052 : knownmalware 
 {
	meta:
		sigid = 131052
		date = "2024-02-16 11:56 AM"
		threatname = "Android.Spyware.SaveStealer"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.intent.action.BOOT_COMPLETED"
	$str_2 = "android.intent.action.QUICKBOOT_POWERON"
	$str_3 = "android.permission.READ_EXTERNAL_STORAGE"
	$str_4 = "android.permission.FOREGROUND_SERVICE"
	$str_5 = "9maWxlcy9zYXZlLmRhdA"
	$str_6 = "L0FuZHJvaWQvZGF0YS9"

condition:
	all of ($str_*)
}

rule Android_Spyware_Spynote_131022 : knownmalware 
 {
	meta:
		sigid = 131022
		date = "2024-02-14 10:35 AM"
		threatname = "Android.Spyware.Spynote"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_EXTERNAL_STORAGE"
	$str_2 = "android.permission.WRITE_EXTERNAL_STORAGE"
	$str_3 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_4 = "android.permission.REQUEST_DELETE_PACKAGES"
	$str_5 = "com.appd.instll.load"
	
condition:
	all of ($str_*)
}

rule Android_Clean_B2M_131007 : knownclean 
 {
	meta:
		sigid = 131007
		date = "2024-02-13 11:36 AM"
		threatname = "Android.Clean.B2M"
		category = "Clean"
		risk = -127
		
	strings:
	$str_2 = "SHA1:E8D363DC15C2F785A83229A9739FB5148A7B3FFE" nocase
	
condition:
	all of ($str_*)
}

rule Android_Trojan_FastSpy_131003 : knownmalware 
 {
	meta:
		sigid = 131003
		date = "2024-02-13 07:33 AM"
		threatname = "Android.Trojan.FastSpy"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "Sms_interval"
		$str_1 = "/sms_loop;"
		$str_2 = "/PostByWeb;"
		$str_3 = "readSMS"
		$str_4 = "sms_prob"
		$str_5 = "send_smsLogs"
		$str_6 = "AppListFiles"
		$str_7 = "start_process"

	condition:
		7 of them
}

rule Android_Spyware_VajraSpy_130945 : knownmalware 
 {
	meta:
		sigid = 130945
		date = "2024-02-06 11:22 AM"
		threatname = "Android.Spyware.VajraSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "uploadUserData"
		$str_1 = "/sms/sms.txt"
		$str_2 = "uploadSMS"
		$str_3 = "fetchMyContacts"
		$str_4 = "getListFiles"
		$str_5 = "uploadContacts"
		$str_6 = "android.permission.RECORD_AUDIO"
		$str_7 = "android.permission.READ_CONTACTS"
		$str_8 = "android.permission.DISABLE_KEYGUARD"

	condition:
		all of them
}

rule Android_Clean_Habbl_130929 : knownclean 
 {
	meta:
		sigid = 130929
		date = "2024-02-02 11:39 AM"
		threatname = "Android.Clean.Habbl"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "Habbl Work"
	$str_2 = "SHA1:f6f747b0ac6f7456188b757cc656cd4ff6eb7f92"
	
condition:
	all of ($str_*)
}

rule Android_Banker_PixBankBot_130887 : knownmalware 
 {
	meta:
		sigid = 130887
		date = "2024-01-30 11:10 AM"
		threatname = "Android.Banker.PixBankBot"
		category = "Banker"
		risk = 127
		
	strings:
		$ser_1 = "com.ticket.action.Service"
		$ser_2 = "com.ticket.stage.Service"
		$ser_3 = "com.sell.allday.Service"
		$str_0 = "InstallWsActivity"
		$str_1 = "android.settings.ACCESSIBILITY_SETTINGS"
		$str_2 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$str_3 = "application/vnd.android.package-archive"
		$str_4 = "android.permission.QUERY_ALL_PACKAGES"

	condition:
		1 of ($ser_*) and 4 of ($str_*)
}

rule Android_Trojan_Joker_130855 : knownmalware 
 {
	meta:
		sigid = 130855
		date = "2024-01-23 12:04 PM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "send_inj_lst"
		$str_1 = "act_perm_dvadmn"
		$str_2 = "Send_Certain_SM"
		$str_3 = "commands_FromPC"
		$str_4 = "faknotiactivity"
		$str_5 = "perm_unknownapps"
		$str_6 = "close_systemnotis"
		$str_7 = "Get_Device_CallLogs"
		$str_8 = "perm_activateoverlay"
		$str_9 = "activity_actionbarhomeclick"

	condition:
		7 of them
}

rule Android_Trojan_FakeApp_130844 : knownmalware 
 {
	meta:
		sigid = 130844
		date = "2024-01-22 12:06 PM"
		threatname = "Android.Trojan.FakeApp"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "getSms"
		$str_1 = "postJsonData"
		$str_2 = "getDeviceInfo"
		$str_3 = "getContacts"
		$str_4 = "android.permission.READ_SMS"
		$str_5 = "NeedsPermissionWithPermissionCheck"
		$str_6 = "LoginActivityNeedsPermissionPermissionRequest"

	condition:
		all of them
}

rule Android_Clean_Mayo_130815 : knownclean 
 {
	meta:
		sigid = 130815
		date = "2024-01-17 11:57 AM"
		threatname = "Android.Clean.Mayo"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "SHA1:1B2C26FDBC600339BFACB1043EFCD6E9696B677F"
		
	condition:
	all of them
}

rule Android_Clean_BluetoothOTA_130810 : knownclean 
 {
	meta:
		sigid = 130810
		date = "2024-01-17 11:53 AM"
		threatname = "Android.Clean.BluetoothOTA"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.jieli.otasdk"
	$str_2 = "com.jieli.otasdk.activities.WelcomeActivity"
	$str_3 = "android.permission.BLUETOOTH_SCAN"


condition:
	all of ($str_*)
}

rule Android_Trojan_SMSThief_130806 : knownmalware 
 {
	meta:
		sigid = 130806
		date = "2024-01-16 11:28 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "android.permission.READ_CONTACTS"
	$str_3 = "android.permission.WRITE_SMS"
	$str_4 = "android.permission.CALL_PHONE"
	$str_5 = "SecretWelcomeActivity"
	$str_6 = "bank01.png"
	$str_7 = "bank02.png"
	$str_8 = "bank11.png"

condition:
	7 of ($str_*)
}

rule Android_Spyware_IRATA_130791 : knownmalware 
 {
	meta:
		sigid = 130791
		date = "2024-01-16 11:25 AM"
		threatname = "Android.Spyware.IRATA"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.SEND_SMS"
	$str_2 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
	$str_3 = "changeicon"
	$str_4 = "setclipboard"
	$str_5 = "send_message_contect"
	$str_6 = "allcontacts"
	$str_7 = "smsbomber"
	$str_8 = "unhideall"

condition:
	all of ($str_*)
}

rule Android_Clean_Ibiz_130789 : knownclean 
 {
	meta:
		sigid = 130789
		date = "2024-01-16 11:23 AM"
		threatname = "Android.Clean.Ibiz"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.icicibank.ibizukcug"
	$str_2 = "com.icicibank.ibizukcug.IncomingSMS"
	$str_3 = "android.provider.Telephony.SMS_RECEIVED"

condition:
	all of ($str_*)
}

rule Android_Ransom_SLocker_130773 : knownmalware 
 {
	meta:
		sigid = 130773
		date = "2024-01-12 12:57 PM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android:minSdkVersion=\"14\""
	$str_2 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_3 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_4 = "android.permission.WRITE_SETTINGS"
	$str_5 = "android:name=\"android.max_aspect\" android:value=\"4\""
	$str_6 = "intent-filter android:priority=\"1000\""
	$str_7 = "android.accessibilityservice.category.FEEDBACK_AUDIBLE"

condition:
	all of ($str_*)
}

rule Android_Ransom_SLocker_130761 : knownmalware 
 {
	meta:
		sigid = 130761
		date = "2024-01-10 11:30 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "com.aide.ui"
	$str_2 = "window"
	$str_3 = "layout_inflater"
	$str_4 = "android.intent.action.BOOT_COMPLETED"
	$str_5 = "logcat -v threadtime"
	$str_6 = "com.aide.runtime.VIEW_LOGCAT_ENTRY"
	$str_7 = "android.permission.RECEIVE_BOOT_COMPLETED"
	$str_8 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_9 = "android:minSdkVersion=\"8\""

condition:
	all of ($str_*)
}

rule Android_Trojan_Xamalicious_130706 : knownmalware 
 {
	meta:
		sigid = 130706
		date = "2024-01-04 15:25 PM"
		threatname = "Android.Trojan.Xamalicious"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = ".AlarmReceiverAction"
		$str_1 = ".ScriptService"
		$str_2 = ".MainJobIntentService"
		$str_3 = ":label=\"TestActivity"
		$str_4 = "android:directBootAware=\"true"
		$str_5 = "mono.MonoRuntimeProvider"
		$str_6 = "permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE"
		$str_7 = "android.permission.SYSTEM_ALERT_WINDOW"
		$str_8 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$str_9 = "assemblies/Core.dll"

	condition:
		all of them
}

rule Android_Spyware_SmsSpy_130703 : knownmalware 
 {
	meta:
		sigid = 130703
		date = "2024-01-03 11:20 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "/Payloads/readCallLogs;"
		$str_1 = "/Payloads/newShell"
		$str_2 = "/Payloads/readSMS;"
		$str_3 = "/controlPanel"
		$str_4 = "getClipData"
		$str_5 = "hideAppIcon"

	condition:
		all of them
}

rule Android_Trojan_TransparentTribe_130702 : knownmalware 
 {
	meta:
		sigid = 130702
		date = "2024-01-03 11:20 AM"
		threatname = "Android.Trojan.TransparentTribe"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0 = "zomatoo.ServiceStuff.MyService"
		$str_1 = "senToServer"
		$str_2 = "Android/media/com.whatsapp/WhatsApp"
		$str_3 = "Please provide a permission, which is required for process"
		$str_4 = "This application is not available in your region"

	condition:
		all of them
}

rule Android_Trojan_SMSThief_130595 : knownmalware 
 {
	meta:
		sigid = 130595
		date = "2023-12-26 15:36 PM"
		threatname = "Android.Trojan.SMSTheif"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.app.role.SMS"
	$str_2 = "android.provider.Telephony.SMS_RECEIVED"
	$str_3 = "https://api.sv-clics-stores.com/api.php"
condition:
	all of ($str_*)
}

rule Android_Trojan_VikingHorde_130590 : knownmalware 
 {
	meta:
		sigid = 130590
		date = "2023-12-22 11:38 AM"
		threatname = "Android.Trojan.VikingHorde"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.WRITE_EXTERNAL_STORAGE"
	$str_2 = "RRR_AAA_FFF"
	$str_3 = "aps_exec"
	$str_4 = "aps_exec_watch_dog"
	$str_5 = "libaps_exec.so"
	$str_6 = "http://loginprotect.mobi"
condition:
	5 of ($str_*)
}

rule Android_RAR_DenDroid_130506 : knownmalware 
 {
	meta:
		sigid = 130506
		date = "2023-12-20 13:05 PM"
		threatname = "Android.Trojan.DenDroid"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "com.connect.Dendroid"
	$str_2 = "com.connect.RecordService"
	$str_3 = "/new-upload.php?"

condition:
	all of ($str_*)
}

rule Android_Trojan_Tasker_130486 : knownmalware 
 {
	meta:
		sigid = 130486
		date = "2023-12-18 12:55 PM"
		threatname = "Android.Trojan.Tasker"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "net.dinglisch.android.taskerm.WILLYUM"
	$str_2 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_3 = "android.permission.SYSTEM_ALERT_WINDOW"

condition:
	all of ($str_*)
}

rule Android_Clean_Ibiz_130485 : knownclean 
 {
	meta:
		sigid = 130485
		date = "2023-12-18 12:55 PM"
		threatname = "Android.Clean.Ibiz"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.icicibank"
	$str_2 = "4F384F2A7FEBD90F182D9FF6600022B220339593"

condition:
	all of ($str_*)
}

rule Android_Spyware_SmsSpy_130445 : knownmalware 
 {
	meta:
		sigid = 130445
		date = "2023-12-12 10:42 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "gossiper.php"
		$str_1 = "androidListener"
		$str_2 = "closeApp"
		$str_3 = "closeKeyboard"
		$str_4 = "addJavascriptInterface"
		$str_5 = "طفا دسترسی های لازم را بدهید !"
		$str_6 = "getMessageBody"
		$str_7 = "android.provider.Telephony.SMS_RECEIVED"
		$recv = "<receiver "

	condition:
		#recv == 0 and all of ($str_*)
}

rule Android_Trojan_SmsSend_130450 : knownmalware 
 {
	meta:
		sigid = 130450
		date = "2023-12-11 10:25 AM"
		threatname = "Android.Trojan.SmsSend"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "getTargetApi"
	$str_2 = "getClipText"
	$str_3 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_4 = "android.permission.SEND_SMS"
	$str_5 = "performGlobalAction"
	$str_6 = "com.googlecode.android_scripting"

condition:
	all of ($str_*)
}

rule Android_Banker_Gen_130436 : knownmalware 
 {
	meta:
		sigid = 130436
		date = "2023-12-08 10:34 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "net.dinglisch.android.taskerm.MyAccessibilityService"
		$str_2 = "net.dinglisch.android.taskerm.MonitorService"
		$str_3 = "net.dinglisch.android.taskerm.ExecuteService"
		$str_4 = "performGlobalAction"
		$str_5 = "lEnable"
		$str_6 = ":targetpackage"

	condition:
		5 of ($str_*)
}

rule Android_Spyware_SmsSpy_130068 : knownmalware 
 {
	meta:
		sigid = 130068
		date = "2023-12-05 16:59 PM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = "GooglePlayServicesUtil"
	$str_3 = "GoogleSignatureVerifier"
	$str_4 = "com.android.chrome"
	$str_5 = "phone_13"
	$str_6 = "devicemodel_13"
	$str_7 = "deviceid_13"
	$str_8 = "senderphone_13"

condition:
	all of ($str_*)
}

rule Android_Spyware_SmsSpy_130337 : knownmalware 
 {
	meta:
		sigid = 130337
		date = "2023-11-24 13:55 PM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "@CafeToseeh"
		$str_2 = "setComponentEnabledSetting"
		$str_3 = "hideAppIcon"
		$str_4 = "/UploadFile"
		$str_5 = "port.txt"
		$str_6 = "sms.txt"
		$str_7 = "/.S/Bot/Panels/"
		$str_8 = "/panel.php"
	condition:
		6 of them
}

rule Android_Banker_Gen_128184 : knownmalware 
 {
	meta:
		sigid = 128184
		date = "2023-04-12 11:47 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.QUERY_ALL_PACKAGES"
	$str_2 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_3 = "android:launchMode=\"4\" android:configChanges=\"screenSize|orientation\">"
	$mtr_7 = "DJU4B6UxRL9xT/3VK+j2xhWTsg001FHHrcVllo4EiXM="
	$mtr_8 = "assets/dancer.jpeg"

condition:
	all of ($str_*) and any of ($mtr_*)
}

rule Android_Trojan_SMSThief_128189 : knownmalware 
 {
	meta:
		sigid = 128189
		date = "2023-04-12 18:20 PM"
		threatname = "Android.Trojan.SMSTheif"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "android.permission.RECEIVE_SMS"
	$str_3 = "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
	$str_4 = "KEY_LAST_SMS_KEY"
	$str_5 = "KEY_MAX_SMS_TIME"
	$str_6 = "MEDIA_TYPE_POS"
	$str_7 = "KEY_USER_KEY"


condition:
	all of ($str_*)
}

rule Android_Spyware_BouldSpy_128234 : knownmalware 
 {
	meta:
		sigid = 128234
		date = "2023-09-26 09:43 AM"
		threatname = "Android.Spyware.BouldSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "F{\"command\":{  \"name\":\"Cameras\",   \"op\":\"takePhoto\""
		$str_2 = "G{\"command\":{  \"name\":\"FunOps\",   \"op\":\"wifiSwitch\""
		$str_3 = "l{\"command\":{  \"name\":\"LocationManager\",   \"op\":\"getLocation\""
		$str_4 = "N{\"command\":{  \"name\":\"Microphone\",   \"op\":\"startRecording\""
		$str_5 = "{\"secret\":\"%s\",\"password\":\"%s\",\"username\":\"%s\",\"server\":\"%s\"}"
		$str_6 = "/api/v1/DeviceInfos/upNode"
		$str_7 = "init camera command"
		$str_8 = "getAllKeyLog"
		$str_9 = "getAppKeylog"
		$str_10 = "clearAllKeyLog"
		$str_11 = "clearKeylogByDate"
		$str_12 = "pingtest:::"
		$str_13 = "servicestart::"
		$mani_1 = "callservice.manager.Keylogger"
		$mani_2 = "name=\"android.permission.READ_SMS\""
		$mani_3 = "name=\"android.permission.SEND_SMS\""
		$mani_4 = "name=\"android.permission.CAMERA\""
		$mani_5 = "name=\"android.permission.RECORD_AUDIO\""
	condition:
		10 of ($str*) and 4 of ($mani*)
}

rule Android_Banker_Rewards_128190 : knownmalware 
 {
	meta:
		sigid = 128190
		date = "2023-04-12 18:37 PM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "Provide Valid mobile No."
	$str_2 = "Provide valid card no."
	$str_3 = "Provide valid cvv"
	$str_4 = "Amount will be credited to your Account"
	$str_5 = "Theme_HDFC"
	$str_6 = "hdfc_logo"
	$str_7 = "android.permission.READ_SMS"


condition:
	all of ($str_*)
}

rule Android_Spyware_Spymax_125554 : knownmalware 
 {
	meta:
		sigid = 125554
		date = "2023-07-14 09:21 AM"
		threatname = "Android.Spyware.Spymax"
		category = "Spyware"
		risk = 127
		
	strings:
		$mani_1 = "android.permission.CALL_PHONE"
		$mani_2 = "android.permission.READ_CONTACTS"
		$mani_3 = "android.permission.READ_CALL_LOG"
		$mani_4 = "android.permission.READ_SMS"
		$mani_5 = "android.permission.RECORD_AUDIO"
		$mani_6 = "android.permission.WRITE_CONTACTS"
		$mani_7 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$str1_1 = "U3RhcnROZXdTY2Fu"
		$str1_2 = "I#C#O#N#S#C#A#N#E#R"
		$str2_1 = "setComponentEnabledSetting"
                $str2_2 = "setJavaScriptEnabled"
                $str2_3 = "removeObserver"

	condition:
		6 of ($mani_*) and all of ($str1*) and 2 of ($str2*)
}

rule Android_Spyware_DonotAPT_128918 : knownmalware 
 {
	meta:
		sigid = 128918
		date = "2023-06-21 18:10 PM"
		threatname = "Android.Spyware.DonotAPT"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.WRITE_EXTERNAL_STORAGE"
	$str_2 = "android.permission.READ_EXTERNAL_STORAGE"
	$str_3 = "android.permission.READ_CONTACTS"
	$str_4 = "android.permission.FOREGROUND_SERVICE"
	$keyc_1 = "CFsRncsyRtRonKoZ"
	$keyc_2 = "ikhfaavpn.com"

condition:
	all of ($str_*) and any of ($keyc_*)
}

rule Android_Trojan_Fleckpe_128534 : knownmalware 
 {
	meta:
		sigid = 128534
		date = "2023-05-16 08:40 AM"
		threatname = "Android.Trojan.Fleckpe"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = {61 73 73 65 74 73 2f [3] 2e 64 61 74}
	$str_2 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
	$str_3 = "android.permission.WRITE_EXTERNAL_STORAGE"
	$str_4 = "android.permission.CHANGE_WIFI_STATE"
	$str_5 = "loadLibrary"
	$ntr_6 = "onNotificationPosted"

condition:
	all of ($str_*) and #ntr_6 == 0
}

rule Android_Anonymizor_Psiphon_127284 : knownmalware 
 {
	meta:
		sigid = 127284
		date = "2023-02-01 10:58 AM"
		threatname = "Android.Anonymizor.Psiphon"
		category = "Anonymizor"
		risk = 127
		
	strings:
	$str_1 = "android.permission.INTERNET"
	$str_2 = "android.permission.ACCESS_WIFI_STATE"
	$str_3 = "com.psiphon3"
	$str_4 = "com.psiphon3.psiphonlibrary.TunnelIntentsHandler"

condition:
	all of ($str_*)
}

rule Android_Clean_AUSpay_127199 : knownclean 
 {
	meta:
		sigid = 127199
		date = "2023-08-21 09:04 AM"
		threatname = "Android.Clean.AUSpay"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "<uses-permission android:name=\"com.pax.appstore.PaxAppStoreService\"/>"
	$str_2 = "package=\"com.fiserv.pax.auspayment\""
	$str_3 = "com.pax.permission.MAGCARD"
	$str_4 = "com.pax.permission.PRINTER"
	$str_5 = "com.pax.permission.PICC"

condition:
	all of ($str_*)
}

rule Android_Banker_Rewards_126710 : knownmalware 
 {
	meta:
		sigid = 126710
		date = "2022-11-08 07:57 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:				
		$str_1 = "android.permission.RECEIVE_SMS"
		$str_2 = "android.permission.READ_SMS"
		$str_3 = "Please put valid  phone No."
		$str_4 = "Please put valid email address"
		$str_5 = "Please put valid  adhaar No."
		$str_6 = "Please add a valid cvc no."
		$str_7 = "Please enter valid Card Holder Name"
		

	condition:
		all of them
}

rule Android_Trojan_HiddenAd_126210 : knownmalware 
 {
	meta:
		sigid = 126210
		date = "2022-08-30 06:11 AM"
		threatname = "Android.Trojan.HiddenAd"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.content.ContactDirectory"
	$str_2 = "android.permission.WAKE_LOCK"
	$str_3 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_4 = "functionads.com:8100"

condition:
	all of them
}

rule Android_Banker_Gen_Itau_124836 : knownmalware 
 {
	meta:
		sigid = 124836
		date = "2021-12-17 06:18 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
$str1="enabled_accessibility_services"
$str2="NEW_CTT"
$str3="KEY_TYPE"
$str4="TIPO_CT"
$str5="CT_DATA_OK"
$str6="PARA_OUTRA"
$str7="KEY_C_INSERTED"
$str8="F_CONFIRMADO"
$str9="PP_OU_CT_CONFIRMAR"
$str10="VAL_OK"
$str11="REVISADO_ACT_OK"
$str12="PWDCARD_INSERTED"
$str13="TSK_FINISH_ACT_OK"
$str14="OK_UNDERSTOOD"
$str15="PWDCARD_INSERTED"
$str16="COMANDO"
$str17="H_ACTION_REC"
$str18="H_ONLY_REC"
$str19="BC_ACT_REC"
$str20="S_OVERLAY"
$str21="H_OVERLAY"
$str22="OP_ACT_REC"
$str23="RESET_ACT_REC"
$str24="YES_ACT_REC"
condition:
15 of ($str*)
}

rule Android_Adware_Leadbolt_125124 : knownmalware 
 {
	meta:
		sigid = 125124
		date = "2022-02-18 07:06 AM"
		threatname = "Android.Adware.Leadbolt"
		category = "Adware"
		risk = 127
		sample = "f3eb35d980d3f1b1fe43d69feee6771c"
	strings:
	$str_1 = "Lcom/Leadbolt/AdController;"
	$str_2 = "Lcom/Leadbolt/AdUtilFuncs;"
	$str_3 = "SD_NOTIFICATION_FIRED_"

condition:
	all of them
}

rule Android_Trojan_SMSStealer_124968 : knownmalware 
 {
	meta:
		sigid = 124968
		date = "2022-01-18 15:37 PM"
		threatname = "Android.Trojan.SMSStealer"
		category = "Trojan"
		risk = 127
		
	strings:
$str1="assets/url.txt"
$str2="/C=US/O=Anywhere Software/CN=Anywhere Software"
$str3="ping -c 2 -W 10 -v google.com"
condition:
all of them
}

rule Android_Spyware_Lydia_129853 : knownmalware 
 {
	meta:
		sigid = 129853
		date = "2023-10-13 09:02 AM"
		threatname = "Android.Spyware.Lydia"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_0 = "package=\"com.lydia.route"
		$str_1 = "Lcom/lydia/route/psms$psms_BR;"
		$str_2 = "Lcom/lydia/route/mysms$mysms_BR;"
		$str_3 = "getOriginatingAddress"
		$str_4 = "android.permission.READ_SMS"
		$str_5 = "android.permission.READ_CONTACTS"
	
	condition:
		5 of ($str_*)
}

rule Android_Trojan_SideWinder_128611 : knownmalware 
 {
	meta:
		sigid = 128611
		date = "2023-05-23 06:35 AM"
		threatname = "Android.Trojan.SideWinder"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1="name=\"apk_name\">Almighty Allah"
		$str_2="name=\"android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
		$str_3="name=\"android.permission.SYSTEM_ALERT_WINDOW"
		$str_4="Go to Accessibility and find <b>Almighty Allah</b>"
		$str_5="fileLoadModule"
		$str_6="WkdGc2RtbHJMbk41YzNSbGJTNUVaWGhEYkdGemMweHZZV1JsY2c9PQ=="
		$str_7="CAPTURE_AUDIO_OUTPUT\": \"512\","
		$str_8="REQUEST_INSTALL_PACKAGES\": \"1048576\","
		$str_9="test.dex"
	condition:
		8 of ($str_*)
}

rule Android_Trojan_GoldDigger_129775 : knownmalware 
 {
	meta:
		sigid = 129775
		date = "2023-10-06 20:32 PM"
		threatname = "Android.Trojan.GoldDigger"
		category = "Trojan"
		risk = 127
		
	strings:
		$ast_0 = "lib/armeabi-v7a/libstrategy.so"
		$ast_1 = "assets/index.html"
		$ast_2 = "assets/mask1.html"
		$ast_3 = "assets/img/mask_bg.png"

		$cert_0 = "SHA256:c83ddae07f46d0c335f990c8ca6dd86207a57cf4449cc26b23bc9888e7f41c89"
		$cert_1 = "SHA256:4fb1eb92e887f711ee2e966d72338c3ae30e8d97e2330b6170fb20e760e341db"
		$cert_2 = "SHA256:81ab778079ae2a36d54ed8c9c85396bfcd1270e44c1532319d65b21e338225a3"

		$mnf_1 = ".ShotApplication"
		$mnf_2 = "android.permission.GET_INSTALLED_APPS"
		$mnf_3 = "android.permission.KILL_BACKGROUND_PROCESSES"
		$mnf_4 = "android.permission.GRANT_RUNTIME_PERMISSIONS"
		$mnf_5 = ".HelpService\" android:permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE"

	condition:
		all of ($ast_*) and ( 1 of ($cert_*) or all of ($mnf_*) )
}

rule Android_Banker_SharkBot_124741 : knownmalware 
 {
	meta:
		sigid = 124741
		date = "2021-11-30 15:42 PM"
		threatname = "Android.Banker.SharkBot"
		category = "Banker"
		risk = 127
		sample1 = "beae001d3bbdcf7a05c053e6773f9796"
sample2 = "55f63478d1f9c52ec783ba1ba987fc65"
	strings:
	$str_1 = "needA11"
	$str_3 = "overlayLife"
	$str_4 = "aa11_start_time"

condition:
	all of them
}

rule Android_Banker_Gen_123763 : knownmalware 
 {
	meta:
		sigid = 123763
		date = "2021-08-06 15:23 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample1 = "706ac516bec70f5fac4d74ad38b450ad"
sample2 = "8c5b2d434d40c35952d2bfb3de5a2483"
	strings:
	$str_1 = ".Acessibilidade\""
	$str_2 = "android.accessibilityservice.AccessibilityService"
	$str_3 = ".MainService\""
        $target_1 = "\"br.com.Inter.CDPro\""
        $target_2 = "\"br.com.intermedium\""
        $target_3 = "\"br.com.uol.ps.myaccount\""
        $target_4 = "\"com.santander.app\""

condition:
	all of ($str_*) and 2 of ($target_*)
}

rule Android_Spyware_Gen_Comm_123739 : knownmalware 
 {
	meta:
		sigid = 123739
		date = "2021-08-05 10:11 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
$comm1="load_settings"
$comm2="send_sms"
$comm3="delete_sms"
$comm4="upload_contracts"
$comm5="upload_call_log"
$comm6="upload_sms"
$comm7="delete_app"
$comm8="upload_location"
$comm9="start_record"
$comm10="end_call"
$comm11="upload_AppInfo"
$comm12="live_on"
$comm13="live_switch"
$comm14="live_off"
$comm15="add_contract"
$comm16="delete_contract"
$comm17="delete_calllog"
$comm18="take_picture"
condition:
15 of ($comm*)
}

rule Android_PWS_Facebook_FlyTrap_123799 : knownmalware 
 {
	meta:
		sigid = 123799
		date = "2021-08-12 10:33 AM"
		threatname = "Android.PWS.Facebook"
		category = "PWS"
		risk = 127
		
	strings:                                                            
$str1="graph.facebook.com" 
$str2="picture?type=large"                                            
$str3="Ynsuper"                                                       
$str4={43 6F 6F 6B 69 65 00 32 43 6F 6F 6B 69 65 4D 61 6E 61 67 65 72 2E 67 65 74 49 6E 73 74 61 6E 63 E2 80 A6 2E 55 52 4C 5F 47 45 54 5F 43 4F 4F 4B 49 45 5F 46 41 43 45 42 4F 4F 4B 29}
condition:                                                            
all of ($str*)
}

rule Android_Clean_App_123588 : knownclean 
 {
	meta:
		sigid = 123588
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		sample = "6D52737D509D36BAEFB85CCEB8A5D71F"
	strings:
	$str_1 = "android:sharedUserId=\"android.uid.system\"" // Signature must be same as system apps
	$str_2 = "package=\"net.soti.mobicontrol."
	$str_3 = "net.soti.mobicontrol.enterprise.SotiEnterpriseService"
	$str_4 = "net.soti.mobicontrol.EnterpriseApplication"
condition:
	$str_1 and $str_2 and ($str_3 or $str_4)
}

rule Android_Banker_Gen_123827 : knownmalware 
 {
	meta:
		sigid = 123827
		date = "2021-08-16 11:48 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
$manifest1="VNCActivity"
$manifest2="InjectionHtmlActivity"
$manifest3="MessageActivity"
$manifest4="Receiver.SmsSendService"
$manifest5="Service.WorkerAccessibilityService"
$manifest6="Service.InstallerService"
$manifest7="Service.DisplayServiceJava"
$manifest8="Service.NotificationService"
$manifest9="Receiver.MmsReceiver"
$manifest10="Service.DeviceAdminService"
$manifest11="Receiver.ScreenReceiver"
$manifest12="Service.InstallerRestarterService"
$manifest13="Receiver.PhoneStateReceiver"
$manifest14="Receiver.BootReceiver"
condition:
all of them
}

rule Android_Spyware_SpinOk_128709 : knownmalware 
 {
	meta:
		sigid = 128709
		date = "2023-05-31 11:25 AM"
		threatname = "Android.Spyware.SpinOk"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "d3hdbjtb1686tn.cloudfront.net/gpsdk.html"
	$str_2 = "s.hisp.in"
	$str_3 = "PlacementId"
	$str_4 = "com.spin.ok.gp"

condition:
	3 of ($str_*)
}

rule Android_Trojan_Downloader_124197 : knownmalware 
 {
	meta:
		sigid = 124197
		date = "2021-10-01 14:11 PM"
		threatname = "Android.Trojan.Downloader"
		category = "Trojan"
		risk = 127
		sample1 = "6345f3fcbc072bcda13f85f4c8e2705e"
sample2 = "605ad7c4647ab196aaca55b7ffb3958c"
	strings:
	$str_1 = "Hidden Install"
	$str_2 = "KEY_JSON_DIALOG"
	$str_3 = "IS_TWO_STEP_PUSH"
	$str_4 = "SERVICES_TWO_STEP"
	$str_5 = "IS_INSTALL_DOWNLOADER"
	$str_6 = "KEY_COMPLETE_SECOND_VAS"
	$str_7 = "COUNT_PUSHED_SERVICE_TWO_STEP"
condition:
	5 of them
}

rule Android_Banker_PixStealer_124179 : knownmalware 
 {
	meta:
		sigid = 124179
		date = "2021-09-30 07:19 AM"
		threatname = "Android.Banker.PixStealer"
		category = "Banker"
		risk = 127
		
	strings:
$str1="Abra o app PagSeg para sincronizar ."
$str2="trava_operacional"
$str3="controle_remoto"
$cls4="/autobot/Acessibilidade"
$cls5="/autobot/Acessibilidade_Telas"
$cls6="/autobot/Acessibilidade_Utils"
$str4="CONFIRMAR TRANSF"
condition:
1 of ($cls*) and 3 of ($str*)
}

rule Android_Trojan_SmsBot_124458 : knownmalware 
 {
	meta:
		sigid = 124458
		date = "2021-10-29 09:50 AM"
		threatname = "Android.Trojan.SmsBot"
		category = "Trojan"
		risk = 127
		sample = "b8815b39d59a1c7694cf941b86484b80"
	strings:
	$str_1 = "qhkzhkwtcwhkbxjhaxsvrhlp" // Decryption key
	$str_2 = "com.whatsapp"

condition:
	all of them
}

rule Android_Trojan_Joker_125571 : knownmalware 
 {
	meta:
		sigid = 125571
		date = "2022-05-12 19:19 PM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "Bsys.modobom.sms2.services.WebActivityReceiver.CODE_RECEIVED_ACTION"
		$str_2 = "Asys.modobom.sms2.services.MainActivityReceiver.OK_RECEIVED_ACTION"
		$str_3 = "Keyword"
		$str_4 = "ShortCode"
		$str_5 = "TelcoID"
		$str_6 = "javascript:document.getElementById('btnSubscriber').click();"
		$str_7 = "javascript:document.getElementById('btn-ReqOTP').click();"
		$str_8 = "javascript:(function(){document.querySelector('#otp-box').value='"
		$str_9 = "javascript:document.getElementById('en-btn-ConfirmOTP').click();"
		$str_10= "https://subs.modogr.com/auto_subs?phone="

	condition:
	 all of them
}

rule Android_Trojan_Cas_126608 : knownmalware 
 {
	meta:
		sigid = 126608
		date = "2022-10-25 07:07 AM"
		threatname = "Android.Trojan.Cas"
		category = "Trojan"
		risk = 127
		
	strings:				
		$str_1 = "com.liveposting.livepostsdk.AdFakeService"
		$str_2 = "com.click.cas"
		$str_3 = "javascript:window.HTMLOUT.procClick('<html>'+document.getElementsByTagName('html')[0].innerHTML+'</html>');"

	condition:
		all of them
}

rule Android_Banker_Gen_KBstar_124973 : knownmalware 
 {
	meta:
		sigid = 124973
		date = "2022-01-19 04:37 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
$str1=".CPMActivity"
$str2=".CommandActivity"
$str3=".service.LInitService"
$str4=".service.MIDService"
$str5=".service.MMService"
$str6=".service.LSService"
$str7=".service.LHoldService"
$str8=".service.LCallService"
$str9=".service.LAutoService"
condition:
all of them
}

rule Android_Banker_Rewards_127154 : knownmalware 
 {
	meta:
		sigid = 127154
		date = "2023-01-17 13:55 PM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "/Kyc_Page;"
		$str_2 = "/Permission_Activity;"
		$str_3 = "/SmsReceiver;"
		$str_4 = "android.provider.Telephony.SMS_RECEIVED"
		$str_5 = "/api/user"
		$str_6 = "/Thank;"
		
		$txt_1 = "Enter Expiry Date"
		$txt_2 = "Enter CVV"
		$txt_3 = "Enter Card"
		$txt_4 = "Redeem Points"

	condition:
		5 of ($str_*) and 2 of ($txt_*)
}

rule Android_Trojan_Dropper_Gen_126795 : knownmalware 
 {
	meta:
		sigid = 126795
		date = "2022-11-18 09:49 AM"
		threatname = "Android.Trojan.Dropper"
		category = "Trojan"
		risk = 127
		
	strings:
		$manifest_1 = "com.mhiauaqmlacl.ypmsfwbkjhsbeoz.cubaihhb"
		$manifest_2 = "com.mhiauaqmlacl.ypmsfwbkjhsbeoz.vakurcpyiawjef"
		$manifest_3 = "com.mhiauaqmlacl.ypmsfwbkjhsbeoz.nfsznithxfoc"
		$manifest_4 = "com.mhiauaqmlacl.ypmsfwbkjhsbeoz.izyiyumk"
		$manifest_5 = "com.mhiauaqmlacl.ypmsfwbkjhsbeoz.gtzkggpuaqjntiao"
		$manifest_6 = "com.mhiauaqmlacl.ypmsfwbkjhsbeoz.edxqppjkyu"
		$manifest_7 = "com.mhiauaqmlacl.ypmsfwbkjhsbeoz.hattohfg"
		$manifest_8 = "com.mhiauaqmlacl.ypmsfwbkjhsbeoz.lwmcrlixkvo"
		$manifestp_9 = "android.permission.CALL_PHONE"
		$manifestp_10 = "android.permission.READ_SMS"
		$manifestp_11 = "android.permission.RECORD_AUDIO"
		$manifestp_12 = "android.permission.SEND_SMS"
		$manifestp_13 = "android.permission.RECEIVE_SMS"
		$manifestp_14 = "android.permission.DISABLE_KEYGUARD"
		$manifestp_15 = "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION"
	condition:
		5 of ($manifest_*) and 5 of ($manifestp_*)
}

rule Android_Banker_Xenomorph_126664 : knownmalware 
 {
	meta:
		sigid = 126664
		date = "2022-11-08 07:59 AM"
		threatname = "Android.Banker.Xenomorph"
		category = "Banker"
		risk = 127
		
	strings:				
		$str_1 = "Google Services"
		$str_2 = "First Fragment"
		$str_3 = "Tap for Additional info!"
		$str_4 = "android.permission.KILL_BACKGROUND_PROCESSES"
		$str_5 = "android.permission.READ_SMS"
		$str_6 = "android.permission.SYSTEM_ALERT_WINDOW"
		

	condition:
		all of them
}

rule Android_Banker_DawDropper_126665 : knownmalware 
 {
	meta:
		sigid = 126665
		date = "2022-11-08 07:59 AM"
		threatname = "Android.Banker.DawDropper"
		category = "Banker"
		risk = 127
		
	strings:				
		$str_1 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$str_2 = "android.permission.WAKE_LOCK"
		$str_3 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$str_4 = "android.permission.RECEIVE_BOOT_COMPLETED"
		$str_5 = "Builder(context, NOTIFIC…tentIntent(pendingIntent)"
		$str_6 = "robin_prefs"
		$str_7 = "Robin"
	condition:
		6 of them
}

rule Android_Ransomware_Nannoware_126369 : knownmalware 
 {
	meta:
		sigid = 126369
		date = "2022-09-26 12:14 PM"
		threatname = "Android.Ransomware.Nannoware"
		category = "Ransomware"
		risk = 127
		
	strings:
	$str_1 = "KwK8iFWNjq2Y8odzV6bCJtvwRGjFt3hLr7XFk1dwpbKJtS5rBziu"
	$str_2 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_3 = "com.termuxhackers.id"
	$str_4 = "com.adrt.CONNECT"


condition:
	3 of them
}

rule Android_Spyware_Spymax_126387 : knownmalware 
 {
	meta:
		sigid = 126387
		date = "2022-09-29 11:19 AM"
		threatname = "Android.Spyware.Spymax"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "U3RhcnROZXdTY2Fu"
		$str_2 = "Config/sys/apps/rc"
		$str_3 = "/Config/sys/apps/log"
		$str_4 = "RecordNow"
		$str_5 = "application/vnd.android.package-archive"
		$str_6 = "setComponentEnabledSetting"
		$str_7 = "ScanPawwords"
	condition:
		6 of them
}

rule Android_Spyware_Uyghurs_126342 : knownmalware 
 {
	meta:
		sigid = 126342
		date = "2022-09-23 09:30 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "Y2htb2QgLVIgNDc1NSAvc3lzdGVtL2Jpbi9zY3JlZW5jYXBcbg"
	$str_2 = "com.android.browser.permission.READ_HISTORY_BOOKMARKS"
	$str_3 = "android.permission.WRITE_SMS"
	$str_4 = "android.intent.action.NEW_OUTGOING_CALL"
	$str_5 = "android.intent.action.PACKAGE_INSTALL"
	$str_6 = "android.permission.READ_SMS"
	$str_7 = "android.permission.READ_CONTACTS"

condition:
	all of them
}

rule Android_Spyware_Gen_125879 : knownmalware 
 {
	meta:
		sigid = 125879
		date = "2022-09-13 07:29 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "CN:Gaurav Kapoor, L:Delhi, O:Mobile, ST:Delhi, OU:Gaurav Kapoor Apps"
		$str_2 = "screenshotsscnds"
		$str_3 = "gkap121"
		$str_4 = "Please Hide notifications for better performance otherwise app will not work properly"
		$str_5 = "Backtrack55@@"
		$str_6 = "savedmessagesd"
		$str_7 = "terminateAndEraseFile"
		$str_8 = "savedcalld"
		$str_9 = "call_recording_instagram"
		$str_10 = "call_recording_messenger"
		$str_11 = "call_recording_whatsapp"
		$mani_1 = "SocialRecordService"
		$mani_2 = "ViberRecordService"
		$mani_3 = "InstagramRecordService"
		$mani_4 = "TeleRecordService"
		$mani_5 = "MessengerRecordService"
	condition:
		8 of ($str*) or
		all of ($mani*) or 
		6 of ($str*) and all of ($mani*)
}

rule Android_Trojan_SMSSpy_125873 : knownmalware 
 {
	meta:
		sigid = 125873
		date = "2022-06-30 08:13 AM"
		threatname = "Android.Trojan.SMSSpy"
		category = "Trojan"
		risk = 127
		
	strings:
		$mani_1 = "android.permission.RECEIVE_SMS"
		$mani_2 = "android.permission.READ_SMS"
		$recv = "<receiver "
		$str_1 = "تارگت جدید نصب کرد"
		$str_2 = "linkrat?phone="
		$str_3 = "erroeererewrwerwer"

	condition:
		#recv == 1 and all of ($mani*) and all of ($str*)
}

rule Android_Banker_Drinik_125802 : knownmalware 
 {
	meta:
		sigid = 125802
		date = "2022-06-20 07:30 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "65 117 116 111 67 77 68" //decodes to AutoCMD
		$str_2 = "73 78 83 84 65 76 76 58 58 58" //decodes to INSTALL:::
		$str_3 = "117 110 108 111 99 107" //decodes to unlock
		$str_4 = "105 110 115 116 97 108 108 83 117 99 99 101 115 115" // decode to installSuccess
		$str_5 = "32 47 32 65 99 99 32 115 116 97 116 32 105 115 32" //decodes to  / Acc stat is 
		$str_6 = "112 114 111 99 101 115 115 67 77 68" //decodes to processCMD
		$str_7 = "73 110 116 101 114 99 101 112 116 77 101 115 115 97 103 101" //decodes to InterceptMessage

	condition:
		all of them
}

rule Android_Banker_Hqwar_125556 : knownmalware 
 {
	meta:
		sigid = 125556
		date = "2022-05-10 10:25 AM"
		threatname = "Android.Banker.Hqwar"
		category = "Banker"
		risk = 127
		
	
	
	strings:
		$perm_1 = "android.permission.WRITE_SMS"
		$perm_2 = "android.permission.SEND_SMS"
		$perm_3 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$perm_4 = "android.permission.RECORD_AUDIO"
		$perm_5 = "android.permission.RECEIVE_SMS"
		$perm_6 = "android.permission.READ_SMS"
		$perm_7 = "android.permission.READ_CONTACTS"
		$perm_8 = "android.permission.DISABLE_KEYGUARD"
		$perm_9 = "android.permission.CALL_PHONE"
		$mani_1 = "bot.sms.SmsReceiver"
		$mani_2 = "bot.sms.ComposeSmsActivity"
		$mani_3 = "bot.components.commands.NLService"
		$mani_4 = "bot.components.injects.system.InjAccessibilityService"
		$mani_5 = "bot.components.screencast.ScreencastService"

	condition:
		all of them


}

rule Android_Trojan_Xhelper_129732 : knownmalware 
 {
	meta:
		sigid = 129732
		date = "2023-10-05 13:47 PM"
		threatname = "Android.Trojan.Xhelper"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "android:minSdkVersion=\"14\" android:targetSdkVersion=\"23\""
		$str_2 = "Begin to invoke attack method"
		$str_3 = "android.permission.REQUEST_INSTALL_PACKAGES"	
		$str_4 = "Attack launched"		
	condition:
		all of them
}

rule Android_Trojan_FakeBankRewards_126329 : knownmalware 
 {
	meta:
		sigid = 126329
		date = "2022-09-22 10:16 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "com.example.test_app"
	$str_2 = "Enter a Valid CRN or Card Number"
	$str_3 = "Select Card Expiry Date"
	$str_4 = "Enter Valid Card CVV"
	$str_5 = "android.permission.READ_CONTACTS"
	$str_6 = "android.permission.READ_SMS"

condition:
	all of them
}

rule Android_Spyware_VINETTHORN_126318 : knownmalware 
 {
	meta:
		sigid = 126318
		date = "2022-09-19 18:21 PM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "GetPublicIp"
	$str_3 = "AndroidDownload"
	$str_4 = "AndroidHttpModuleData"
	$str_5 = "AndroidBigDownload"
	$str_6 = "IsRunClipboard"

condition:
	all of them
}

rule Android_Spyware_PINEFLOWER_126317 : knownmalware 
 {
	meta:
		sigid = 126317
		date = "2022-09-19 18:16 PM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "commands_data"
	$str_3 = "data"
	$str_4 = "request_without_response"
	$str_5 = "send_text_response"

condition:
	all of them
}

rule Android_Trojan_Harly_126322 : knownmalware 
 {
	meta:
		sigid = 126322
		date = "2022-09-20 10:58 AM"
		threatname = "Android.Trojan.Harly"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "Brave"
	$str_2 = "Chet"
	$str_3 = "Gray"
	$str_4 = "Martin"
	$str_5 = "com.clear.memory.gl"
	$str_6 = "https://apphelper.s3-ap-southeast-1.amazonaws.com"
	$str_7 = "cleanmaster.apk"

condition:
	4 of them
}

rule Android_Trojan_SLocker_126264 : knownmalware 
 {
	meta:
		sigid = 126264
		date = "2022-09-10 16:09 PM"
		threatname = "Android.Trojan.SLocker"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.intent.action.BOOT_COMPLETE"
	$str_2 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_3 = "com.adrt.LOGCAT_ENTRIES"
	$str_4 = "com.adrt.STOP"
	$str_5 = "stackLocationKinds"
	$str_6 = "logcat -v threadtime"

condition:
	all of them
}

rule Android_Spyware_VINETTHORN_126261 : knownmalware 
 {
	meta:
		sigid = 126261
		date = "2022-09-10 06:54 AM"
		threatname = "Android.Spyware.APT42"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "android.permission.ACCESS_FINE_LOCATION"
	$str_3 = "IsRunClipboard"
	$str_4 = "AndroidHttpModuleData"
	$str_5 = "AndroidBigDownload"
	$str_6 = "GetPublicIp"

condition:
	all of them
}

rule Android_Spyware_FinSpy_126251 : knownmalware 
 {
	meta:
		sigid = 126251
		date = "2022-09-07 19:11 PM"
		threatname = "Android.Trojan.FinSpy"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "8a0ea65bd5"
		$mani_2 = "android.permission.SEND_SMS"
		$mani_3 = "android.permission.READ_SMS"
		$mani_4 = "android.permission.INTERNET"

	condition:
		all of them
}

rule Android_Banker_Installer_126176 : knownmalware 
 {
	meta:
		sigid = 126176
		date = "2022-08-25 08:39 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "https://raw.githubusercontent.com"
		$str_2 = "android.intent.action.VIEW"
		$str_3 = "file://"
		$mani_1 = "application/vnd.android.package-archive"
		$mani_2 = "android.intent.action.DOWNLOAD_COMPLETE"
		$mani_3 = "android.permission.READ_EXTERNAL_STORAGE"
		$mani_4 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$mani_5 = "android.permission.WAKE_LOCK"
		$mani_6 = "android.support.FILE_PROVIDER_PATHS"
	
	condition:
		all of them
}

rule Android_Banker_Anatsa_126178 : knownmalware 
 {
	meta:
		sigid = 126178
		date = "2022-08-25 08:39 AM"
		threatname = "Android.Banker.Anatsa"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "in.makaek.galbak.KAopneaoniAoiasM"
		$mani_1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"

	condition:
		all of them
}

rule Android_Spyware_Badbazaar_129726 : knownmalware 
 {
	meta:
		sigid = 129726
		date = "2023-09-29 07:28 AM"
		threatname = "Android.Spyware.Badbazaar"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "com.SolARCS.SolClient.Client"
		$str_2 = "com.solarcs.executor.CommandHandler"
		$str_3 = "CommandExecute"
		$str_4 = "assets/server.cer"
	condition:
		all of them
}

rule Android_Spyware_ToadFraud_126494 : knownmalware 
 {
	meta:
		sigid = 126494
		date = "2022-10-13 13:21 PM"
		threatname = "Android.Spyware.ToadFraud"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.WRITE_EXTERNAL_STORAGE"
	$str_2 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_3 = "Vuoi installare questa app sicura?"
	$str_4 = "install_non_market_apps"
	$str_5 = "AppUpdateExample.txt"
	$str_6 = "tap.apk"
condition:
	5 of them
}

rule Android_Spyware_RatMilad_126484 : knownmalware 
 {
	meta:
		sigid = 126484
		date = "2022-10-13 09:06 AM"
		threatname = "Android.Spyware.RatMilad"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_CALL_LOG"
	$str_2 = "android.permission.WRITE_EXTERNAL_STORAGE"
	$str_3 = "android.permission.READ_EXTERNAL_STORAGE"
	$str_4 = "android.permission.READ_PHONE_STATE"
	$str_5 = "android.permission.GET_ACCOUNTS"
	$str_6 = "android.permission.BLUETOOTH_ADMIN"
	$str_7 = "android.permission.READ_SMS"
	$str_8 = "android.permission.READ_CONTACTS"
	$str_9 = "getNumbersStatus"
	$str_10 = "userid"
	$str_11 = "getNumber"
	$str_12 = "setStatus"
	$str_13 = "orderBy"
	
condition:
	all of them
}

rule Android_Banker_Gen_125049 : knownmalware 
 {
	meta:
		sigid = 125049
		date = "2022-02-04 12:45 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample1 = "90cd32e995b031368f3338136696124a"
sample2 = "50ba955ff89e6d4ea873ea35459cd696"
	strings:
	$str_1 = "SMSData"
	$str_2 = "ApiService"
	$str_3 = "SMS_RECIEVE"
	$str_4 = "Intent Avtion"
	$str_5 = "get-all-number"
	$str_6 = "sendTextMessage"
	$str_7 = "complaint_register"

condition:
	all of them
}

rule Android_Trojan_GriftHorse_125137 : knownmalware 
 {
	meta:
		sigid = 125137
		date = "2023-09-26 09:40 AM"
		threatname = "Android.Trojan.GriftHorse"
		category = "Trojan"
		risk = 127
		sample = "0111ca320dff30f333fa317ad0cb1d8f,036820e9600275cb4914f9b38a9c34bf,032158e16b40f3308710e21654847170"
	strings:
		$str_1 = "getActiveNetworkInfo" //checking for network connection to load the url in webview
		$str_2 = "android_id" //getting device id for subscription registration
		$str_3 = "loadurl" nocase   //function that loads the malicious url in webview
		$str_4 = /[a-z0-9]{12,14}.cloudfront.net/  //malicious url working as proxy
		$str_5 = "sendfirstpackage" nocase  //sending packets with device details

	condition:
		all of them
}

rule Android_Banker_Flubot_125161 : knownmalware 
 {
	meta:
		sigid = 125161
		date = "2023-09-26 09:40 AM"
		threatname = "Android.Banker.Flubot"
		category = "Banker"
		risk = 127
		sample="7dad305e548697c077cc952c8288f9c,a0002e660cc263420965f7655d26e078,96883b264b6d3ff4cb1b6ee3567fc3d8"
	strings:
		$receiver = "<receiver "
		$service = "<service "
		$provider = "<provider "
		$manifest1 = "android.permission.CALL_PHONE"
		$manifest2 = "android.permission.QUERY_ALL_PACKAGES"
		$manifest3 = "android.permission.READ_CONTACTS"
		$manifest4 = "android.permission.READ_SMS"
		$manifest5 = "android.permission.RECEIVE_SMS"
		$manifest6 = "android.permission.REQUEST_DELETE_PACKAGES"
		$manifest7 = "android.permission.SEND_SMS"
		$manifest8 = "android.permission.WRITE_SMS"
		$manifest9 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
		$manifest10 = "service.notification.NotificationListenerService"
		$manifest11 = "accessibilityservice.AccessibilityService"

	condition:
		#receiver >=2 and #receiver <=5 and #service >=5 and #service <=9 and #provider == 0 and all of ($manifest*)
}

rule Android_Trojan_SMForw_125190 : knownmalware 
 {
	meta:
		sigid = 125190
		date = "2022-02-25 10:19 AM"
		threatname = "Android.Trojan.SMForw"
		category = "Trojan"
		risk = 127
		sample1 = "f3544c9ccaf0fca7ded55e2f2dacead2"
sample2 = "1d1fb3362dedf5eb4ada486c3d59c75f"
	strings:
	$str_1 = "kill_app_hint"
	$str_2 = "TARGET_PHONE_NUMBER"
	$str_3 = "enter the phone number forward to"
	$str_4 = "Feel free to remove this App from background App list, it will run permanently."

condition:
	all of them
}

rule Android_Spyware_DomesticKitten_125154 : knownmalware 
 {
	meta:
		sigid = 125154
		date = "2022-02-23 06:38 AM"
		threatname = "Android.Spyware.DomesticKitten"
		category = "Spyware"
		risk = 127
		
	strings:
$c2urlpath="get-function.php?uuid="
$c2comms1="AllLog"
$c2comms2="AllContact"
$c2comms3="AllFile"
$c2comms4="AllSms"
$c2comms5="AllCall"
$c2comms6="AllApp"
$c2comms7="AllBrowser"
$c2comms8="AllAccount"
$c2comms9="AllSetting"
$c2comms10="Location"
$c2comms11="HardwareInfo"
condition:
all of them
}

rule Android_Spyware_Joker_124859 : knownmalware 
 {
	meta:
		sigid = 124859
		date = "2021-12-23 10:26 AM"
		threatname = "Android.Spyware.Joker"
		category = "Spyware"
		risk = 127
		sample = "38B3955BFF7D241C9EF06BDB17F7DCEF"
	strings:
	$str_1 = "FOUR_JING"
	$str_2 = "subscribecount"
	$str_3 = "suSuccessLimit"
	$str_4 = "appCampTrackUrl"
	$str_5 = "appCampSuccessKey"
	$str_6 = "setNovaSdkExecuteCallback"

condition:
	4 of them
}

rule Android_Trojan_Cynos_124739 : knownmalware 
 {
	meta:
		sigid = 124739
		date = "2021-11-30 13:24 PM"
		threatname = "Android.Trojan.Cynos"
		category = "Trojan"
		risk = 127
		sample = "88f8a2e6dd41022db7d0c79d5fe607b0"
	strings:
	$str_1 = "SMSNUMBER_QIXINTONG"
	$str_2 = "URL_GETPROVANDCITY_TAOBAO"
	$str_3 = "/sdk/api/init/advert/advertLogin"
	$str_4 = "://dns1.sdkbalance.com:"

condition:
	3 of them
}

rule Android_RAT_SSLlove_124647 : knownmalware 
 {
	meta:
		sigid = 124647
		date = "2022-03-02 11:59 AM"
		threatname = "Android.RAT.SSLlove"
		category = "RAT"
		risk = 127
		
	strings:
$str1="insert into targets values("
$str2="into commands_tb values("
$str3="insert into gbwhatssappp values("
$str4="insert into contacts_ values("
$str5="insert into messages"
$str6="insert into files"
$str7="insert into con_type values("
condition:
all of them
}

rule Android_Trojan_Gen_124404 : knownmalware 
 {
	meta:
		sigid = 124404
		date = "2021-10-25 07:54 AM"
		threatname = "Android.Trojan.Gen"
		category = "Trojan"
		risk = 127
		
	strings:
		$str1="AMStrings:fps"
		$str2="desilib"
		$str3="Shell terminated unexpectedly"
		$str4="echo -BOC-"
		$str5="su --mount-master"
		$str6="removeObserver"
		$str7="xxxxxxxxxxxxxxxxxxxx"
		$str8="YW1pdGRlc2lzZ2g="
		$str9="696969"
		$str10="Permission:ACCESS_SUPERUSER"
		$str11="LIBSU"
	condition:
	5 of ($str*)
}

rule Android_Trojan_FakeApp_NTT_124228 : knownmalware 
 {
	meta:
		sigid = 124228
		date = "2021-10-06 09:17 AM"
		threatname = "Android.Trojan.FakeApp"
		category = "Trojan"
		risk = 127
		
	strings:
$str1="share_pref"
$str2="Status"
$str4="android.settings.WIFI_SETTINGS"
$str5="TenJS"
$str6="docomo.ne.jp"
$str7="DES"
condition:
all of them
}

rule Android_Banker_Gen_124322 : knownmalware 
 {
	meta:
		sigid = 124322
		date = "2021-10-14 15:32 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample = "E15B9BEF5D1C00AE80AC9ED86D5FFBAF"
	strings:
	$str_1 = ".Call2Activity"
	$str_2 = ".NotifyService"
	$str_3 = ".receiver.MmsReceiver"
	$str_4 = ".service.FloatingWindow"
	$str_5 = ".service.MyAccessService"
	$str_6 = ".service.RecorderService"
	$str_7 = ".service.HeadlessSmsSendService"

condition:
	6 of them
}

rule Android_Ransom_Locker_124254 : knownmalware 
 {
	meta:
		sigid = 124254
		date = "2021-10-08 09:54 AM"
		threatname = "Android.Ransom.Locker"
		category = "Ransom"
		risk = 127
		sample = "cdc77f3dfabdea5c5278ac9e50841ff3"
	strings:
	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = ".FloatingWindowService"
	$str_3 = "RunBackgoundTips"
	$str_4 = ".SmSserver"
	$str_5 = "SmsReceiver"
	$str_6 = "android.permission.BIND_DEVICE_ADMIN"

condition:
	all of them
}

rule Android_Trojan_Gen_124252 : knownmalware 
 {
	meta:
		sigid = 124252
		date = "2021-10-07 18:37 PM"
		threatname = "Android.Trojan.Gen"
		category = "Trojan"
		risk = 127
		sample = "4609172d3aeb3dd270cc9afbeff2940c"
	strings:
	$str_1 = "TenJS"
	$str_2 = "share_pref"
	$str_3 = "EmailSender"
	$str_4 = "EncryptUtils"
	$str_5 = "mail.smtp.host"
	$str_6 = "decryptPassword"
	$str_7 = "PASSWORD_ENC_SECRET"

condition:
	all of them
}

rule Android_Banker_Cerberus_Ermac_124145 : knownmalware 
 {
	meta:
		sigid = 124145
		date = "2021-09-27 07:31 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
$str1= "filename:assets/66666692.amr filetype: b'Zip archive data, at least v2.0 to extract'"
$str2="filename:assets/lastAccetsbkup.zip filetype: b'Zip archive data, at least v2.0 to extract'"
condition:
all of them
}

rule Android_Banker_Gen_Mexico_124034 : knownmalware 
 {
	meta:
		sigid = 124034
		date = "2021-09-14 13:40 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
$str1="/acceso.jpg"
$str2="/error.php?id="
$str4="/recibidos.php?id="
$str5="/recibidos.php?id=&clave="
$str6="/recibidos.php?id=&usuario="
condition:
all of them
}

rule Android_Trojan_FBCredstealer_123553 : knownmalware 
 {
	meta:
		sigid = 123553
		date = "2021-07-09 15:50 PM"
		threatname = "Android.Trojan.FBCredstealer"
		category = "Trojan"
		risk = 127
		sample1 = "0e8805b683bc0fd8a6d49b07205f1a4b"
sample2 = "263b0851156f7d77fb43368ce13bede1"
	strings:
	$str_1 = "isForceLogin"
	$str_2 = "updateSystemConfig"
	$str_3 = "AES/ECB/PKCS5Padding"
	$str_4 = "delayUploadData"
	$str_5 = "decodeString"
	$str_6 = "com.facebook.FacebookActivity"

condition:
	all of them
}

rule Android_Trojan_FakeApp_129522 : knownmalware 
 {
	meta:
		sigid = 129522
		date = "2023-09-11 07:16 AM"
		threatname = "Android.Trojan.FakeApp"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "Lcom/wsys/sync/UploadChatManager;"
		$str_2 = "uploadTextMessageToService"
		$str_3 = "cacheDataAndSendToService"
		$str_4 = "uploadFileToBeCloud"
		$str_5 = "uploadFriendData"

	condition:
		all of them
}

rule Android_Trojan_WyrmSpy_129158 : knownmalware 
 {
	meta:
		sigid = 129158
		date = "2023-07-25 12:02 PM"
		threatname = "Android.Trojan.WyrmSpy"
		category = "Trojan"
		risk = 127
		
	strings:
		$cls_1 = "Lcom/flash18/service_invoker;"
		$cls_2 = "/MainifestFile.json"
		$cls_3 = "assets/Module"

		$str_1 = "SystemPhotos"
		$str_2 = "getcallhistory"
		$str_3 = "configCommandServer"
		$str_4 = "ExecServerCmd"
		$str_5 = "execute_command_handler"
		$str_6 = "/AdobeService;"
		$str_7 = "nableSocks5"
		$str_8 = "getContacts"

	condition:
		all of ($cls_*) and 5 of ($str_*)
}

rule Android_Spyware_Gen_123929 : knownmalware 
 {
	meta:
		sigid = 123929
		date = "2021-08-27 07:47 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		sample = "d9bb807475089d7495c9d5712bd9d701"
	strings:
	$str_1 = "/openVip.htm"
	$str_2 = "/uploadSms.htm"
	$str_3 = "/uploadAlbum.htm"
	$str_4 = "/sychonizeUser.htm"
	$str_5 = "/uploadContact.htm"
	$str_6 = "uploadEnvironmentRecord"

condition:
	5 of them
}

rule Android_Spyware_Joker_123863 : knownmalware 
 {
	meta:
		sigid = 123863
		date = "2021-08-20 06:26 AM"
		threatname = "Android.Spyware.Joker"
		category = "Spyware"
		risk = 127
		sample = "121c0a7501ce7256ad778e438c2f8ce4"
	strings:
	$str_1 = "task_smsPkg"
	$str_2 = "imageDama Post:"
	$str_3 = "initPinReceiver"
	$str_4 = "moSend--->:address:"
	$str_5 = "getSuspectNumbers--:"
	$str_6 = "getEvinaData--post--country:"

condition:
	4 of them
}

rule Android_Trojan_SmsSend_HushSMS_123812 : knownmalware 
 {
	meta:
		sigid = 123812
		date = "2021-08-13 12:55 PM"
		threatname = "Android.Trojan.SmsSend"
		category = "Trojan"
		risk = 127
		sample = "1f0d5f287d19bcbbe7049d6e1cd2c777"
	strings:
	$str_1 = "com.silentservices.hushsms.XposedIntentReceiver"
	$str_2 = "HUSHSMS_MESSAGE_RECEIVED"	
	$str_3 = "FRPFILE SMS"

condition:
	all of them
}

rule Android_Banker_Gen_125670 : knownmalware 
 {
	meta:
		sigid = 125670
		date = "2022-05-26 08:27 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample1 = "6903e41347af87f4c4865c90f2217ea8"
sample2 = "3d92ba1a26ffde6239542a2fbe683871"
	strings:
	$str_1 = "cmd_done"
	$str_2 = "force_calls"
	$str_3 = "<>Silent_done"
	$str_4 = "all_sms_received"
	$str_5 = "all_call_received"
	$str_6 = "activity_login_kotak_cvv"
	$str_7 = "Call Logs Permission Denies"

condition:
	5 of them
}

rule Android_Spyware_Gen_125884 : knownmalware 
 {
	meta:
		sigid = 125884
		date = "2022-07-03 18:37 PM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		sample = "b1e0ad60b4113ecfdf74e930848dcab4"
	strings:
	$str_1 = "SecIncoms"
	$str_2 = "kuN5EwGGo0"
	$str_3 = "ProfService"
	$str_4 = "PBS Protector ha bisogno di questa"

condition:
	3 of them
}

rule Android_Clean_HondaAssist_123807 : knownclean 
 {
	meta:
		sigid = 123807
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		author = "Sdesai"
desc = "inline yara - c61ba780590bd1b270b748b9974a3f85, 5c1d7fed77de765487f4f87c101666b6"
	strings:
		$str1 = "package=\"jp.co.honda"
		$str2 = "SHA-256-Digest: jWWBevK7vuIdPflQSkSYE3/TkQGHZEBdl/SnK7NySJ8=" // Name: lib/armeabi/libbackup_crypto.so
		$str3 = "SHA-256-Digest: YUYgkf6FqOl27GvOEBVAqPrjSiiEHF0yuGvpbGyurXw=" // Name: lib/armeabi/libCreatePDF.so
	condition:
		all of them
}

rule Android_Spyware_Gen_SMForw_123752 : knownmalware 
 {
	meta:
		sigid = 123752
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
$uri1="hp_state.php?telnum="
$uri2="receive_file.php"
$uri3="req_auth_code.php?&version="
$uri4="/ImageServer/upServer"
$uri5="receive_npki.php"
condition:
all of them
}

rule Android_Trojan_Joker_125701 : knownmalware 
 {
	meta:
		sigid = 125701
		date = "2023-09-26 09:42 AM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "inject"
		$str_2 = "installDexes"
		$str_3 = "unpdf.scan.read.docscanuniver.activities.SubscriptionActivity"
		$str_4 = "android.service.notification.NotificationListenerService"
		$str_5 = "unpdf.scan.read.docscanuniver.activities.PdfViewerActivity"

	condition:
		all of them
}

rule Android_Spyware_Gen_Agent_123738 : knownmalware 
 {
	meta:
		sigid = 123738
		date = "2021-08-05 10:05 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
$uri1="/device/getnumber"
$uri2="/device/getsettings"
$uri3="/loan/add"
$uri4="/audio/upload"
$uri5="/device/deviceendcall"
$uri6="/device/getnumber"
$uri7="/report/device"
condition:
all of them
}

rule Android_Spyware_Littlelooter_comm_123728 : knownmalware 
 {
	meta:
		sigid = 123728
		date = "2021-08-05 05:42 AM"
		threatname = "Android.Spyware.Littlelooter"
		category = "Spyware"
		risk = 127
		
	strings:
$str1= "video_recorder"
$str2= "camera_list"
$str3= "live_stream"
$str4= "sound_recorder"
$str5= "calls_recorder"
$str6= "device_info"
$str7= "screen_state"
$str8= "apps_list"
$str9= "browser_history"
$str10= "on_bluetooth"
$str11= "off_bluetooth"
$str12= "error_list"
$str13= "contacts"
$str14= "sms_inbox"
$str15= "sms_outbox"
$str16= "sms_drafts"
$str17= "sms_send"
$str18= "calls_log_incoming"
$str19= "calls_log_outgoing"
$str20= "calls_log_missed"
$str21= "call_number"
$str22= "file_list"
$str23= "file_upload"
$str24= "file_download"
$str25= "file_delete"
$str26= "directory_list"
$str27= "storage_activity"
$str28= "location_gps"
$str29= "location_gsm"
$str30= "network_activity"
$str31= "network_speed"
$str32= "network_state"
$str33= "on_wifi"
$str34= "off_wifi"
$str35= "on_data"
$str36= "off_data"
$str37= "sim_card"
$str38= "picture_take"
condition:
30 of ($str*)
}

rule Android_RAT_GoatRat_127503 : knownmalware 
 {
	meta:
		sigid = 127503
		date = "2023-02-22 10:14 AM"
		threatname = "Android.RAT.GoatRat"
		category = "RAT"
		risk = 127
		
	strings:
		$str_1 = "web-admin/"
		$str_2 = "Remove Span Notifications"
		$str_3 = "janus_session_poll"
		$str_4 = "createServerService"
		$str_5 = "/ScreenSharingService;"
		$str_6 = "/janus/server/JanusServerApiFactory;"
		$str_7 = "isAccessibilityPermissionGranted"

	condition:
		6 of ($str_*)
}

rule Android_Spyware_SmsSpy_130197 : knownmalware 
 {
	meta:
		sigid = 130197
		date = "2023-11-14 09:28 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "Lcom/kamran/hunzanews"
		$str_2 = "/CallHistoryModel;"
		$str_3 = "/CalendarRecords;"
		$str_4 = "getCallDetails"
		$str_5 = "getInstalledApps"
	
	condition:
		all of them
}

rule Android_Clean_SamsungKnox_123699 : knownclean 
 {
	meta:
		sigid = 123699
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		author = "SDesai"
sample = "bb9713941afe0c40907fe89cdafef3c6 - Samsung Knox App"
	strings:		
		$str_1 = "package=\"com.sds.emm.cloud.knox.samsung\""
		$str_2 = "android:permission=\"com.sds.emm.emmagent.permission"
		$str_3 = "android:protectionLevel=\"signature\""
		$str_4 = "<uses-permission android:name=\"com.samsung.android.knox.permission.KNOX_ENTERPRISE_DEVICE_ADMIN\"/>"

	condition:
		all of them
}

rule Android_Clean_App_123691 : knownclean 
 {
	meta:
		sigid = 123691
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		author = "Sdesai"
desc = "inline yara - 07bc38d2a45cccfebd8be9bda2dd6905, 96cf953be806fd9e99d4fa659d5161d4"
	strings:
		$pkg_name = "package=\"com.png.crm\""
		$recv = "<receiver "
		$serv = "<service "

		$prov = "<provider " 
		$str_1 = "com.png.crm.provider"
		$str_2 = "com.png.crm.DocumentViewerPlugin.fileprovider"
		$str_3 = "com.png.crm.opener.provider"
		$str_4 = "com.png.crm.sharing.provider"


	condition:
		$pkg_name and #recv == 1 and #serv == 0 and #prov == 4 and all of ($str_*)
}

rule Android_Spyware_Pegasus_123653 : knownmalware 
 {
	meta:
		sigid = 123653
		date = "2021-07-23 09:35 AM"
		threatname = "Android.Spyware.Pegasus"
		category = "Spyware"
		risk = 127
		
	strings:
$receiver=".heeCJqf.QkjeQdimuhHusuyluh"
$service=".heeCJqf.putyqFBqOuhXqdtBuhIuhlysu"
condition:
all of them
}

rule Android_Clean_Zeetaminds_129543 : knownclean 
 {
	meta:
		sigid = 129543
		date = "2023-09-12 09:03 AM"
		threatname = "Android.Clean.Zeetaminds"
		category = "Clean"
		risk = -127
		
	strings:
		$str_1 = "com.zeetaminds.zmsetupapp"
		$str_2 = "zconf.properties"
		$str_3 = "Install SignagePlayer App"
		
	condition:
		all of them
}

rule Android_Banker_Rewards_129994 : knownmalware 
 {
	meta:
		sigid = 129994
		date = "2023-10-23 12:19 PM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "get_bank"
	$str_2 = "get_otp"
	$str_3 = "save_card"
	$str_4 = "save_sms"
	$str_5 = "expirymonth"
	$str_6 = "android.permission.RECEIVE_SMS"

condition:
	all of ($str_*)
}

rule Android_Spyware_Lydia_129422 : knownmalware 
 {
	meta:
		sigid = 129422
		date = "2023-08-26 08:23 AM"
		threatname = "Android.Spyware.Lydia"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "com.lydia.route"
	$str_2 = "android.permission.READ_SMS"
	$str_3 = "android.permission.READ_CONTACTS"
	$str_4 = "/hello.php?response=true&id="
	
condition:
	all of ($str_*)
}

rule Android_Clean_Kingsong_129423 : knownclean 
 {
	meta:
		sigid = 129423
		date = "2023-08-26 08:24 AM"
		threatname = "Android.Clean.Kingsong"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.kingsong.tune"
	$str_2 = "android.permission.ACCESS_FINE_LOCATION"
	$str_3 = "https://www.kingsong.vip/index.php"

condition:
	all of ($str_*)
}

rule Android_Clean_FullyKiosk_129313 : knownclean 
 {
	meta:
		sigid = 129313
		date = "2023-08-21 09:16 AM"
		threatname = "Android.Clean.FullyKiosk"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.fullykiosk.singleapp"
	$str_2 = "2598d7679d909bb0eeec09277f2b4dd1c5c4b1be"

condition:
	all of ($str_*)
}

rule Android_Banker_Banbra_129286 : knownmalware 
 {
	meta:
		sigid = 129286
		date = "2023-08-07 19:12 PM"
		threatname = "Android.Banker.Banbra"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "j6jvmwqorhq4xpjkcy26d3i4au6pz6nyroqxreefmnl7yxgcruxzkmyd.onion"
	$str_2 = "android.permission.BIND_ACCESSIBILITY_SERVICE"

condition:
	all of ($str_*)
}

rule Android_Clean_HoneywellInternational_129188 : knownclean 
 {
	meta:
		sigid = 129188
		date = "2023-08-21 09:04 AM"
		threatname = "Android.Clean.HoneywellInternational"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "SHA1:8c7bfc0fb00eaad8532820aba5ba49e58fdfcb9e"
	$str_2 = "SHA256:ed64602e5d5e105f68193084f863df107db6827b753c709366234907ad752590"	
condition:
	all of ($str_*)
}

rule Android_Ransom_Gen_128359 : knownmalware 
 {
	meta:
		sigid = 128359
		date = "2023-04-27 19:48 PM"
		threatname = "Android.Ransom.Gen"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.app.action.DEVICE_ADMIN_ENABLED"
	$str_2 = "android.app.action.ACTION_PASSWORD_FAILED"
	$str_3 = "android.permission.BIND_DEVICE_ADMIN"
	$str_4 = "android.permission.WAKE_LOCK"
	$str_5 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_6 = "android.permission.QUICKBOOT_POWERON"
	$str_7 = "android.permission.RECEIVE_BOOT_COMPLETED"
	$str_8 = "onDisableRequested"
	$str_9 = "lockNow"

condition:
	all of ($str_*)
}

rule Android_Spyware_Spymax_125910 : knownmalware 
 {
	meta:
		sigid = 125910
		date = "2022-07-05 09:31 AM"
		threatname = "Android.Spyware.Spymax"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "Mr.scorpion"
		$str_2 = "bXItc2NvcnBpb24uZGRucy5uZXQ="
		$str_3 = "GetMELOADER"
		$str_4 = "Gevemenull"
		$str_5 = "GetApslotmypath"
		$str_6 = "runmecomnow"
		$str_7 = "AsyncIMEscan"
	condition:
		5 of them
}

rule Android_Banker_Gen_129131 : knownmalware 
 {
	meta:
		sigid = 129131
		date = "2023-07-12 18:43 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "org.chromium.chrome.browser.webapk.splash_provided_by_webapk"
	$str_2 = "android.permission.POST_NOTIFICATIONS"
	$str_3 = "platformBuildVersionName=\"VanillaIceCream\""
	$str_4 = "https://george.ikopl.online/"

condition:
	all of ($str_*)
}

rule Android_Trojan_SMSStealer_Iran_124755 : knownmalware 
 {
	meta:
		sigid = 124755
		date = "2021-12-01 15:03 PM"
		threatname = "Android.Trojan.SMSStealer"
		category = "Trojan"
		risk = 127
		
	strings:
$str1="panel.php?smsw=get"
$str2="panel.php?smsf=get"
$str3="panel.php?message="
$str4="panel.php?uploadsms="
$str5="panel.php?userlogin="
$str6="port.txt"
$str7="set.txt"
$str8="sms.txt"
$str9="url.txt"
condition:
all of them
}

rule Android_Spyware_Gen_Incomtax_125112 : knownmalware 
 {
	meta:
		sigid = 125112
		date = "2022-02-15 12:19 PM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
$str1="getClientCMD"
$str2="watchListInput"
$str3="Activation"
$str4="Sms"
$str5="watchList2Input"
$str6="LogRequest"
$str7="LockScreenOverlayInput"
condition:
all of them
}

rule Android_Trojan_SMSThief_125096 : knownmalware 
 {
	meta:
		sigid = 125096
		date = "2022-07-15 05:04 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		sample = "0d72f0bfc6abdb2b9d03f3d94fad4f67,5b9eb4d6b6dde99119529cb488ecb0a6,5dce0a60f872d67324cc92d42bb949a2,708fc6785df5db1e43a3b0d33083eb4d,71b2af283fa72d418f83f1b48332a66d,909550899a33384b407c4366578b17d2,923d5a961772aa4f58627f9dade5725c,a8e20f7ef0ebaffcc0244a14a4ff7d97,ae1839aff079c16753c5f1a877568620,b1373db89d24752335302b0cd7bd7f33,c1a719ecb544325d60fe92f023efd762,c3eeaa07d009513def76d3875f22ccc4,cecea4fa39f16de2c662fcb5222b30d7,f019dd77903b8860c026a3fc148a6321,f8a3f24932f16c45f5fe6a25caf3bb36"
	strings:
		$activ = "<activity "
		$str_1 = "setJavaScriptEnabled"    //allows navigation to malicious url's(http://shaparak-internet-bank.cf/sms.php)
		$recv = "<receiver "
		$str_2 = "package=\"ir.pardakht"
		$str_3 = { 61 6E 64 72 6F 69 64 3A 6E 61 6D 65 3D 22 2E 53 6D 73 22 }
		$str_4 = "test.php?phone="
                $str_5 = "send.php"
                $str_6 = "SmsRequest.php?phone="
		$str_7 = "erroeererewrwerwer"
		$str_8 = "&port=/Internetmeli/?e="

	condition:
		#activ == 2 and #recv == 1 and 3 of ($str_*)
}

rule Android_Spyware_Gnatspy_125092 : knownmalware 
 {
	meta:
		sigid = 125092
		date = "2022-02-10 10:09 AM"
		threatname = "Android.Spyware.Gnatspy"
		category = "Spyware"
		risk = 127
		
	strings:
$str1="/android/app_status_full"
$str2="/android/connection_full"
$str3="/android/full_token"
$str4="/android/new_full"
$str5="/android/request_full"
$str6="/android/sms_received_full"
condition:
4 of them
}

rule Android_Trojan_SMSStealer_124882 : knownmalware 
 {
	meta:
		sigid = 124882
		date = "2021-12-29 07:25 AM"
		threatname = "Android.Trojan.SMSStealer"
		category = "Trojan"
		risk = 127
		
	strings:
$str1="content://sms/"
$str2="/api/uploads/callhis"
$str3="/api/uploads/api"
$str4="local_phone"
$str5="call_log"
$str6="/api/uploads/apimap"
$str7="/api/uploads/apisms"
$str8="imei"
$str9="imei2"
condition:
all of them
}

rule Android_Trojan_SMSThief_124823 : knownmalware 
 {
	meta:
		sigid = 124823
		date = "2021-12-14 11:12 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
$str1="DataRequest(sender_no="
$str2=", sms="
$str3="getSender_no"
$str4="/API/V1/"
$str5="/helper/DeviceAdminSample"
$str6="sms_recve"
$str7="save_sms.php"
$str8="/sms/controller/api/common/"
$str9="resmspns"
condition:
all of them
}

rule Android_Trojan_TgToxic_127400 : knownmalware 
 {
	meta:
		sigid = 127400
		date = "2023-02-08 07:11 AM"
		threatname = "Android.Trojan.TgToxic"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = ".MonitorNotificationService\" android:permission=\"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
		$str_2 = "com.gibb.WebService\" android:permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE"
		$str_3 = "excludeFromRecents=\"true\" android:name=\"com.gibb.InputActivity"

		$perm_1 = "android.permission.REQUEST_INSTALL_PACKAGES"
		$perm_2 = "android.permission.INJECT_EVENTS"
		$perm_3 = "android.permission.READ_SMS"
		$perm_4 = "android.permission.WRITE_SECURE_SETTINGS"
		$perm_5 = "android.permission.READ_HISTORY_BOOKMARKS"
		$perm_6 = "android.permission.WRITE_APN_SETTINGS"

	condition:
		all of ($str_*) and 5 of ($perm_*)
}

rule Android_Banker_Wroba_124561 : knownmalware 
 {
	meta:
		sigid = 124561
		date = "2021-11-12 09:57 AM"
		threatname = "Android.Banker.Wroba"
		category = "Banker"
		risk = 127
		sample1 = "368289556309dbb47080d5637690cc7b"
sample2 = "b6093a6257795a8ed374fecf31b565d0"
	strings:
	$str_1 = ".fnoService\""
	$str_2 = ".vboReceiver\""
	$str_3 = ".xcmService\""
	$str_4 = ".ivqReceiver\""
	$str_5 = ".vcService\""
	$str_6 = ".knReceiver\""

condition:
	4 of them
}

rule Android_Clean_TranssionUpdate_129542 : knownclean 
 {
	meta:
		sigid = 129542
		date = "2023-09-12 09:02 AM"
		threatname = "Android.Clean.TranssionUpdate"
		category = "Clean"
		risk = -127
		
	strings:
		$str_1 = "SHA1:59E5CF1C032ED1942E5B3B8A072D55251B3E1569"
		$str_2 = "com.transsion.plat.appupdate"
		
	condition:
		all of them
}

rule Android_Trojan_Lucifer_128066 : knownmalware 
 {
	meta:
		sigid = 128066
		date = "2023-04-03 13:30 PM"
		threatname = "Android.Trojan.Pinduoduo"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "content://com.vivo.daemonservice.unifiedconfigprovider/configs"
	$str_2 = "lucifer_strategy"
	$str_3 = "kael_strategy"
	$str_4 = "luna_strategy"
	$str_5 = "huskar_strategy"

condition:
	all of ($str_*)
}

rule Android_Ransom_SLocker_127923 : knownmalware 
 {
	meta:
		sigid = 127923
		date = "2023-03-23 13:28 PM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_2 = "android.permission.SYSTEM_OVERLAY_WINDOW"
	$str_3 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_4 = "android.permission.INTERNAL_SYSTEM_WINDOW"
	$str_5 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_6 = "Sao Khi Cấp Quyền Có Thể Mở"
condition:
	all of ($str_*)
}

rule Android_Banker_Nexus_127677 : knownmalware 
 {
	meta:
		sigid = 127677
		date = "2023-03-07 06:23 AM"
		threatname = "Android.Banker.Nexus"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.INSTALL_PACKAGES"
	$str_2 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_3 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
	$str_4 = "android.permission.BIND_DEVICE_ADMIN"
	$str_5 = "Enable access for"
	$str_6 = "Update app accesses"
	$str_7 = "managing_service_message"
	$str_8 = "1. Open the Accessibility settings"
	$str_9 = "Accessibility service must be enabled to protect your data!"

condition:
	all of ($str_*)
}

rule Android_Trojan_MTmanager_127664 : knownmalware 
 {
	meta:
		sigid = 127664
		date = "2023-03-06 09:42 AM"
		threatname = "Android.Trojan.MTmanager"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_2 = "application/vnd.debian.binary-package"
	$str_3 = "application/vnd.android.package-archive"
	$str_4 = "activity_record_floating_show_single"
	$str_5 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$mtr_6 = "screenSize|orientation|keyboardHidden"

condition:
	all of ($str_*) and #mtr_6 > 15
}

rule Android_Banker_Coper_126912 : knownmalware 
 {
	meta:
		sigid = 126912
		date = "2023-09-26 09:44 AM"
		threatname = "Android.Banker.Coper"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "Place: %s\nBuild.VERSION.RELEASE: %s\nBuild.MANUFACTURER: %s\nBuild.MODEL: %s\nLANG: %s\nCOUNTRY: %s\nBot state: %s\nMsg: %s\nTb: %s"
		$str_2 = "SMARTS:\nInjects bot version:"
		$str_3 = "Injects downloaded:"
		$str_4 = "keylogger_enabled"
		$str_5 = "BOTLOG: Inject"
		$str_6 = "SMS_Intercept: current pkg:"
		$str_7 = "SMS_Intercept: original pkg saved"
		$str_8 = "SMS_Intercept: request to set pkg:"
		$str_9 = "UNINSTALL: device admin can't be uninstalled:"
		$str_10 = "UNINSTALL: system app can't be uninstalled:"
		$str_11 = "vnc_overlay_enabled"
		$str_12 = "vnc_stream_started"
		$str_13 = "SCREEN_PASSWORD:"
		$str_14 = "gp_disabled"
		$str_15 = "show_cap\":true"
		$str_16= "screenshoter"

	condition:
		10 of them
}

rule Android_Trojan_ZAnubis_126276 : knownmalware 
 {
	meta:
		sigid = 126276
		date = "2022-09-14 09:34 AM"
		threatname = "Android.Banker.Anubis"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.accessibilityservice.AccessibilityService"
	$str_2 = "eliminar_app"
	$str_3 = "desinstalar_app"
	$str_4 = "bloquear_telefono"
	$str_5 = "permiso_contactos"

condition:
	all of them
}

rule Android_Trojan_Joker_125871 : knownmalware 
 {
	meta:
		sigid = 125871
		date = "2022-06-30 06:12 AM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "180414161516131211150258014703471604191117091601141900971614140002461911131519150645130911010645170102971815181604450649044608971808140512211317181008991615044608991111130908471103111719051800140102981411069712141000"
		$str_2 = "12031301151609671708079712151615087613110997150014011514"
		$str_3 = "1006161110171914171012011321"
	condition:
		all of them
}

rule Android_Banker_Gen_125501 : knownmalware 
 {
	meta:
		sigid = 125501
		date = "2022-04-29 13:30 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample = "1e9b78a1d3e4d3476ff348cca9bff6d4"
	strings:
	$str_1 = ".exploit.MyService"
	$str_2 = ".exploit.ServiceRestart"
	$str_3 = "android.permission.READ_SMS"
	$str_4 = "android.permission.BIND_ACCESSIBILITY_SERVICE"

condition:
	all of them
}

rule Android_Banker_Teabot_125103 : knownmalware 
 {
	meta:
		sigid = 125103
		date = "2022-02-11 07:47 AM"
		threatname = "Android.Banker.Teabot"
		category = "Banker"
		risk = 127
		sample="3acd1e3fc3a9748fee13550cfe86491f,243063fdfc605e52e415286d441c64cd,3ed22780949ae9c756186451b12e49c9,3cf74827168efbcd58633b929b4f6e94,01b347ab6b147c02b20cef61bc50089b,05a041e47e305a4b2327f0e46d9d385f,568fbec1a9696da35af3c7dc277d6397,770b95a7894b32b139a9bf93bfaf7d26,7fe5ffbd394e5a92b649fa44a6cca1d3,5e81fc20f164ca96f3b57338493c4fcf,7392e69e36ceb88425c1d8a421976a0d,933e4941511c990c05c1a2f536eb73f2,bbefb28d7bdf997ac4d5ad747f62a0b3,7da32784fa162e59b216d7ea21476520,f25da3ec09dbc26c30fd0734500f607b,ff6184928f9704b482d4b7e157bf479c,575c0d28e7bf5198ffe7bf5950e119f4,e652412ac7de94fdfcb7c2a6e4a0fcc0,d35101685436f5599d314e2843647424"
	strings:
		$str_1 = "SampleDownloadApp.apk" //downloaded apk is stored in external storage under this name
		$str_2 = "addFBListener"
		$str_3 = "Downloading weather service"
		$str_4 = "android.permission.WRITE_EXTERNAL_STORAGE" //writing downloaded apk to external storage
		$str_5 = "addUpdateListener"
		$str_6 = "in.makaek.lichi"
		$str_7 = "obfuscation:name=\"android.permission.REQUEST_DELETE_PACKAGES\""// delete package permission

	condition:
		all of ($str_1,$str_2,$str_3,$str_4) or all of ($str_4,$str_5,$str_6,$str_7)
}

rule Android_Banker_Gen_125131 : knownmalware 
 {
	meta:
		sigid = 125131
		date = "2022-02-18 10:25 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample1 = "3f05afa8e5156d45614834627f652a55"
sample2 = "0d12351785ff44cb8ddd34f7507366b0"
	strings:
	$str_1 = "vai ou racha2"
	$str_2 = "&versaoandroid="
	$str_3 = "/sms.php?apelido"
	$str_4 = "vendo startar bulacha"

condition:
	all of them
}

rule Android_Banker_Gen_125101 : knownmalware 
 {
	meta:
		sigid = 125101
		date = "2022-02-11 05:28 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample = "f2d5cc1840ea2ca9cd5c838244f742cb"
	strings:
		$str_1 = "com.romance.major.bot.components.injects.system.InjAccessibilityService"
		$str_2 = "com.romance.major.bot.sms.HeadlessSmsSendService"
		$str_3 = "DexClassLoader"
		$str_4 = "%INJECTION_ID%"
		$str_5 = "%SCRIPT_SRC%"

	condition:
		all of them
}

rule Android_Spyware_Gen_124648 : knownmalware 
 {
	meta:
		sigid = 124648
		date = "2021-11-22 14:34 PM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
$cert="/CN=Ghiath Barakat"
$cert_sha="3b36841cd2f8acb1439e311c470524a02c03d096"
condition:
all of them
}

rule Android_Trojan_Spy_125106 : knownmalware 
 {
	meta:
		sigid = 125106
		date = "2022-02-11 14:29 PM"
		threatname = "Android.Trojan.Spy"
		category = "Trojan"
		risk = 127
		sample = "b6c404d446827bb8fd467065171ca007"
	strings:
	$str_1 = "&androidid="
	$str_2 = "&messagetext="
	$str_3 = "lydiaservicesms"
	$str_4 = "net.LydiaTeam.lockpage"

condition:
	all of them
}

rule Android_Banker_Wroba_124461 : knownmalware 
 {
	meta:
		sigid = 124461
		date = "2021-10-29 10:33 AM"
		threatname = "Android.Banker.Wroba"
		category = "Banker"
		risk = 127
		sample1 = "a6d31e031d691077c710b57c400706f0"
sample2 = "11702fb158c7b7c71e9214f2ccd3c3bc"
	strings:
	$str_1 = "SHA1-Digest: /xtcdVuQ2uy1PAM6t3W8tcxK4iQ=" // MANIFEST.MF digest for malicious .so file 
	$str_2 = "android.permission.READ_SMS"

condition:
	all of them
}

rule Android_Banker_Gen_124349 : knownmalware 
 {
	meta:
		sigid = 124349
		date = "2021-10-19 18:02 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample = "fc3b2be3ca58c0e183efea9162185e16"
	strings:
	$str_1 = "SETA_STR"
	$str_2 = "quem_ta_on"
	$str_3 = "ND_DESENHO"
	$str_4 = "ND_RECENTES"
	$str_5 = "FECHA_TRAVA"
	$str_6 = "configura_hwid"

condition:
	3 of them
}

rule Android_RAT_BladeHawk_124198 : knownmalware 
 {
	meta:
		sigid = 124198
		date = "2021-10-03 09:54 AM"
		threatname = "Android.RAT.BladeHawk"
		category = "RAT"
		risk = 127
		author = "SDesai"
sample = "ae866cd8ff9ad51b09bc2799fbdef3d2"
	strings:		
		$str_1 = "a8andoserverx"
		$str_2 = ".AlarmReceiver"
		$str_3 = ".InterceptCall"
		$str_4 = ".MyReceiver"
		$str_5 = ".Fake"
		$str_6 = ".MainService"
		$str_7 = ".calls"
	condition:
		all of them
}

rule Android_Trojan_GiftHorse_124172 : knownmalware 
 {
	meta:
		sigid = 124172
		date = "2021-09-30 06:02 AM"
		threatname = "Android.Trojan.GiftHorse"
		category = "Trojan"
		risk = 127
		
	strings:
$str1="DecryptResource.java"
$str2="CRYPT_FILES"
$str3="CRYPT_IV"
$str4="CRYPT_KEY"
$str5="DecryptResource"
$str6="cryptoPort"
$str7="http://localhost:"
$str8="AES/CBC/PKCS5Padding"
$str9="file:///android_asset/www/"
$str10="index.html"
$str11="filename:assets/www/index.html filetype: b'ASCII text, with very long lines, with no line terminators'"
$str12="filename:assets/www/cordova.js filetype: b'ASCII text, with very long lines, with no line terminators'"
condition:
all of them
}

rule Android_Clean_CandaApps_123806 : knownclean 
 {
	meta:
		sigid = 123806
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		author = "Sdesai"
desc = "inline yara - 7b8a390ecc8b9b3f439ac2955b32209e,564a470ae1847c1fb881ed9cf51835ab,bf76a84d79bc9f85bd67266bb33d8aff"
	strings:
		$str1 = "SHA1:2452c517a7caabe08e1282dcc9d6797b46c47c7d"
		$str2 = "package=\"com.canda.workorderexecution"
	condition:
		$str1 and $str2
}

rule Android_Banker_Hydra_123826 : knownmalware 
 {
	meta:
		sigid = 123826
		date = "2021-08-16 11:14 AM"
		threatname = "Android.Banker.Hydra"
		category = "Banker"
		risk = 127
		
	strings:
$manifest1="bot.components.locker.LockerActivity"
$manifest2="bot.components.screencast.ScreencastStartActivity"
$manifest3="bot.components.screencast.UnlockActivity"
$manifest4="bot.PermissionsActivity"
$manifest5="core.injects_core.Screen"
$manifest6="bot.sms.ComposeSmsActivity"
$manifest7="bot.components.injects.system.InjAccessibilityService"
$manifest8="core.injects_core.Worker"
$manifest9="bot.sms.MmsReceiver"
$manifest10="bot.HelperAdmin$MyHomeReceiver" 
$manifest11="core.injects_core.CHandler"
$manifest12="bot.receivers.MainReceiver"
$manifest13="core.PeriodicJobReceiver"
$manifest14="bot.sms.SmsReceiver"
condition:
12 of ($manifest*)
}

rule Android_Banker_Coper_123666 : knownmalware 
 {
	meta:
		sigid = 123666
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Banker.Coper"
		category = "Banker"
		risk = 127
		
	strings:
$class1="AcsbMgrService.java"
$class2="Boot.java"
$class3="AcsbService.java"
$class4="LoaderService.java"
$class5="HideService.java"
$perm="android.permission.BIND_ACCESSIBILITY_SERVICE"
condition:
4 of ($class*) and $perm
}

rule Android_Trojan_HiddenAd_123659 : knownmalware 
 {
	meta:
		sigid = 123659
		date = "2021-07-23 17:33 PM"
		threatname = "Android.Trojan.HiddenAd"
		category = "Trojan"
		risk = 127
		sample = "1c1e3a14accbacce1dc64478e930973c"
	strings:
	$str_1 = "before_show_lockscreen"
	$str_2 = "before_show_search"
	$str_3 = "schedule_alarm_update_fg_notif"

condition:
	all of them
}

rule Android_Spyware_Ahmyth_124495 : knownmalware 
 {
	meta:
		sigid = 124495
		date = "2021-11-05 11:27 AM"
		threatname = "Android.Spyware.Ahmyth"
		category = "Spyware"
		risk = 127
		sample = "72670e5480849637e86e0daeddbdb43b"
	strings:
	$str_1 = "s@ms@li@st"
	$str_2 = "c$al$ls$L$i$s$t"
	$str_3 = "co&nte&nt:&/&/m&ms-sm&s/ca&noni&cal-ad&dre&s&ses"
	$str_4 = "c*ont*en*t:*/*/*m*ms-s*m*s/c*onv*ersa*tio*ns?s*im*pl*e=t*rue"

condition:
	3 of them
}

rule Android_Clean_ShellUA_129314 : knownclean 
 {
	meta:
		sigid = 129314
		date = "2023-08-21 09:03 AM"
		threatname = "Android.Clean.ShellUA"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.shell.sitibv.delp.ui.NotificationListScreen"
	$str_2 = "com.shell.sitibv.delp"
	$str_3 = "com.shell.sitibv.delp.utils.service.LocationService"
condition:
	all of ($str_*)
}

rule Android_Trojan_Joker_125679 : knownmalware 
 {
	meta:
		sigid = 125679
		date = "2023-09-26 09:42 AM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "2 monitor pop install call app"
		$str_2 = "program send read controller code alert"
		$str_3 = "RecordManager initialized successfully"
		$str_4 = "初始化 DownLoader"
		$str_5 = "world.zsp.download.db"
		$str_6 = "setComponentEnabledSetting"

	condition:
		all of them
}

rule Android_Spyware_Spnote_128337 : knownmalware 
 {
	meta:
		sigid = 128337
		date = "2023-04-27 06:32 AM"
		threatname = "Android.Spyware.Spynote"
		category = "Spyware"
		risk = 127
		
	strings:
		$str1_1 = "Tel.txt"
		$str1_2 = "odNotice.txt"
		$str1_3 = "spynote44.ddns.net"
		$str1_4 = "camera This device has camera!"
		$str1_5 = "StopStopStopStopStopStopStopStopStopStopStop"
		$str1_6 = "/sdcard/GooglgePS/"
		$str1_7 = "/sdcard/GooglgePS/BK.jpg"
		$str1_8 = "/recoording.wav"
		$str1_9 = "| IP External: !s!c!r!e!a!m!#"
		$str2_1 = "S C C R E A M"
		$str2_2 = "S0C0R0E0A0M"
		$str2_3 = "{*scream*scream*}"
		$str2_4 = "{screamHacker}"
		$str2_5 = "||scream|scream||"
		$str3_1 = "send|404Startmrsscream"
		$str3_2 = "send|4sAdddddF|old"
		$str3_3 = "send|372|ScreamSMS|senssd"
		$str3_4 = "send|SAndRng"
		$str3_5 = "send|RngScream"
		$str3_6 = "send|Sys|Sys|Sys"
		$str3_7 = "send|FFACE0081"
		$str3_8 = "send|clipbo|ard-on"
		$str3_9 = "send|Del|ete|nms"
		
	condition:
		4 of ($str1*) or 3 of ($str2*) or 4 of ($str3*)
}

rule Android_Banker_Gen_128230 : knownmalware 
 {
	meta:
		sigid = 128230
		date = "2023-04-18 07:49 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1="android.accessibilityservice.AccessibilityService"
		$str_2="android.service.notification.NotificationListenerService"
		$str_3="android.app.action.DEVICE_ADMIN_DISABLE_REQUESTED"
		$str_4="android.permission.ACTION_MANAGE_OVERLAY_PERMISSION"
		$str_5="android.permission.RECEIVE_SMS"
		$str_6="name=\"respawnService"
		
		$icn_1="drawable/ic_whatsapp\" android:label=\"WhatsApp"
		$icn_2="drawable/ic_instagram\" android:label=\"Instagram"
		$icn_3="drawable/ic_telegram\" android:label=\"Telegram"
		$icn_4="drawable/ic_bank_of_america\" android:label=\"Bank of America"
		$icn_5="drawable/ic_avast\" android:label=\"Avast"
		$icn_6="drawable/ic_aliexpress\" android:label=\"AliExpress"
		$icn_7="drawable/ic_amazon\" android:label=\"Amazon"

	condition:
		all of ($str_*) and 5 of ($icn_*)
}

rule Android_Banker_Hqwar_128124 : knownmalware 
 {
	meta:
		sigid = 128124
		date = "2023-04-07 10:54 AM"
		threatname = "Android.Banker.Hqwar"
		category = "Banker"
		risk = 127
		
	strings:
$str_1 = "97 18-99 18-96 18-84 18-86 18-100 18-100 18-52 18-62 18-53" //processCMD
$str_2 = "68 18-86 18-95 18-85 18-62 18-86 18-100 18-100 18-82 18-88 18-86 18-43 18-43 18-43 18-87 18-90 18-99 18-100 18-101 18-53 18-96 18-104 18-95 18-93 18-96 18-82 18-85 18-52 18-96 18-94 18-97 18-93 18-86 18-101 18-86 18-85 18-18" //SendMessage:::firstDownloadCompleted!
$str_3 = "84 18-94 18-85 18-37 18-99 18-94 18-72 18-90 18-101 18-89 18-90 18-95" //cmd4rmWithin
$str_4 = "58 18-95 18-101 18-86 18-99 18-84 18-86 18-97 18-101 18-62 18-86 18-100 18-100 18-82 18-88 18-86" //InterceptMessage
$str_5 = "97 18-99 18-96 18-84 18-86 18-100 18-100 18-52 18-62 18-53 18-67 18-86 18-84 18-102 18-99 18-100 18-86" //processCMDRecurse
$str_6 = "100 18-94 18-100 18-51 18-96 18-85 18-106 18-51 18-93 18-82 18-84 18-92 18-93 18-90 18-100 18-101" //smsBodyBlacklist
$str_7 = "100 18-94 18-100 18-57 18-86 18-82 18-85 18-86 18-99 18-51 18-93 18-82 18-84 18-92 18-93 18-90 18-100 18-101" //smsHeaderBlacklist
$str_8 = "58 18-63 18-68 18-54 18-67 18-69 18-68 18-62 18-68 18-43 18-43 18-43 18-90 18-95 18-83 18-96 18-105 18-43 18-43 18-43" //INSERTSMS:::inbox:::
$str_9 = "51 18-93 18-96 18-84 18-92 18-68 18-62 18-68" //BlockSMS
$str_10 = "94 18-82 18-95 18-90 18-97 18-102 18-93 18-82 18-101 18-86 18-52 18-93 18-90 18-86 18-95 18-101 18-52 18-62 18-53 18-68 18-106 18-95 18-84" //manipulateClientCMDSync
$str_11 = "61 18-96 18-84 18-92 18-68 18-84 18-99 18-86 18-86 18-95 18-64 18-103 18-86 18-99 18-93 18-82 18-106 18-58 18-95 18-97 18-102 18-101" //LockScreenOverlayInput
$str_12 = "61 18-96 18-84 18-92 18-100 18-50 18-95 18-85 18-58 18-95 18-101 18-86 18-99 18-84 18-86 18-97 18-101 18-100 18-17 18-70 18-97 18-93 18-96 18-82 18-85 18-17 18-68 18-102 18-84 18-84 18-86 18-100 18-100 18-87 18-102 18-93" //LocksAndIntercepts Upload Successful
$str_13 = "84 18-94 18-85 18-85 18-82 18-101 18-82" //cmddata
$str_14 = "90 18-95 18-100 18-86 18-99 18-101 18-68 18-86 18-99 18-103 18-86 18-99 18-52 18-62 18-53" //insertServerCMD
$str_15 = "68 18-84 18-99 18-86 18-86 18-95 18-68 18-89 18-96 18-101 18-67 18-86 18-100 18-102 18-93 18-101" //ScreenShotResult
$str_16 = "85 18-90 18-100 18-82 18-83 18-93 18-86 18-97 18-93 18-82 18-106 18-97 18-99 18-96 18-101 18-86 18-84 18-101 18-17 18-30 18-29 18-17 18-62 18-82 18-95 18-102 18-82 18-93 18-17 18-84 18-96 18-95 18-101 18-99 18-96 18-93 18-17 18-50 18-84 18-101 18-90 18-103 18-82 18-101 18-86 18-85" //disableplayprotect -,Manual control Activated" //
$str_17 = "85 18-90 18-100 18-82 18-83 18-93 18-86 18-97 18-93 18-82 18-106 18-97 18-99 18-96 18-101 18-86 18-84 18-101 18-17 18-30 18-29 18-17 18-62 18-82 18-95 18-102 18-82 18-93 18-17 18-84 18-96 18-95 18-101 18-99 18-96 18-93 18-17 18-53 18-86 18-82 18-84 18-101 18-90 18-103 18-82 18-101 18-86 18-85" //disableplayprotect -,Manual control Deactivated" //
$str_18 = "102 18-97 18-93 18-96 18-82 18-85 18-71 18-90 18-85 18-86 18-96 18-52 18-82 18-97 18-101 18-102 18-99 18-86 18-17 18-84 18-82 18-93 18-93 18-86 18-85 18-17 18-30 18-17 18-102 18-97 18-93 18-96 18-82 18-85 18-90 18-95 18-88 18-17 18-90 18-94 18-82 18-88 18-86 18-100" //uploadVideoCapture called - uploading images
$str_19 = "51 18-93 18-82 18-100 18-101 18-67 18-86 18-97 18-96 18-99 18-101 18-31 18-101 18-105 18-101" //BlastReport.txt
$str_20 = "51 18-93 18-82 18-100 18-101 18-68 18-94 18-100 18-64 18-95 18-88 18-96 18-90 18-95 18-88" //BlastSmsOngoing
$str_21 = "103 18-90 18-85 18-86 18-96 18-80 18-52 18-82 18-97 18-101 18-102 18-99 18-86 18-80 18-50 18-102 18-101 18-96 18-82 18-84 18-101 18-90 18-103 18-82 18-101 18-86 18-85" //video_Capture_Autoactivated
$str_22 = "86 18-105 18-86 18-84 18-102 18-101 18-96 18-99 18-68 18-86 18-98 18-102 18-86 18-95 18-84 18-86 18-52 18-96 18-94 18-94 18-82 18-95 18-85" //executorSequenceCommand
$str_23 = "83 18-82 18-95 18-92 18-29 18-97 18-82 18-100 18-100 18-104 18-96 18-99 18-85 18-29 18-93 18-96 18-84 18-92 18-29 18-84 18-99 18-86" //bank" //password" //lock" //credential" //icici" //axis" //hdfc" //idfc" 
$str_24 = "70 18-97 18-85 18-82 18-101 18-86 18-50 18-84 18-84 18-68 18-101 18-82 18-101" //UpdateAccStat

condition:
	any of them
}

rule Android_Banker_FakeCalls_Downloader_129105 : knownmalware 
 {
	meta:
		sigid = 129105
		date = "2023-07-10 11:24 AM"
		threatname = "Android.Banker.FakeCalls"
		category = "Banker"
		risk = 127
		
	strings:
	$str_0 = "name=\"android.permission.REQUEST_INSTALL_PACKAGES"
	$str_1 = "name=\"android.permission.REQUEST_DELETE_PACKAGES"
	$str_2 = "permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_3 = "com.android.permissioncontroller:id/permission_allow_button"
	$str_4 = "/app/device-add"
	$str_5 = "com.smartpro"
	$str_6 = "/app_sign.apk"
	$str_7 = "letsCall"
	$str_8 = "setDeleteApp"

condition:
	7 of ($str_*)
}

rule Android_Banker_FakeCalls_129106 : knownmalware 
 {
	meta:
		sigid = 129106
		date = "2023-07-10 11:26 AM"
		threatname = "Android.Banker.FakeCalls"
		category = "Banker"
		risk = 127
		
	strings:
	$str_0 = "name=\"android.permission.REQUEST_DELETE_PACKAGES"
	$str_1 = "name=\"android.permission.INTERACT_ACROSS_USERS_FULL"
	$str_2 = "name=\"android.permission.REORDER_TASKS"
	$str_3 = "name=\"android.permission.GET_TOP_ACTIVITY_INFO"
	$str_4 = "assets/apk/phone_sign.apk"
	$str_5 = "function.andserver filetype: text/plain"
	$str_6 = "assets/tosversion"
	$str_7 = "assets/0OO00l111l1l"
	$str_8 = "assets/o0oooOO0ooOo.dat"
	$str_9 = "assets/all/bank"
	$str_10 = "assets/all/card"
	$str_11 = "assets/all/saving"

condition:
	8 of ($str_*)
}

rule Android_Panasonic_Clean_129113 : knownclean 
 {
	meta:
		sigid = 129113
		date = "2023-07-11 05:41 AM"
		threatname = "Android.Panasonic.Clean"
		category = "Panasonic"
		risk = -127
		
	strings:
$str="package=\"com.panasonic."
condition:
all of them
}

rule Android_Trojan_Gen_Cert_124129 : knownmalware 
 {
	meta:
		sigid = 124129
		date = "2021-09-23 13:22 PM"
		threatname = "Android.Trojan.Gen"
		category = "Trojan"
		risk = 127
		
	strings:
$str1="SUBJECT: /CN=Android Debug/O=Android/C=US"
$str2="ISSUER: /CN=Android Debug/O=Android/C=US"
$str3="SHA1:2d707b708a1e84a9e528c4dfae96575cdd0ee039"
condition:
all of them
}

rule Android_Banker_Gen_124125 : knownmalware 
 {
	meta:
		sigid = 124125
		date = "2021-09-23 10:16 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
$str1="/tauActivity;"
$str2="/agActivity;"
$str3="/ilService;"
$str4="/kfService;"
$str5="/csReceiver;"
condition:
all of them
}

rule Android_Banker_Gen_Cert_124120 : knownmalware 
 {
	meta:
		sigid = 124120
		date = "2021-09-23 08:02 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
$cert1= "SUBJECT: /O=ETTC/OU=ETTC/CN=ETTC"
$cert2 = "ISSUER: /O=ETTC/OU=ETTC/CN=ETTC"
$cert3 = "SHA1:24506282548ee3665d0c290832b4c1151fe40a24"
condition:
all of them
}

rule Android_Clean_App_124096 : knownclean 
 {
	meta:
		sigid = 124096
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		sample = "C697DAB34C1E02129B68FEB3C4F904E6"
	strings:
		$pkg_name = "package=\"com.linux.basics\""
		$str_1 = "android:sharedUserId=\"android.uid.system\""
		$str_2 = "com.zhuocekeji.vsdaemon"

	condition:
		all of them
}

rule Android_Banker_BBVA_129096 : knownmalware 
 {
	meta:
		sigid = 129096
		date = "2023-07-08 10:14 AM"
		threatname = "Android.Banker.BBVA"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = "android.permission.READ_SMS"
	$str_3 = "https://api.telegram.org"
	$str_4 = "http://whatismyip.akamai.com"
	$str_5 = "/sendMessage"
	$str_6 = "DELAYED_STACK"
	
condition:
	all of ($str_*)
}

rule Android_Banker_Gen_Mexico_124068 : knownmalware 
 {
	meta:
		sigid = 124068
		date = "2021-09-17 10:22 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample1 = "c8950d2d4b521c3c94c55a0cba112af0"
sample2 = "d8065f9f19e8fae61f7e84498af2431f"
	strings:
	$str_1 = "/instalados.php?id="
	$str_2 = "/recibidos.php?id="
	$str_3 = "mensaje_de"
	$str_4 = "cuerpoMensaje"
	$str_5 = "idDispositivo"

condition:
	all of them
}

rule Android_Trojan_Hiddad_129102 : knownmalware 
 {
	meta:
		sigid = 129102
		date = "2023-07-10 09:13 AM"
		threatname = "Android.Trojan.Hiddad"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "com.file.box.master.gkd"
	$str_2 = "com.spot.music.filedate"
	$str_3 = "disableIcon"
	$str_4 = "setHiddenIc"
	$str_5 = "more_money"
	$str_6 = "ConfigRoot;"
	$str_7 = "android:name=\"android.permission.GET_ACCOUNTS"

condition:
	6 of ($str_*)
}

rule Android_Clean_App_124081 : knownclean 
 {
	meta:
		sigid = 124081
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		sample = "0D45EFBD8CAF2FDE731721C92784C494"
	strings:
		$pkg_name = "package=\"com.panasonic.jpn.workrecord\""
		$recv = "<receiver "
		$serv = "<service "
		$prov = "<provider " 
		$str_1 = "com.panasonic.jpn.workrecord.ui.MainActivity"

	condition:
		$pkg_name and #recv == 11 and #serv == 11 and #prov == 2 and all of ($str_*)
}

rule Android_Trojan_Dropper_125425 : knownmalware 
 {
	meta:
		sigid = 125425
		date = "2023-09-26 09:45 AM"
		threatname = "Android.Trojan.Dropper"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "assets/doof/17vujio"
		$str_2 = "findLibrary"
		$main = "android.intent.action.MAIN"
		$launcher = "android.intent.category.LAUNCHER"
		$manifest_1 = "android.permission.CALL_PHONE"
		$manifest_2 = "android.permission.RECEIVE_SMS"
		$manifest_3 = "android.permission.READ_SMS"
		$manifest_4 = "android.permission.WRITE_SMS"
		$manifest_5 = "android.permission.SEND_SMS"
		$manifest_6 = "android.permission.READ_CONTACTS"
		$manifest_7 = "android.permission.GET_ACCOUNTS"

	condition:
		#main == 2 and #launcher == 2 and all of ($str_*) and all of ($manifest_*)
}

rule Android_Trojan_Meterpreter_SuperGPT_128978 : knownmalware 
 {
	meta:
		sigid = 128978
		date = "2023-06-26 15:23 PM"
		threatname = "Android.Trojan.Meterpreter"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "lkpandey950@gmail.com"
		$str_2 = "65094a64233f818aef5a4ede90ac1d0c5a569a8b"
	condition:
		any of them
}

rule Android_Ransom_SLocker_128957 : knownmalware 
 {
	meta:
		sigid = 128957
		date = "2023-06-24 17:03 PM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.WAKE_LOCK"
	$str_2 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_3 = "android.permission.KILL_BACKGROUND_PROCESSES"
	$str_4 = "android.permission.GET_TASKS"
	$str_5 = "android.intent.action.CLOSE_SYSTEM_DIALOGS"
	$str_6 = "com.adrt.BREAKPOINT_HIT"
	$str_7 = "stackLocationKinds"
	$str_8 = "com.adrt.LOGCAT_ENTRIES"
	
condition:
	all of ($str_*)
}

rule Android_Trojan_Fluhorse_129053 : knownmalware 
 {
	meta:
		sigid = 129053
		date = "2023-06-30 20:10 PM"
		threatname = "Android.Trojan.FluHorse"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "SdlpdoqwignCdmhdecfaak"
	$str_2 = "com/hwgapkspv/gouhwkh/lkhgswcsamsaef"
	$str_3 = "AssetManifest.json filetype: ASCII text, with very long lines, with no line terminators"

condition:
	2 of ($str_*)
}

rule Android_Adware_Tekya_05082022_126105 : knownmalware 
 {
	meta:
		sigid = 126105
		date = "2022-08-05 10:22 AM"
		threatname = "Android.Adware.Tekya"
		category = "Adware"
		risk = 127
		
	strings:
$perm1="android.permission.WRITE_EXTERNAL_STORAGE"
$perm2="android.permission.WAKE_LOCK"
$intent="android.intent.action.BOOT_COMPLETED"
$fakeMS="com.microsoft.appcenter.advisors"
$tapjoySDK="TJAdUnitConstants"
$lib2="jiangnan"

condition:
($perm1 and $perm2 and $intent and $fakeMS) or ($perm1 and $perm2 and $intent and $tapjoySDK and $lib2)
}

rule Android_Banker_Xenomorph_125174 : knownmalware 
 {
	meta:
		sigid = 125174
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Banker.Xenomorph"
		category = "Banker"
		risk = 127
		
	strings:
$str1=".DozeModeActivity"
$str2=".OverlayInjectActivity"
$str3=".AccessibilityEnableHintActivity"
$str4=".SmsComposeActivity"
$str5=".FitnessAccessibilityService"
$str6=".NotificationService"
$str7=".Services.KingService"
$str8=".Services.DummyReceiver"
condition:
all of them
}

rule Android_RAT_GoatRat_128800 : knownmalware 
 {
	meta:
		sigid = 128800
		date = "2023-06-06 10:56 AM"
		threatname = "Android.RAT.GoatRat"
		category = "RAT"
		risk = 127
		
	strings:
		$str_0 = "Theme.Goat"
		$str_1 = "/LiveLiterals$ServerKt;"
		$str_2 = "/bankers/"
		$str_3 = "addOverlay"
		$str_4 = "setupMoney"
		$str_5 = "Server$autoPing"
		$str_6 = "Utils$callOverlayPermission"
		$str_7 = ".online/devices/init"

	condition:
		7 of ($str_*)
}

rule Android_Ransom_SLocker_128642 : knownmalware 
 {
	meta:
		sigid = 128642
		date = "2023-05-25 11:07 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_2 = "com.aide.runtime.VIEW_LOGCAT_ENTRY"
	$str_3 = "logcat -v threadtim"
	$str_4 = "android.intent.action.BOOT_COMPLETED"
	$ntr_5 = "layout_inflater"

condition:
	all of ($str_*) and #ntr_5 == 1
}

rule Android_Spyware_Ahmyth_128641 : knownmalware 
 {
	meta:
		sigid = 128641
		date = "2023-05-25 10:35 AM"
		threatname = "Android.Spyware.Ahmyth"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_MEDIA_AUDIO"
	$str_2 = "android.permission.READ_MEDIA_IMAGES"
	$str_3 = "android.permission.READ_MEDIA_VIDEO"
	$str_4 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_5 = "android.permission.READ_PRIVILEGED_PHONE_STATE"
	$str_6 = "android.permission.RECORD_AUDI"
	$str_7 = "respawnService"
	$str_8 = "android.content.ClipboardManager"
	$str_9 = "http://80876dd5.shop:22223"
condition:
	all of ($str_*)
}

rule Android_Spyware_SmsSpy_129842 : knownmalware 
 {
	meta:
		sigid = 129842
		date = "2023-10-12 08:45 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "android.permission.READ_SMS"
		$str_2 = "android.permission.RECEIVE_SMS"
		$str_3 = "android.permission.READ_CONTACTS"
		$str_4 = "com.drnull.v3.smsReceiver"
		$str_5 = "com.drnull.v3.smsService"
		$str_6 = "chat_id.txt"
		$str_7 = "&issms=true"

	condition:
		all of them
}

rule Android_Spyware_Loan_128645 : knownmalware 
 {
	meta:
		sigid = 128645
		date = "2023-05-25 11:59 AM"
		threatname = "Android.Spyware.Loan"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_CONTACTS"
	$str_2 = "/cashbee/caapsph/boepeen"
	$str_3 = "/cashbee/caapsph/bceoede"
	$str_4 = "/cashbee/caapsph/baecetivate"
	$str_5 = "/cashbee/caapsph/bfeierebase-upload"

condition:
	all of ($str_*)
}

rule Android_Spyware_Joker_125228 : knownmalware 
 {
	meta:
		sigid = 125228
		date = "2023-09-26 09:43 AM"
		threatname = "Android.Spyware.Joker"
		category = "Spyware"
		risk = 127
		sample = "b973d2eb0b41b6cb613cc8bed01e20e7"
	
	strings:
		$str_1 = "test-keys"
		$str_2 = "/system/xbin/su"
		$str_3 = "setComponentEnabledSetting"
		$str_4 = "isDebuggerConnected"
		$mani_1 = "android.permission.READ_CONTACTS"
		$mani_2 = "android.permission.READ_PHONE_STATE"
		$mani_3 = "com.lihtkeyboard.colortheme.keyboard.service.FCMService"
		$mani_4 = "com.liulishuo.filedownloader.services.FileDownloadService"

	condition:
		7 of them

}

rule Android_Trojan_Gigabud_127232 : knownmalware 
 {
	meta:
		sigid = 127232
		date = "2023-01-24 12:25 PM"
		threatname = "Android.Trojan.Gigabud"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "TouchAccessibilityService"
		$str_2 = ".record.ScreenRecordService"
		$str_3 = "user-bank-pwd"
		$str_4 = "/push-streaming?"
		$str_5 = "/command?token="

		$perm_1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
		$perm_2 = "android.permission.SYSTEM_OVERLAY_WINDOW"
		$perm_3 = "android.permission.SYSTEM_ALERT_WINDOW"
		$perm_4 = "android.permission.RECEIVE_SMS"

	condition:
		all of ($str_*) and 2 of ($perm_*)
}

rule Android_Banker_Rewards_127681 : knownmalware 
 {
	meta:
		sigid = 127681
		date = "2023-03-07 07:06 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "example.permanence"
	$str_3 = "Removing App"
	$str_4 = "Apply Successful\nRemoving app from your Mobile"
	$str_5 = "@style/Theme.HDFCRewards"

condition:
	all of ($str_*)
}

rule Android_Spyware_Vision_127705 : knownmalware 
 {
	meta:
		sigid = 127705
		date = "2023-03-10 08:33 AM"
		threatname = "Android.Spyware.Vision"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_CALL_LOG"
	$str_2 = "android.permission.RECORD_AUDIO"
	$str_3 = "android.permission.STORAGE"
	$str_4 = "android.permission.READ_CONTACTS"
	$str_5 = "android.permission.READ_SMS"
	$str_6 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_7 = "http://diashq.com:8080"
	$str_8 = "Application will Not work Properly If you Deny Any Permsion Next Time"

condition:
	all of ($str_*)
}

rule Android_Spyware_Gen_127707 : knownmalware 
 {
	meta:
		sigid = 127707
		date = "2023-03-10 08:33 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "your-app.xyz/dadaalp"
	$str_2 = "multipart/form-data; boundary=---------------------------1461124740692"
	$str_3 = "result=ok&action=pingone&androidid="
	$str_4 = "result=ok&action=hideicon&androidid="
	$str_5 = "/applist.php?result=ok&action=applist&androidid="
	$str_6 = "result=ok&action=lastsms&androidid="
	$str_7 = "result=ok&action=install&androidid="
	$str_8 = "result=ok&action=nwmessage&androidid="

condition:
	7 of ($str_*)
}

rule Android_Banker_Xenomorph_127717 : knownmalware 
 {
	meta:
		sigid = 127717
		date = "2023-03-10 16:26 PM"
		threatname = "Android.Banker.Xenomorph"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1="res/raw/rum_modules.json"
		$str_2="permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE"
		$str_3="permission=\"android.permission.BIND_DEVICE_ADMIN"
		$str_4="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
		$str_5="android.permission.KILL_BACKGROUND_PROCESSES"
		$str_6="android.permission.QUERY_ALL_PACKAGES"
		$str_7="android.permission.SYSTEM_ALERT_WINDOW"
		$str_8="android.permission.RECEIVE_SMS"
		$str_9="excludeFromRecents=\"true"
	condition:
		all of them
}

rule Android_Backdoor_Basdoor_127016 : knownmalware 
 {
	meta:
		sigid = 127016
		date = "2023-09-26 09:44 AM"
		threatname = "Android.Backdoor.Basdoor"
		category = "Backdoor"
		risk = 127
		
	strings:
		$str_1 = "result=ok&action=getdevicefullinfo&androidid="
		$str_2 = "result=ok&action=pingone&androidid="
		$str_3 = "result=ok&action=ping&androidid"
		$str_4 = "result=ok&action=testphone&sendsms="
		$str_5 = "@IRANIN_MAFIA"
		$str_6 = "/upload.php?result=ok&action=upload&androidid="
		$str_7 = "/upload.php?result=ok&action=upload1&androidid="
		$str_8 = "result=ok&action=lastsms&androidid="
		$str_9 = "result=ok&action=firstinstall&androidid="
		$str_10 = "result=ok&action=nwmessage&androidid="
	condition:
		6 of them
}

rule Android_Spyware_Spynote_127557 : knownmalware 
 {
	meta:
		sigid = 127557
		date = "2023-02-28 11:37 AM"
		threatname = "Android.Spyware.Spynote"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_CALL_LOG"
	$str_2 = "android.permission.READ_SMS"
	$str_3 = "android.permission.SEND_SMS"
	$str_4 = "android.permission.RECORD_AUDIO"
	$str_5 = "android.permission.CAMERA"
	$str_6 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
	$str_7 = "context.assets.open(\"data.json\")"
	$str_8 = "willi/fiend/Utils/AppTools"

condition:
	all of ($str_*)
}

rule Android_Spyware_Joker_125353 : knownmalware 
 {
	meta:
		sigid = 125353
		date = "2023-09-26 09:45 AM"
		threatname = "Android.Spyware.Joker"
		category = "Spyware"
		risk = 127
		
	  
	strings:
		$str_1 = "Subscribed!"
		$str_2 = "HeadlessSmsSendService"
		$str_3 = "setComponentEnabledSetting"
		$recv = "<receiver "
		$serv = "<service "
		$query = "<queries>"

	condition:
		#query == 1 and #recv == 28 and #serv == 29 and all of ($str_*)

}

rule Android_Spyware_Bahamut_125426 : knownmalware 
 {
	meta:
		sigid = 125426
		date = "2022-04-20 12:25 PM"
		threatname = "Android.Spyware.Bahamut"
		category = "Spyware"
		risk = 127
		
	strings:
$str1="callLogObserver__"
$str2="contactObserver"
$str3="smsObserver"
$str4="PhoneCallBroadcast"
$str5="callingMe"
condition:
all of them
}

rule Android_Spyware_Realrat_125534 : knownmalware 
 {
	meta:
		sigid = 125534
		date = "2023-09-26 09:41 AM"
		threatname = "Android.Spyware.Realrat"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "/rat.php"
		$str_2 = "resultend=ok&action=nwmessageencode&messagetext="
		$str_3 = "resultend=ok&action=nwmessage&messagetext="
		$str_4 = ".fakemain"

	condition:
		all of them
}

rule Android_Banker_Banbra_127472 : knownmalware 
 {
	meta:
		sigid = 127472
		date = "2023-02-16 12:43 PM"
		threatname = "Android.Banker.Banbra"
		category = "Banker"
		risk = 127
		
	strings:
		$bnk_1 = "NubankPaymentHijark"
		$bnk_2 = "PagbankPaymentHijark"
		$bnk_3 = "InterPayPaymentHijark"
		$bnk_4 = "BrazilBankPaymentHijark"
		$bnk_5 = "BitzPayPaymentHijark"

		$str_1 = "autoRetry"
		$str_2 = "updateReceiveSmsAsync"
		$str_3 = "updateBalanceAsync"
		$str_4 = "/RootAutomator;"

	condition:
		3 of ($bnk_*) and 3 of ($str_*)
}

rule Android_Trojan_Joker_125667 : knownmalware 
 {
	meta:
		sigid = 125667
		date = "2023-09-26 09:41 AM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "videosdownloader.shortvideo.fortiktok"
		$str_2 = "fortiktok.DownloadProcessService"
		$str_3 = "sendToServerRewardInfo" nocase
		$str_4 = "setComponentEnabledSetting"
		$mani_1 = "<service "
		$mani_2 = "<receiver "
		$mani_3 = "<provider "
		$mani_4 = "<activity "

	condition:
		 #mani_1 == 13 and #mani_2 == 11 and #mani_3 == 6 and #mani_4 == 17 and all of ($str_*)
}

rule Android_Trojan_Dropper_125625 : knownmalware 
 {
	meta:
		sigid = 125625
		date = "2023-09-26 09:41 AM"
		threatname = "Android.Trojan.Dropper"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "Vuoi installare questa app sicura?"
		$str_2 = "A single sub call does it all\n"
		$str_3 = "User asked to install newer version\n"
		$str_4 = "AppUpdateExample.txt"
		$str_5 = "appp.apk"
		$str_6 = "Cannot send files from the assets folder"
		$support = "application/vnd.android.package-archive"
	condition:
		all of them
}

rule Android_Spyloan_Gen_125463 : knownmalware 
 {
	meta:
		sigid = 125463
		date = "2022-04-25 20:21 PM"
		threatname = "Android.Spyloan.Gen"
		category = "Spyloan"
		risk = 127
		
	strings:
		$str_1 = "com.rupee_loan.dream_loan.ui.CardInfoActivity"
		$str_2 = "com.rupee_loan.dream_loan.ui.BorrowBankActivity"
		$str_3 = "com.rupee_loan.dream_loan.ui.ACardActivity"
		$str_4 = "content://sms/"
		$str_5 = "getJsonArrayContact"
		$str_6 = "getJsonArraySms"
		$receiver = "<receiver "
		$services = "<service "

	condition:
		#receiver == 3 and #services == 4 and all of ($str_*)
}

rule Android_Banker_Gen_FakeMaid_125370 : knownmalware 
 {
	meta:
		sigid = 125370
		date = "2022-04-07 18:08 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
$str1="/api_espanol/api.php?sid=%1$s&sms=%2$s"
$str2="/dl.php"
$str3="sid="
$str4="&agent="
$str5="Please allow SMS before proceed or reinstall the app"
condition:
all of them
}

rule Android_Trojan_SMSThief_125987 : knownmalware 
 {
	meta:
		sigid = 125987
		date = "2022-07-15 09:56 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		sample = "e7f22546c9d55cd9450f75a00b843316"
	strings:
	$str_1 = "MyReceiver"
	$str_2 = "erroeererewrwerwer"
	$str_3 = "android.permission.READ_SMS"
	$str_4 = "android.permission.RECEIVE_SMS"

condition:
	all of them
}

rule Android_Spyware_Realrat_125693 : knownmalware 
 {
	meta:
		sigid = 125693
		date = "2023-09-26 09:42 AM"
		threatname = "Android.Spyware.Realrat"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "/rat.php"
		$str_2 = "allsms.txt"
		$str_3 = "allcontact.txt"
		$str_4 = "Get SmS is OK"
		$str_5 = "result=ok&action=lastsms&androidid="
		$str_6 = "result=ok&action=getdevicefullinfo&androidid="
		$str_7 = "result=ok&action=hideicon&androidid="
		$str_8 = "/upload.php?result=ok&action=upload&androidid="
		$str_9 = "result=ok&action=ping&androidid="
		$str_10 = "result=ok&action=firstinstall&androidid="
		$str_11 = "result=ok&action=nwmessage&androidid="
	condition:
		5 of them
}

rule Android_Banker_Gen_128385 : knownmalware 
 {
	meta:
		sigid = 128385
		date = "2023-05-02 09:15 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0="com.investtrack.portfolio.MainActivity"
		$str_1="android.permission.REQUEST_INSTALL_PACKAGES"
		$str_2="android.permission.QUERY_ALL_PACKAGES"
		$str_3="installed_a"
		$str_4="HttpUrlPinger"
		$str_5="Carregando!"

	condition:
		all of ($str_*)
}

rule Android_Trojan_SLocker_127790 : knownmalware 
 {
	meta:
		sigid = 127790
		date = "2023-03-16 08:46 AM"
		threatname = "Android.Trojan.SLocker"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android:sharedUserId=\"android.uid.systemui\""
	$str_2 = "coreApp=\"true\""
	$str_3 = "<uses-sdk android:minSdkVersion=\"22\" android:targetSdkVersion=\"22\"/>"
	$str_4 = "android:hardwareAccelerated=\"true\""
	$str_5 = "android:persistent=\"true\""
	$str_6 = "android.intent.action.BOOT_COMPLETED"
	$str_7 = "android.permission.MANAGE_USB"
	$str_8 = "android:excludeFromRecents=\"true\" android:launchMode=\"singleTop\""
	$str_9 = "android.permission.BIND_DREAM_SERVICE"
	$str_10 = "android.intent.category.DESK_DOCK"
	$str_11 = "android.permission.INTERACT_ACROSS_USERS_FULL"
	$str_12 = "android.permission.CLEAR_APP_USER_DATA"
	$str_13 = "android.permission.RECEIVE_BOOT_COMPLETED"
	$str_14 = "android.permission.READ_EXTERNAL_STORAGE"
	$str_15 = "android.permission.WRITE_EXTERNAL_STORAGE"
	$str_16 = "android.permission.ACCESS_ALL_EXTERNAL_STORAGE"
	$str_17 = "android.permission.WAKE_LOCK"
	$str_18 = "android.permission.INJECT_EVENTS"
	$str_19 = "android.permission.DUMP"
	$str_20 = "android.permission.WRITE_SETTINGS"
	$str_21 = "android.permission.STATUS_BAR_SERVICE"
	$str_22 = "android.permission.STATUS_BAR"
	$str_23 = "android.permission.EXPAND_STATUS_BAR"
	$str_24 = "android.permission.REMOTE_AUDIO_PLAYBACK"
	$str_25 = "android.permission.MANAGE_USERS"
	$str_26 = "android.permission.READ_PROFILE"
	$str_27 = "android.permission.READ_CONTACTS"
	$str_28 = "android.permission.CONFIGURE_WIFI_DISPLAY"
	$str_29 = "android.permission.WRITE_SECURE_SETTINGS"
	$str_30 = "android.permission.GET_APP_OPS_STATS"
	$str_31 = "android.permission.BLUETOOTH"
	$str_32 = "android.permission.BLUETOOTH_ADMIN"
	$str_33 = "android.permission.ACCESS_NETWORK_STATE"
	$str_34 = "android.permission.CHANGE_NETWORK_STATE"
	$str_35 = "android.permission.READ_PHONE_STATE"
	$str_36 = "android.permission.ACCESS_WIFI_STATE"
	$str_37 = "android.permission.CHANGE_WIFI_STATE"
	$str_38 = "android.permission.MANAGE_NETWORK_POLICY"
	$str_39 = "android.permission.CONNECTIVITY_INTERNAL"
	$str_40 = "android.permission.READ_NETWORK_USAGE_HISTORY"
	$str_41 = "android.permission.CONTROL_VPN"
	$str_42 = "android.permission.MANAGE_USB"
	$str_43 = "android.permission.DEVICE_POWER"
	$str_44 = "android.permission.MOUNT_UNMOUNT_FILESYSTEMS"
	$str_45 = "android.permission.MASTER_CLEAR"
	$str_46 = "android.permission.VIBRATE"
	$str_47 = "android.permission.REAL_GET_TASKS"
	$str_48 = "android.permission.GET_DETAILED_TASKS"
	$str_49 = "android.permission.REORDER_TASKS"
	$str_50 = "android.permission.REMOVE_TASKS"
	$str_51 = "android.permission.STOP_APP_SWITCHES"
	$str_52 = "android.permission.SET_SCREEN_COMPATIBILITY"
	$str_53 = "android.permission.START_ANY_ACTIVITY"
	$str_54 = "android.permission.INTERACT_ACROSS_USERS"
	$str_55 = "android.permission.INTERACT_ACROSS_USERS_FULL"
	$str_56 = "android.permission.GET_TOP_ACTIVITY_INFO"
	$str_57 = "android.permission.MANAGE_ACTIVITY_STACKS"
	$str_58 = "android.permission.START_TASKS_FROM_RECENTS"
	$str_59 = "android.permission.INTERNAL_SYSTEM_WINDOW"
	$str_60 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_61 = "android.permission.READ_FRAME_BUFFER"
	$str_62 = "android.permission.MANAGE_APP_TOKENS"
	$str_63 = "android.permission.SET_ORIENTATION"
	$str_64 = "android.permission.DISABLE_KEYGUARD"
	$str_65 = "android.permission.READ_DREAM_STATE"
	$str_66 = "android.permission.WRITE_DREAM_STATE"
	$str_67 = "android.permission.CONTROL_KEYGUARD"
	$str_68 = "android.permission.MODIFY_PHONE_STATE"
	$str_69 = "android.permission.GET_ACCOUNTS"
	$str_70 = "android.permission.MANAGE_ACCOUNTS"
	$str_71 = "android.permission.BIND_DEVICE_ADMIN"
	$str_72 = "android.permission.CHANGE_COMPONENT_ENABLED_STATE"
	$str_73 = "android.permission.MEDIA_CONTENT_CONTROL"
	$str_74 = "android.permission.ACCESS_KEYGUARD_SECURE_STORAGE"
	$str_76 = "android.permission.BIND_APPWIDGET"
	$str_77 = "android.permission.CONFIGURE_WIFI_DISPLAY"
	$str_78 = "android.permission.ACCESS_TORCH_SERVICE"
	$str_79 = "android.permission.MANAGE_MEDIA_PROJECTION"
	$str_80 = "android.permission.MODIFY_AUDIO_SETTINGS"
	$str_81 = "android.permission.RECORD_AUDIO"
	$str_82 = "android.permission.ACCESS_SURFACE_FLINGER"
	$str_83 = "android.permission.FORCE_STOP_PACKAGES"
	$str_84 = "android.permission.READ_SYNC_SETTINGS"
	$str_85 = "android.permission.WRITE_SYNC_SETTINGS"
	$str_86 = "android.permission.HARDWARE_ABSTRACTION_ACCESS"
	$str_87 = "android.permission.ACCESS_FINGERPRINT_SERVICE"
condition:
	all of ($str_*)
}

rule Android_RAT_CapraRAT_APT36_124995 : knownmalware 
 {
	meta:
		sigid = 124995
		date = "2022-01-25 08:02 AM"
		threatname = "Android.RAT.CapraRAT"
		category = "RAT"
		risk = 127
		
	strings:
$str1="callMoniter<"
$str2="recCall<"
$str3="recMic<"
$str4="rmUser<"
$str5="smsMoniter<"
$str6="userID<"
condition:
all of them
}

rule Android_Backdoor_Sunbird_125091 : knownmalware 
 {
	meta:
		sigid = 125091
		date = "2022-02-10 08:36 AM"
		threatname = "Android.Backdoor.Sunbird"
		category = "Backdoor"
		risk = 127
		
	strings:
$str1="save_target_call_log.php"
$str2="save_target_sms_log.php"
$str3="savetargetdeviceinfo.php"
$str4="savetargetgeolocation.php"
$str5="UploadToServer.php"
$str6="createDirecotory.php"
$str7="getTargetDatabase.php"
$str8="save_target_applist.php"
$str9="save_whats_chat.php"
condition:
4 of ($str*)
}

rule Android_Spyware_DonotAPT_Base64_125563 : knownmalware 
 {
	meta:
		sigid = 125563
		date = "2022-05-11 08:06 AM"
		threatname = "Android.Spyware.DonotAPT"
		category = "Spyware"
		risk = 127
		
	strings:
$str1="Q2FsbExvZ3MudHh0"
$str2="VHJlZS50eHQ="
$str3="YWNjb3VudHMudHh0"
$str4="YncudHh0"
$str5="Q2xpc3QudHh0"
$str6="Y29udGFjdHMudHh0"
$str7="cGtpbmZvLnR4dA=="
$str8="bmV0aW5mby50eHQ="
$str9="cWxscg=="
condition:
7 of ($str*)
}

rule Android_Clean_Citrus_129690 : knownclean 
 {
	meta:
		sigid = 129690
		date = "2023-09-26 14:42 PM"
		threatname = "Android.Clean.Citrus"
		category = "Clean"
		risk = -127
		
	strings:
		$str_1 = "vi-protocol.creativestudios.syneoshealth.com"
		$str_2 = "com.citrussuite.vipro"
		$str_3 = "com.citrussuite.androidengine.CitrusAndroidActivity"		
	condition:
		all of them
}

rule Android_Rat_Vultur_123696 : knownmalware 
 {
	meta:
		sigid = 123696
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Rat.Vultur"
		category = "Rat"
		risk = 127
		
	strings:
$str1 = { 73 00 74 00 61 00 72 00 74 00 20 00 64 00 6F 00 77 00 6E 00 6C 00 6F 00 61 00 64 00 69 00 6E 00 67 }//start.download
$str2 = {72 00 69 00 6E 00 67 00 2E 00 66 00 75 00 6C 00 69 00 66}//ring.fulif
$str3={53 00 63 00 72 00 65 00 65 00 6E 00 52 00 65 00 63 00 6F 00 72 00 64 00 65 00 72 00 48 00 65 00 6C 00 70 00 65 00 72 00 3A 00 3A 00 73 00 74 00 61 00 72 00 74 00 53 00 63 00 72 00 65 00 65 00 6E 00 43 00 61 00 70 00 74 00 75 00 72 00 65}//ScreenRecorderHelper::startScreenCapture
$str4="nstart_vnc"
condition:
all of them
}

rule Android_Banker_Gen_124350 : knownmalware 
 {
	meta:
		sigid = 124350
		date = "2021-10-19 18:04 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample = "826f36592ca7b49f695016b423492a13"
	strings:
	$str_1 = "ND_CLICK_DRAW"
	$str_2 = "seta_tela_cef"
	$str_3 = "seta_tela_santa"
	$str_4 = "get_tamanho_tela"
	$str_5 = "desativar_operador"
	$str_6 = "PIRUZADA_TUTAKAMON"

condition:
	3 of them
}

rule Android_Banker_Anubis_125811 : knownmalware 
 {
	meta:
		sigid = 125811
		date = "2022-06-22 11:09 AM"
		threatname = "Android.Banker.Anubis"
		category = "Banker"
		risk = 127
		
	strings:
		$mani_1 = "anubis.bot.myapplication.ServiceInjections"
		$mani_2 = "anubis.bot.myapplication.Receiver.ReceiverBoot"
		$mani_3 = "anubis.bot.myapplication.API.Screenshot.ServiceScreenshot"
		$mani_4 = "anubis.bot.myapplication.Activity.ActivityInjection"
		$mani_5 = "anubis.bot.myapplication.Activity.ActivityGetNumber"
		$mani_6 = "anubis.bot.myapplication.Activity.ActivityGetSMS"
		$mani_7 = "anubis.bot.myapplication.Activity.ActivityPushInjection"	
		$mani_8 = "anubis.bot.myapplication.ServiceCommands"
		$mani_9 = "anubis.bot.myapplication.ServiceDeleteSMS"
		$mani_10 = "anubis.bot.myapplication.ServiceModuleNotification"
		$mani_11 = "anubis.bot.myapplication.ServiceAccessibility"
		$mani_12 = "anubis.bot.myapplication.API.Screenshot.ServiceSendRequestImageVNC"
		$mani_13 = "anubis.bot.myapplication.API.Sound.ServiceStreamSound"
		$mani_14 = "anubis.bot.myapplication.ServiceRAT"
		$mani_15 = "anubis.bot.myapplication.ServiceCryptFiles"
		$mani_16 = "anubis.bot.myapplication.Activity.LookScreen"
	
	condition:
		10 of them
}

rule Android_Trojan_Dropper_126048 : knownmalware 
 {
	meta:
		sigid = 126048
		date = "2022-07-29 12:11 PM"
		threatname = "Android.Trojan.Dropper"
		category = "Trojan"
		risk = 127
		sample1 = "e55ab94acd8eac7a2f497012e10ba36f"
sample2 = "3e436a2051c63c26a684873ddcdfd0af"
	strings:
	$str_1 = "defender_plugin.jar"
	$str_2 = "Are you sure to disable?"
	$str_3 = "android.permission.BIND_DEVICE_ADMIN"

condition:
	all of them
}

rule Android_Rat_Brata_125866 : knownmalware 
 {
	meta:
		sigid = 125866
		date = "2022-06-29 07:11 AM"
		threatname = "Android.RAT.Brata"
		category = "RAT"
		risk = 127
		
	strings:
$str1="/centralmessagebox" 
$str2="/lockedoutactold"
$str3="/onlytestmp"
$str4="/regetthedevicesizes"
$str5="/reqpermissionsforsystem"
$str6="/runussdcodefast"
$str7="/scenebuilderrect"
$str8="/senderrorlogtodb"
$str9="/startactdevmang"
$str10="/startactgpper"
$str11="/startactoverlay"
$str12="/startactwritesy"
$str13="/startscreencap"
$str14="/startsmspermnew"
$str15="/takescreenshot"
condition:
10 of ($str*)
}

rule Android_Spyware_AndroMonitor_125287 : knownmalware 
 {
	meta:
		sigid = 125287
		date = "2022-03-17 17:22 PM"
		threatname = "Android.Spyware.AndroMonitor"
		category = "Spyware"
		risk = 127
		sample = "4eedccedcdf6a1eda56d1b44211a0df3"
	strings:		
	$str_1 = "DeleteSMSPref"
	$str_2 = "ForceLockScreen"
	$str_3 = "ALLOW_APP_HIDING"
	$str_4 = "StartAudioCapture"
	$str_5 = "TakePicFromFrontCam"

condition:
	4 of them
}

rule Android_Trojan_Joker_125677 : knownmalware 
 {
	meta:
		sigid = 125677
		date = "2023-09-26 09:42 AM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "gamorium.launcher.easymode.EasyModeActivity@"
		$str_2 = "HZwqAqk4Fv9ceuZPmq0Cwj3kncUUYg2xp61iTSqDZ5w="
		$str_3 = "android.permission.CALL_PHONE"
		$str_4 = "android.permission.READ_CONTACTS"
		$str_5 = "android.permission.WRITE_CONTACTS"

	condition:
		all of them
}

rule Android_Spyware_Joker_125495 : knownmalware 
 {
	meta:
		sigid = 125495
		date = "2023-09-26 09:41 AM"
		threatname = "Android.Spyware.Joker"
		category = "Spyware"
		risk = 127
		
	strings:
		$str1 = "/eodBEiUaPyoQhmMKDqutXbVoQmtE1zk"  //encoded-encrypted url for subscription
		$str2 = "Lp..B>N=" //url decryption key
		$recv = "<receiver "
		$servc = "<service " 

	condition:
		#recv == 16 and #servc == 12 and all of ($str*)
}

rule Android_Banker_MoqHao_125998 : knownmalware 
 {
	meta:
		sigid = 125998
		date = "2022-07-18 16:51 PM"
		threatname = "Android.Banker.MoqHao"
		category = "Banker"
		risk = 127
		
	strings:
$str1=".MkActivity\">" 
$str2=".Nt\">"
$str3=".je\"/>"
$str4=".Ql\" android:permission"
$str5=".Ne\">"
$str6=".Cr\"/>"
$str7=".Iv\" android:permission="
$str8=".Sg\" android:permission"
condition:
all of them
}

rule Android_Trojan_Fakeapp_125286 : knownmalware 
 {
	meta:
		sigid = 125286
		date = "2022-03-17 17:22 PM"
		threatname = "Android.Trojan.Fakeapp"
		category = "Trojan"
		risk = 127
		sample1 = "33a4e750374cc1e261ae091b32f2a7a4"
sample2 = "5586670e2e074349b0efee45935551d6"
	strings:
	$str_1="funciones"
	$str_2="interval_sms"
	$str_3="app_db=apks_data"
	$str_4="android.permission.BIND_DEVICE_ADMIN"

condition:
	all of them
}

rule Android_RAT_Teardroid_125858 : knownmalware 
 {
	meta:
		sigid = 125858
		date = "2022-06-27 15:24 PM"
		threatname = "Android.Rat.Teardroid"
		category = "Rat"
		risk = 127
		
	strings:
$str1="SMS_CATCHER"
$str2="keylog_table"
$str3="/keylog/insert"
$str4="/sms/insert"
$str5="SMS_RECIVER"
$str6="DeviceID_Store"
$str7="/user/insert"
condition:
all of them
}

rule Android_Trojan_SMSThief_125883 : knownmalware 
 {
	meta:
		sigid = 125883
		date = "2022-07-03 18:36 PM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		sample = "845081a4e07eddd02a963d8ee885e6b6"
	strings:
	$str_1 = "pass=app168&cmd=sms&sid="
	$str_2 = "pass=app168&cmd=paysg&agent_id="

condition:
	any of them
}

rule Android_Trojan_SMSThief_125251 : knownmalware 
 {
	meta:
		sigid = 125251
		date = "2022-03-11 10:22 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		sample1 = "f493d784d06d6ecf87d38152146aa85c"
sample2 = "a888407469e0ab87fa2adb5e1c702d07"
	strings:
	$str_1 = "/Rat.php?phone="
	$str_2 = "erroeererewrwerwer"

condition:
	all of them
}

rule Android_Banker_Gen_126012 : knownmalware 
 {
	meta:
		sigid = 126012
		date = "2022-07-22 12:27 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample = "04af65f411817e1f4b267c948f7c4bbc"
	strings:
	$str_1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_2 = "Our app use this service for make your device safety"

condition:
	all of them
}

rule Android_Banker_Coper_125975 : knownmalware 
 {
	meta:
		sigid = 125975
		date = "2022-07-14 07:26 AM"
		threatname = "Android.Banker.Coper"
		category = "Banker"
		risk = 127
		
	strings:
$str1="com.fromtoo2."
$str2="android.permission.BIND_ACCESSIBILITY_SERVICE"
$str3="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
condition:
all of them
}

rule Android_Trojan_SideWinder_125733 : knownmalware 
 {
	meta:
		sigid = 125733
		date = "2022-06-02 13:11 PM"
		threatname = "Android.Trojan.SideWinder"
		category = "Trojan"
		risk = 127
		
	strings:
$act1="p4d236d9a.pc31b3236.peae18bc4.p7d5c009e."
condition:
all of them
}

rule Android_Trojan_Joker_125734 : knownmalware 
 {
	meta:
		sigid = 125734
		date = "2023-09-26 09:43 AM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "address = ? AND body = ? AND read = ?"
		$str_2 = "trustsms"
		$mani_1 = "android.permission.WRITE_SMS"
		$mani_2 = "android.permission.READ_SMS"
		$mani_3 = "android.permission.SEND_SMS"
		$mani_4 = "android.permission.READ_CONTACTS"
		$recv = "<receiver "
		$activ = "<activity "
		$serv = "<service "
	condition:
		#recv == 5 and #activ == 18 and #serv == 8 and all of ($str*) and all of ($mani*)
}

rule Android_Spyware_Joker_125227 : knownmalware 
 {
	meta:
		sigid = 125227
		date = "2023-09-26 09:39 AM"
		threatname = "Android.Spyware.Joker"
		category = "Spyware"
		risk = 127
		sample="d3d8dbb9a4dffc1e7007b771e09b5b38"
	strings:
		$str_1 = "addAppInstallIdTo"
		$str_2 = "isDebuggerConnected"
		$str_3 = "isRooted"
		$str_4 = "bit.ly/svslink"
		$str_5 = "com.svs.shareviasms.Reciever.SmsReceiver"
		$str_6 = "com.svs.shareviasms.Services.SmsSendService"
	
	condition:
		all of them
}

rule Android_Spyware_Hermit_125846 : knownmalware 
 {
	meta:
		sigid = 125846
		date = "2022-06-27 05:15 AM"
		threatname = "Android.Spyware.Hermit"
		category = "Spyware"
		risk = 127
		
	strings:
$str1="RECORDER_INFO_MAX_DURATION_REACHED"
$str2="RECORDER_INFO_MAX_FILESIZE_REACHED"
$str3="RECORDER_EVENT_ERROR"
$str4="PERMISSION_INFO_DENIED"
$str5="MISSING_PARAMETER"
$str6="LOCATION_INFO_CHANGED"
$str7="ROOT_INFO_SUCCEDED"
$str8="ROOT_INFO_FAILED"
$str9="EXPLOIT_SUCCEDED"
$str10="EXPLOIT_FAILED"
$str11="PACKAGES_CHANGES"
$str12="PLATFORM_LEVELS_CHANGES"
$str13="PLATFORM_LIMIT_REACHED"
$str14="SCREEN_OFF"
$str15="DEVICE_IDLE"
$str16="APP_WATCHING"
$str17="STARTING_RECORDING"
$str18="PAUSE_RECORDING"
$str19="LIMITS_REACHED"
$str20="CALL"
$str21="TIME_CHANGED"
$str22="CREADY"
$str23="HTTP"
$str24="SCREEN_ON_REQUESTED"
$str25="LOG"
$str26="CELLINFO"
condition:
all of them
}

rule Android_Trojan_Ddos_15072022_125989 : knownmalware 
 {
	meta:
		sigid = 125989
		date = "2022-07-15 11:05 AM"
		threatname = "Android.Trojan.Ddos"
		category = "Trojan"
		risk = 127
		sample = "745e8c90a8e76f81021ff491cbc275bc134cdd7d23826b8dd23e58297fd0dd33"
	strings:
	$str_1 = "ShBHVUdRUkxKEls5QQwREhcbU0VEAQIdBAYZVxhUV19dW1MZS"

condition:
	all of them
}

rule Android_APT_Bahamut_125290 : knownmalware 
 {
	meta:
		sigid = 125290
		date = "2022-03-21 11:00 AM"
		threatname = "Android.Spyware.Bahamut"
		category = "Spyware"
		risk = 127
		
	strings:
$URI1="/save.php?type=data&imei="
$URI2="/check.php?type=files&imei="
$URI3="/check.php?type=cmd&imei="
condition:
all of them
}

rule Android_Spyware_Facestealer_125703 : knownmalware 
 {
	meta:
		sigid = 125703
		date = "2023-09-26 09:05 AM"
		threatname = "Android.Spyware.Facestealer"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "Starting PIP"
		$str_2 = "com_facebook_login_fragment.xml"
		$str_3 = "$avd_hide_password__0.xml"
		$str_4 = "com.facebook.CurrentAccessTokenExpirationBroadcastReceiver"
		$str_5 = "com.facebook.katana"
		$str_6 = "gosharephoto"
	condition:
		all of them
}

rule Android_Spyware_CryptoHashStealer_125715 : knownmalware 
 {
	meta:
		sigid = 125715
		date = "2023-09-26 09:42 AM"
		threatname = "Android.Spyware.Crypto"
		category = "Spyware"
		risk = 127
		
	strings:
		$mani0_1 = "android:name=\"android.accessibilityservice.AccessibilityService\""
		$mani0_2 = "android:name=\"android.permission.CALL_PHONE\""
		$mani0_3 = "android:name=\"android.permission.READ_SMS\""
		$mani0_4 = "android:name=\"android.permission.RECEIVE_SMS\""
		$mani0_5 = "android:name=\"android.permission.SEND_SMS\""
		$mani0_6 = "android:name=\"android.permission.REQUEST_DELETE_PACKAGES\""
		$mani1_1 = "com.talkleadihr"
		$mani1_2 = "peJYMiwCOTmHpQA"
		$mani2_1 = "quicksilverCardAutomation"
		$mani2_2 = "logicafford"
		$mani2_3 = "com.kuvojivutayu"
		$mani3_1 = "oBKclAdETlsioHA"
		$mani3_2 = "RlqaMp"
		$mani4_1 = "BAWAG PSK Security"
		$mani4_2 = "com.mango.shakee"

	condition:
		all of ($mani0_*) and all of ($mani1_*) or 
		all of ($mani0_*) and all of ($mani2_*) or 
		all of ($mani0_*) and all of ($mani3_*) or 
		all of ($mani0_*) and all of ($mani4_*)
}

rule Android_Banker_Coper_Stage_125984 : knownmalware 
 {
	meta:
		sigid = 125984
		date = "2022-07-15 09:07 AM"
		threatname = "Android.Banker.Coper"
		category = "Banker"
		risk = 127
		
	strings:
$str1="e89b158e4bcf988ebd09eb83f5378e87" //certmd5
$str2=".LogSrv"
$str3="android.permission.BIND_ACCESSIBILITY_SERVICE"
$str4="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
condition:
all of them
}

rule Android_Trojan_SMSFactory_125981 : knownmalware 
 {
	meta:
		sigid = 125981
		date = "2022-07-15 07:01 AM"
		threatname = "Android.Trojan.SMSFactory"
		category = "Trojan"
		risk = 127
		sample = "eb96ebd6835638f0a4c2b2849564fb4f"
	strings:
	$str_1 = "PhoneFactory"
	$str_2 = "hide_app_icon"
	$str_3 = "MessageFactory"
	$str_4 = "$this$hideAppIcon"
	$str_5 = "setComponentEnabledSetting"
	$str_6 = "MANAGE_OVERLAY_PERMISSION"

condition:
	all of them
}

rule Android_RAT_Teardroid_125597 : knownmalware 
 {
	meta:
		sigid = 125597
		date = "2022-05-20 09:42 AM"
		threatname = "Android.RAT.Teardroid"
		category = "RAT"
		risk = 127
		sample = "f7a33600195a1bf45ca0281c7971e970"
	strings:
	$str_1 = "CommandReciver"
	$str_2 = "VictimInformation"
	$str_3 = "getVictimDatastore"
	$str_4 = "Device Owner Enabled"

condition:
	3 of them
}

rule Android_Clean_App_125596 : knownclean 
 {
	meta:
		sigid = 125596
		date = "2022-05-20 09:18 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		sample = "5dcf2045905c4925b7f00e9cee2bc045"
	strings:
	$str_1 = "android:sharedUserId=\"android.uid.system\""
	$str_2 = "package=\"com.rjil.jiostbsetting\""

condition:
	all of them
}

rule lazaspy_android_rat_126131 : knownmalware 
 {
	meta:
		sigid = 126131
		date = "2022-08-08 11:01 AM"
		threatname = "Android.Rat.Bitter"
		category = "Rat"
		risk = 127
		
	strings:
 $s0 = "/.System/Ct.csv/"
 $s1 = "/.System/sm.csv/"
 $s2 = "logg.txt"
 $s3 = "ulog.txt"
 $s4 = "This Feature is currently Unavailable. Comming Soon!"
 $s5 = "Press Back Again to Exit."
 $s6 = "Please Grant Permission to Continue"
 $s7 = "Try Again something went wrong"
 $s8 = "Deleting Conversation Please wait"
 $s9 = "please type something"
 $s10 = "Message not Sent"
 condition:
 9 of ($s*)
}

rule Android_Spyware_Spymax_125781 : knownmalware 
 {
	meta:
		sigid = 125781
		date = "2022-06-10 11:30 AM"
		threatname = "Android.Spyware.Spymax"
		category = "Spyware"
		risk = 127
		
	strings:
		$mani_1 = "android.permission.READ_CONTACTS"
		$mani_2 = "android.permission.WRITE_CONTACTS"
		$mani_3 = "android.permission.WRITE_CALL_LOG"
		$mani_4 = "android.permission.CALL_PHONE"
		$mani_5 = "android.permission.WRITE_CONTACTS"
		$mani_6 = "android.permission.READ_SMS"
		$mani_7 = "android.permission.RECORD_AUDIO"
		$mani_8 = "android.permission.WRITE_SMS"
		$mani_9 = "android.permission.CAMERA"
		$str_1  = "spyandroidscreespyandroidnshotspyandroidshow"
		$str_4  = "spyandroid/exitspyandroid/chatspyandroid/"
		$str_5  = "spyandroidPANG spyandroid!!"
		$str_6  = "spyandroiddefauspyandroidlt--/spyandroid/>+"
		$str_7  = "spyandroidhttp:spyandroid//wwwspyandroid.mobispyandroidhok.nspyandroidet/chspyandroid/ch2.spyandroidphp?sspyandroidsl="

	condition:
		all of them
}

rule Android_RAT_AndroRAT_125779 : knownmalware 
 {
	meta:
		sigid = 125779
		date = "2022-06-10 10:24 AM"
		threatname = "Android.RAT.AndroRAT"
		category = "RAT"
		risk = 127
		
	strings:
		$mani_1 = "android.permission.READ_SMS"
		$mani_2 = "android.permission.SEND_SMS"
		$mani_3 = "android.permission.PROCESS_OUTGOING_CALL"
		$mani_4 = "android.permission.RECORD_AUDIO"
		$mani_5 = "android.permission.CALL_PHONE"
		$mani_6 = "android.permission.READ_CONTACTS"
		$str1_1 =  "getBasicInfos"
		$str1_2 =  "ProcessCommand"
		$str1_3 =  "registerSMSAndCall"
		$str1_4 =  "MessageDecoupator"
		$str2_1 =  "Audio streaming request received"
		$str2_2 =  "Start monitoring call"
		$str2_3 =  "Contacts request received"
		$str2_4 =  "List directory request received"
		$str2_5 =  "Photo picture request received"
		$str2_6 =  "SMS list request received"
		$str2_7 =  "Start SMS monitoring"
		$str2_8 =  "smsKeyWords"
		$str2_9 =  "Called uselessly by: "

	condition:
		all of ($mani*) and 3 of ($str1*) and 5 of ($str2*)
}

rule Android_Banker_Aberbot_125256 : knownmalware 
 {
	meta:
		sigid = 125256
		date = "2022-03-14 10:19 AM"
		threatname = "Android.Banker.Aberbot"
		category = "Banker"
		risk = 127
		
	strings:
$str1="/register.php?botid="
$str2="/updateLoc.php?botid="
$str3="/updateStat.php?botid="
$str4="/uploadCall.php?botid="
$str5="/uploadFilesList.php?botid="
$str6="/uploadInbox.php?botid="
$str7="/uploadLog.php?log="
$str8="/uploadVNC.php?botid="
condition:
7 of ($str*)
}

rule Android_Trojan_Joker_125773 : knownmalware 
 {
	meta:
		sigid = 125773
		date = "2023-09-26 09:43 AM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "^vv06!IIGoY~^vXSfM66&XY&5XjvSoG&lfoGABYj56f5M*I5Go66A5++++++"
		$str_2 = "telephony_subscription_service"
		$str_3 = "GMou3Go66+++"
		$str_4 = "~Xv3Go66EMouXS++++++++++"

	condition:
		all of them
}

rule Android_Spyware_FakeCall_KakaoBank_125461 : knownmalware 
 {
	meta:
		sigid = 125461
		date = "2022-04-22 10:14 AM"
		threatname = "Android.Spyware.FakeCall"
		category = "Spyware"
		risk = 127
		
	strings:
$str1="CustomCallService"
$str2="blackCount="
$str3="needShow="
$str4="enable="
$str5="KEY_P3_NUMBER2_1"
$str6="uploadNumber="
$str7="onCallRemoved number="
$str8="p2number="
$str9="CallReject:"
$str10="last Call Out number="
$str11="CallOut_Number="
condition:
all of them
}

rule Android_Banker_Aberbot_125271 : knownmalware 
 {
	meta:
		sigid = 125271
		date = "2022-03-15 06:27 AM"
		threatname = "Android.Banker.Aberbot"
		category = "Banker"
		risk = 127
		
	strings:
$str1="Push CC Injection"
$str2="Take Photo"
$str3="Send SMS to All Contacts"
$str4="Inject a web page"
$str5="Download File"
$str6="Kill Bot"
$str7="Push Bank Injection with Time"
$str8="Push Bank Injection"
$str9="Uninstall an app"
$str10="Record Audio"
$str11="Get Google Authenticator Codes"
$str12="Call a number/Run USSD code"
$str13="Start VNC"
condition:
all of them
}

rule Android_Spyware_Bahamut20072022_126003 : knownmalware 
 {
	meta:
		sigid = 126003
		date = "2023-01-12 08:20 AM"
		threatname = "Android.Spyware.Strongpity"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "Hh5cWB8="
		$str_2 = "Hh4BHg=="

	condition:
		all of them
}

rule Android_Spyware_AhMyth_125365 : knownmalware 
 {
	meta:
		sigid = 125365
		date = "2022-04-06 17:43 PM"
		threatname = "Android.Spyware.AhMyth"
		category = "Spyware"
		risk = 127
		
	strings:
$str1="0xCL"
$str2="0xFI"
$str3="0xSM"
$str4="0xGP"
$str5="0xCO"
$str6="0xIN"
$str7="0xLO"
$str8="0xPM"
$str9="0xWI"
$str10="0xNO"
$str11="0xCB"
$str12="0xMI"
$str13="0xLO"
$str14="enabled_notification_listeners"
condition:
all of them
}

rule Android_Trojan_SMSThief_125755 : knownmalware 
 {
	meta:
		sigid = 125755
		date = "2023-09-26 09:43 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "sms.php?port=YourPort&phone="
		$str_2 = "تارگت جدید نصب کرد"
		$str_3 = "android.permission.READ_SMS"
		$recv = "<receiver "
	condition:
		#recv == 1 and all of ($str_*)
}

rule Android_Banker_MoqHao_125428 : knownmalware 
 {
	meta:
		sigid = 125428
		date = "2022-04-20 12:54 PM"
		threatname = "Android.Banker.MoqHao"
		category = "Banker"
		risk = 127
		
	strings:
$act=".bmActivity"
$lib="libuw.so"
$mani1=".onz\"/>"
$mani2=".ev\">"
$mani3=".yz\"/>"
$mani4=".tm\"/>"
$mani5=".qjf\"/>"
$mani6=".ow\"/>"
condition:
$act and $lib and 4 of ($mani*)
}

rule Android_Spyware_Joker_125207 : knownmalware 
 {
	meta:
		sigid = 125207
		date = "2023-09-26 09:39 AM"
		threatname = "Android.Spyware.Joker"
		category = "Spyware"
		risk = 127
		sample = "c1987fbc40416dec638ca382f0bc2ec3"
	strings:
	$activity = "<activity "
	$receiver = "<receiver "
	$service = "<service "
	$str_1 = "subscriberCount"
	$str_2 = "com.moez.QKSMS.receiver.SmsSentReceiver"
	$str_3 = "com.moez.QKSMS.common.util.QkChooserTargetService"

condition:
	#activity == 12 and #receiver == 20 and #service == 7 and all of ($str_*)
}

rule Android_Banker_MaliBot_125800 : knownmalware 
 {
	meta:
		sigid = 125800
		date = "2022-06-17 11:07 AM"
		threatname = "Android.Banker.MaliBot"
		category = "Banker"
		risk = 127
		sample1 = "e3281f0f5840038135e319419e3d5338"
sample2 = "c9ddaa4d670c262bf2621b8299ccf84e"
	strings:
	$str_1 = "managing_service_message"
	$str_2 = "Enable accessibility access"
	$str_3 = "Service allows Accessibility for Android to scan your device for accessibility issues."
	$str_4 = "Enable accessibility to %1$s. Settings-&gt; Accessibility-&gt; Installed services-&gt; %1$s-&gt; ON"
	$str_5 = "Enable accessibility to %1$s. Installed services-&gt; %1$s-&gt; ON"

condition:
	3 of them
}

rule Android_Banker_GodFather_125332 : knownmalware 
 {
	meta:
		sigid = 125332
		date = "2022-03-25 17:31 PM"
		threatname = "Android.Banker.GodFather"
		category = "Banker"
		risk = 127
		sample1 = "ec9f857999b4fc3dd007fdb786b7a8d1"
sample2 = "d7118d3d6bf476d046305be1e1f9b388"
	strings:
	$str_1="inject_check"
	$str_2="vnc_permission"
	$str_3="app_perm_check"
	$str_4="- Incoming SMS -"
	$str_5="send_all_permission"

condition:
	4 of them
}

rule Android_Ransom_Locker_125786 : knownmalware 
 {
	meta:
		sigid = 125786
		date = "2022-06-14 07:24 AM"
		threatname = "Android.Ransom.Locker"
		category = "Ransom"
		risk = 127
		
	strings:
		$str_1 = "Free Followers"
		$str_2 = "You are Hacked By Anonymous Group"
		$str_3 = "Pay 1000/Rs to Get UnlocK Key on that number"
	condition:
		all of them
}

rule Android_Trojan_Kimsuky_3005982 : knownmalware 
 {
	meta:
		sigid = 3005982
		date = "2022-04-20 12:25 PM"
		threatname = "Android.Trojan.Kimsuky"
		category = "Trojan"
		risk = 127
		
	strings:
$charcode1="4aebb56e13e983015d5173e93686be3f22bd7c624b8d21416c4d1098da71a2f89c1ac382f87f98fcd9a6a52462"
$charcode2="52524aaae25a259014072e5aebd1a81b19021bf04d513bf9a8e894813fa04c08091e06fa514828e7bdf58f9c31a942181e0500e459402dfca6ef8492"
$charcode3="4aebb56e13e983015d5173e93686be3f22bd7c624b8d21416c4d1098da71a2f89c1ac382f87f98fcd9a6a52462"
condition:
all of them
}

rule Android_Trojan_SMSThief_125690 : knownmalware 
 {
	meta:
		sigid = 125690
		date = "2023-09-26 09:42 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "Please allow SMS before proceed or reinstall the app"
		$str_2 = "api.php?sid=%1$s&sms=%2$s"
		$str_3 = "FPX Payment"
		$str_4 = "end.php"
		$str_5 = "ecommerce_channel_01"
	condition:
		all of them
}

rule Android_Trojan_Joker_125583 : knownmalware 
 {
	meta:
		sigid = 125583
		date = "2022-05-16 12:07 PM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str1_1 = "/SVS/Pictures/Sent"
		$str1_2 = "/SVS/Audio/Sent"
		$str1_3 = "going to spam list"
		$str1_4 = "returning back from spam list"
		$str1_5 = "SmsContactsLogManager"
		$str1_6 = "Menu, Add spammer click"
		$str2_1 = "nwocgrka"
		$str2_2 = "picla.oss-eu-central-1"
		$str3_1 = "showInterAd"
		$str3_2 = "safedk_MainActivity_startActivity_44efa0e839eab3160759d66806c85cd2"
		$str3_3 = "grid.cool.photobackground"
		$str4_1 = "TAGTOOOOOOOOO"
		$str4_2 = "DocScanTv"
		$str4_3 = "com.jiao.hdcam.docscanner.NL"
		$supporting_str = "play.google.com/store/apps/details?id="

	condition:
		all of ($str1*) and $supporting_str or 
		all of ($str2*) and $supporting_str or 
		all of ($str3*) and $supporting_str or 
		all of ($str4*)
}

rule Android_Trojan_GriftHorse_125572 : knownmalware 
 {
	meta:
		sigid = 125572
		date = "2022-05-12 19:19 PM"
		threatname = "Android.Trojan.GriftHorse"
		category = "Trojan"
		risk = 127
		sample1 = "3ed41d81c15f6479ec0e0bca69c5c55f"
sample2 = "5d9c9d7725ea4e47fc319384b2f88dad"
	strings:
		$str_1 = "CloacaConfig"
		$str_2 = "InorganicConfig"
		$str_3 = "AdjustInstallInfo"
		$str_4 = "PayActivityConfig"
		$str_5 = "LoggingUriService"
		$str_6 = "ALARM_TRIGGERS_STARTED"
		$str_7 = "CLEAR_HISTORY_TRIGGERS_ONCE"

	condition:
		4 of them
}

rule Android_Banker_BBVA_125934 : knownmalware 
 {
	meta:
		sigid = 125934
		date = "2022-07-07 19:33 PM"
		threatname = "Android.Banker.BBVA"
		category = "Banker"
		risk = 127
		
	strings:
$str1="com.hellobbva.bbva.MainActivity"
$str2="com.hellobbva.bbva.SendTry"
$str3="com.hellobbva.bbva.ServiceTry"
$str4="com.hellobbva.bbva.ReceiverTry"
$str5="com.hellobbva.bbva.ReceiverWapTry"
condition:
all of them
}

rule Android_Spyware_Hermit2_125902 : knownmalware 
 {
	meta:
		sigid = 125902
		date = "2022-07-04 12:51 PM"
		threatname = "Android.Spyware.Hermit"
		category = "Spyware"
		risk = 127
		
	strings:
 $allyperm = "android.permission.BIND_ACCESSIBILITY_SERVICE"
 $str1 = "7d12aaf7-240e-4e58-bc52-8809edb20e73"
 $str2 = "8fec1ada039b36a8fc3cd93b24f737fa43166645"
condition:
all of them
}

rule Android_Backdoor_Hornbill_124996 : knownmalware 
 {
	meta:
		sigid = 124996
		date = "2022-01-25 10:56 AM"
		threatname = "Android.Backdoor.Hornbill"
		category = "Backdoor"
		risk = 127
		
	strings:
$str1="/SaveCallLogs"
$str2="/SaveContactDetails"
$str3="/UpdateMobileState"
$str4="/UploadFile"
$str5="/SaveGpsDetails"
$str6="/SaveMessages"
$str7="/SignUp"
$str8="/UpdateMobileState"
condition:
all of them
}

rule Android_Trojan_SMSThief_124890 : knownmalware 
 {
	meta:
		sigid = 124890
		date = "2021-12-31 09:54 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		sample = "13f023a19268062d2c22c7ccff8694ff"
	strings:
	$str_1 = "/api_espanol/api.php?sid="
	$str_2 = "SMSBroadcastReceiver"
	$str_3 = "Please allow SMS before proceed or reinstall the app."

condition:
	all of them
}

rule Android_Banker_Gen_124873 : knownmalware 
 {
	meta:
		sigid = 124873
		date = "2021-12-27 13:20 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample = "536301e5ae0859e117648b169d81e7ae"
	strings:
	$str_1 = "cmd_done"
	$str_2 = "<>sms_app"
	$str_3 = "card_cvv_s"
	$str_4 = "force_calls"
	$str_5 = "<>Silent_done"
	$str_6 = "all_sms_received"
	$str_7 = "all_call_received"

condition:
	6 of them
}

rule Android_Spyware_PINEFLOWER_126260 : knownmalware 
 {
	meta:
		sigid = 126260
		date = "2022-09-09 10:25 AM"
		threatname = "Android.Spyware.APT42"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "commands_data"
	$str_3 = "data"
	$str_4 = "request_without_response"
	$str_5 = "send_text_response"

condition:
	all of them
}

rule Android_Banker_Anubis_3006475 : knownmalware 
 {
	meta:
		sigid = 3006475
		date = "2022-09-10 06:54 AM"
		threatname = "Android.Banker.ZAnubis"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "zanubis"
		$str_2 = "startAlarm"
		$str_3 = "pref_toke_pedir"
		$mani_1 = "android.permission.WAKE_LOCK"
		$mani_2 = "android.permission.BIND_ACCESSIBILITY_SERVICE"

	condition:
		all of them
}

rule Android_Clean_necti_129425 : knownclean 
 {
	meta:
		sigid = 129425
		date = "2023-08-26 08:26 AM"
		threatname = "Android.Clean.necti"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.necti.fieldofficer.app"
	$str_2 = "com.necti.fieldofficer.app.shared.MyLocationService"
	$str_3 = "icccapi.nectechnologies.in:8183"

condition:
	all of ($str_*)
}

rule Android_Banker_Gen_124702 : knownmalware 
 {
	meta:
		sigid = 124702
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		sample = "c051ff0c9633323ad3a4c025b4d53dc9"
	strings:
	$str_1 = "KEY_ENABLE_LOAN"
	$str_2 = "KEY_ENABLE_SPAM"
	$str_3 = "KEY_ENABLE_INCOMING"
	$str_4 = "KEY_OUTGOING_REPLACE_NUMBER"

condition:
	all of them
}

rule Android_Spyware_Gen_124976 : knownmalware 
 {
	meta:
		sigid = 124976
		date = "2022-03-17 17:21 PM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		sample1 = "8de3adb048737984967bed54f838548f"
sample2 = "324584f8081417a3a1695860bd915bae"
	strings:
	$str_1 = "getdevicefullinfo"
	$str_2 = "SendSingleMessage"
	$str_3 = "result=ok&action=nwmessage&androidid="
	$str_4 = "result=ok&action=ping&androidid="
	$str_5 = "result=ok&action=hideicon&androidid="
	$str_6 = "result=ok&action=pingall&androidid="
	$str_7 = "result=ok&action=getcontact&androidid="
	$str_8 = "result=ok&action=getsms&androidid="
	$str_9 = "result=ok&action=lastsms&androidid="
	$str_10 = "result=ok&action=checkphone&androidid="
	$str_11 = "result=ok&action=smsdel&androidid="

condition:
	3 of them
}

rule Android_Banker_Rewards_129297 : knownmalware 
 {
	meta:
		sigid = 129297
		date = "2023-08-09 08:00 AM"
		threatname = "Android.Banker.Rewards"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = "Please fill Username"
	$str_3 = "userMst"	
	$str_4 = "MySharedPref"
	$str_5 = "AlreadyLogin"
	$str_6 = "Please enter receipt number"
	$str_7 = "smsMst"


condition:
	6 of ($str_*)
}

rule Android_Ransom_SLocker_128554 : knownmalware 
 {
	meta:
		sigid = 128554
		date = "2023-05-17 10:35 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "com.aide.ui"
	$str_2 = "com.adrt.LOGCAT_ENTRIES"
	$str_3 = "android:name=\"android.max_aspect\" android:value=\"4\""
	$str_4 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_5 = "android.permission.SYSTEM_OVERLAY_WINDOW"
	$str_6 = "android.permission.INTERNAL_SYSTEM_WINDOW"
	$str_7 = "android.permission.BIND_ACCESSIBILITY_SERVICE"

	condition:
	all of ($str_*)
}

rule Android_Spyware_SmsSpy_130100 : knownmalware 
 {
	meta:
		sigid = 130100
		date = "2023-11-02 17:36 PM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "android.permission.READ_SMS"
		$str_2 = "android.permission.RECEIVE_SMS"
		$str_3 = "dev.dizel.smsreceiver.MySMSBroadcastReceiver"
		$str_4 = "Ldev/dizel/smsreceiver/MainActivity$sendMessage"
		$str_5 = "getOriginatingAddress"
		$str_6 = "/libsmsreceiver.so"

	condition:
		all of them
}

rule Android_Trojan_Dropper_129374 : knownmalware 
 {
	meta:
		sigid = 129374
		date = "2023-08-21 07:13 AM"
		threatname = "Android.Trojan.Dropper"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "com.tencent.shopcj.receiver.MyDeviceAdminReceiver"
		$str_2 = "com.tencent.shopcj.receiver.SmsReceiver"
		$str_3 = "com.tencent.shopcj.service.RemoteService"
		$str_4 = "android.permission.GET_TOP_ACTIVITY_INFO"
		$str_5 = "android.permission.INTERACT_ACROSS_USERS_FULL"
		$str_6 = "assets/dex/classes-v1.bin"
		$str_7 = "com.mcal.apkprotector.activities.CopyClipActivity"

	condition:
		all of them
}

rule Android_Banker_MMRat_129487 : knownmalware 
 {
	meta:
		sigid = 129487
		date = "2023-09-05 06:17 AM"
		threatname = "Android.Banker.MMRat"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "com.mm.user.ui.service.CancelNoticeService"
		$str_2 = "com.mm.user.ui.service.MyAccessibilityService"
		$str_3 = "findAccessibilityNodeInfosByText"
		$str_4 = "system/deviceInfo/uploadLockScreenPassword"
		$str_5 = ":8554/live/"

	condition:
		all of them
}

rule Android_Clean_App_Readband_129237 : knownclean 
 {
	meta:
		sigid = 129237
		date = "2023-08-02 09:32 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.redbend.client"
	$str_2 = "com.redbend.client.permission.EVENT_INTENT"
condition:
	all of ($str_*)
}

rule Android_Clean_FPAC_129429 : knownclean 
 {
	meta:
		sigid = 129429
		date = "2023-08-26 08:32 AM"
		threatname = "Android.Clean.FPAC"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.pax.fpac.base24"
	$str_2 = "com.pax.appstore.DownloadParamReceiver"
	$str_3 = "com.pax.market.android.app.sdk.DownloadParamReceiver"

condition:
	all of ($str_*)
}

rule Android_Clean_OlamDigital_129428 : knownclean 
 {
	meta:
		sigid = 129428
		date = "2023-08-26 08:29 AM"
		threatname = "Android.Clean.OlamDigital"
		category = "Clean"
		risk = -127
		
	strings:				
	$str_1 = "com.olam.digital.ofis.HomeActivity"
	$str_2 = "com.olam.digital.ofis.FindFarmerActivity"
	$str_3 = "https://www.olamagri.com/privacy.html"
		
	condition:
		all of them
}

rule Android_Clean_iSOSAndroid_129427 : knownclean 
 {
	meta:
		sigid = 129427
		date = "2023-08-26 08:27 AM"
		threatname = "Android.Clean.iSOSAndroid"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.infostretch.iSOSAndroid"
	$str_2 = "com.marianhello.bgloc.sync.SyncService"
	$str_3 = "com.outsystems.plugins.oslogger.key.apikey"

condition:
	all of ($str_*)
}

rule Android_Clean_SGMappstore_129365 : knownclean 
 {
	meta:
		sigid = 129365
		date = "2023-08-19 07:13 AM"
		threatname = "Android.Clean.SGMappstore"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "android.uid.system"
	$str_2 = "com.sgm.appstore"
	$str_3 = "https://ninfo-securitygateway.sgmlink.com"
	$str_4 = "release"

condition:
	all of ($str_*)
}

rule Android_Clean_Suez_129424 : knownclean 
 {
	meta:
		sigid = 129424
		date = "2023-08-26 08:25 AM"
		threatname = "Android.Clean.Suez"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.suez.operationapp"
	$str_2 = "com.suez.operationapp.DemandActivity"
	$str_3 = "https://gisropes.com"

condition:
	all of ($str_*)
}

rule Android_Clean_SionInformatica_130056 : knownclean 
 {
	meta:
		sigid = 130056
		date = "2023-10-31 04:08 AM"
		threatname = "Android.Clean.SionInformatica"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.genexus.carcara.CarcaraSD"
	$str_2 = "6D7C7BE76EE851821DE3A47A633C2B01F307FF85"

condition:
	all of ($str_*)
}

rule Android_Trojan_Rokrat_127964 : knownmalware 
 {
	meta:
		sigid = 127964
		date = "2023-03-27 12:55 PM"
		threatname = "Android.Trojan.Rokrat"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0="Lcom/personal/info/plugin;"
		$str_1="com.sec.android.acservice.Command"
		$str_2="assets/1qaz2wsx"
		$str_3="/SMS_RT"
		$str_4="CMDEXECUTE"
		$str_5="SMSREALTIME"
		$str_6="CMDDEXDOWN"
	condition:
		6 of ($str_*)
}

rule Android_Downloader_Coper_129348 : knownmalware 
 {
	meta:
		sigid = 129348
		date = "2023-08-17 08:29 AM"
		threatname = "Android.Downloader.Coper"
		category = "Downloader"
		risk = 127
		
	strings:
	$str_1 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_2 = "android.permission.MANAGE_EXTERNAL_STORAGE"
	$str_3 = "scanlala"
	$str_4 = "Robin"

condition:
	all of ($str_*)
}

rule Android_Clean_Olam_129364 : knownclean 
 {
	meta:
		sigid = 129364
		date = "2023-08-19 07:09 AM"
		threatname = "Android.Clean.Olam"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.olam.digital."
	$str_2 = "android.hardware.Camera"
	$str_3 = "android.hardware.location.gps"
	$str_4 = "android.hardware.usb.host"

condition:
	all of ($str_*)
}

rule Android_Banker_Zombinder_129289 : knownmalware 
 {
	meta:
		sigid = 129289
		date = "2023-08-08 07:30 AM"
		threatname = "Android.Banker.Zombinder"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "/LuckyService;"
		$str_2 = "/OverlayActivity;"
		$str_3 = "isAppInstalled"
		$str_4 = "showDialog"
		$str_5 = "getLaunchIntentForPackage"
		$str_6 = "This app requires the plugin app to be installed"
		$str_7 = "android.permission.REQUEST_INSTALL_PACKAGES"

	condition:
		all of them
}

rule Android_Clean_App_Panasonic_130050 : knownclean 
 {
	meta:
		sigid = 130050
		date = "2023-10-27 11:39 AM"
		threatname = "Android.Clean.App"
		category = "Clean"
		risk = -127
		
	strings:
$pkg_name = "package=\"panacim.one\""
condition:
all of them
}

rule Android_Clean_WoyaTech_130038 : knownclean 
 {
	meta:
		sigid = 130038
		date = "2023-10-26 11:45 AM"
		threatname = "Android.Clean.WoyaTech"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.woyatech.hhc"
	$str_2 = "07F7DC40DF376DE422EAAA2DD9F84397B3804AFD"

condition:
	all of ($str_*)
}

rule Android_Spyware_Gen_130023 : knownmalware 
 {
	meta:
		sigid = 130023
		date = "2023-10-26 11:34 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "4463436743674366425442504350436642664167416743614265416542664162425042694169426943504366426741664169416241614262420076"
	$str_2 = "http://portalmod.xyz"
	$str_3 = "prostsdesk"
	$str_4 = "prodevmem2"
condition:
	3 of ($str_*)
}

rule Android_Trojan_SMSThief_129298 : knownmalware 
 {
	meta:
		sigid = 129298
		date = "2023-08-09 08:32 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "Lcom/drnull/fcm/smsReceiver;"
		$str_2 = "firsttimeSms"
		$str_3 = "firstinstall"
		$str_4 = "smsreceived"
		$str_5 = "send_message_contect"
		$str_6 = "hideall"
		$str_7 = "smsbomber"
		$str_8 = "readcontacts"
		$str_9 = "/upload/"

	condition:
		all of them
}

rule Android_Clean_CiontekPOS_129267 : knownclean 
 {
	meta:
		sigid = 129267
		date = "2023-08-21 09:15 AM"
		threatname = "Android.Clean.CiontekPOS"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.ciontek"
	$str_2 = "sharedUserId=\"android.uid.system\""
	$str_3 = "android.permission.READ_PRIVILEGED_PHONE_STATE"	
	$str_4 = "pos.intent.action.PAY_HARDWARE"

condition:
	all of ($str_*)
}

rule Android_Clean_FiservDirectPay2_129266 : knownclean 
 {
	meta:
		sigid = 129266
		date = "2023-08-21 09:15 AM"
		threatname = "Android.Clean.FiservDirectPay2"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.pax.fpac.base24"
	$str_2 = "com.pax.permission.PRINTER"
	$str_3 = "com.pax.permission.PICC"	
	$str_4 = "TransactionManagement/restapi/createChargeSlip"


condition:
	all of ($str_*)
}

rule Android_Clean_VLC_129264 : knownclean 
 {
	meta:
		sigid = 129264
		date = "2023-08-21 09:15 AM"
		threatname = "Android.Clean.VLC"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "SHA1:eefbc981428343bbddfff6b23b6bd8717351410c"
	$str_2 = "SHA256:c8768d2cea0c4b622e419b4b4715981946821e4ebc035fb41776cad395a7f68e"	
condition:
	all of ($str_*)
}

rule Android_Clean_FiservDirectPay_129209 : knownclean 
 {
	meta:
		sigid = 129209
		date = "2023-08-21 09:05 AM"
		threatname = "Android.Clean.FiservDirectPay"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.pax.fpac.base24"
	$str_2 = "com.pax.view.widget.AmountWidget"	
	$str_3 = "com.pax.appstore.PaxAppStoreService"	
condition:
	all of ($str_*)
}

rule Android_RAT_CapraRAT_APT36_124994 : knownmalware 
 {
	meta:
		sigid = 124994
		date = "2022-01-25 07:02 AM"
		threatname = "Android.RAT.CapraRAT"
		category = "RAT"
		risk = 127
		
	strings:
$str1=".MainActivity"
$str2=".Main2Activity"
$str3=".GalleryActivity"
$str4=".ScreenshotService"
$str5=".TCPClient"
$str6=".callRecording"
condition:
all of them
}

rule Android_Clean_Awinvest_130002 : knownclean 
 {
	meta:
		sigid = 130002
		date = "2023-10-23 12:21 PM"
		threatname = "Android.Clean.Awinvest"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "ttl.android.winvest.citic"
	$str_2 = "ttl.android.winvest.ui.StartAppActivity"
	$str_3 = "FBD3BDCB6E77520B0F9EDA6566C76907884DA76A"

condition:
	2 of ($str_*)
}

rule Android_Banker_Falcon_129172 : knownmalware 
 {
	meta:
		sigid = 129172
		date = "2023-07-27 10:13 AM"
		threatname = "Android.Banker.Falcon"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "ActivityFakeAppStartFaApp"
		$str_2 = "ActivityStartInjectionFaApp"
		$str_3 = "ActivitySpamSmsFaApp"
		$str_4 = "ServiceInteractionServerFaApp"
		$str_5 = "ActivityStartUSSDFaApp"
		$str_6 = "ServiceReadNotificationsFaApp"
		$str_7 = "ReceiverBootStarter"
		$str_8 = "saveInjData"
		$str_9 = "findAccessibilityNodeInfosByText"
	condition:
		7 of them
}

rule Android_Banker_Banbra_129156 : knownmalware 
 {
	meta:
		sigid = 129156
		date = "2023-07-25 09:54 AM"
		threatname = "Android.Banker.Banbra"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "Theme.NewBankingTrojan"
		$str_2 = "permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE"
		$str_3 = "name=\"android.permission.SYSTEM_ALERT_WINDOW"
		$str_4 = "Utils$callOverlayPermission"
		$str_5 = "onAllowClick"
		$str_6 = "bankoverlay.png"
		$str_7 = "bankoverlay.xml"
	condition:
		all of them
}

rule Android_Banker_smsFish_129176 : knownmalware 
 {
	meta:
		sigid = 129176
		date = "2023-07-28 07:40 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_0 = "/MyService$SMSBroadCast;"
		$str_1 = "createNotificationAndroidO"
		$str_2 = "isReceiveSMS"
		$str_3 = "isReadSMS"
		$str_4 = "sendData.php"
		$str_5 = "updateMessageToken.php"
		$str_6 = "/smsFish/sendLoginData.php"
		$str_7 = "/SmsModel;"
		$str_8 = "/api/ApiService;"
		$str_9 = "app_share"
		$str_10 = "dialog_my_permission"
	condition:
		10 of them
}

rule Android_Clean_PitneyBowesInc_129186 : knownclean 
 {
	meta:
		sigid = 129186
		date = "2023-08-21 09:04 AM"
		threatname = "Android.Clean.PitneyBowesInc"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "SHA256:2a4ac5251aa7f56a6b61a594d9e81d204586c4bdf517fc9909bf890ceba45cba"
	$str_2 = "SHA1:bc6447db1c8cfce8cc629af3ed67e32322f20eee"
condition:
	all of ($str_*)
}

rule Android_spyware_SmsSpy_129971 : knownmalware 
 {
	meta:
		sigid = 129971
		date = "2023-10-20 10:55 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.app.action.DEVICE_ADMIN_ENABLED"
	$str_2 = "android.permission.SEND_SMS"
	$str_3 = "android.permission.RECEIVE_SMS"
	$str_4 = "ashishmessage"
	$str_5 = "getrequestashish"

condition:
	all of ($str_*)
}

rule Android_Trojan_Joker_128102 : knownmalware 
 {
	meta:
		sigid = 128102
		date = "2023-05-18 18:16 PM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.FOREGROUND_SERVICE"
	$str_2 = "android.intent.action.VIEW"
	$str_3 = "android.permission.CHANGE_NETWORK_STATE"
	$str_4 = "android.permission.WAKE_LOCK"
	$str_5 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
	$str_6 = "lib/arm"
	$nostr_1 = "onNotificationPosted"
	$nostr_2 = "\"android.text\""
	$nostr_3 = "lib/x86/lib"
	$nostr_4 = "lib/x86_64/lib"	
condition:
	all of ($str_*) and #nostr_1 == 0 and #nostr_2 == 0 and #nostr_3 == 0 and #nostr_4 == 0
}

rule Android_Trojan_SMSThief_128271 : knownmalware 
 {
	meta:
		sigid = 128271
		date = "2023-04-20 08:47 AM"
		threatname = "Android.Trojan.SMSTheif"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = "android.permission.READ_SMS"
	$str_3 = "android.permission.RECEIVE_SMS"
	$str_4 = "Please enter the valid card number"
	$str_5 = "Please enter the valid expiry date"
	$str_6 = "Please enter the valid CVV number"

condition:
	all of ($str_*)
}

rule Android_Trojan_SMSThief_128270 : knownmalware 
 {
	meta:
		sigid = 128270
		date = "2023-04-20 07:28 AM"
		threatname = "Android.Trojan.SMSTheif"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_CONTACTS"
	$str_2 = "android.permission.READ_SMS"
	$str_3 = "android.permission.RECEIVE_SMS"
	$str_4 = "/api_phonebook.shtml"
	$str_5 = "/api_msg.shtml"
	$str_6 = "/api_calllog.shtml"

condition:
	all of ($str_*)
}

rule Android_Ransom_SLocker_128269 : knownmalware 
 {
	meta:
		sigid = 128269
		date = "2023-04-20 06:42 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_2 = "logcat -v threadtime"
	$str_3 = "com.adrt.BREAKPOINT_HIT"
	$str_4 = "stackLocationKinds"
	$str_5 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_6 = "android:name=\"android.max_aspect\" android:value=\"4\""

condition:
	all of ($str_*)
}

rule Android_Banker_Gen_128067 : knownmalware 
 {
	meta:
		sigid = 128067
		date = "2023-04-03 13:46 PM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "notification_accessibility_required_for_show_over_everything_flash"
	$str_2 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_3 = "performGlobalAction: failed"
	$str_4 = "assets/kid/data.xml"
	$str_5 = "lEnable"
	$str_6 = "leEnle"
	$str_7 = "tEnable"
	
condition:
	all of ($str_*)
}

rule Android_Trojan_Rokrat_127970 : knownmalware 
 {
	meta:
		sigid = 127970
		date = "2023-03-27 13:47 PM"
		threatname = "Android.Trojan.Rokrat"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_0="com.personal.info.plugin"
		$str_1="PLUGINDEXDOWN"
		$str_2="/.temp/plugin"
		$str_3="ARStop"
		$str_4="android.permission.RECORD_AUDIO"
		$str_5="android.permission.READ_SMS"
		$str_6="android.permission.READ_CONTACTS"
		$str_7="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
	condition:
		all of ($str_*)
}

rule Android_Spyware_Boogr_127865 : knownmalware 
 {
	meta:
		sigid = 127865
		date = "2023-09-26 09:44 AM"
		threatname = "Android.Spyware.Boogr"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "execulator.rat"
		$str_2 = "LAst sms ok"
		$str_3 = "allsms.txt"
		$str_4 = "hideAppIcon"
		$str_5 = "fullinfo"
	condition:
		all of them
}

rule Android_Spyware_FakeCall_127870 : knownmalware 
 {
	meta:
		sigid = 127870
		date = "2023-03-21 12:06 PM"
		threatname = "Android.Spyware.FakeCall"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1="com.wish.lmbank."
		$str_2="/service/LAutoService;"
		$str_3="/service/TeleNotifyService;"
		$str_4="/ApkInstallerAsyncTask;"
		$str_5="/user/upload_recording_file"
		$str_6="/user/submit_loan_application"
		$str_7="/user/get_limit_phone_number"
		$str_8="installApk"
	condition:
		6 of ($str_*)
}

rule Android_Spyware_Spynote_127854 : knownmalware 
 {
	meta:
		sigid = 127854
		date = "2023-03-21 06:28 AM"
		threatname = "Android.Spyware.Spynote"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "key_loggerfxf0x4x4x0fxfstartc0c1c3a2c0c1c"
		$str_2 = "record_audiofxf0x4x4x0fxf"
		$str_3 = "AudioRecorder.wav"
		$str_4 = "chatfxf0x4x4x0fxfConnectedc0c1c3a2c0c1cOpWin"
		$str_5 = "phonefxf0x4x4x0fxfphone_sendc0c1c3a2c0c1c[SMS]:SMS Sent"
		$str_6 = "com.xxx.broadcast.xxx"
		$str_7 = "shell_terminalfxf0x4x4x0fxf"
		$str_8 = "/exit/chat/"
		$str_9 = "PANG !!"

	condition:
		all of them
}

rule Android_Trojan_SMSThief_127833 : knownmalware 
 {
	meta:
		sigid = 127833
		date = "2023-03-20 06:56 AM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1="/service/DeviceIdKeeperService;"
		$str_2="/request/SmsPushRequest;"
		$str_3="/request/DefaultSmsPush;"
		$str_4="/request/SmsPermissionPush;"
		$str_5="/SmsPush;"
		$str_6="/UrlConstant;"
		$str_7="getMessageBody"
		$str_8="setInterceptedTime"
	condition:
		7 of ($str_*)
}

rule Android_Ransomware_SLocker_126577 : knownmalware 
 {
	meta:
		sigid = 126577
		date = "2022-10-17 14:13 PM"
		threatname = "Android.Ransomware.SLocker"
		category = "Ransomware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.FOREGROUND_SERVICE"
	$str_2 = "android.permission.WAKE_LOCK"
	$str_3 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_4 = "android.permission.USE_FULL_SCREEN_INTENT"
	$str_5 = {476f6f676c65205031d0b079205365637572697479}

condition:
	all of them
}

rule Android_Spyware_Gen_125500 : knownmalware 
 {
	meta:
		sigid = 125500
		date = "2022-04-29 12:48 PM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		sample = "6b2d8b82efb9990b4d5e2687e4cad11d"
	strings:
	$str_1 = "doesDeviceHaveSecuritySetup"
	$str_2 = "ScreenSharingHelper"
	$str_3 = ".control.GestureDispatchService"
	$str_4 = "KEY_TEST_DST_IP"

condition:
	all of them
}

rule Android_Banker_Teabot_125102 : knownmalware 
 {
	meta:
		sigid = 125102
		date = "2022-02-11 06:50 AM"
		threatname = "Android.Banker.Teabot"
		category = "Banker"
		risk = 127
		sample = "6be155472cedc94d834a220b6217c029"
	strings:
		$strg_1 = "isaacluten"
		$strg_2 = "lotterevich"
		$strg_3 = "rosamundstone393"
		$str_1 = "getNetworkCountryIso"
		$str_2 = "startDownload"
		$str_3 = "launchInstalledApp"
		$str_4 = "GooglePlayActivity"
	condition:
		any of ($strg_*) and all of ($str_*)
}

rule Android_Spyware_Chrysaor_123679 : knownmalware 
 {
	meta:
		sigid = 123679
		date = "2021-07-28 12:35 PM"
		threatname = "Android.Spyware.Chrysaor"
		category = "Spyware"
		risk = 127
		sample1 = "7c3ad8fec33465fed6563bbfabb5b13d"
sample2 = "9bff9eeafd4ab60e645d494573052880"
	strings:
	$str_1 = "GOT_TAP_SMS_CALL_NOT_YET_ARRIVED"
	$str_2 = "SMS_LOC_MON"

condition:
	all of them
}

rule Android_Backdoor_Hornbill_124998 : knownmalware 
 {
	meta:
		sigid = 124998
		date = "2022-01-25 11:01 AM"
		threatname = "Android.Backdoor.Hornbill"
		category = "Backdoor"
		risk = 127
		
	strings:
$str1="/sdcard/.system0/.cr"
$str2="/sdcard/.system0/.ia"
$str3="/sdcard/.system0/.is/.ifcc"
$str4="sdcard/.system0/.is/.ircc"
$str5="/sdcard/.system0/.is/.iss"
condition:
4 of ($str*)
}

rule Android_Trojan_SMSThief_124862 : knownmalware 
 {
	meta:
		sigid = 124862
		date = "2021-12-23 18:33 PM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		sample = "4ff8e27f3b51e0990bfbb7da42ab0ad3"
	strings:
	$str_1 = "FBF50JU2FY"
	$str_2 = "/Install.php?serialNumber="
	$str_3 = "/index.php?deviceid="

condition:
	all of them
}

rule Android_Banker_Zanubis_129790 : knownmalware 
 {
	meta:
		sigid = 129790
		date = "2023-10-10 06:44 AM"
		threatname = "Android.Banker.Zanubis"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
		$str_2 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
		$str_3 = "ruta-toos.pp"	
		$str_4 = "permisoNotificacion"		
	condition:
		all of them
}

rule Android_Trojan_Xhelper_128418 : knownmalware 
 {
	meta:
		sigid = 128418
		date = "2023-05-06 07:16 AM"
		threatname = "Android.Trojan.Xhelper"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "/firehelper.jar"
	$str_2 = "ZWXFB_2"
	$str_3 = "ZGFsdmlrLnN5c3RlbS5EZXhDbGFzc0xvYWRlcg"
	$str_4 = "com.mufc"
	$str_5 = "android.intent.action.mainintentex"

condition:
	4 of ($str_*)
}

rule Android_Trojan_SMSThief_125015 : knownmalware 
 {
	meta:
		sigid = 125015
		date = "2022-01-28 15:50 PM"
		threatname = "Android.Trojan.SMSThief"
		category = "Trojan"
		risk = 127
		sample = "5aa62fdbf1256ded64b2627d3c871608"
	strings:
	$str_1 = "all_sms"
	$str_2 = "hidden_icon"
	$str_3 = "device_token"
	$str_4 = "sms_contacts"
	$str_5 = "visible_icon"
	$str_6 = "online_devices"
	$str_7 = "MS_SMS"

condition:
	all of them
}

rule Android_RAT_GravityRAT_124572 : knownmalware 
 {
	meta:
		sigid = 124572
		date = "2022-06-23 07:46 AM"
		threatname = "Android.RAT.GravityRAT"
		category = "RAT"
		risk = 127
		
	strings:
$str2="UpdateLastActiveTime"
$str3="Phone Number:---"
$str4="Call Type:---"
$str5="Call Date:---"
$str6="Call duration in sec :---"
$str7="sms_stat"
$str8="sms_file_status"
$str9="call_file_status"
$str10="call_file_status"
condition:
8 of ($str*)
}

rule Android_Spyware_AhMyth_TransTribe_123794 : knownmalware 
 {
	meta:
		sigid = 123794
		date = "2021-08-11 15:28 PM"
		threatname = "Android.Spyware.AhMyth"
		category = "Spyware"
		risk = 127
		
	strings:                                                                                                                                                                                                                  
$c2comm="x000upd"                                                                                                                                                                                                         
$c2comm1="x000adm"                                                                                                                                                                                                        
$c2comm2="x0000mc"                                                                                                                                                                                                        
$c2comm3="x0000lm"                                                                                                                                                                                                        
$c2comm4="x0000fm"                                                                                                                                                                                                        
$c2comm5="x0000cn"                                                                                                                                                                                                        
$c2comm6="x0000cl"                                                                                                                                                                                                        
condition:                                                                                                                                                                                                                
all of them
}

rule Android_Banker_Axisapp_126242 : knownmalware 
 {
	meta:
		sigid = 126242
		date = "2022-09-06 06:29 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = "message.php"
		$str_2 = "sendData"
		$str_3 = "api/signup.php"
		$str_4 = "cardno"
		$str_5 = "cvv"
		$str_6 = "name"
		$str_7 = "meetings"
		$str_8 = "cards.php"
		$mani_1 = "android.permission.RECEIVE_SMS"
		$mani_2 = "android.permission.SEND_SMS"
		$mani_3 = "android.permission.READ_SMS"
		$mani_4 = "android.permission.INTERNET"
		$activ = "<activity "
		$recei = "<receiver "

	condition:
		#activ == 5 and #recei == 1 and all of ($mani*) and 7 of ($str*)
}

rule Android_Trojan_Metasploit_129712 : knownmalware 
 {
	meta:
		sigid = 129712
		date = "2023-09-27 17:57 PM"
		threatname = "Android.Trojan.Metasploit"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "android.intent.action.BOOT_COMPLETED"
		$str_2 = "android.permission.RECORD_AUDIO"
		$str_3 = "android.permission.READ_SMS"
		$str_4 = "usrioUsrio"
		$str_5 = "usrioTlfnoCllar"
		$str_6 = "usrioEmprsaId"
		$str_7 = "progresando.api/rest/servicios_usuario"
				
	condition:
		all of them
}

rule Android_Banker_Coper_124969 : knownmalware 
 {
	meta:
		sigid = 124969
		date = "2022-01-18 15:57 PM"
		threatname = "Android.Banker.Coper"
		category = "Banker"
		risk = 127
		
	strings:
$str1="/C=US/ST=California/L=Mountain View/O=Android/OU=Android"
$str2=".LogSrv"
$str3=".OverlayAct"
$str4="attachBaseContext"
$str5="loadLibrary"
$str6="onCreate"
condition:
all of them
}

rule Android_Trojan_Test_125530 : knownmalware 
 {
	meta:
		sigid = 125530
		date = "2022-05-05 04:23 AM"
		threatname = "Android.Trojan.Test"
		category = "Trojan"
		risk = 127
		sample = "50a9c960410ef3d3e41c160b852f870f"
	strings:
	$str_1 = "panwtest"
	$str_2 = "This is PANW APK TEST Application!"
	$str_3 = "com.panw.panwapktest.MainActivity"

condition:
	all of them
}

rule Android_Spyware_Joker_125480 : knownmalware 
 {
	meta:
		sigid = 125480
		date = "2022-04-27 10:30 AM"
		threatname = "Android.Spyware.Joker"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "com.applovin.app_killed"
		$str_2 = "android.app.role.SMS"
		$str_3 = "secretChat"
		$str_4 = "getNumberOfCameras"
		$str_5 = "setComponentEnabledSetting"
	condition:
		all of them
}

rule Android_Ransom_Gen_126011 : knownmalware 
 {
	meta:
		sigid = 126011
		date = "2022-07-22 11:32 AM"
		threatname = "Android.Ransom.Gen"
		category = "Ransom"
		risk = 127
		sample = "a849e2d0fd4800c3d3073c1e280369a8"
	strings:
	$str_1 = "com.termuxhackers.id.MyService"
	$str_2 = "com.termuxhackers.id.BootReceiver"
	$str_3 = "android.permission.SYSTEM_ALERT_WINDOW"

condition:
	all of them
}

rule Android_Spyware_Gen_125963 : knownmalware 
 {
	meta:
		sigid = 125963
		date = "2022-07-12 10:47 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "freeandroidspy"
		$str_2 = "openMp3"
		$str_3 = "refreshDoter"
		$str_4 = "دسترسی پرداخت فعال نیست. تنظیمات دسترسی برنامه بررسی شو"
		$str_5 = "YourFuckingIPAddress"

	condition:
		4 of them
}

rule Android_Spyware_Gen_125747 : knownmalware 
 {
	meta:
		sigid = 125747
		date = "2022-06-03 11:56 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		sample = "bf9a2e4bf73ccaadc2e57face79621d5"
	strings:
	$str_1 = "txt_use_an_valid_email"
	$str_2 = "is_the_email_address_valid"
	$str_3 = "This prevents the app from being uninstalled by the child or staff."
	$str_4 = "So that the app can capture messages from WhatsApp, Instagram and other messengers."
	$str_5 = "It enables that the program captures messages from WhatsApp, Instagram and other messengers."

condition:
	3 of them
}

rule Android_Banker_SOVA_124029 : knownmalware 
 {
	meta:
		sigid = 124029
		date = "2022-03-02 11:59 AM"
		threatname = "Android.Banker.SOVA"
		category = "Banker"
		risk = 127
		
	strings:
$str1=".GrantAccessibilityActivity"
$str2=".WebViewActivity"
$str3=".GrantIgnoreBatteryOptimizationsActivity"
$str4=".LauncherActivity"
$str5=".GrantAdminActivity"
$str6=".GrantPermissionsActivity"
$str7=".SmsActivity"
$str8=".service.SmsSendService"
$str9=".service.NotificationListener"
$str10=".service.RequestService"
$str11=".service.CBWatcherService"
$str12=".AccessibilityServiceImpl"
$str13=".service.GlobalManagingService"
$str14="secondary-dexes"
$str15="assets/packageList.txt"
condition:
13 of them
}

rule Xploit_Spy_Rat_126127 : knownmalware 
 {
	meta:
		sigid = 126127
		date = "2022-08-08 10:48 AM"
		threatname = "Android.RAT.Bitter"
		category = "RAT"
		risk = 127
		
	strings:
$func0 = "0xAU"
$func1 = "0xCL"
$func2 = "0xCO"
$func3 = "0xFI"
$func4 = "0xGP"
$func5 = "0xIN"
$func6 = "0xLO"
$func7 = "0xMI"
$func8 = "0xPM"
$func9 = "0xSM"
$func10 = "0xWI"
$func11 = "0xCB"
$func12 = "0xNO"
$applist0 = "appName"
$applist1 = "packageName"
$applist2 = "versionName"
$applist3 = "versionCode"
$notif0 = "appName"
$notif1 = "postTime"

condition:
(7 of ($func*) and (all of ($applist*) or all of($notif*)))
}

rule Android_Spyware_Badbazaar_129555 : knownmalware 
 {
	meta:
		sigid = 129555
		date = "2023-09-13 08:28 AM"
		threatname = "Android.Spyware.Badbazaar"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = "org.telegram"
		$str_2 = "/tgmcache/tgdata.rc"
		$str_3 = "uploadfile?imei="
		$str_4 = "&remotefilesize="		
	condition:
		all of them
}

rule Android_Clean_ICICIuat_129568 : knownclean 
 {
	meta:
		sigid = 129568
		date = "2023-09-14 15:20 PM"
		threatname = "Android.Clean.ICICuat"
		category = "Clean"
		risk = -127
		
	strings:
		$str_1 = "com.icicibank."
		$str_2 = "com.icici.icapturenext"
		$str_3 = "com.microsoft.intune.mam.client.service.MAMBackgroundReceiver"
		$str_4 = "android.intent.action.DOWNLOAD_COMPLETE"		
	condition:
		3 of them
}

rule Android_Spyware_IRATA_130127 : knownmalware 
 {
	meta:
		sigid = 130127
		date = "2023-11-06 05:29 AM"
		threatname = "Android.Spyware.IRATA"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "android.permission.SEND_SMS"
	$str_3 = "result=ok&action=nwmessage&messagetext="
	$str_4 = "/web.txt"
	$str_5 = "jobdone"
	$str_6 = "offlinemode.txt"
	$str_7 = "OFFLINE TARGET"

condition:
	all of ($str_*)
}

rule Android_Banker_Coper_130126 : knownmalware 
 {
	meta:
		sigid = 130126
		date = "2023-11-06 05:28 AM"
		threatname = "Android.Banker.Coper"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "android.permission.SEND_SMS"
	$str_3 = "android.app.action.DEVICE_ADMIN_DISABLED"
	$str_4 = "android.app.action.ACTION_PASSWORD_SUCCEEDED"
	$str_5 = "android.app.action.DEVICE_ADMIN_ENABLED"
	$str_6 = "android.intent.action.SCREEN_OFF"
	$str_7 = "android.accessibilityservice.AccessibilityService"
	$str_8 = "android.service.notification.NotificationListenerService"
	$str_9 = "Enable this service to protect your device"
condition:
	all of ($str_*)
}

rule Android_Ransom_SLocker_128037 : knownmalware 
 {
	meta:
		sigid = 128037
		date = "2023-03-31 06:34 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "<uses-sdk android:minSdkVersion=\"14\" android:targetSdkVersion=\"23\"/>"
	$str_2 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_3 = "android.permission.SYSTEM_OVERLAY_WINDOW"
	$str_4 = "android.permission.INTERNAL_SYSTEM_WINDOW"
	$str_5 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_6 = "android.accessibilityservice.category.FEEDBACK_AUDIBLE"
	$str_7 = "android.accessibilityservice.category.FEEDBACK_VISUAL"
	$str_8 = "<meta-data android:name=\"android.max_aspect\" android:value=\"4\"/>"
	$str_9 = "android.permission.BLUETOOTH_ADMIN"
	$str_10 = "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
condition:
	all of ($str_*)
}

rule Android_Spyware_SmsSpy_130113 : knownmalware 
 {
	meta:
		sigid = 130113
		date = "2023-11-02 17:33 PM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str1 = "/main.php?get=sms"
		$str2 = "oncesms.txt"
		$str3 = "@CafeToseeh"
		$str4 = "Private-sms-detected : "
		$str5 = "&messagetext="
		$str6 = "&name="
		$str7 = "&action=sms&network="
		$str8 = "&oncesms="
	condition:
		5 of them
}

rule Android_Backdoor_Basdoor_129516 : knownmalware 
 {
	meta:
		sigid = 129516
		date = "2023-09-09 19:17 PM"
		threatname = "Android.Backdoor.Basdoor"
		category = "Backdoor"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_CONTACTS"
	$str_2 = "android.permission.WAKE_LOCK"
	$str_3 = "android.permission.READ_SMS"
	$str_4 = "result=ok&action=silent&androidid="
	$str_5 = "result=ok&action=hideicon&androidid="
	$str_6 = "allsms.txt"

condition:
	all of ($str_*)
}

rule Android_Trojan_SMSFraudGen_127558 : knownmalware 
 {
	meta:
		sigid = 127558
		date = "2023-06-28 11:04 AM"
		threatname = "Android.Trojan.SMSFraudGen"
		category = "Trojan"
		risk = 127
		
	strings:
	$str1_1 = "android.permission.SEND_SMS"
	$str1_2 = "huycoi"
	$str1_3 = "telpoo"
	$str1_4 = "convert2NetParrams"
	$str1_5 = "dataApi"
	$str1_6 = "SEND_AIS"
	$str1_7 = "https://apkafe.com/what-is-chatgpt"
	$str2_1 = "+4541770"
	$str2_2 = "+4541546"
	$str2_3 = "af63b434-ec50-46a0-9374-d57a383f2e03"


condition:
	5 of ($str1*) and 1 of ($str2*)
}

rule Android_Clean_Teeptrack_129754 : knownclean 
 {
	meta:
		sigid = 129754
		date = "2023-10-05 13:40 PM"
		threatname = "Android.Clean.Teeptrack"
		category = "Clean"
		risk = -127
		
	strings:
		$str_1 = "SHA1:2500FDFE10F85115FDD79A1D09F87B9C85C29268"
		$str_2 = "com.teeptrak.main"
		
	condition:
		all of them
}

rule Android_Spyware_Gen_125986 : knownmalware 
 {
	meta:
		sigid = 125986
		date = "2022-07-15 09:45 AM"
		threatname = "Android.Spyware.Gen"
		category = "Spyware"
		risk = 127
		sample = "5eb3cb08f601caa62cffec3d2defba76"
	strings:
	$str_1 = "&battry="
	$str_2 = "&androidid="
	$str_3 = "result=ok&action=nwmessageencode&messagetext="

condition:
	all of them
}

rule Android_Trojan_Joker_125774 : knownmalware 
 {
	meta:
		sigid = 125774
		date = "2023-09-26 09:43 AM"
		threatname = "Android.Trojan.Joker"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "/hwRQ08cjLxJAXBQlliRKBACDrq9BboodiOGm23/3y3+XsQAcY1b4K0ed0aGIdthOKW6Qjy/sfiXRrEXFnNycQ=="
		$str_2 = "FcFQK3j7A"
		$str_3 = "cYMmluGr8"
		$str_4 = "YYnIROraY"
	condition:
		all of them
}

rule Android_Backdoor_Chinotto_ScarCruft_124756 : knownmalware 
 {
	meta:
		sigid = 124756
		date = "2021-12-02 07:27 AM"
		threatname = "Android.Backdoor.Chinotto"
		category = "Backdoor"
		risk = 127
		
	strings:
$str1="?type=hello&direction=send&id="
$str2="?type=command&direction=receive&id="
$str3="?type=file&direction=send&id="
$str4="/Info.txt"
$str5="/Sms.txt"
$str6="/Calllog.txt"
$str7="/Contact.txt"
$str8="/Account.txt"
condition:
all of them
}

rule Android_Clean_mpmkvvcl_129426 : knownclean 
 {
	meta:
		sigid = 129426
		date = "2023-08-26 08:27 AM"
		threatname = "Android.Clean.mpmkvvcl"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.mpmkvvcl.nishthacollectionagent"
	$str_2 = "com.paytm.pgsdk.PaytmPGActivity"
	$str_3 = "services.mpcz.in"

condition:
	all of ($str_*)
}

rule Android_Ransom_SLocker_128497 : knownmalware 
 {
	meta:
		sigid = 128497
		date = "2023-05-13 08:11 AM"
		threatname = "Android.Ransom.SLocker"
		category = "Ransom"
		risk = 127
		
	strings:
	$str_1 = "android.permission.SYSTEM_ALERT_WINDOW"
	$str_2 = "android.permission.SYSTEM_OVERLAY_WINDOW"
	$str_3 = "FAKE_CAMERA_ROTATE_ANTI_CLOCKWISE"
	$ptr_4 = "AndHook"
	$str_5 = "SandHook"

condition:
	all of ($str_*) and #ptr_4 > 10
}

rule Android_Trojan_CherryBlos_129197 : knownmalware 
 {
	meta:
		sigid = 129197
		date = "2023-07-31 06:41 AM"
		threatname = "Android.Trojan.CherryBlos"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "cherryblos.framework.exception.ReadPictureServices"
		$str_2 = ".cherryblos.YFServer"
		$str_3 = ".cherryblos.SensorRestarterBroadcastReceiver"
		$str_4 = "libjiagu_sdk_cherryBlos"
		$str_5 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
		$str_6 = ".cherryblos.NotifyServer"

	condition:
		5 of them
}

rule Android_Spyware_Spymax_127916 : knownmalware 
 {
	meta:
		sigid = 127916
		date = "2023-03-23 09:44 AM"
		threatname = "Android.Spyware.SpyMax"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_CALL_LOG"
	$str_2 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_3 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_4 = "android:targetSdkVersion=\"25\""
	$str_5 = "package android:name=\"null\""
	$str_6 = "android:label=\"Play Store\""
	$str_7 = "怅态怅怃怅恱怀怊怅态怀怀怀恷怀怊怀怄怀怃怅恲怅怆怅怃怀恰怅恷怀态"

condition:
	all of ($str_*)
}

rule Android_Banker_SmsSpy_127913 : knownmalware 
 {
	meta:
		sigid = 127913
		date = "2023-03-23 09:31 AM"
		threatname = "Android.Banker.Gen"
		category = "Banker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.RECEIVE_SMS"
	$str_2 = "android.permission.READ_SMS"
	$str_3 = "/api/message"
	$str_4 = "/api/phone"
	$str_5 = "android.app.lib_name"
	$str_6 = ".foreground"
	$str_7 = ".smsReceiver"
	$str_8 = "com.miui.permcenter.autostart.AutoStartManagementActivity"

condition:
	all of ($str_*)
}

rule Android_Banker_MoqHao_ELF_125799 : knownmalware 
 {
	meta:
		sigid = 125799
		date = "2022-06-17 07:31 AM"
		threatname = "Android.Banker.MoqHao"
		category = "Banker"
		risk = 127
		
	strings:
$str="lib/armeabi-v7a/libjv.so"
condition:
all of them
}

rule Android_Banker_Zanubis_129736 : knownmalware 
 {
	meta:
		sigid = 129736
		date = "2023-10-05 13:46 PM"
		threatname = "Android.Banker.Zanubis"
		category = "Banker"
		risk = 127
		
	strings:
		$str_1 = ".servicio.SrvToastAccesibilidad"
		$str_2 = ".servicio.SrvAccesibilidad"
		$str_3 = "comando\":\"INICIANDO"
		$str_4 = "comando\": \"BATERIA"
		$str_5 = "PrefGetLinkTarget"
		$str_6 = "bloquear_telefono"
		$str_7 = "AcaSeIniciaLaConexionAlServer"
		$str_8 = "/instalado"

	condition:
		6 of them
}

rule Android_Trojan_APTC23_130101 : knownmalware 
 {
	meta:
		sigid = 130101
		date = "2023-11-02 17:37 PM"
		threatname = "Android.Trojan.APTC23"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "checksAppearPerms"
		$str_2 = "OPEN_AUTO_START"
		$str_3 = "OPEN_HIDE_APP"
		$str_4 = "INSTALL_APP_DONE"
		$str_5 = "OUTGOING_WHATSAPP_CALL"
		$str_6 = "APP_CALL_RECORD_STATUS"
		$str_7 = "encSocketID.enc"
		$str_8 = "system_log.txt"

condition:
		all of them
}

rule Android_Spyware_DonotAPT_125153 : knownmalware 
 {
	meta:
		sigid = 125153
		date = "2022-02-23 05:20 AM"
		threatname = "Adroid.Spyware.Donot"
		category = "Spyware"
		risk = 127
		
	strings:
$comm1="CallLogs.txt"
$comm2="Tree.txt"
$comm3="accounts.txt"
$comm4="bw.txt"
$comm5="Clist.txt"
$comm6="contacts.txt"
$comm7="pkinfo.txt"
$comm8="netinfo.txt"
condition:
6 of ($comm*)
}

rule Android_Trojan_Gen_125803 : knownmalware 
 {
	meta:
		sigid = 125803
		date = "2022-06-21 06:38 AM"
		threatname = "Android.Trojan.Gen"
		category = "Trojan"
		risk = 127
		
	strings:
		$str_1 = "c4483796439e222a529b412ac06e68056c9f4634953f08cdced29e0e8bdde2bf359e0ec1f856f757697b3b1c639ee5d0"
		$str_2 = "536cdf70d539388209398a09cf1c5733"
		$str_3 = "e1bfcd80c4869160a0a16f6f171ad390"
		$str_4 = "8ae0f541587944458c6d38930c873c33b81e307ed67151fe27b01b1baef12e913e59dcc246514e6ae5c0a850922f6f31"

	condition:
		all of them
}

rule Android_Banker_Wroba_124463 : knownmalware 
 {
	meta:
		sigid = 124463
		date = "2021-10-29 11:40 AM"
		threatname = "Android.Banker.Wroba"
		category = "Banker"
		risk = 127
		sample1 = "4d98bfc5bca2b275fa551f750faa8bf3"
sample2 = "68bd9db3d429e3d95548b93a1f1ee8f0"
	strings:
	$str_1 = "ClientPhoneStatus"
	$str_2 = "notifySmsOrCallLog"
	$str_3 = "SmsOrCallLogChanged"

condition:
	all of them
}

rule Android_Trojan_HiddenAd_126268 : knownmalware 
 {
	meta:
		sigid = 126268
		date = "2022-09-12 10:12 AM"
		threatname = "Android.Trojan.HiddenAd"
		category = "Trojan"
		risk = 127
		
	strings:
	$str_1 = "TBU7Qg4BGhYwDBcA"
	$str_2 = "TBU7QhYXEwcrDBE"
	$str_3 = "TBIqAwZLABsxC0oSUA"
	$api_4 = "GET_DA_VINCI_AD"
	$api_5 = "GET_FUNCTION_CONFIG"
	$api_6 = "GET_ADVERTISE_CONFIG"

condition:
	all of ($str_*) or all of ($api_*)
}

rule Android_Banker_Cerberus_123796 : knownmalware 
 {
	meta:
		sigid = 123796
		date = "2021-08-12 10:12 AM"
		threatname = "Android.Banker.Cerberus"
		category = "Banker"
		risk = 127
		
	strings:
$a1="app_inject"
$a2="device_policy"
$a3="android.settings.ACCESSIBILITY_SETTINGS"
$a4="enabled_accessibility_services"
$a5="HideInject"
$a6="inj_start"
$a7="old_start_inj"
 condition:
all of them
}

rule Android_Banker_Gigabud_127909 : knownmalware 
 {
	meta:
		sigid = 127909
		date = "2023-03-23 09:06 AM"
		threatname = "Android.Bnaker.Gigabud"
		category = "Bnaker"
		risk = 127
		
	strings:
	$str_1 = "android.permission.REQUEST_INSTALL_PACKAGES"
	$str_2 = "android.permission.RECORD_AUDIO"
	$str_3 = "android.permission.SEND_SMS"
	$str_4 = "(Ministry of Commerce)"
	$mtr_5 = "junk_"

condition:
	(all of ($str_*)) and (#mtr_5 > 15)
}

rule Android_Dropper_SecuriDropper_130153 : knownmalware 
 {
	meta:
		sigid = 130153
		date = "2023-11-07 10:56 AM"
		threatname = "Android.Dropper.SecuriDropper"
		category = "Dropper"
		risk = 127
		
	strings:
		$str_0 = "com.appd.instll.load.action.RootlessSaiPiBroadcastReceiver"
		$str_1 = "RootlessSaiPi Worker"
		$str_2 = "requestInstallPermission"
		$str_3 = "setInstallLocation"
		$str_4 = "setInstallReason"

condition:
		all of them
}

rule Android_Clean_Airwatch_130129 : knownclean 
 {
	meta:
		sigid = 130129
		date = "2023-11-06 05:30 AM"
		threatname = "Android.Clean.Airwatch"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.airwatch.rm.agent.cloud"
	$str_2 = "com.aetherpal.core.interfaces.Toast"
	$str_3 = "com.aetherpal.device.events.PackageUpdatedReceiver"

condition:
	all of ($str_*)
}

rule Android_Clean_ZebraTech_129544 : knownclean 
 {
	meta:
		sigid = 129544
		date = "2023-09-12 09:04 AM"
		threatname = "Android.Clean.ZebraTech"
		category = "Clean"
		risk = -127
		
	strings:
		$str_1 = "SHA1:D91380AE9C9CD3AB429C367BE4801085887EC289"
		$str_2 = "com.symbol.enterprisebrowser"
		
	condition:
		all of them
}

rule Android_Worm_GoodNews_124565 : knownmalware 
 {
	meta:
		sigid = 124565
		date = "2021-11-12 11:18 AM"
		threatname = "Android.Worm.GoodNews"
		category = "Worm"
		risk = 127
		sample1 = "fd40817334a6ca3e472166ffdfd6bdb4"
sample2 = "0b13252561a62277faeae97cc22dcddc"
	strings:
	$str_1 = "Share this APP on Whatsapp groups 10 Times."
	$str_2 = "Congratulations!! You are just one step ahead to"
	$str_3 = "Click on Ad and install app to"
	$str_4 = "qazxsw0123456789"
	$str_5 = "9876543210wsxzaq"

condition:
	3 of them
}

rule Android_Spyware_Spynote_129897 : knownmalware 
 {
	meta:
		sigid = 129897
		date = "2023-10-17 09:25 AM"
		threatname = "Android.Spyware.Spynote"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.BIND_DEVICE_ADMIN"
	$str_2 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
	$str_3 = "android.permission.BIND_VPN_SERVICE"
	$str_4 = "android.permission.READ_SMS"
	$str_5 = "android.permission.RECORD_AUDIO"
	$str_6 = "smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard"
	$str_7 = ".xyz\"/>"

condition:
	all of ($str_*)
}

rule Android_Backdoor_PreloadAMZ_127182 : knownmalware 
 {
	meta:
		sigid = 127182
		date = "2023-01-19 13:19 PM"
		threatname = "Android.Backdoor.PreloadAMZ"
		category = "Backdoor"
		risk = 127
		
	strings:
	$str_1 = "797292445CD83E009F85DB1F3242922D"
	$str_2 = "SDK_SHARE_DATA"
	$str_3 = "key_cnz_loop"
	$str_4 = "key_st_date"
	$str_5 = "MainWorker"

condition:
	all of ($str_*)
}

rule Android_spyware_SmsSpy_130294 : knownmalware 
 {
	meta:
		sigid = 130294
		date = "2023-11-22 08:39 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
	$str_1 = "android.permission.READ_SMS"
	$str_2 = "android.permission.RECEIVE_SMS"
	$str_3 = "b4a_internal_intent"
	$str_4 = "offlinemode2.txt"
	$str_5 = "/log.php"
	$str_6 = "result=ok&action=nwmessage&messagetext="
	$str_7 = "result=ok&action=install&androidid="

condition:
	6 of ($str_*)
}

rule Android_Spyware_SmsSpy_130293 : knownmalware 
 {
	meta:
		sigid = 130293
		date = "2023-11-22 08:38 AM"
		threatname = "Android.Spyware.SmsSpy"
		category = "Spyware"
		risk = 127
		
	strings:
		$str_1 = ".ReceiveSms"
		$str_2 = ".startupOnBootUpReceiver"
		$str_3 = "loadUrl"
		$str_4 = "android.permission.SEND_SMS"
		$recv = "<receiver "
		$serv = "<service "
		$perm = "<uses-permission "

	condition:
		#perm == 5 and #recv == 2 and #serv == 2 and all of ($str_*)
}

rule Android_Clean_BGuard_130249 : knownclean 
 {
	meta:
		sigid = 130249
		date = "2023-11-20 10:42 AM"
		threatname = "Android.Clean.BGuard"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.bosch.app.guardme"
	$str_2 = "de.isatelematics.lwpa.receivers.AdminReceiver"

condition:
	all of ($str_*)
}

rule Android_Clean_Ibiz_130248 : knownclean 
 {
	meta:
		sigid = 130248
		date = "2023-11-20 10:42 AM"
		threatname = "Android.Clean.Ibiz"
		category = "Clean"
		risk = -127
		
	strings:
	$str_1 = "com.icicibank.ibizukcug"
	$str_2 = "com.icicibank.ibizukcug.IncomingSMS"

condition:
	all of ($str_*)
}

