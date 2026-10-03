/*
    Android capability rules
    ------------------------
    These describe what an app *can* do, established statically. A capability
    is not a verdict — an accessibility service is how a screen reader works —
    so severities here stay proportionate and the confirmation comes from the
    dynamic sandbox, where the hook engine sees whether the capability is
    actually exercised.
*/

rule Android_Accessibility_Service_Abuse
{
    meta:
        description = "Declares an accessibility service — can read and act on every other app's screen"
        severity = "high"
        confidence = "medium"
        family = "banking_trojan"
        category = "capability"
        mitre = "T1417.001,T1516"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $bind = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
        $service = "android.accessibilityservice.AccessibilityService" ascii wide
        $config = "accessibilityservice" ascii wide nocase

        $act1 = "performGlobalAction" ascii wide
        $act2 = "ACTION_CLICK" ascii wide
        $act3 = "findAccessibilityNodeInfosByText" ascii wide
        $act4 = "findAccessibilityNodeInfosByViewId" ascii wide
        $act5 = "getRootInActiveWindow" ascii wide

        $target1 = "TYPE_VIEW_TEXT_CHANGED" ascii wide
        $target2 = "TYPE_WINDOW_STATE_CHANGED" ascii wide

    condition:
        ($bind or $service or $config) and (2 of ($act*) or any of ($target*))
}

rule Android_Overlay_Attack
{
    meta:
        description = "Can draw over other applications — the banking-overlay precondition"
        severity = "high"
        confidence = "medium"
        family = "banking_trojan"
        category = "capability"
        mitre = "T1417.002,T1516"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $perm = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
        $type1 = "TYPE_APPLICATION_OVERLAY" ascii wide
        $type2 = "TYPE_SYSTEM_ALERT" ascii wide
        $api1 = "addView" ascii wide
        $api2 = "WindowManager$LayoutParams" ascii wide
        $api3 = "canDrawOverlays" ascii wide

        /* Knowing which app is in front is what makes an overlay targeted */
        $watch1 = "getRunningTasks" ascii wide
        $watch2 = "getRunningAppProcesses" ascii wide
        $watch3 = "UsageStatsManager" ascii wide
        $watch4 = "TYPE_WINDOW_STATE_CHANGED" ascii wide

    condition:
        ($perm or any of ($type*)) and any of ($api*) and any of ($watch*)
}

rule Android_SMS_Interception
{
    meta:
        description = "Reads or intercepts incoming SMS and can send messages silently"
        severity = "high"
        confidence = "high"
        family = "sms_stealer"
        category = "capability"
        mitre = "T1636.004,T1582"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $recv1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $recv2 = "android.permission.RECEIVE_SMS" ascii wide
        $read1 = "android.permission.READ_SMS" ascii wide
        $read2 = "content://sms" ascii wide
        $send1 = "android.permission.SEND_SMS" ascii wide
        $send2 = "sendTextMessage" ascii wide
        $send3 = "sendMultipartTextMessage" ascii wide

        /* Suppressing the notification is what makes it interception */
        $hide = "abortBroadcast" ascii wide

    condition:
        (any of ($recv*) or any of ($read*)) and (any of ($send*) or $hide)
}

rule Android_Runtime_Dex_Loading
{
    meta:
        description = "Loads executable code at runtime that was not in the scanned package"
        severity = "high"
        confidence = "high"
        family = "dropper"
        category = "capability"
        mitre = "T1407,T1027"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $loader1 = "dalvik.system.DexClassLoader" ascii wide
        $loader2 = "dalvik.system.PathClassLoader" ascii wide
        $loader3 = "dalvik.system.InMemoryDexClassLoader" ascii wide
        $loader4 = "dalvik.system.BaseDexClassLoader" ascii wide

        $crypto1 = "javax.crypto.Cipher" ascii wide
        $crypto2 = "AES/CBC/PKCS5Padding" ascii wide
        $crypto3 = "javax.crypto.spec.SecretKeySpec" ascii wide

        $assets = "getAssets" ascii wide
        $install = "application/vnd.android.package-archive" ascii wide

    condition:
        any of ($loader*) and (any of ($crypto*) or $assets or $install)
}

rule Android_Device_Admin_Persistence
{
    meta:
        description = "Requests device-administrator rights — resists uninstall, can wipe or lock the device"
        severity = "high"
        confidence = "high"
        family = "persistence"
        category = "capability"
        mitre = "T1626.001,T1629.002"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $admin1 = "android.app.action.ADD_DEVICE_ADMIN" ascii wide
        $admin2 = "android.permission.BIND_DEVICE_ADMIN" ascii wide
        $admin3 = "DeviceAdminReceiver" ascii wide
        $admin4 = "DevicePolicyManager" ascii wide

        $power1 = "lockNow" ascii wide
        $power2 = "wipeData" ascii wide
        $power3 = "resetPassword" ascii wide
        $power4 = "setMaximumFailedPasswordsForWipe" ascii wide

    condition:
        2 of ($admin*) and any of ($power*)
}
