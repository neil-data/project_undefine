/*
    Light-bill / electricity disconnection scam
    -------------------------------------------
    Delivered by SMS impersonating the state distribution company: "Dear
    customer, your electricity will be disconnected tonight at 9:30 PM as your
    previous bill was not updated. Contact our officer." The victim is walked
    through installing a "bill payment app" — in practice a remote-access tool
    or an SMS interceptor — and pays a small "verification" amount that exposes
    their banking credentials.

    The vocabulary is regional and specific: every state has its own DISCOM,
    and the message templates reuse the same disconnection language.
*/

rule IN_Electricity_Bill_Scam_App
{
    meta:
        description = "App built around the electricity-disconnection ('light bill') scam script"
        severity = "high"
        confidence = "medium"
        family = "light_bill_scam"
        category = "india_scam"
        mitre = "T1660,T1636.004"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        /* State distribution companies */
        $discom1 = "MSEDCL" ascii wide nocase
        $discom2 = "MSEB" ascii wide nocase
        $discom3 = "BSES" ascii wide nocase
        $discom4 = "TNEB" ascii wide nocase
        $discom5 = "UPPCL" ascii wide nocase
        $discom6 = "PSPCL" ascii wide nocase
        $discom7 = "TSSPDCL" ascii wide nocase
        $discom8 = "APEPDCL" ascii wide nocase
        $discom9 = "CESC" ascii wide nocase
        $discom10 = "JBVNL" ascii wide nocase
        $discom11 = "PVVNL" ascii wide nocase
        $discom12 = "electricity board" ascii wide nocase

        /* The script itself */
        $script1 = "electricity will be disconnected" ascii wide nocase
        $script2 = "power will be disconnected" ascii wide nocase
        $script3 = "previous month bill was not updated" ascii wide nocase
        $script4 = "bijli bill" ascii wide nocase
        $script5 = "light bill" ascii wide nocase
        $script6 = "meter reading" ascii wide nocase
        $script7 = "bill payment" ascii wide nocase
        $script8 = "consumer number" ascii wide nocase

        $pay1 = "upi://pay" ascii wide nocase
        $pay2 = "payment" ascii wide nocase
        $pay3 = "pay bill" ascii wide nocase

    condition:
        any of ($discom*) and 2 of ($script*) and any of ($pay*)
}

rule IN_Electricity_Scam_With_Remote_Access
{
    meta:
        description = "Light-bill scam package bundling remote access or screen sharing"
        severity = "critical"
        confidence = "high"
        family = "light_bill_scam"
        category = "india_scam"
        mitre = "T1660,T1417.001,T1513"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $script1 = "electricity" ascii wide nocase
        $script2 = "bijli" ascii wide nocase
        $script3 = "light bill" ascii wide nocase
        $script4 = "disconnect" ascii wide nocase

        /* The "helpful officer" needs to see your screen */
        $rat1 = "MediaProjection" ascii wide
        $rat2 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
        $rat3 = "quicksupport" ascii wide nocase
        $rat4 = "anydesk" ascii wide nocase
        $rat5 = "teamviewer" ascii wide nocase
        $rat6 = "screen_share" ascii wide nocase
        $rat7 = "createScreenCaptureIntent" ascii wide

    condition:
        2 of ($script*) and any of ($rat*)
}
