/*
    Fake e-Challan / RTO / Parivahan apps
    ------------------------------------
    Delivered by SMS: "Your vehicle DL8CAB1234 has a pending challan, pay via
    this app." The APK imitates the government mParivahan / e-Challan app,
    collects the payment, and — the part that actually matters — installs an
    SMS interceptor so the bank OTP for the "payment" never reaches the owner.

    The tell is imitation without provenance: government vocabulary and
    branding, a payment flow, and SMS interception, in a package that is not
    signed by or served from a `.gov.in` origin.
*/

rule IN_Fake_EChallan_App
{
    meta:
        description = "Application imitating the government e-Challan / Parivahan service"
        severity = "high"
        confidence = "medium"
        family = "echallan_scam"
        category = "india_scam"
        mitre = "T1660,T1636.004"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $gov1 = "echallan" ascii wide nocase
        $gov2 = "e-challan" ascii wide nocase
        $gov3 = "parivahan" ascii wide nocase
        $gov4 = "mparivahan" ascii wide nocase
        $gov5 = "vahan" ascii wide nocase fullword
        $gov6 = "sarathi" ascii wide nocase
        $gov7 = "traffic police" ascii wide nocase
        $gov8 = "rto office" ascii wide nocase
        $gov9 = "challan number" ascii wide nocase

        $pay1 = "upi://pay" ascii wide nocase
        $pay2 = "razorpay" ascii wide nocase
        $pay3 = "payment_gateway" ascii wide nocase
        $pay4 = "pay now" ascii wide nocase
        $pay5 = "fine amount" ascii wide nocase

        /* A genuine government app is served from a gov.in origin */
        $legit1 = "parivahan.gov.in" ascii wide nocase
        $legit2 = "echallan.parivahan.gov.in" ascii wide nocase

    condition:
        2 of ($gov*) and any of ($pay*) and not any of ($legit*)
}

rule IN_EChallan_OTP_Interceptor
{
    meta:
        description = "Fake challan app that also intercepts the bank OTP for the payment it triggers"
        severity = "critical"
        confidence = "high"
        family = "echallan_scam"
        category = "india_scam"
        mitre = "T1636.004,T1582,T1660"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $gov1 = "echallan" ascii wide nocase
        $gov2 = "parivahan" ascii wide nocase
        $gov3 = "challan" ascii wide nocase
        $gov4 = "rto" ascii wide nocase fullword

        $sms1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $sms2 = "android.permission.RECEIVE_SMS" ascii wide
        $sms3 = "android.permission.READ_SMS" ascii wide
        $sms4 = "content://sms" ascii wide

        $fwd1 = "sendTextMessage" ascii wide
        $fwd2 = "forwardSms" ascii wide nocase
        $fwd3 = "otp" ascii wide nocase fullword
        $fwd4 = "abortBroadcast" ascii wide

    condition:
        any of ($gov*) and 2 of ($sms*) and 2 of ($fwd*)
}
