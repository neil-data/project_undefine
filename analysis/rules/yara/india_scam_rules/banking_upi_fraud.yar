/*
    UPI and banking fraud
    ---------------------
    Two distinct techniques, both built on the same infrastructure:

    1. Collect-request abuse — the victim is told to "accept the refund", but
       a UPI *collect* request debits rather than credits. The app pre-fills
       the payee and amount so the victim only has to enter their PIN.

    2. OTP interception against Indian banks — the SMS layer is the second
       factor for almost every Indian bank, so reading and forwarding the
       inbox is equivalent to holding the second factor.

    A hardcoded payee VPA in a sample is a directly actionable indicator:
    unlike a C2 domain, it maps to a real bank account through the NPCI.
*/

rule IN_UPI_Collect_Request_Abuse
{
    meta:
        description = "Hardcoded UPI payee with collect-request flow — 'refund' that debits the victim"
        severity = "high"
        confidence = "medium"
        family = "upi_fraud"
        category = "india_scam"
        mitre = "T1660"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $upi_uri = "upi://pay" ascii wide nocase
        $upi_mandate = "upi://mandate" ascii wide nocase
        $collect = "collect_request" ascii wide nocase

        /* Hardcoded payee handles — the money's destination */
        $vpa1 = "@okhdfcbank" ascii wide nocase
        $vpa2 = "@okicici" ascii wide nocase
        $vpa3 = "@okaxis" ascii wide nocase
        $vpa4 = "@oksbi" ascii wide nocase
        $vpa5 = "@paytm" ascii wide nocase
        $vpa6 = "@ybl" ascii wide nocase
        $vpa7 = "@upi" ascii wide nocase

        $param1 = "pa=" ascii wide
        $param2 = "&am=" ascii wide
        $param3 = "&tn=" ascii wide

        $refund1 = "refund" ascii wide nocase
        $refund2 = "cashback" ascii wide nocase
        $refund3 = "reward" ascii wide nocase

    condition:
        ($upi_uri or $upi_mandate or $collect)
        and any of ($vpa*)
        and (2 of ($param*) or any of ($refund*))
}

rule IN_Bank_OTP_Interception
{
    meta:
        description = "SMS interception targeting Indian bank sender IDs — defeats the second factor"
        severity = "critical"
        confidence = "high"
        family = "otp_theft"
        category = "india_scam"
        mitre = "T1636.004,T1582"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        /* Bank/DLT sender IDs seen in Indian transactional SMS */
        $sender1 = "HDFCBK" ascii wide nocase
        $sender2 = "ICICIB" ascii wide nocase
        $sender3 = "SBIINB" ascii wide nocase
        $sender4 = "AXISBK" ascii wide nocase
        $sender5 = "KOTAKB" ascii wide nocase
        $sender6 = "PNBSMS" ascii wide nocase
        $sender7 = "CANBNK" ascii wide nocase
        $sender8 = "BOIIND" ascii wide nocase
        $sender9 = "UNIONB" ascii wide nocase
        $sender10 = "PAYTMB" ascii wide nocase

        $otp1 = "otp" ascii wide nocase fullword
        $otp2 = "one time password" ascii wide nocase
        $otp3 = "verification code" ascii wide nocase
        $otp4 = "do not share" ascii wide nocase

        $intercept1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $intercept2 = "abortBroadcast" ascii wide
        $intercept3 = "content://sms/inbox" ascii wide
        $intercept4 = "sendTextMessage" ascii wide

    condition:
        any of ($sender*) and any of ($otp*) and any of ($intercept*)
}

rule IN_Fake_KYC_Update
{
    meta:
        description = "Fake KYC / account-reactivation app harvesting identity documents"
        severity = "high"
        confidence = "medium"
        family = "kyc_fraud"
        category = "india_scam"
        mitre = "T1660,T1636"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $kyc1 = "kyc update" ascii wide nocase
        $kyc2 = "kyc verification" ascii wide nocase
        $kyc3 = "account will be blocked" ascii wide nocase
        $kyc4 = "re-kyc" ascii wide nocase
        $kyc5 = "video kyc" ascii wide nocase

        $id1 = "aadhaar" ascii wide nocase
        $id2 = "aadhar" ascii wide nocase
        $id3 = "pan card" ascii wide nocase
        $id4 = "pan number" ascii wide nocase
        $id5 = "voter id" ascii wide nocase

        $harvest1 = "android.permission.CAMERA" ascii wide
        $harvest2 = "debit card" ascii wide nocase
        $harvest3 = "cvv" ascii wide nocase
        $harvest4 = "atm pin" ascii wide nocase
        $harvest5 = "net banking" ascii wide nocase

    condition:
        any of ($kyc*) and any of ($id*) and 2 of ($harvest*)
}
