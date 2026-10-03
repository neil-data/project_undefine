/*
    Predatory instant-loan apps ("loan app scams")
    ----------------------------------------------
    The fraud is not the loan. The app disburses a small amount, then uses the
    contact list and photo gallery it harvested at install time to threaten the
    borrower's family, employer and colleagues until an inflated "settlement"
    is paid. Several documented suicides in India trace directly to this.

    What separates it from a legitimate lender's app is the combination:
    lending vocabulary, bulk contact and gallery access, and an upload
    endpoint — a real NBFC app does not need every contact on the phone to
    assess a 5,000-rupee loan.

    Manifest strings live in a binary XML string pool as UTF-16, so permission
    and component names are matched `wide` as well as `ascii`.
*/

rule IN_LoanApp_Contact_Harvesting
{
    meta:
        description = "Instant-loan app harvesting the full contact list — the extortion precondition"
        severity = "high"
        confidence = "medium"
        family = "loan_app_scam"
        category = "india_scam"
        mitre = "T1636.003"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $lending1 = "instant loan" ascii wide nocase
        $lending2 = "quick cash" ascii wide nocase
        $lending3 = "loan approval" ascii wide nocase
        $lending4 = "emi" ascii wide nocase fullword
        $lending5 = "disbursal" ascii wide nocase
        $lending6 = "repayment" ascii wide nocase
        $lending7 = "creditline" ascii wide nocase
        $lending8 = "borrower" ascii wide nocase

        $contacts1 = "android.permission.READ_CONTACTS" ascii wide
        $contacts2 = "content://com.android.contacts" ascii wide
        $contacts3 = "ContactsContract" ascii wide

        $upload1 = "uploadContacts" ascii wide nocase
        $upload2 = "contact_list" ascii wide nocase
        $upload3 = "syncContacts" ascii wide nocase
        $upload4 = "/api/contacts" ascii wide nocase
        $upload5 = "phonebook" ascii wide nocase

    condition:
        2 of ($lending*) and any of ($contacts*) and any of ($upload*)
}

rule IN_LoanApp_Extortion_Payload
{
    meta:
        description = "Loan app carrying the harassment stage: gallery, SMS and threat messaging"
        severity = "critical"
        confidence = "high"
        family = "loan_app_scam"
        category = "india_scam"
        mitre = "T1636.003,T1582,T1636.004"
        platform = "android"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $lending1 = "instant loan" ascii wide nocase
        $lending2 = "loan app" ascii wide nocase
        $lending3 = "disbursal" ascii wide nocase
        $lending4 = "repayment" ascii wide nocase
        $lending5 = "creditline" ascii wide nocase

        /* Collection surface far beyond what a credit decision needs */
        $grab1 = "android.permission.READ_CONTACTS" ascii wide
        $grab2 = "android.permission.READ_SMS" ascii wide
        $grab3 = "android.permission.READ_EXTERNAL_STORAGE" ascii wide
        $grab4 = "android.permission.READ_CALL_LOG" ascii wide
        $grab5 = "MediaStore.Images" ascii wide

        /* The harassment stage itself */
        $threat1 = "defaulter" ascii wide nocase
        $threat2 = "legal notice" ascii wide nocase
        $threat3 = "your contacts will be informed" ascii wide nocase
        $threat4 = "sendToAllContacts" ascii wide nocase
        $threat5 = "bulk_sms" ascii wide nocase

    condition:
        any of ($lending*) and 3 of ($grab*) and any of ($threat*)
}
