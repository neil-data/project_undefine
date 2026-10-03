/*
    Command-and-control and exfiltration infrastructure
    ---------------------------------------------------
    Platform-independent: a Telegram bot token is equally damning in an APK, a
    PE and an ELF. These rules describe the operator's *plumbing*, which is
    often the only part of a sample that ties several cases to one actor.
*/

rule C2_Telegram_Bot_Channel
{
    meta:
        description = "Telegram bot API used as the command-and-control channel"
        severity = "high"
        confidence = "high"
        family = "c2"
        category = "infrastructure"
        mitre = "T1102,T1071.001"
        platform = "any"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $api1 = "api.telegram.org" ascii wide nocase
        $api2 = "/bot" ascii wide
        $method1 = "sendMessage" ascii wide
        $method2 = "sendDocument" ascii wide
        $method3 = "getUpdates" ascii wide
        $method4 = "chat_id" ascii wide

        /* bot<digits>:<35-char token> — a live credential, not just a mention */
        $token = /[0-9]{8,10}:[A-Za-z0-9_-]{35}/ ascii wide

    condition:
        ($api1 and any of ($method*)) or ($token and ($api1 or $api2))
}

rule C2_Discord_Webhook
{
    meta:
        description = "Discord webhook used for exfiltration or tasking"
        severity = "high"
        confidence = "high"
        family = "c2"
        category = "infrastructure"
        mitre = "T1102,T1567"
        platform = "any"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $webhook = /https:\/\/discord(app)?\.com\/api\/webhooks\/[0-9]{15,25}\/[A-Za-z0-9_-]{60,80}/ ascii wide

    condition:
        $webhook
}

rule C2_Tor_Hidden_Service
{
    meta:
        description = "Contacts a Tor hidden service — a destination chosen to be untraceable"
        severity = "high"
        confidence = "medium"
        family = "c2"
        category = "infrastructure"
        mitre = "T1090.003"
        platform = "any"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $onion_v3 = /[a-z2-7]{56}\.onion/ ascii wide
        $onion_v2 = /[a-z2-7]{16}\.onion/ ascii wide
        $tor1 = "socks5" ascii wide nocase
        $tor2 = "127.0.0.1:9050" ascii wide
        $tor3 = "torproject" ascii wide nocase

    condition:
        any of ($onion*) or 2 of ($tor*)
}

rule Exfil_Dynamic_DNS_Endpoint
{
    meta:
        description = "Hardcoded dynamic-DNS hostname — cheap, disposable C2 infrastructure"
        severity = "medium"
        confidence = "medium"
        family = "c2"
        category = "infrastructure"
        mitre = "T1071.001"
        platform = "any"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $ddns1 = ".duckdns.org" ascii wide nocase
        $ddns2 = ".no-ip.org" ascii wide nocase
        $ddns3 = ".no-ip.biz" ascii wide nocase
        $ddns4 = ".ddns.net" ascii wide nocase
        $ddns5 = ".hopto.org" ascii wide nocase
        $ddns6 = ".serveo.net" ascii wide nocase
        $ddns7 = ".ngrok.io" ascii wide nocase
        $ddns8 = ".trycloudflare.com" ascii wide nocase
        $ddns9 = ".portmap.io" ascii wide nocase

    condition:
        any of them
}

rule Exfil_Paste_And_Shortener_Staging
{
    meta:
        description = "Retrieves configuration from a paste site or URL shortener"
        severity = "medium"
        confidence = "low"
        family = "loader"
        category = "infrastructure"
        mitre = "T1102.001"
        platform = "any"
        author = "SentinelScan / Team HackersAPK"
        date = "2026-01-15"

    strings:
        $paste1 = "pastebin.com/raw" ascii wide nocase
        $paste2 = "hastebin.com/raw" ascii wide nocase
        $paste3 = "ghostbin.co" ascii wide nocase
        $paste4 = "paste.ee" ascii wide nocase
        $short1 = "bit.ly/" ascii wide nocase
        $short2 = "tinyurl.com/" ascii wide nocase
        $short3 = "is.gd/" ascii wide nocase
        $short4 = "cutt.ly/" ascii wide nocase
        $short5 = "rebrand.ly/" ascii wide nocase

    condition:
        any of ($paste*) or 2 of ($short*)
}
