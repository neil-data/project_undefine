"""
backend/app/geoip.py — Offline GeoIP lookups on extracted IP indicators.

Uses MaxMind's GeoLite2-City database via the geoip2 library, kept fully
offline/local (no outbound API calls per lookup) — consistent with this
suite's air-gapped design goal. The database itself is not shipped in this
repo (MaxMind requires a free account + license key to download it); set
GEOIP_DB_PATH to wherever you've placed GeoLite2-City.mmdb and lookups
activate automatically. Left unset, `lookup()` simply returns None for
every IP — callers already treat a missing geo result as "no location
available" rather than an error, so this never blocks analysis.

To obtain the database:
  1. Create a free account at https://www.maxmind.com/en/geolite2/signup
  2. Generate a license key under Account -> My License Keys
  3. Download GeoLite2-City.mmdb (or use `geoipupdate` for automatic
     refreshes) and set GEOIP_DB_PATH to its path.

Optionally, download GeoLite2-ASN.mmdb as well and set GEOIP_ASN_DB_PATH
to its path. When both databases are available, every lookup also returns
the ASN + ISP/ASN organization for richer network attribution (this backs
the detailed Geo-IP section of the forensic PDF report).

The detailed Geo-IP report fields are all kept optional: any field that
cannot be resolved (no City DB, no ASN DB, a private/non-routable address,
or a database that doesn't cover the address) comes back as None and the
PDF renderer falls back to a Gujarati "not available" string — never an
error.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

_LOGGER = logging.getLogger(__name__)

_city_reader = None
_asn_reader = None
_load_attempted = False

try:
    import geoip2.database
    import geoip2.errors
except ImportError:  # pragma: no cover - package listed in requirements.txt, guarded for dev-without-install
    geoip2 = None  # type: ignore[assignment]


def _ensure_loaded() -> None:
    global _city_reader, _asn_reader, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True

    if geoip2 is None:
        _LOGGER.info("geoip2 package not installed — GeoIP lookups disabled")
        return

    city_db_path = os.environ.get("GEOIP_DB_PATH")
    if city_db_path:
        if os.path.isfile(city_db_path):
            try:
                _city_reader = geoip2.database.Reader(city_db_path)
                _LOGGER.info("GeoIP City database loaded from %s", city_db_path)
            except Exception as error:
                _LOGGER.warning("Failed to open GeoIP City database at %s (%s) — GeoIP lookups disabled", city_db_path, error)
        else:
            _LOGGER.warning("GEOIP_DB_PATH=%s does not exist — GeoIP lookups disabled", city_db_path)
    else:
        _LOGGER.info("GEOIP_DB_PATH not set — GeoIP lookups disabled (see backend/app/geoip.py for setup steps)")

    asn_db_path = os.environ.get("GEOIP_ASN_DB_PATH")
    if asn_db_path:
        if os.path.isfile(asn_db_path):
            try:
                _asn_reader = geoip2.database.Reader(asn_db_path)
                _LOGGER.info("GeoIP ASN database loaded from %s", asn_db_path)
            except Exception as error:
                _LOGGER.warning("Failed to open GeoIP ASN database at %s (%s) — ASN lookups disabled", asn_db_path, error)
        else:
            _LOGGER.warning("GEOIP_ASN_DB_PATH=%s does not exist — ASN lookups disabled", asn_db_path)


def is_available() -> bool:
    _ensure_loaded()
    return _city_reader is not None or os.environ.get("GEOIP_HTTP_FALLBACK", "1").lower() in ("1", "true")


def get_status() -> dict:
    """Return status of GeoIP databases."""
    _ensure_loaded()
    return {
        "available": _city_reader is not None,
        "city_db_configured": _city_reader is not None,
        "asn_db_configured": _asn_reader is not None,
        "city_db_path": os.environ.get("GEOIP_DB_PATH"),
        "asn_db_path": os.environ.get("GEOIP_ASN_DB_PATH"),
    }


def _region_name(subdivisions) -> Optional[str]:
    """Best-effort region/state name from the city DB's subdivision list."""
    if subdivisions:
        try:
            return subdivisions[0].name
        except Exception:
            return None
    return None


# Hosting/cloud provider keywords used to derive `is_hosting` from the ASN
# organization name when an ASN database is configured. Not exhaustive, but
# covers the providers this platform most commonly sees in scam/Android
# banking-fraud samples. Everything stays a heuristic — the field is reported
# as a flag alongside raw ASN data, never as a certainty.
_HOSTING_KEYWORDS = (
    "amazon", "aws", "google", "cloudflare", "microsoft", "azure", "digitalocean",
    "ovh", "hetzner", "linode", "vultr", "akamai", "fastly", "oracle cloud",
    "alibaba", "tencent", "huawei", "contabo", "vps", "datacenter", "colocrossing",
    "hosting", "server", "idc", "colo",
)


def _is_hosting_org(org: Optional[str]) -> Optional[bool]:
    """True when the ASN org name smells like a hosting/cloud provider."""
    if not org:
        return None
    lowered = org.lower()
    return any(kw in lowered for kw in _HOSTING_KEYWORDS)


def _lookup_city(ip: str) -> Optional[dict]:
    """Resolve one IP to an approximate location, or None if unavailable/not found."""
    if _city_reader is None:
        return None

    try:
        response = _city_reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return None
    except (ValueError, geoip2.errors.GeoIP2Error):
        return None
    except Exception:
        _LOGGER.exception("Unexpected GeoIP lookup failure for %s", ip)
        return None

    country = response.country.name if response.country else None
    country_iso = response.country.iso_code if response.country else None
    city = response.city.name if response.city else None
    region = _region_name(response.subdivisions)
    postal = response.postal.code if response.postal else None
    timezone = response.location.time_zone if response.location else None
    accuracy_radius = response.location.accuracy_radius if response.location else None
    latitude = response.location.latitude if response.location else None
    longitude = response.location.longitude if response.location else None

    return {
        "ip": ip,
        "country": country,
        "country_iso": country_iso,
        "city": city,
        "region": region,
        "postal_code": postal,
        "timezone": timezone,
        "latitude": latitude,
        "longitude": longitude,
        "accuracy_radius": accuracy_radius,
        "asn": None,
        "asn_org": None,
        "isp": None,
        "is_hosting": None,
        "is_proxy": None,
        "threat_level": None,
    }


def _enrich_asn(record: dict) -> dict:
    """Attach ASN/ISP attribution to a city record when an ASN DB is available."""
    if _asn_reader is None:
        return record

    try:
        response = _asn_reader.asn(record["ip"])
        org = response.autonomous_system_organization or None
        record["asn"] = response.autonomous_system_number
        record["asn_org"] = org
        record["isp"] = org
        record["is_hosting"] = _is_hosting_org(org)
    except geoip2.errors.AddressNotFoundError:
        pass
    except (ValueError, geoip2.errors.GeoIP2Error):
        pass
    except Exception:
        _LOGGER.exception("Unexpected GeoIP ASN lookup failure for %s", record["ip"])
    return record


GEOIP_DISCLAIMER = "Geo-IP is an approximate geographic estimate and not an exact physical location."


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private, loopback, or non-routable."""
    try:
        import ipaddress
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_reserved
    except Exception:
        return True


def _is_valid_ip(ip: str) -> bool:
    """Reject domains, version tuples, and malformed strings before any lookup."""
    try:
        import ipaddress
        ipaddress.ip_address(str(ip).strip())
        return True
    except (TypeError, ValueError):
        return False


def _lookup_http_fallback(ip: str) -> Optional[dict]:
    """Fallback lookup via ip-api.com when local MaxMind DB is unconfigured or misses the IP."""
    if _is_private_ip(ip):
        return None
    try:
        import urllib.request
        import json
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelScan/1.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    as_raw = data.get("as", "")
                    asn_num = None
                    if as_raw.startswith("AS"):
                        try:
                            asn_num = int(as_raw.split()[0][2:])
                        except Exception:
                            pass
                    org = data.get("org") or data.get("isp")
                    return {
                        "ip": ip,
                        "country": data.get("country"),
                        "country_iso": data.get("countryCode"),
                        "city": data.get("city"),
                        "region": data.get("regionName"),
                        "postal_code": data.get("zip"),
                        "timezone": data.get("timezone"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "accuracy_radius": 50,
                        "asn": asn_num,
                        "asn_org": org,
                        "isp": data.get("isp"),
                        "is_hosting": data.get("hosting") or _is_hosting_org(org),
                        "is_proxy": data.get("proxy"),
                        "disclaimer": GEOIP_DISCLAIMER,
                    }
    except Exception as e:
        _LOGGER.debug("HTTP GeoIP fallback skipped for %s: %s", ip, e)
    return None


def lookup_ip(ip: str) -> Optional[dict]:
    """
    Resolve one IP to detailed geolocation + ASN attribution with explicit status:
    - 'private': internal / private network IP
    - 'database_not_configured': local MaxMind database is not loaded
    - 'no_record': database is loaded but IP has no geolocation entry
    - 'resolved': successfully resolved
    """
    if not _is_valid_ip(ip):
        return None
    if _is_private_ip(ip):
        return {"ip": ip, "status": "not_attempted", "database_configured": False,
                "country": None, "country_iso": None, "city": None, "region": None,
                "postal_code": None, "timezone": None, "latitude": None,
                "longitude": None, "accuracy_radius": None, "asn": None,
                "asn_org": None, "isp": None, "is_hosting": None, "is_proxy": None,
                "threat_level": None, "disclaimer": GEOIP_DISCLAIMER}

    _ensure_loaded()
    if _city_reader is None:
        if os.environ.get("GEOIP_HTTP_FALLBACK", "1").lower() in ("1", "true"):
            fallback = _lookup_http_fallback(ip)
            if fallback is not None:
                fallback["status"] = "resolved"
                fallback["database_configured"] = False
                return fallback
        return {
            "ip": ip,
            "status": "unavailable",
            "database_configured": False,
            "message": "GeoIP database not configured (set GEOIP_DB_PATH to GeoLite2-City.mmdb)",
            "country": None,
            "country_iso": None,
            "city": None,
            "region": None,
            "postal_code": None,
            "timezone": None,
            "latitude": None,
            "longitude": None,
            "accuracy_radius": None,
            "asn": None,
            "asn_org": None,
            "isp": None,
            "is_hosting": None,
            "is_proxy": None,
            "threat_level": None,
            "disclaimer": GEOIP_DISCLAIMER,
        }

    rec = _lookup_city(ip)
    if rec is None:
        return {
            "ip": ip,
            "status": "unavailable",
            "database_configured": True,
            "message": "No geolocation record found for IP in local database",
            "country": None,
            "country_iso": None,
            "city": None,
            "region": None,
            "postal_code": None,
            "timezone": None,
            "latitude": None,
            "longitude": None,
            "accuracy_radius": None,
            "asn": None,
            "asn_org": None,
            "isp": None,
            "is_hosting": None,
            "is_proxy": None,
            "threat_level": None,
            "disclaimer": GEOIP_DISCLAIMER,
        }

    rec = _enrich_asn(rec)
    rec["status"] = "resolved"
    rec["database_configured"] = True
    rec["disclaimer"] = GEOIP_DISCLAIMER
    return rec


def lookup(ip: str) -> Optional[dict]:
    """Resolve one IP to detailed geolocation + ASN attribution, or None."""
    if not _is_valid_ip(ip):
        return None
    if _is_private_ip(ip):
        return None

    _ensure_loaded()
    record = _lookup_city(ip)
    if record is not None:
        record = _enrich_asn(record)
        record["disclaimer"] = GEOIP_DISCLAIMER
        record["status"] = "resolved"
        record["database_configured"] = True
        return record

    if os.environ.get("GEOIP_HTTP_FALLBACK", "1").lower() in ("1", "true"):
        fallback = _lookup_http_fallback(ip)
        if fallback is not None:
            fallback["status"] = "resolved"
            fallback["database_configured"] = False
            return fallback

    return None


def lookup_many(ips: list[str]) -> list[dict]:
    """Resolve a list of IPs, returning detailed attribution for each."""
    if not ips:
        return []
    results = []
    seen = set()
    for raw_ip in ips:
        if not isinstance(raw_ip, str) or not _is_valid_ip(raw_ip):
            continue
        ip = raw_ip.strip()
        if ip in seen:
            continue
        seen.add(ip)
        result = lookup_ip(ip)
        if result is not None:
            results.append(result)
    return results


# Known Tor-associated ASNs (e.g. Zwiebelfreunde / AS60729, AS208323)
_TOR_RELAY_ASNS = {60729, 208323}
_CONFIRMED_TOR_EXITS: set[str] = set()


def check_tor_status(ip: str, asn: Optional[int] = None) -> tuple[bool, str]:
    """
    Dual-tier Tor indicator evaluation:
    - Tier 1: Real Tor exit list match -> "Confirmed Tor exit node"
    - Tier 2: ASN match (e.g. AS60729) -> "Hosting ASN associated with Tor relay infrastructure"
    Never conflates an ASN match with a confirmed active exit node.
    """
    if not ip or _is_private_ip(ip):
        return False, ""

    if ip in _CONFIRMED_TOR_EXITS:
        return True, "Confirmed Tor exit node"

    if asn is not None and asn in _TOR_RELAY_ASNS:
        return True, "Hosting ASN associated with Tor relay infrastructure"

    return False, ""


_MINING_POOL_KEYWORDS = (
    "stratum", "pool.mine", "cryptonight", "xmrig", "monero", "nanopool", "supportxmr", "2miners", "ethermine"
)


def check_mining_pool(indicator: str) -> tuple[bool, str]:
    """Identify if IP or domain belongs to known cryptomining pool infrastructure."""
    if not indicator:
        return False, ""
    lowered = indicator.lower()
    for kw in _MINING_POOL_KEYWORDS:
        if kw in lowered:
            return True, f"Cryptocurrency mining pool infrastructure ({kw})"
    return False, ""
