import os
import base64
import requests

from dotenv import load_dotenv

from cache import cached_lookup
from ecs_utils import (
    get_field,
    first_value,
    flatten_values,
    is_private_ip,
    pick_public_ip,
)

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")


# ======================================================
# IOC Extraction
# ======================================================

def extract_iocs(alert):
    """
    Extract IOCs from an Elastic Security alert using ECS paths.
    Pulls IPs from multiple locations, plus domain/url/hash/file.
    """
    source_ip = first_value(*flatten_values(get_field(alert, "source.ip")))
    destination_ip = first_value(
        *flatten_values(get_field(alert, "destination.ip"))
    )
    client_ip = first_value(*flatten_values(get_field(alert, "client.ip")))
    server_ip = first_value(*flatten_values(get_field(alert, "server.ip")))
    host_ip = first_value(*flatten_values(get_field(alert, "host.ip")))
    forwarded_ip = first_value(
        *flatten_values(get_field(alert, "network.forwarded_ip"))
    )
    related_ips = flatten_values(get_field(alert, "related.ip"))

    all_ips = []
    for value in [
        source_ip,
        destination_ip,
        client_ip,
        server_ip,
        host_ip,
        forwarded_ip,
        *related_ips,
    ]:
        for ip in flatten_values(value):
            if ip not in all_ips:
                all_ips.append(ip)

    public_ips = [ip for ip in all_ips if not is_private_ip(ip)]
    private_ips = [ip for ip in all_ips if is_private_ip(ip)]

    # Best external IP for reputation lookups
    lookup_ip = pick_public_ip(
        source_ip,
        destination_ip,
        client_ip,
        server_ip,
        forwarded_ip,
        related_ips,
        host_ip,
    )

    domain = get_field(
        alert,
        "dns.question.name",
        "destination.domain",
        "url.domain",
        "server.domain",
        "threat.indicator.domain",
    )

    url = get_field(
        alert,
        "url.full",
        "url.original",
        "threat.indicator.url.full",
    )

    file_name = get_field(alert, "file.name")
    file_path = get_field(alert, "file.path")
    command_line = get_field(alert, "process.command_line")

    sha256 = first_value(
        get_field(alert, "file.hash.sha256"),
        get_field(alert, "process.hash.sha256"),
        get_field(alert, "dll.hash.sha256"),
        get_field(alert, "threat.indicator.file.hash.sha256"),
    )

    sha1 = first_value(
        get_field(alert, "file.hash.sha1"),
        get_field(alert, "process.hash.sha1"),
        get_field(alert, "dll.hash.sha1"),
        get_field(alert, "threat.indicator.file.hash.sha1"),
    )

    md5 = first_value(
        get_field(alert, "file.hash.md5"),
        get_field(alert, "process.hash.md5"),
        get_field(alert, "dll.hash.md5"),
        get_field(alert, "threat.indicator.file.hash.md5"),
    )

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "client_ip": client_ip,
        "server_ip": server_ip,
        "host_ip": host_ip,
        "forwarded_ip": forwarded_ip,
        "related_ips": related_ips,
        "all_ips": all_ips,
        "public_ips": public_ips,
        "private_ips": private_ips,
        "lookup_ip": lookup_ip,
        "domain": domain,
        "url": url,
        "file_name": file_name,
        "file_path": file_path,
        "command_line": command_line,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
    }


def primary_hash(iocs):
    """Prefer sha256, then sha1, then md5 for reputation lookups."""
    iocs = iocs or {}
    return first_value(
        iocs.get("sha256"),
        iocs.get("sha1"),
        iocs.get("md5"),
    )


# ======================================================
# VirusTotal
# ======================================================

def _virustotal_ip_api(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code != 200:
        return None
    return response.json()


def _virustotal_hash_api(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code != 200:
        return None
    return response.json()


def _virustotal_domain_api(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code != 200:
        return None
    return response.json()


def _virustotal_url_api(url_value):
    # VT URL lookup uses base64 URL-safe id without padding
    url_id = base64.urlsafe_b64encode(
        url_value.encode()
    ).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code != 200:
        return None
    return response.json()


def virustotal_ip(ip):
    if not ip or is_private_ip(ip):
        return None, False
    return cached_lookup(
        provider="virustotal",
        ioc_type="ip",
        ioc_value=ip,
        fetch_fn=lambda: _virustotal_ip_api(ip),
    )


def virustotal_hash(file_hash):
    if not file_hash:
        return None, False
    return cached_lookup(
        provider="virustotal",
        ioc_type="hash",
        ioc_value=file_hash,
        fetch_fn=lambda: _virustotal_hash_api(file_hash),
    )


def virustotal_domain(domain):
    if not domain:
        return None, False
    return cached_lookup(
        provider="virustotal",
        ioc_type="domain",
        ioc_value=domain,
        fetch_fn=lambda: _virustotal_domain_api(domain),
    )


def virustotal_url(url_value):
    if not url_value:
        return None, False
    return cached_lookup(
        provider="virustotal",
        ioc_type="url",
        ioc_value=url_value,
        fetch_fn=lambda: _virustotal_url_api(url_value),
    )


# ======================================================
# AbuseIPDB / Shodan / Hybrid Analysis
# ======================================================

def _abuseipdb_api(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(
        url, headers=headers, params=params, timeout=30
    )
    if response.status_code != 200:
        return None
    return response.json()


def abuseipdb_lookup(ip):
    if not ip or is_private_ip(ip):
        return None, False
    return cached_lookup(
        provider="abuseipdb",
        ioc_type="ip",
        ioc_value=ip,
        fetch_fn=lambda: _abuseipdb_api(ip),
    )


def _shodan_api(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    response = requests.get(url, timeout=30)
    if response.status_code != 200:
        return None
    return response.json()


def shodan_lookup(ip):
    if not ip or is_private_ip(ip):
        return None, False
    return cached_lookup(
        provider="shodan",
        ioc_type="ip",
        ioc_value=ip,
        fetch_fn=lambda: _shodan_api(ip),
    )


def _hybrid_analysis_api(hash_value):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "accept": "application/json",
        "user-agent": "Falcon Sandbox",
    }
    response = requests.post(
        url,
        headers=headers,
        data={"hash": hash_value},
        timeout=30,
    )
    if response.status_code != 200:
        return None
    payload = response.json()
    if isinstance(payload, list) and not payload:
        return None
    return payload


def hybrid_analysis_lookup(hash_value):
    if not hash_value:
        return None, False
    return cached_lookup(
        provider="hybrid_analysis",
        ioc_type="hash",
        ioc_value=hash_value,
        fetch_fn=lambda: _hybrid_analysis_api(hash_value),
    )


def _cache_status(hit, applicable):
    if not applicable:
        return "skipped"
    return "hit" if hit else "miss"


# ======================================================
# Master Function
# ======================================================

def enrich_alert(alert):
    iocs = extract_iocs(alert)

    ip = iocs.get("lookup_ip")
    file_hash = primary_hash(iocs)
    domain = iocs.get("domain")
    url_value = iocs.get("url")

    vt_ip, vt_ip_cached = virustotal_ip(ip)
    abuse, abuse_cached = abuseipdb_lookup(ip)
    shodan, shodan_cached = shodan_lookup(ip)

    vt_hash, vt_hash_cached = virustotal_hash(file_hash)
    vt_domain, vt_domain_cached = virustotal_domain(domain)
    vt_url, vt_url_cached = virustotal_url(url_value)
    hybrid, hybrid_cached = hybrid_analysis_lookup(file_hash)

    # Prefer the most specific VT result available
    vt = first_value(vt_hash, vt_url, vt_domain, vt_ip)

    if file_hash and vt_hash is not None:
        vt_cache_status = _cache_status(vt_hash_cached, True)
    elif url_value and vt_url is not None:
        vt_cache_status = _cache_status(vt_url_cached, True)
    elif domain and vt_domain is not None:
        vt_cache_status = _cache_status(vt_domain_cached, True)
    elif ip:
        vt_cache_status = _cache_status(vt_ip_cached, True)
    else:
        vt_cache_status = "skipped"

    return {
        "iocs": iocs,
        "virustotal": vt,
        "virustotal_ip": vt_ip,
        "virustotal_hash": vt_hash,
        "virustotal_domain": vt_domain,
        "virustotal_url": vt_url,
        "abuseipdb": abuse,
        "shodan": shodan,
        "hybrid_analysis": hybrid,
        "cache": {
            "virustotal": vt_cache_status,
            "virustotal_ip": _cache_status(vt_ip_cached, bool(ip)),
            "virustotal_hash": _cache_status(
                vt_hash_cached, bool(file_hash)
            ),
            "virustotal_domain": _cache_status(
                vt_domain_cached, bool(domain)
            ),
            "virustotal_url": _cache_status(
                vt_url_cached, bool(url_value)
            ),
            "abuseipdb": _cache_status(abuse_cached, bool(ip)),
            "shodan": _cache_status(shodan_cached, bool(ip)),
            "hybrid_analysis": _cache_status(
                hybrid_cached, bool(file_hash)
            ),
        },
    }
