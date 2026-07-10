import os
import requests

from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")


# ======================================================
# IOC Extraction
# ======================================================

def extract_iocs(alert):

    source_ip = (
        alert.get("source.ip")
        or alert.get("source", {}).get("ip")
    )

    destination_ip = (
        alert.get("destination.ip")
        or alert.get("destination", {}).get("ip")
    )

    domain = (
        alert.get("dns.question.name")
        or alert.get("dns", {}).get("question", {}).get("name")
    )

    url = (
        alert.get("url.full")
        or alert.get("url", {}).get("full")
    )

    sha256 = (
        alert.get("file.hash.sha256")
        or alert.get("file", {}).get("hash", {}).get("sha256")
    )

    md5 = (
        alert.get("file.hash.md5")
        or alert.get("file", {}).get("hash", {}).get("md5")
    )

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "domain": domain,
        "url": url,
        "sha256": sha256,
        "md5": md5
    }


# ======================================================
# VirusTotal
# ======================================================

def virustotal_ip(ip):

    if not ip:
        return None

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None

    return response.json()


# ======================================================
# AbuseIPDB
# ======================================================

def abuseipdb_lookup(ip):

    if not ip:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        url,
        headers=headers,
        params=params
    )

    if response.status_code != 200:
        return None

    return response.json()


# ======================================================
# Shodan
# ======================================================

def shodan_lookup(ip):

    if not ip:
        return None

    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"

    response = requests.get(url)

    if response.status_code != 200:
        return None

    return response.json()


# ======================================================
# Hybrid Analysis
# ======================================================

def hybrid_analysis_lookup(hash_value):

    if not hash_value:
        return None

    url = (
        "https://www.hybrid-analysis.com/api/v2/search/hash"
    )

    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "accept": "application/json",
        "user-agent": "Falcon Sandbox"
    }

    data = {
        "hash": hash_value
    }

    response = requests.post(
        url,
        headers=headers,
        data=data
    )

    if response.status_code != 200:
        return None

    return response.json()


# ======================================================
# Master Function
# ======================================================

def enrich_alert(alert):

    iocs = extract_iocs(alert)

    ip = iocs["source_ip"] or iocs["destination_ip"]

    enrichment = {

        "iocs": iocs,

        "virustotal": virustotal_ip(ip),

        "abuseipdb": abuseipdb_lookup(ip),

        "shodan": shodan_lookup(ip),

        "hybrid_analysis": hybrid_analysis_lookup(
            iocs["sha256"] or iocs["md5"]
        )

    }

    return enrichment