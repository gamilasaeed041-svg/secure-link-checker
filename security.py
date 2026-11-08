import ipaddress
import os
import socket
import ssl
import requests
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv

load_dotenv()


def is_safe_target(url):
    """يتأكد إن الرابط مش بيشاور على شبكة داخلية (حماية SSRF)."""
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False, "البروتوكول مش مسموح"

    host = parsed.hostname
    if not host:
        return False, "الرابط بدون اسم موقع"

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        infos = socket.getaddrinfo(host, port)
    except socket.gaierror:
        return False, "الدومين مش موجود أو مش بيرد"

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False, "الرابط بيشاور على شبكة داخلية"

    return True, ""


def follow_redirects(url, max_hops=5):
    """يتبع التحويلات يدوياً ويفحص كل خطوة."""
    chain = [url]
    current = url

    for _ in range(max_hops):
        safe, reason = is_safe_target(current)
        if not safe:
            return chain, reason

        try:
            r = requests.get(current, allow_redirects=False, timeout=5,
                             headers={"User-Agent": "LinkChecker/1.0"}, stream=True)
        except requests.RequestException:
            return chain, "الموقع مش بيرد"

        if r.status_code in (301, 302, 303, 307, 308) and "Location" in r.headers:
            current = urljoin(current, r.headers["Location"])
            chain.append(current)
        else:
            return chain, ""

    return chain, "تحويلات كتير زيادة"


def check_ssl(host, port=443):
    """يرجّع (معلومات الشهادة، مشكلة لو فيه)."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError:
        return None, "الشهادة غير صالحة أو غير موثوقة"
    except (socket.timeout, OSError):
        return None, "مقدرتش أفحص الشهادة"

    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    expires = expires.replace(tzinfo=timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days

    issuer = dict(x[0] for x in cert["issuer"]).get("organizationName", "غير معروف")
    info = {"issuer": issuer, "days_left": days_left}

    if days_left < 0:
        return info, "الشهادة منتهية"
    if days_left < 7:
        return info, "الشهادة هتنتهي خلال أقل من أسبوع"
    return info, ""


def check_domain_age(host):
    """يرجّع (عمر الدومين بالأيام، مشكلة لو فيه)."""
    try:
        data = whois.whois(host)
        created = data.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None, ""
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created).days
    except Exception:
        return None, ""

    if age < 30:
        return age, "الدومين جديد جداً (أقل من 30 يوم)"
    if age < 180:
        return age, "الدومين جديد (أقل من 6 شهور)"
    return age, ""


def check_safe_browsing(url):
    """Google Safe Browsing. يرجّع (True لو الرابط معروف إنه خطر / None لو مش متاح)."""
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return None
    body = {
        "client": {"clientId": "link-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": key}, json=body, timeout=8)
        if r.status_code != 200:
            return None
        return bool(r.json().get("matches"))
    except (requests.RequestException, ValueError):
        return None


def check_virustotal(url):
    """VirusTotal. يرجّع عدد المحركات اللي اعتبرته خطر / None لو مش متاح."""
    key = os.getenv("VIRUSTOTAL_KEY")
    if not key:
        return None
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/urls/" + url_id,
            headers={"x-apikey": key}, timeout=8)
        if r.status_code != 200:
            return None
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except (requests.RequestException, KeyError, ValueError):
        return None