
"""
PHISHSHIELD – FINAL BACKEND
Security Decision Engine for Phishing & Malware Prevention

Key Capabilities:
- Real-time link scanning (pre-click)
- VPN / Proxy / anonymized network detection
- Multi-source phishing detection
- DNS-level blocking signals
- Risk score (0–100)
- Explainable verdicts
- APK malware scanning (hash-based)
- Language support + voice alert text
- Privacy-first (no personal data stored)

NOTE:
Actual DNS blocking, VPN enforcement, input locking
must be implemented at OS / frontend level.
"""

import os
import time
import hashlib
import ipaddress
import requests
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

FLAGGED_URLS = []   

LANG = {
    "en": {
        "safe": "This link appears to be safe.",
        "suspicious": "Suspicious link detected. Please be cautious.",
        "dangerous": "Dangerous phishing link blocked for your safety."
    },
    "ta": {
        "safe": "இந்த இணைப்பு பாதுகாப்பானதாக உள்ளது.",
        "suspicious": "சந்தேகமான இணைப்பு கண்டறியப்பட்டது. கவனமாக இருங்கள்.",
        "dangerous": "ஆபத்தான பிஷிங் இணைப்பு தடுக்கப்பட்டது."
    },
    "hi": {
        "safe": "यह लिंक सुरक्षित प्रतीत होता है।",
        "suspicious": "संदिग्ध लिंक पाया गया है। सावधान रहें।",
        "dangerous": "खतरनाक फ़िशिंग लिंक को ब्लॉक कर दिया गया है।"
    }
}

def extract_domain(url: str) -> str:
    try:
        return url.split("//")[-1].split("/")[0].lower()
    except Exception:
        return url.lower()

def detect_vpn_proxy(ip: str) -> dict:
    result = {
        "vpn": False,
        "proxy": False,
        "tor": False,
        "hosting": False,
        "risk": 0
    }

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_reserved:
            result["vpn"] = True
            result["risk"] += 30

        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()

        org = (r.get("org") or "").lower()
        if any(k in org for k in ["vpn", "proxy", "hosting", "cloud"]):
            result["hosting"] = True
            result["risk"] += 20

        if r.get("privacy", {}).get("vpn"):
            result["vpn"] = True
            result["risk"] += 40

        if r.get("privacy", {}).get("tor"):
            result["tor"] = True
            result["risk"] += 50

    except Exception:
        pass

    return result

def google_safe_browsing(url: str) -> bool:
    if not GSB_API_KEY:
        return False

    payload = {
        "client": {"clientId": "phishshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload,
            timeout=3
        )
        return "matches" in r.json()
    except Exception:
        return False

def virustotal_url_check(url: str) -> bool:
    if not VT_API_KEY:
        return False

    headers = {"x-apikey": VT_API_KEY}

    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=5
        )

        analysis_id = submit.json()["data"]["id"]
        time.sleep(1)

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=5
        )

        stats = report.json()["data"]["attributes"]["stats"]
        return stats.get("malicious", 0) > 0

    except Exception:
        return False

def virustotal_apk_check(file_hash: str) -> bool:
    if not VT_API_KEY:
        return False

    headers = {"x-apikey": VT_API_KEY}

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers,
            timeout=5
        )
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) > 0
    except Exception:
        return False


def local_heuristic(url: str) -> bool:
    keywords = [
        "login", "verify", "secure", "update",
        "account", "bank", "wallet", "otp", "signin"
    ]
    return any(k in url.lower() for k in keywords)

@app.route("/scan-link", methods=["POST"])
def scan_link():
    data = request.get_json(force=True)
    url = data.get("link")
    lang = data.get("lang", "en")

    user_ip = request.headers.get(
        "X-Forwarded-For", request.remote_addr
    )

    if not url:
        return jsonify({"error": "Missing link"}), 400

    domain = extract_domain(url)

    verdict = "safe"
    reasons = []
    risk_score = 0

    vpn_info = detect_vpn_proxy(user_ip)
    if vpn_info["vpn"] or vpn_info["tor"]:
        reasons.append("Anonymized network detected")
        risk_score += vpn_info["risk"]

    if google_safe_browsing(url):
        verdict = "dangerous"
        reasons.append("Flagged by Google Safe Browsing")
        risk_score += 50

    elif virustotal_url_check(url):
        verdict = "dangerous"
        reasons.append("Flagged by VirusTotal")
        risk_score += 40

    elif local_heuristic(url):
        verdict = "suspicious"
        reasons.append("Credential-harvesting pattern detected")
        risk_score += 20

    risk_score = min(risk_score, 100)

    dns_block = verdict == "dangerous"

    if verdict != "safe":
        FLAGGED_URLS.append({
            "url": url,
            "domain": domain,
            "verdict": verdict,
            "risk": risk_score,
            "time": datetime.utcnow().isoformat()
        })

    text = LANG.get(lang, LANG["en"])[verdict]

    return jsonify({
        "verdict": verdict,
        "risk_score": risk_score,

        "action": (
            "block" if verdict == "dangerous"
            else "warn" if verdict == "suspicious"
            else "allow"
        ),

        "dns_block": dns_block,
        "block_domain": domain if dns_block else None,

        
        "network_security": vpn_info,

        
        "explanation": reasons,

        
        "warning_text": text,
        "voice_alert": (
            f"Warning! {text} Do not open this link."
            if verdict == "dangerous"
            else f"Alert! {text}"
            if verdict == "suspicious"
            else text
        ),

        
        "session_guard": {
            "disable_sensitive_inputs": verdict != "safe",
            "timeout_seconds": 120 if verdict != "safe" else 0
        }
    }), 200


@app.route("/scan-apk", methods=["POST"])
def scan_apk():
    apk = request.files.get("apk")
    if not apk:
        return jsonify({"error": "APK file missing"}), 400

    content = apk.read()
    file_hash = hashlib.sha256(content).hexdigest()

    malicious = virustotal_apk_check(file_hash)

    return jsonify({
        "hash": file_hash,
        "verdict": "malicious" if malicious else "clean",
        "action": "block_install" if malicious else "allow_install"
    }), 200


@app.route("/flagged", methods=["GET"])
def flagged():
    return jsonify(FLAGGED_URLS), 200




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)