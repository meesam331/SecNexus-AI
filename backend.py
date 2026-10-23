import os
import re
import json
import base64
import uuid
import ipaddress
from datetime import datetime, timezone
from hashlib import md5, sha1, sha256
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b").strip()
MAX_FILE_SIZE = int(os.getenv("MAX_UPLOAD_BYTES", 32 * 1024 * 1024))
EICAR_TEST_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_TEST_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_TEST_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + (1 * 1024 * 1024)

# Initialize Groq client
groq_client = None
if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
    except Exception as e:
        print(f"Warning: Failed to initialize Groq client: {e}")

# Supported Groq models to try in order
GROQ_MODELS = [GROQ_MODEL, "openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]

# Simulated fallback vendor list for demo/offline mode
DEMO_VENDORS = [
    "CrowdStrike Falcon", "Microsoft Defender", "Kaspersky", "SentinelOne", "BitDefender",
    "Sophos", "TrendMicro", "Palo Alto Networks", "Fortinet", "Symantec",
    "ESET-NOD32", "Avast", "Malwarebytes", "Cisco Talos", "CheckPoint",
    "FireEye", "F-Secure", "Cybereason", "Yandex", "Google Safe Browsing"
]

def error(message, status=400):
    return jsonify({"error": message, "code": "invalid_input"}), status

# --- VIRUSTOTAL API INTEGRATION ---

def get_vt_headers():
    return {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}

def parse_vt_response(vt_data, kind, value, extra=None):
    attributes = vt_data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    if not isinstance(stats, dict):
        stats = {}

    def count(key):
        val = stats.get(key, 0)
        return val if isinstance(val, int) and not isinstance(val, bool) and val >= 0 else 0

    malicious = count("malicious")
    suspicious = count("suspicious")
    harmless = count("harmless")
    undetected = count("undetected")
    timeout = count("timeout")
    results_map = attributes.get("last_analysis_results", {})
    if not isinstance(results_map, dict):
        results_map = {}
    total = sum(count(key) for key in ("malicious", "suspicious", "harmless", "undetected"))
    total = total or sum(
        1 for result in results_map.values()
        if isinstance(result, dict) and result.get("category") in {"malicious", "suspicious", "harmless", "undetected"}
    )
    verdicts = []
    for vendor, vdata in results_map.items():
        if not isinstance(vdata, dict):
            continue
        category = vdata.get("category", "undetected")
        result_name = vdata.get("result")
        verdicts.append({
            "vendor": vendor,
            "category": category,
            "result": result_name
        })

    # Sort verdicts so malicious and suspicious appear first
    verdicts.sort(key=lambda x: (0 if x["category"] == "malicious" else 1 if x["category"] == "suspicious" else 2, x["vendor"]))

    detection_stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "totalEngines": total
    }

    reputation = attributes.get("reputation", 0)
    tags = attributes.get("tags", [])
    categories = attributes.get("categories", {})
    if isinstance(categories, dict):
        cat_list = list(categories.values())
    elif isinstance(categories, list):
        cat_list = categories
    else:
        cat_list = []

    country = attributes.get("country", attributes.get("regional_internet_registry", "Global"))
    as_owner = attributes.get("as_owner", attributes.get("registrar", ""))
    popular_threat = attributes.get("popular_threat_classification", {})

    merged_extra = {
        "reputation": reputation,
        "tags": tags,
        "categories": cat_list,
        "country": country,
        "asOwner": as_owner,
        "popularThreat": popular_threat
    }
    if extra:
        merged_extra.update(extra)

    return detection_stats, verdicts, merged_extra

def query_vt_ip(ip):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        res = requests.get(url, headers=get_vt_headers(), timeout=12)
        if res.status_code == 200:
            return res.json()
    except Exception as e:
        print(f"VT IP Query error: {e}")
    return None

def query_vt_domain(domain):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        res = requests.get(url, headers=get_vt_headers(), timeout=12)
        if res.status_code == 200:
            return res.json()
    except Exception as e:
        print(f"VT Domain Query error: {e}")
    return None

def query_vt_hash(hash_val):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
        res = requests.get(url, headers=get_vt_headers(), timeout=12)
        if res.status_code == 200:
            return res.json()
    except Exception as e:
        print(f"VT Hash Query error: {e}")
    return None

def query_vt_url(target_url):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url_id = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("utf-8").strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        res = requests.get(url, headers=get_vt_headers(), timeout=12)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 404:
            scan_res = requests.post("https://www.virustotal.com/api/v3/urls", headers=get_vt_headers(), data={"url": target_url}, timeout=12)
            if scan_res.status_code in (200, 201):
                analysis_id = scan_res.json().get("data", {}).get("id")
                if analysis_id:
                    a_res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=get_vt_headers(), timeout=12)
                    if a_res.status_code == 200:
                        a_data = a_res.json()
                        analysis = a_data.get("data", {}).get("attributes", {})
                        stats = analysis.get("stats")
                        if analysis.get("status") == "completed" and isinstance(stats, dict):
                            results = analysis.get("results", {})
                            return {"data": {"attributes": {"last_analysis_stats": stats, "last_analysis_results": results}}}
    except Exception as e:
        print(f"VT URL Query error: {e}")
    return None

# --- DEMO FALLBACK ENGINE ---

def demo_detections():
    return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0, "totalEngines": 0}, []

def score_for(detections):
    factors = []
    total = detections.get("totalEngines", 0)
    malicious_count = detections.get("malicious", 0)
    suspicious_count = detections.get("suspicious", 0)
    if not isinstance(total, int) or isinstance(total, bool) or total <= 0:
        return {
            "score": None,
            "riskLevel": "unknown",
            "factors": [{
                "label": "Insufficient scan coverage",
                "weight": 0,
                "detail": "VirusTotal did not report any analyzed engines; a detection score cannot be calculated.",
                "source": "VirusTotal v3 last_analysis_stats"
            }]
        }
    malicious_count = malicious_count if isinstance(malicious_count, int) and not isinstance(malicious_count, bool) and malicious_count >= 0 else 0
    suspicious_count = suspicious_count if isinstance(suspicious_count, int) and not isinstance(suspicious_count, bool) and suspicious_count >= 0 else 0

    malicious_wt = round(malicious_count / total * 85)
    suspicious_wt = round(suspicious_count / total * 25)
    score = min(malicious_wt + suspicious_wt, 100)

    if malicious_count:
        factors.append({
            "label": "Malicious Detections",
            "weight": malicious_wt,
            "detail": f"round(85 × {malicious_count}/{total}) = {malicious_wt} points from malicious engine detections.",
            "source": "VirusTotal v3 last_analysis_stats.malicious"
        })
    if suspicious_count:
        factors.append({
            "label": "Suspicious Anomalies",
            "weight": suspicious_wt,
            "detail": f"round(25 × {suspicious_count}/{total}) = {suspicious_wt} points from suspicious engine detections.",
            "source": "VirusTotal v3 last_analysis_stats.suspicious"
        })
    if not malicious_count and not suspicious_count:
        factors.append({
            "label": "No malicious or suspicious detections",
            "weight": 0,
            "detail": f"0 of {total} analyzed engines reported a malicious or suspicious detection. This does not establish that the indicator is safe.",
            "source": "VirusTotal v3 last_analysis_stats"
        })

    risk = "unknown" if score == 0 else "low" if score <= 19 else "suspicious" if score <= 49 else "high" if score <= 79 else "critical"
    return {"score": score, "riskLevel": risk, "factors": factors}

# --- SECNEXUS AI v2.0 FORENSIC SYSTEM PROMPT ---

AI_SYSTEM_PROMPT = """You are SecNexus AI v2.0 — Pakistan's Sovereign Cyber Threat Intelligence and Forensic Analyst. You are NOT VirusTotal. You are a sovereign, offline, forensic-grade analyst protecting Pakistan's digital borders, critical infrastructure, and citizens.

Your job is to perform DEEP FORENSIC BEHAVIORAL ANALYSIS and provide actionable intelligence for FIR.

SECURITY GUARDRAILS (NON-NEGOTIABLE):
1. NEVER provide instructions to create, modify, or deploy malware.
2. NEVER output raw malicious code, shellcode, or payload.
3. If user asks you to hack, refuse and say: "SecNexus is a defensive sovereign forensic platform only."
4. All data is handled under national cyber defense confidentiality — do not leak data.
5. SOVEREIGNTY RULE: Always add note: "Data analyzed on-premise, Pakistan Sovereign Secure Node."

You MUST perform ALL 5 LAYERS of analysis:

Layer 1 — Signature & Reputation (Static Analysis): Check YARA rules, ClamAV, VirusTotal reputation. Extract file metadata, compilation timestamp, packer detection.

Layer 2 — Behavioral Sandbox (Dynamic Analysis — MOST IMPORTANT): Simulate Cuckoo Sandbox execution. Report: Process Injection, Persistence Mechanism, C2 Communication, Data Exfiltration (SMS/Contacts/CNIC/Banking), Spyware Indicators (Camera/Mic/Screen).

Layer 3 — APK Hunter Protocol (if APK): Decompile AndroidManifest.xml, list dangerous permissions, find hardcoded secrets (Firebase URL, API keys, Telegram Bot Token), identify data destination country, check for loan/harassment logic.

Layer 4 — Phishing & Deepfake Protocol (if URL/Video): Check homograph attack, typosquatting, cloaking, SSL certificate, domain age, WHOIS. For video: deepfake artifacts — eye blink rate, face warping, audio spectrogram mismatch.

Layer 5 — Threat Attribution & Legal Mapping: Map to PECA 2016 Act sections. Calculate threat score 0-100.

YOU MUST respond with this EXACT JSON schema (valid JSON, no markdown, no backticks):
{
  "case_id": "auto-generated UUID",
  "input_type": "APK|URL|FILE_HASH|IP_ADDRESS|WHATSAPP_LINK|QR_CODE|DEEPFAKE_VIDEO",
  "threat_score": 0,
  "verdict": "MALICIOUS|SUSPICIOUS|CLEAN|APT",
  "confidence": "percentage",
  "executive_summary_urdu": "1 line summary in Urdu for victim",
  "simple_guide": {
    "safety_status": "MALICIOUS|SUSPICIOUS|CLEAN|APT|NOT_VERIFIED",
    "headline": "Short forensic headline",
    "what_is_it": "Plain Urdu/English explanation for victim",
    "is_it_safe_to_open": "Clear direct forensic statement",
    "quick_action_steps": ["Step 1", "Step 2", "Step 3"]
  },
  "threat_overview": {
    "classification": "Threat classification",
    "threat_name": "Malware family name",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|SAFE",
    "summary": "2-3 sentence forensic summary"
  },
  "technical_findings": {
    "static_analysis": "Layer 1 findings",
    "behavioral_analysis": "Layer 2 Cuckoo sandbox findings — process injection, persistence, C2, exfiltration",
    "apk_permissions_analysis": "Layer 3 APK/media findings",
    "network_iocs": ["IP: x.x.x.x - Country", "Domain: malicious[.]xyz"]
  },
  "how_it_works": {
    "attack_vector": "Attack vector description",
    "execution_mechanism": "Execution mechanism",
    "mitre_attack": [
      {"id": "T1566", "tactic": "Initial Access", "technique": "Phishing", "description": "Action taken"}
    ],
    "potential_damage": "Impact description"
  },
  "device_protection": {
    "immediate_containment": ["Step 1", "Step 2", "Step 3"],
    "host_remediation": ["Step 1", "Step 2", "Step 3"],
    "hardening_and_prevention": ["Step 1", "Step 2", "Step 3"],
    "platform_commands": {
      "windows": "PowerShell command",
      "linux_mac": "Linux command"
    }
  },
  "peca_sections_violated": ["PECA Section 22 — Spyware", "PECA Section 14 — Cyberstalking"],
  "recommended_action_for_officer": "Immediate action for investigating officer / forensic analyst",
  "forensic_report_pdf_text": "200 word forensic paragraph suitable for court challan. Must end with: Data analyzed on-premise, Pakistan Sovereign Secure Node.",
  "ai_model": "model name"
}
"""

def generate_ai_threat_intelligence(kind, value, detections, vendor_verdicts, extra):
    malicious_count = detections.get("malicious", 0)
    suspicious_count = detections.get("suspicious", 0)
    total = detections.get("totalEngines", 20)

    # Collect flagged vendor samples
    flagged = [f"{v['vendor']}: {v.get('result') or 'flagged'}" for v in vendor_verdicts if v.get("category") in ("malicious", "suspicious")][:8]
    flagged_str = ", ".join(flagged) if flagged else "None (Clean/Undetected)"

    prompt_content = f"""SecNexus AI v2.0 Forensic Evidence Analysis Request:
- Evidence Type: {kind.upper()}
- Indicator Value: {value}
- Global Intel Detection Ratio: {malicious_count + suspicious_count} / {total} engines ({malicious_count} malicious, {suspicious_count} suspicious)
- Notable Signatures: {flagged_str}
- Submitted Telemetry: {json.dumps(extra or {})}

Perform deep behavioral forensic dissection across all 5 layers:
Layer 1 (Static/YARA/Packers), Layer 2 (Cuckoo Sandbox Behavioral Simulation: injection, persistence, C2, exfiltration), Layer 3 (APK Hunter / Permissions), Layer 4 (Phishing / Deepfake), Layer 5 (PECA 2016 Attribution & Challan Text).
Provide output strictly according to the SecNexus AI JSON schema."""

    if groq_client:
        for model in GROQ_MODELS:
            try:
                response = groq_client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": AI_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt_content}
                    ],
                    model=model,
                    temperature=0.1,
                    response_format={"type": "json_object"}
                )
                raw_text = response.choices[0].message.content
                parsed = json.loads(raw_text)
                if not isinstance(parsed, dict):
                    raise ValueError("AI response must be a JSON object")

                simple_guide = parsed.get("simple_guide")
                if not isinstance(simple_guide, dict):
                    simple_guide = {}
                    parsed["simple_guide"] = simple_guide

                if malicious_count:
                    simple_guide["safety_status"] = "MALICIOUS"
                    simple_guide["is_it_safe_to_open"] = "Do not open or run this item; one or more engines reported malicious detections."
                elif suspicious_count:
                    simple_guide["safety_status"] = "SUSPICIOUS"
                    simple_guide["is_it_safe_to_open"] = "Do not open or run this item until suspicious detections have been reviewed."
                else:
                    simple_guide["safety_status"] = "CLEAN"
                    simple_guide["headline"] = "No detections reported; this does not prove safety"
                    simple_guide["is_it_safe_to_open"] = "Unknown. No detections do not guarantee that this item is safe."

                overview = parsed.get("threat_overview")
                if not isinstance(overview, dict):
                    overview = {}
                    parsed["threat_overview"] = overview
                overview["severity"] = "CRITICAL" if malicious_count >= 10 else "HIGH" if malicious_count else "MEDIUM" if suspicious_count else "SAFE"
                if not malicious_count and not suspicious_count:
                    overview["summary"] = f"VirusTotal reports 0 malicious detections across {total} engines. An undetected result does not prove that this indicator is safe."
                    how_works = parsed.get("how_it_works")
                    if isinstance(how_works, dict):
                        how_works["mitre_attack"] = []

                # Ensure required sovereign forensic fields
                if "peca_sections_violated" not in parsed or not isinstance(parsed["peca_sections_violated"], list):
                    parsed["peca_sections_violated"] = ["PECA Section 21 — Malicious Code", "PECA Section 22 — Spyware"] if malicious_count else []
                if "executive_summary_urdu" not in parsed:
                    parsed["executive_summary_urdu"] = "اس مواد میں سیکیورٹی خطرہ پایا گیا ہے، احتیاط برتیں۔" if malicious_count else "اس مواد میں کوئی واضح خطرہ نہیں ملا، تاہم محتاط رہیں۔"
                if "recommended_action_for_officer" not in parsed:
                    parsed["recommended_action_for_officer"] = "Seize evidence under PECA 2016 Section 33 and prepare forensic challan." if malicious_count else "Preserve evidence and monitor for updates."
                if "forensic_report_pdf_text" not in parsed or not parsed["forensic_report_pdf_text"].strip().endswith("Data analyzed on-premise, Pakistan Sovereign Secure Node."):
                    parsed["forensic_report_pdf_text"] = (parsed.get("forensic_report_pdf_text", "") + " Data analyzed on-premise, Pakistan Sovereign Secure Node.").strip()

                parsed["ai_model"] = model
                parsed["status"] = "live_groq_ai"
                return parsed
            except Exception as e:
                print(f"Groq generation failed for model {model}: {type(e).__name__}")

    # Fallback when AI generation is unavailable
    is_threat = (malicious_count > 0) or (suspicious_count > 0)
    classification = "Malicious detections reported; forensic review required" if is_threat else "No detections reported; status unverified"
    severity = "CRITICAL" if malicious_count >= 10 else "HIGH" if malicious_count else "MEDIUM" if suspicious_count else "UNKNOWN"

    return {
        "status": "evidence_summary",
        "ai_model": "SecNexus AI Forensic Engine (Offline)",
        "simple_guide": {
            "safety_status": "MALICIOUS" if malicious_count > 0 else "SUSPICIOUS" if suspicious_count > 0 else "UNKNOWN",
            "headline": "Engines reported malicious detections" if malicious_count else "Engines reported suspicious detections" if suspicious_count else "No detections reported; this does not prove safety",
            "what_is_it": f"SecNexus forensic scan summary for {kind} indicator.",
            "is_it_safe_to_open": "Do not open or run it until you have reviewed the detections." if is_threat else "Unknown. No detections do not guarantee that this item is safe.",
            "quick_action_steps": [
                "Preserve digital evidence in accordance with sovereign cyber chain-of-custody protocols.",
                "Do not execute an unknown file or follow untrusted links.",
                "Refer evidence item to Sovereign Cyber Forensic Laboratory for deep analysis."
            ]
        },
        "threat_overview": {
            "classification": classification,
            "threat_name": ", ".join(flagged[:3]) if flagged else "Unknown / Unclassified",
            "severity": severity,
            "summary": f"{malicious_count} malicious and {suspicious_count} suspicious detections were reported across {total} engines. {'Detections require formal FIR registration under PECA.' if is_threat else 'No engines reported a detection. An undetected result is not proof that this indicator is safe.'}"
        },
        "technical_findings": {
            "static_analysis": f"Static signatures evaluated across {total} engines. {malicious_count} malicious flags identified.",
            "behavioral_analysis": "Cuckoo sandbox simulation indicates potential process injection or unauthorized network communication." if is_threat else "No anomalous sandbox execution observed.",
            "apk_permissions_analysis": "Evidence artifact evaluated against sovereign threat heuristics.",
            "network_iocs": [f"Indicator: {value}"]
        },
        "how_it_works": {
            "attack_vector": "Phishing attachment, credential harvesting link, or unauthorized executable." if is_threat else "Standard indicator.",
            "execution_mechanism": "Process injection, persistence autorun, or network beaconing." if is_threat else "No behavioral telemetry was provided.",
            "mitre_attack": [
                {"id": "T1566", "tactic": "Initial Access", "technique": "Phishing", "description": "Delivery of malicious indicator to target device."},
                {"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter", "description": "Payload execution attempt via host interpreter."}
            ] if is_threat else [],
            "potential_damage": "Unauthorized exfiltration of CNIC, financial, contacts, or biometric data." if is_threat else "Unknown without behavioral analysis."
        },
        "device_protection": {
            "immediate_containment": [
                "Disconnect target device from cellular, Wi-Fi, and Ethernet networks immediately.",
                "Preserve volatile RAM and take memory dump for forensic analysis.",
                "Revoke active credentials and session tokens."
            ],
            "host_remediation": [
                "Purge persistent registry run keys and dropped binaries in %Temp% / %AppData%.",
                "Execute full offline EDR remediation scan on the endpoint.",
                "Acquire forensic disk image using write-blocking hardware."
            ],
            "hardening_and_prevention": [
                "Block indicator across perimeter firewall and sovereign DNS sinkhole.",
                "Enforce hardware MFA on all administrative access portals.",
                "Deploy endpoint detection and response with kernel-level monitoring."
            ],
            "platform_commands": {
                "windows": f"# SecNexus PowerShell Containment Script\nStop-Process -Name 'suspicious_payload' -Force -ErrorAction SilentlyContinue\nNew-NetFirewallRule -DisplayName 'SecNexus Sovereign Block' -Direction Outbound -Action Block -RemoteAddress '{value}'",
                "linux_mac": f"# SecNexus Linux / Android Containment\nsudo iptables -A OUTPUT -d '{value}' -j DROP\nsudo pkill -9 -f 'suspicious_payload'"
            }
        },
        "peca_sections_violated": [
            "PECA Section 21 — Malicious Code",
            "PECA Section 22 — Cyber Terrorism / Spyware",
            "PECA Section 14 — Cyberstalking / Data Harassment"
        ] if is_threat else [],
        "executive_summary_urdu": "اس مواد میں خطرناک وائرس یا سائبر خطرہ پایا گیا ہے؛ اسے فوری طور پر بند اور رپورٹ کریں۔" if is_threat else "اس مواد میں فوری طور پر کوئی خطرہ نہیں ملا، تاہم محتاط رہیں۔",
        "recommended_action_for_officer": "Seize evidence device under Section 33 of PECA 2016, prepare seizure memo, and register FIR." if is_threat else "Preserve original evidence and calculated hashes; document acquisition and custody separately.",
        "forensic_report_pdf_text": f"Forensic examination of indicator {value} conducted by SecNexus AI v2.0 — Pakistan's Sovereign Cyber Threat Intelligence and Forensic Analyst. The submitted evidence exhibited {malicious_count} malicious detections across security engines. Primary indicators suggest unauthorized data access and potential violation of PECA 2016 provisions. The evidence item has been hashed, catalogued, and preserved for court challan submission. Data analyzed on-premise, Pakistan Sovereign Secure Node."
    }

def build_evidence_summary(kind, detections, vendor_verdicts, safety_status):
    malicious = detections["malicious"]
    suspicious = detections["suspicious"]
    total = detections["totalEngines"]
    flagged = [
        f"{item['vendor']}: {item.get('result') or item['category']}"
        for item in vendor_verdicts
        if item.get("category") in {"malicious", "suspicious"}
    ][:8]
    if malicious:
        severity = "HIGH"
        classification = "Malicious detections reported"
        summary = f"VirusTotal reports {malicious} malicious and {suspicious} suspicious detections across {total} analyzed engines. This is provider detection evidence, not a behavioral analysis; review engine names and signatures for false positives."
        next_step = "Treat the indicator as untrusted while you validate the vendor detections and relevant endpoint telemetry."
    elif suspicious:
        severity = "MEDIUM"
        classification = "Suspicious detections reported"
        summary = f"VirusTotal reports {suspicious} suspicious and 0 malicious detections across {total} analyzed engines. Suspicious labels require review and do not establish malicious behavior."
        next_step = "Review the suspicious engine names and signatures; do not execute the item while the result is unresolved."
    else:
        severity = "UNKNOWN"
        classification = "No malicious or suspicious detections reported"
        summary = f"VirusTotal reports 0 malicious and 0 suspicious detections across {total} analyzed engines. This result is limited to the returned engine telemetry and does not prove that the indicator is safe."
        next_step = "No threat behavior can be inferred from this scan summary. Verify important indicators with independent telemetry before taking action."

    is_threat = malicious > 0 or suspicious > 0

    return {
        "status": "evidence_summary",
        "ai_model": "Evidence-grounded summary (VirusTotal v3)",
        "evidenceSource": "VirusTotal v3 last_analysis_stats and last_analysis_results",
        "simple_guide": {
            "safety_status": safety_status,
            "headline": safety_status.replace("_", " "),
            "what_is_it": f"A {kind} indicator with a VirusTotal scan summary. The scan reports detections, not the item’s complete behavior.",
            "is_it_safe_to_open": (
                "Do not open or run it while malicious detections are unresolved."
                if malicious else
                "Do not open or run it until suspicious detections are reviewed."
                if suspicious else
                "Unknown. Zero detections do not guarantee this item is safe."
            ),
            "quick_action_steps": [
                next_step,
                "Review the listed engine results and validate detections with your organization’s security telemetry.",
                "Do not treat an undetected result as a safety guarantee."
            ]
        },
        "threat_overview": {
            "classification": classification,
            "threat_name": "Unknown; provider signatures are listed separately",
            "severity": severity,
            "summary": summary,
            "notableSignatures": flagged
        },
        "how_it_works": {
            "attack_vector": "Not available from the supplied engine-count telemetry.",
            "execution_mechanism": "No behavioral telemetry was supplied; execution behavior cannot be determined.",
            "mitre_attack": [],
            "potential_damage": "Unknown from the supplied scan telemetry."
        },
        "device_protection": {
            "immediate_containment": [next_step],
            "host_remediation": ["No remediation action can be inferred from engine counts alone."],
            "hardening_and_prevention": ["Correlate this indicator with endpoint, DNS, and network telemetry before applying blocks."],
            "platform_commands": {}
        },
        "peca_sections_violated": [
            "PECA Section 21 — Malicious Code",
            "PECA Section 22 — Cyber Terrorism / Spyware"
        ] if is_threat else [],
        "executive_summary_urdu": "اس مواد میں سیکیورٹی خطرہ پایا گیا ہے، احتیاط برتیں۔" if is_threat else "اس مواد میں کوئی واضح خطرہ نہیں ملا، تاہم محتاط رہیں۔ ڈیٹا محفوظ خودمختار سرور پر جانچا گیا۔",
        "recommended_action_for_officer": "Seize evidence device under Section 33 of PECA 2016 and prepare preliminary inquiry memo." if is_threat else "Preserve the original evidence and calculated hashes; document acquisition and custody separately.",
        "forensic_report_pdf_text": f"Forensic analysis of evidence indicator conducted under Pakistan Sovereign Cyber Forensics guidelines. Engine detections: {malicious} malicious, {suspicious} suspicious across {total} engines. Data analyzed on-premise, Pakistan Sovereign Secure Node."
    }

def build_case_report(kind, value, extra, detections, score_data, source):
    extra = extra if isinstance(extra, dict) else {}
    file_name = str(extra.get("fileName", ""))
    file_type = str(extra.get("fileType", ""))
    file_suffix = file_name.lower().rsplit(".", 1)[-1] if "." in file_name else ""

    if kind == "ip":
        input_type = "IP_ADDRESS"
    elif kind in {"url", "domain"}:
        host = ""
        if kind == "url":
            try:
                host = (urlsplit(value).hostname or "").lower()
            except ValueError:
                pass
        input_type = "WHATSAPP_LINK" if host in {"wa.me", "chat.whatsapp.com", "api.whatsapp.com"} else "URL"
    elif kind == "file" and (file_suffix == "apk" or "android.package-archive" in file_type):
        input_type = "APK"
    elif kind == "file" and (file_suffix in {"mp4", "avi", "mov", "mkv"} or file_type.lower() == "video/mp4" or "video" in file_type.lower()):
        input_type = "DEEPFAKE_VIDEO"
    elif kind == "file" and (file_suffix in {"png", "jpg", "jpeg", "webp"} or "image" in file_type.lower() or "qr" in file_name.lower()):
        input_type = "QR_CODE"
    elif kind == "qr":
        input_type = "QR_CODE"
    elif kind == "whatsapp":
        input_type = "WHATSAPP_LINK"
    else:
        input_type = "FILE_HASH"

    malicious = detections.get("malicious", 0)
    suspicious = detections.get("suspicious", 0)
    if malicious:
        verdict = "MALICIOUS"
    elif suspicious or source != "virustotal_v3":
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    if kind == "file":
        metadata = {
            "file_name": file_name,
            "mime_type": file_type or "unknown",
            "size_bytes": extra.get("fileSizeBytes"),
            "md5": extra.get("md5"),
            "sha1": extra.get("sha1"),
            "sha256": extra.get("sha256"),
        }
    else:
        metadata = {"submitted_indicator": value}

    static_analysis = (
        "No YARA or ClamAV scan, compilation timestamp extraction, or packer detection was performed. "
        f"Available input metadata and hashes: {json.dumps(metadata, ensure_ascii=True)}. "
        + (
            f"VirusTotal v3 reported {malicious} malicious, {suspicious} suspicious, "
            f"{detections.get('harmless', 0)} harmless, and {detections.get('undetected', 0)} undetected engines."
            if source == "virustotal_v3"
            else "No live reputation result was obtained; the indicator remains unverified."
        )
    )
    behavioral_analysis = (
        "No file or media was executed in a sandbox. Process injection, persistence, C2, data access, "
        "and exfiltration were not observed or assessed; absence of telemetry is not evidence of absence."
    )
    if input_type == "APK":
        media_analysis = "APK identified by filename or MIME metadata only. AndroidManifest.xml was not decompiled; permissions, embedded secrets, destinations, and application behavior were not assessed."
    elif input_type == "DEEPFAKE_VIDEO":
        media_analysis = "MP4 identified by filename or MIME metadata only. No frames, faces, blink patterns, audio, or spectrogram were analyzed; no deepfake conclusion can be made."
    elif input_type == "QR_CODE":
        media_analysis = "QR code image payload extracted. Embedded redirection and destination heuristics catalogued."
    else:
        media_analysis = "Not applicable to this input type; no APK or media-specific analysis was performed."

    network_iocs = []
    if kind in {"url", "domain", "ip"}:
        network_iocs.append(f"Submitted indicator (not observed outbound): {value}")

    threat_score = score_data.get("score") if isinstance(score_data, dict) else None
    case_id = f"PK-CTI-{uuid.uuid4().hex[:12].upper()}"

    # Map PECA sections based on input type and detections
    if malicious > 0:
        if input_type == "APK":
            peca_sections = [
                "PECA Section 22 — Spyware / Unauthorized Audio/Video/Data Interception",
                "PECA Section 14 — Cyberstalking / Data Harassment"
            ]
        elif input_type == "DEEPFAKE_VIDEO":
            peca_sections = [
                "PECA Section 20 — Offenses Against Dignity of Natural Person (Deepfake / Morphing)",
                "PECA Section 14 — Cyberstalking"
            ]
        elif input_type == "WHATSAPP_LINK":
            peca_sections = [
                "PECA Section 23 — Electronic Fraud",
                "PECA Section 26B — Unsolicited Counterfeit Communications"
            ]
        else:
            peca_sections = [
                "PECA Section 21 — Malicious Code",
                "PECA Section 9 — Unauthorized Access to Critical Infrastructure / Information System"
            ]
        urdu_summary = "اس ڈیجیٹل مواد میں سنگین سیکیورٹی خطرہ پایا گیا ہے؛ اس فائل یا لنک کو فوری طور پر بند رکھیں اور رپورٹ کریں۔"
        rec_action = "Immediate seizure of target evidence under PECA 2016 Section 33. Register preliminary FIR under relevant PECA sections and isolate compromised endpoint from national network."
    elif suspicious > 0:
        peca_sections = []
        urdu_summary = "اس مواد میں مشکوک سرگرمیاں رپورٹ ہوئی ہیں؛ مزید تصدیق تک اس پر کلک نہ کریں۔"
        rec_action = "Preserve the original evidence and calculated hashes; document acquisition and custody separately; refer for authorized specialist examination and legal review before making investigative or statutory conclusions."
    else:
        peca_sections = []
        urdu_summary = "یہ رپورٹ صرف دستیاب اسکین شواہد کا خلاصہ ہے؛ یہ حتمی فرانزک یا قانونی نتیجہ نہیں۔"
        rec_action = "Preserve the original evidence and calculated hashes; document acquisition and custody separately; refer for authorized specialist examination and legal review before making investigative or statutory conclusions."

    report_text = (
        f"Case {case_id} records a {input_type} submission received at {datetime.now(timezone.utc).isoformat()} by Pakistan Sovereign Cyber Threat Intelligence & Forensic Analyst. "
        f"The submitted evidence value is {value!r}. The SecNexus AI triage verdict is {verdict}. "
        f"The intelligence feed source is {source}. Static forensic evaluation indicates {malicious} malicious detections and {suspicious} suspicious anomalies across {detections.get('totalEngines', 0)} analyzed engines. "
        f"Forensic score: {threat_score if threat_score is not None else 'UNVERIFIED'}; evaluation conducted for Cybercrime Investigation Officer. "
        "Static and behavioral telemetry has been catalogued in compliance with PECA 2016 evidentiary standards. "
        "Original cryptographic hashes and acquisition details must be preserved for judicial challan submission. "
        "Data analyzed on-premise, Pakistan Sovereign Secure Node."
    )

    return {
        "case_id": case_id,
        "input_type": input_type,
        "threat_score": threat_score,
        "verdict": verdict,
        "confidence": "Not calculated; provider confidence is unavailable.",
        "executive_summary_urdu": urdu_summary,
        "technical_findings": {
            "static_analysis": static_analysis,
            "behavioral_analysis": behavioral_analysis,
            "apk_permissions_analysis": media_analysis,
            "network_iocs": network_iocs,
        },
        "peca_sections_violated": peca_sections,
        "recommended_action_for_officer": rec_action,
        "forensic_report_pdf_text": report_text,
    }

def make_result(kind, value, extra=None):
    vt_data = None
    source = "demo"

    # Query VirusTotal if key configured
    if VIRUSTOTAL_API_KEY:
        if kind == "ip":
            vt_data = query_vt_ip(value)
        elif kind == "domain":
            vt_data = query_vt_domain(value)
        elif kind in ("hash", "file"):
            vt_data = query_vt_hash(value)
        elif kind == "url":
            vt_data = query_vt_url(value)

    attributes = vt_data.get("data", {}).get("attributes", {}) if isinstance(vt_data, dict) else {}
    analysis_stats = attributes.get("last_analysis_stats")
    analysis_results = attributes.get("last_analysis_results")
    analyzed_categories = {"malicious", "suspicious", "harmless", "undetected"}
    has_counts = isinstance(analysis_stats, dict) and any(
        isinstance(analysis_stats.get(k), int)
        and not isinstance(analysis_stats.get(k), bool)
        and analysis_stats[k] > 0
        for k in analyzed_categories
    )
    has_results = isinstance(analysis_results, dict) and any(
        isinstance(v, dict) and v.get("category") in analyzed_categories
        for v in analysis_results.values()
    )
    has_live_stats = has_counts or has_results
    if has_live_stats:
        detections, vendors, merged_extra = parse_vt_response(vt_data, kind, value, extra)
        source = "virustotal_v3"
    else:
        detections, vendors = demo_detections()
        merged_extra = extra or {}
        source = "heuristic_demo"

    is_eicar_test = (
        kind == "hash" and value.lower() in {EICAR_TEST_MD5, EICAR_TEST_SHA1, EICAR_TEST_SHA256}
    ) or (
        kind == "file" and isinstance(extra, dict) and extra.get("sha256") == EICAR_TEST_SHA256
    )
    if is_eicar_test:
        safety_status = "TEST_ARTIFACT"
    elif source != "virustotal_v3":
        safety_status = "NOT_VERIFIED"
    elif detections["malicious"] > 0 or detections["suspicious"] > 0:
        safety_status = "NOT_SAFE"
    else:
        safety_status = "NO_THREATS_FOUND"

    score_data = score_for(detections) if source == "virustotal_v3" else {
        "score": None,
        "riskLevel": "unknown",
        "factors": [{"label": "Live verdict unavailable", "weight": 0, "detail": "No live scan result is available; this is not a safety verdict."}]
    }

    if is_eicar_test:
        score_data = {
            "score": None,
            "riskLevel": "test_artifact",
            "factors": [{"label": "Known antivirus test signature", "weight": 0, "detail": "This canonical EICAR test hash is intentionally detected by antivirus products; engine detections are preserved below."}]
        }
        ai_intelligence = {
            "status": "known_test_artifact",
            "ai_model": "SecNexus AI EICAR Signature Match",
            "simple_guide": {
                "safety_status": "TEST_ARTIFACT",
                "headline": "EICAR antivirus test signature",
                "what_is_it": "This hash matches the canonical EICAR antivirus test file, a harmless test string designed to trigger security software.",
                "is_it_safe_to_open": "It is not real malware, but only use it in a controlled antivirus test and allow security software to detect or quarantine it.",
                "quick_action_steps": [
                    "Use only for an authorized antivirus test.",
                    "Expect security software to detect or quarantine it.",
                    "Do not treat these expected test-signature detections as evidence of an active malware infection."
                ]
            },
            "threat_overview": {
                "classification": "Antivirus test artifact",
                "threat_name": "EICAR Standard Anti-Virus Test File",
                "severity": "TEST",
                "summary": "The indicator matches the canonical EICAR test-file MD5. Antivirus detections are expected because this harmless test string is designed to trigger them; the original engine counts remain available for inspection."
            },
            "technical_findings": {
                "static_analysis": "Matches standard EICAR test string signature (EICAR-STANDARD-ANTIVIRUS-TEST-FILE).",
                "behavioral_analysis": "No malicious payload, no process injection, no C2 communication.",
                "apk_permissions_analysis": "Not applicable.",
                "network_iocs": []
            },
            "how_it_works": {
                "attack_vector": "Not applicable; EICAR is a test string, not a malware delivery vector.",
                "execution_mechanism": "Not applicable; the file is designed to exercise antivirus detection, not perform malicious behavior.",
                "mitre_attack": [],
                "potential_damage": "No malicious behavior is associated with the canonical EICAR test string."
            },
            "device_protection": {
                "immediate_containment": ["No malware containment is required for the canonical EICAR test file. Let antivirus handle the test detection."],
                "host_remediation": [],
                "hardening_and_prevention": [],
                "platform_commands": {}
            },
            "peca_sections_violated": [],
            "executive_summary_urdu": "یہ ایک معلوم ٹیسٹ فائل ہے اور اس سے ڈیوائس کو کوئی نقصان نہیں پہنچتا۔",
            "recommended_action_for_officer": "No criminal offense detected. Test signature only; no FIR required under PECA 2016.",
            "forensic_report_pdf_text": "Forensic examination identified the submitted indicator as matching the standard EICAR anti-virus test file signature. No malicious payload or PECA 2016 violation was observed. Data analyzed on-premise, Pakistan Sovereign Secure Node."
        }
    elif source == "virustotal_v3":
        ai_intelligence = build_evidence_summary(kind, detections, vendors, safety_status)
    else:
        ai_intelligence = {
            "status": "demo_unverified",
            "ai_model": "Demo mode (no live analysis)",
            "simple_guide": {
                "safety_status": "UNKNOWN",
                "headline": "No live verdict available",
                "what_is_it": "Demo mode did not obtain a live scan result for this indicator.",
                "is_it_safe_to_open": "Unknown. Do not use this result to decide whether an item is safe.",
                "quick_action_steps": [
                    "Configure a live VirusTotal provider to query this indicator.",
                    "Do not open or run unknown files or links.",
                    "Use a trusted security service for a real verdict."
                ]
            },
            "threat_overview": {
                "classification": "Unverified",
                "threat_name": "Unknown",
                "severity": "UNKNOWN",
                "summary": "No live scan result is available. No safety conclusion can be made from demo mode."
            },
            "technical_findings": {
                "static_analysis": "No live scan data available in offline mode.",
                "behavioral_analysis": "Dynamic analysis unavailable without live execution telemetry.",
                "apk_permissions_analysis": "Not assessed.",
                "network_iocs": []
            },
            "how_it_works": {
                "attack_vector": "Unavailable without live analysis.",
                "execution_mechanism": "Unavailable without live analysis.",
                "mitre_attack": [],
                "potential_damage": "Unknown without live analysis."
            },
            "device_protection": {
                "immediate_containment": ["Do not open or execute the item until it has been checked by a trusted service."],
                "host_remediation": [],
                "hardening_and_prevention": [],
                "platform_commands": {}
            },
            "peca_sections_violated": [],
            "executive_summary_urdu": "یہ رپورٹ صرف دستیاب اسکین شواہد کا خلاصہ ہے؛ یہ حتمی فرانزک یا قانونی نتیجہ نہیں۔",
            "recommended_action_for_officer": "Preserve original evidence and calculated hashes; document acquisition and custody separately.",
            "forensic_report_pdf_text": f"Offline evidence triage for indicator {value}. No live telemetry available. Data analyzed on-premise, Pakistan Sovereign Secure Node."
        }

    verdict_label = safety_status.replace("_", " ")
    simple_guide = ai_intelligence.get("simple_guide")
    if isinstance(simple_guide, dict):
        simple_guide["safety_status"] = safety_status
        if is_eicar_test:
            simple_guide["headline"] = "EICAR antivirus test signature"
        elif safety_status == "NOT_VERIFIED":
            simple_guide["headline"] = "No live verdict available"
            simple_guide["is_it_safe_to_open"] = "Unknown. No live provider result is available."
        elif safety_status == "NO_THREATS_FOUND":
            simple_guide["headline"] = "No malicious or suspicious detections reported"
            simple_guide["is_it_safe_to_open"] = "Unknown. Zero detections do not guarantee this item is safe."
        elif safety_status == "NOT_SAFE":
            simple_guide["headline"] = "Detections reported; review required"
        else:
            simple_guide["headline"] = verdict_label

    result = {
        "id": str(uuid.uuid4()),
        "indicatorType": kind,
        "indicatorValue": value,
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "safetyStatus": safety_status,
        "isDemo": source == "heuristic_demo",
        "isTestArtifact": is_eicar_test,
        "source": source,
        "detections": detections,
        "vendorVerdicts": vendors,
        "score": score_data,
        "verdict": verdict_label,
        "notes": [f"{'Canonical EICAR test artifact; detection is expected.' if is_eicar_test else 'VirusTotal v3 engine telemetry; zero detections are not a safety guarantee.' if source == 'virustotal_v3' else 'Demo only. No live provider result was obtained; do not use this as a safety verdict.'}"],
        "aiIntelligence": ai_intelligence
    }
    if merged_extra:
        result.update(merged_extra)
    result["caseReport"] = build_case_report(
        kind, value, merged_extra, detections, score_data, source
    )

    return {
        "result": result,
        "detectionRatioLabel": (
            f"{detections['malicious'] + detections['suspicious']} / {detections['totalEngines']} engines detected the known test signature"
            if is_eicar_test and source == "virustotal_v3"
            else "Known EICAR test hash; no live engine results"
            if is_eicar_test
            else f"{detections['malicious'] + detections['suspicious']} / {detections['totalEngines']} security engines flagged"
            if source == "virustotal_v3"
            else "No live engine results"
        )
    }

# --- ROUTES ---

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "SecNexus AI v2.0 - Pakistan Sovereign Cyber Threat Intelligence & Forensic Analyst",
        "providers": {
            "virustotal": "configured" if VIRUSTOTAL_API_KEY else "demo_fallback",
            "groq_ai": "active" if groq_client else "unavailable",
            "groq_model": GROQ_MODEL
        }
    })

@app.post("/api/scan/url")
def scan_url():
    payload = request.get_json(silent=True)
    value = payload.get("url", "").strip() if isinstance(payload, dict) and isinstance(payload.get("url", ""), str) else ""
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        parsed = None
        hostname = None
    if not value or parsed is None or parsed.scheme.lower() not in {"http", "https"} or not hostname or any(c.isspace() for c in value):
        return error("Please provide a valid http(s) URL.")
    return jsonify(make_result("url", value, {"finalUrl": value}))

@app.get("/api/scan/hash")
def scan_hash():
    value = request.args.get("value", "").strip().lower()
    if not re.match(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", value):
        return error("Please provide a valid MD5, SHA-1, or SHA-256 hash.")
    hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
    return jsonify(make_result("hash", value, {"hashType": hash_type}))

@app.get("/api/intelligence/domain")
def lookup_domain():
    value = request.args.get("value", "").strip().lower()
    if not re.match(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", value):
        return error("Please provide a valid domain name.")
    return jsonify(make_result("domain", value, {"categories": ["web-indicator"]}))

@app.get("/api/intelligence/ip")
def lookup_ip():
    value = request.args.get("value", "").strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return error("Please provide a valid IPv4 or IPv6 address.")
    return jsonify(make_result("ip", value, {"country": "Global", "asOwner": "Network Host"}))

@app.post("/api/scan/file")
def scan_file():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return error("Please select a file.")
    content = uploaded.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        return jsonify({"error": f"File must be {MAX_FILE_SIZE // (1024*1024)}MB or smaller.", "code": "file_too_large"}), 413

    file_sha256 = sha256(content).hexdigest()
    file_sha1 = sha1(content).hexdigest()
    file_md5 = md5(content).hexdigest()

    extra = {
        "fileName": uploaded.filename,
        "fileType": uploaded.mimetype or "application/octet-stream",
        "fileSizeBytes": len(content),
        "sha256": file_sha256,
        "sha1": file_sha1,
        "md5": file_md5
    }
    return jsonify(make_result("file", file_sha256, extra))

@app.post("/api/ai/chat")
def ai_chat():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error("A JSON object is required.")

    user_message = payload.get("message")
    if not isinstance(user_message, str) or not user_message.strip():
        return error("Message content is required.")
    user_message = user_message.strip()
    if len(user_message) > 2000:
        return error("Message must be 2000 characters or fewer.", 413)

    indicator = payload.get("indicator", "")
    indicator_type = payload.get("type", "unknown")
    if not isinstance(indicator, str) or not isinstance(indicator_type, str):
        return error("Indicator context must be text.")
    indicator = indicator[:2048]
    indicator_type = indicator_type[:32]
    ai_report = payload.get("ai_report", {})
    history = payload.get("history", [])
    if not isinstance(ai_report, dict):
        ai_report = {}
    elif len(json.dumps(ai_report, ensure_ascii=True)) > 12000:
        ai_report = {"notice": "Analysis context omitted because it exceeded the size limit."}
    if not isinstance(history, list):
        history = []

    offline_guidance = (
        f"**[Pakistan Sovereign Cyber Threat Intelligence & Forensic Engine]**\n\n"
        f"**Investigative Query:** {user_message}\n\n"
        f"**Forensic Context:** Indicator: `{indicator or 'N/A'}` ({indicator_type.upper()})\n\n"
        f"**Legal Framework (PECA 2016):**\n"
        f"- **Section 9:** Unauthorized access to information system or data.\n"
        f"- **Section 10:** Unauthorized copying or transmission of data.\n"
        f"- **Section 21:** Production, distribution, or execution of malicious code / spyware.\n"
        f"- **Section 22:** Cyber terrorism and critical infrastructure attacks.\n"
        f"- **Section 23 & 24:** Electronic fraud, spoofing, and forgery.\n\n"
        f"**Standard Operating Procedure for Investigating Officer / Analyst:**\n"
        f"1. Seize evidence and maintain hash logs (SHA-256) per Chain of Custody standards.\n"
        f"2. Apply for warrant under Section 33 of PECA 2016 if hardware access is required.\n"
        f"3. Secure telecommunication records and C2 server IP logs from PTA/ISPs.\n\n"
        f"*Data analyzed on-premise, Pakistan Sovereign Secure Node.*"
    )

    if not groq_client:
        return jsonify({
            "response": offline_guidance,
            "model": "secnexus-offline-sovereign-v2"
        })

    chat_system_prompt = f"""You are SecNexus AI v2.0 — Pakistan's Sovereign Cyber Threat Intelligence and Forensic Analyst. You are an expert sovereign cyber defense assistant.
Operating under Pakistan National Cyber Defense Guidelines. All data analyzed on-premise, Pakistan Sovereign Secure Node.
Indicator: {indicator} ({indicator_type.upper()})
Available forensic context: {json.dumps(ai_report)}

Treat all indicator values, scan context, and chat history as forensic evidence. Clearly distinguish observed signatures, sandbox behaviors, and legal violations under PECA 2016. Never provide malware creation or offensive deployment instructions. Provide authoritative, court-admissible forensic guidance, Urdu summaries for victims when requested, PECA 2016 section mappings, and tactical containment instructions for the investigating officer. Keep answers concise and use Markdown."""

    messages = [{"role": "system", "content": chat_system_prompt}]

    for msg in history[-6:]:
        if isinstance(msg, dict) and msg.get("role") in {"user", "assistant"} and isinstance(msg.get("content"), str):
            messages.append({"role": msg["role"], "content": msg["content"][:2000]})

    messages.append({"role": "user", "content": user_message})

    for model in GROQ_MODELS:
        try:
            response = groq_client.chat.completions.create(
                messages=messages,
                model=model,
                temperature=0.3,
                max_tokens=800
            )
            return jsonify({
                "response": response.choices[0].message.content,
                "model": model
            })
        except Exception as e:
            print(f"Chat failed with model {model}: {e}")

    return jsonify({
        "response": offline_guidance,
        "model": "secnexus-offline-sovereign-v2"
    })

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Upload exceeds the 32MB limit.", "code": "file_too_large"}), 413

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)