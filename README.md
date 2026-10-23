# SecNexus AI v2.0 — Pakistan's Sovereign Cyber Threat Intelligence & Forensic Analyst

**Pakistan's Sovereign Cyber Threat Intelligence & Forensic Behavioral Analyst**

> 🇵🇰 **SOVEREIGN CYBER DEFENSE** — Pakistan National Cyber Defense Framework  
> Data analyzed on-premise, Pakistan Sovereign Secure Node.

SecNexus AI v2.0 is a sovereign, forensic-grade cyber threat intelligence and behavioral analysis platform designed to protect Pakistan's cyberspace and digital infrastructure. It performs deep behavioral dissection of digital evidence, maps offenses directly to the **Pakistan Electronic Crimes Act (PECA 2016)**, and synthesizes court-admissible FIR evidence packets.

## Features

- **MODULE 1 — Input Classification**: FILE_HASH, URL, APK, IP_ADDRESS, WHATSAPP_LINK, QR_CODE, DEEPFAKE_VIDEO
- **MODULE 2 — 5-Layer Forensic Analysis**: Static Signatures → Cuckoo Behavioral Sandbox Simulation → APK Hunter / Android Permission Telemetry → Phishing & Deepfake Artifact Detection → PECA 2016 Statutory Attribution
- **MODULE 3 — Evidentiary Output**: Structured court-ready JSON with PECA sections, Urdu victim explanation, investigating officer action recommendations, and formal court challan text
- **AI Engine**: Groq AI with SecNexus sovereign forensic system prompt (with offline sovereign fallback)
- **Threat Intelligence**: VirusTotal v3 API integration (70+ security engines)
- **PECA 2016 Mapping**: Automatic statutory violation identification and legal attribution
- **Urdu Summaries**: Clear, compassionate, plain-language summaries for citizens and victims in Urdu
- **Export**: 1-click FIR Markdown copy and Sovereign JSON case packet download

## Tech Stack

- **Backend**: Python 3.10+ · Flask · Groq AI SDK · Requests
- **Frontend**: Vanilla HTML5 · CSS3 (Sovereign Cyber Theme) · JavaScript (ES6+)
- **AI Model**: Groq (openai/gpt-oss-120b or offline heuristic engine)
- **Threat Intel**: VirusTotal v3 API

## Demo Video

[Recording.mp4](Recording.mp4) — SecNexus AI v2.0 Demo

## Run Locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python backend.py
```

Open http://127.0.0.1:5000

## Configuration

Copy `.env.example` to `.env`:

```env
VIRUSTOTAL_API_KEY=your_vt_key_here
GROQ_API_KEY=your_groq_key_here
GROQ_MODEL=openai/gpt-oss-120b
```

Never commit `.env` or publish private API keys.

## API Endpoints

| Route | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Sovereign system health and provider status |
| `/api/scan/url` | POST | URL, domain, and WhatsApp link forensic analysis |
| `/api/scan/hash?value=...` | GET | Cryptographic hash lookup (MD5/SHA-1/SHA-256) |
| `/api/intelligence/ip?value=...` | GET | IP address telemetry and C2 indicator analysis |
| `/api/intelligence/domain?value=...` | GET | Domain reputation and spoofing analysis |
| `/api/scan/file` | POST | APK, media, binary, or evidence artifact upload |
| `/api/ai/chat` | POST | Interactive sovereign forensic defense analyst chat |

## PECA 2016 Reference

| Section | Offense |
|---|---|
| Section 9 | Unauthorized access to critical infrastructure / information system |
| Section 10 | Unauthorized copying or transmission of critical data |
| Section 14 | Cyberstalking and digital harassment |
| Section 20 | Offenses against dignity of natural persons (morphing / deepfakes) |
| Section 21 | Malicious code production, distribution, or execution |
| Section 22 | Cyber terrorism and espionage / spyware |
| Section 23 | Electronic fraud and identity theft |
| Section 24 | Electronic forgery and counterfeit digital assets |
| Section 26B | Unsolicited counterfeit communications / spam |

## Project Structure

```
backend.py
requirements.txt
templates/index.html
static/style.css
static/app.js
tests/test_backend.py
Recording.mp4
```

## Sovereignty Notice

This system operates under sovereign cyber defense guidelines. All evidence submissions are handled securely on-premise without exposing private telemetry to unauthorized third parties.
