# ThreatLens

ThreatLens is a standalone security intelligence dashboard built with Flask, HTML, CSS, and browser JavaScript. It supports file, URL, domain, IP, and hash analysis. Without a live VirusTotal result, the app labels the result unverified instead of inventing detections or declaring the indicator safe.

The canonical EICAR antivirus test-file hashes are identified as a test artifact. Expected antivirus detections remain visible, but are not presented as a malware risk score. Results distinguish an unavailable live verdict (`NOT VERIFIED`) from a live scan with no malicious or suspicious detections (`NO THREATS FOUND`); no-detection results are not guarantees that an indicator is safe. Scan summaries use only returned VirusTotal engine telemetry. They do not infer file behavior, threat actors, or MITRE ATT&CK techniques without supporting evidence.

The 0–100 detection score is a transparent heuristic, not a probability: malicious detections contribute `round(85 × malicious / analyzed_engines)` points and suspicious detections contribute `round(25 × suspicious / analyzed_engines)` points, capped at 100. The result lists the evidence source and calculation for each factor. If no engines returned an analyzed result, the score is unavailable rather than zero.

## Run locally

Install Python 3.10+ and then run:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python backend.py
```

Open http://127.0.0.1:5000.

The app runs in clearly labeled demo mode. Demo results are not real security verdicts and no uploaded file is written to disk or executed. File bytes are held in memory only long enough to calculate MD5, SHA-1, and SHA-256 hashes.

To enable live lookups, copy `.env.example` to `.env` and set your own `VIRUSTOTAL_API_KEY`. Groq is optional and is used for analyst chat; it does not generate scan verdicts. Never commit `.env` or publish API keys.

## Verify

Run the focused backend tests with:

```bash
python -m unittest discover -s tests -v
```

## API

| Route | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Health check |
| `/api/scan/url` | POST | JSON body: `{ "url": "https://example.com" }` |
| `/api/scan/hash?value=...` | GET | MD5, SHA-1, or SHA-256 lookup |
| `/api/intelligence/ip?value=...` | GET | IP lookup |
| `/api/intelligence/domain?value=...` | GET | Domain lookup |
| `/api/scan/file` | POST | Multipart upload using the `file` field |

## Project structure

```text
backend.py
requirements.txt
templates/index.html
static/style.css
static/app.js
```
