# 🛡️ SajagQR Shield (सजग QR)
> **Defensive Security & Threat Forensics Engine for Nepal's Digital Payment Ecosystem**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Framework: Streamlit](https://img.shields.io/badge/Framework-Streamlit-red.svg)](https://streamlit.io/)
[![Standard: NepalQR / EMVCo](https://img.shields.io/badge/Standard-NRB%20NepalQR%20%2F%20EMVCo-orange.svg)](https://www.nrb.org.np/)

**SajagQR Shield** is an open-source, client-side cybersecurity tool engineered to detect **quishing (QR phishing)**, physical standee sticker swaps, and malicious financial redirections targeting Nepal's digital payment infrastructure. 

It provides real-time forensic payload decoding, zero-trust beneficiary inspection, and deterministic threat scoring across licensed Class "A" commercial banks, digital payment service providers (PSPs), and enterprise mobile attribution routers.

---

## 🌟 Key Capabilities

* **EMVCo & NepalQR TLV Decoding:** Parses Tag-Length-Value (TLV) structures on official retail standees to extract merchant names (Tag `59`), registered cities (Tag `60`), and acquirer endpoints.
* **Physical Standee Tamper Detection:** Distinguishes peer-to-peer (P2P) personal wallet IDs from merchant stands, warning users when an individual's QR sticker is overlaid on a retail standee.
* **Fintech & Banking Typosquatting Defense:** Detects homoglyph attacks, Punycode tricks (`xn--`), sub-domain nesting, and deceptive brand-impersonation URLs mimicking licensed institutions.
* **App Router & Deep-Link Attribution:** Differentiates legitimate campaign smart-routers (AppsFlyer, Firebase, Branch.io) from obfuscated link shorteners (Bitly, TinyURL).
* **Multi-Format Ingestion:** Accepts live camera feeds, screenshot/image uploads, or direct raw URI/deep-link payloads for instant auditing.
* **Official Incident Reporting:** Auto-generates structured incident telemetry compatible with the **Nepal Police Cyber Bureau** reporting desk.

---

## 🏛️ Ecosystem Coverage

| Category | Monitored Entities & Protocols |
| :--- | :--- |
| **National Standards** | NepalQR Interoperable Specification, EMVCo Merchant Standards |
| **Commercial Banks (20)** | Nabil, Global IME, NIC Asia, Laxmi Sunrise, Sanima, Himalayan, Siddhartha, Nepal Bank, RBB, Everest, Standard Chartered, Prabhu, Kumari, NMB, Prime, Machhapuchchhre, Nepal SBI, NIMB, Citizens, ADBL |
| **Digital Wallets & PSPs** | eSewa, Khalti, Fonepay, PrabhuPAY, Hamro Pay, IME Pay, Namaste Pay, Moru, connectIPS (NCHL) |
| **Smart Routers** | AppsFlyer (`onelink.me`), Branch.io (`app.link`), Firebase Dynamic Links (`page.link`), Adjust, Kochava, Singular, Airbridge, uLink, Tenjin, Linkrunner |

---

## 🚀 Quickstart & Installation

### Prerequisites
* Python 3.10 or higher
* System OpenCV / ZBar libraries:
  * **Arch Linux:** `sudo pacman -S zbar libglvnd`
  * **Ubuntu / Debian:** `sudo apt install libzbar0 libgl1`
  * **Windows:** Ensure [Microsoft Visual C++ Redistributable (x64)](https://aka.ms/vs/17/release/vc_redist.x64.exe) is installed.

### 1. Clone the Repository
```bash
git clone [https://github.com/Sangharsa-adk/QR-shield.git](https://github.com/Sangharsa-adk/QR-shield.git)
cd QR-shield

2. Set Up Virtual Environment
Bash
# Linux / macOS
python -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

3. Install Dependencies
Bash
pip install --upgrade pip
pip install -r requirements.txt

4. Launch the Telemetry Dashboard
Bash
streamlit run app.py
The application will open in your browser at http://localhost:8501.

🛠️ Detection Methodology & Scoring Architecture
Every ingested QR code passes through a four-stage forensic pipeline:

Plaintext
[QR Matrix / Raw URL]
         │
         ▼
[Multi-Stage Decoder] ── (Pyzbar ➜ Otsu Adaptive Threshold ➜ OpenCV Fallback)
         │
         ▼
[Payload Classifier]
         ├── EMVCo Standee ────────► Decodes POS Merchant & Location (Risk: 0)
         ├── P2P Wallet JSON ──────► Extracts Beneficiary & Verifies Telecom Syntax (Risk: 0-5)
         ├── Deep Link Scheme ─────► Validates Whitelisted App Invocations (Risk: 10)
         └── Web URL / Gateway ────► Audits SSL, Punycode, Routers & Brand Keywords
                                           │
                                           ▼
[Threat Engine] ─────────────────► Outputs Verdict (SAFE / LOW_RISK / SUSPICIOUS / CRITICAL)

* Threat Scoring Metrics
SAFE (0 / 100): Official EMVCo NepalQR specifications, licensed banking portals, verified merchant standees.

* LOW RISK (5–15 / 100): Validated in-app wallet transfers, verified AppsFlyer/Branch app attribution routing.

* SUSPICIOUS (30–65 / 100): Unencrypted HTTP endpoints, unrecognized external hosts, nested subdomain chains.

* CRITICAL FRAUD RISK (70–100 / 100): Detected brand typosquatting, Punycode homoglyphs, naked IP destinations, or obfuscated link shorteners concealing payment requests.

🚨 Incident Response & Reporting
When a payload receives a CRITICAL_FRAUD_RISK rating, SajagQR generates an exportable JSON incident artifact containing:
* Raw payload signature and canonical target URL.
* Triggered threat markers and heuristic flags.
* Timestamped telemetry for filing fraud alerts with the Nepal Plice  Cyber Bureau:
    Hotline: 01-5319044 / 100
    Email: cyberbureau@nepalpolice.gov.np

🤝 Contributing
Contributions to expand signature coverage, improve CV decoding under extreme lighting, or add new PSP schemes are welcome!

Fork the Project

Create your Feature Branch (git checkout -b feature/NewFintechSupport)

Commit your Changes (git commit -m 'Add detection rule for XYZ Gateway')

Push to the Branch (git push origin feature/NewFintechSupport)

Open a Pull Request

📄 License
Distributed under the MIT License. See LICENSE for more information.

👤 Author
Developed and maintained by Sangharsa Adhikari.


---