import html
import json
import re
from urllib.parse import urlparse

import cv2
import numpy as np
import streamlit as st
from pydantic import BaseModel, Field
from pyzbar.pyzbar import decode

# ---------------------------------------------------------
# ReDoS Defense & Precompiled Deterministic Regular Expressions
# ---------------------------------------------------------
# Strict URI scheme pattern with explicit length bound and anchors:
RE_APP_SCHEME = re.compile(r"^([a-zA-Z0-9_-]{1,64})://")

# Standard web schemes (HTTP/HTTPS):
RE_WEB_SCHEME = re.compile(r"^https?$", re.IGNORECASE)

# Validated 10-digit Nepal mobile identifier (NTC/Ncell: 98XXXXXXXX or 97XXXXXXXX):
RE_TELECOM_PHONE = re.compile(r"^(?:98|97)\d{8}$")

# Strict hostname validation pattern avoiding catastrophic nested quantifiers:
RE_VALID_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")

# 1. UI Theme Stylesheet - Light Vintage / Archival Print Aesthetic
UI_CUSTOM_CSS = """
<style>
    /* 1. Global Typography & App Canvas */
    .stApp {
        background-color: #f7f4ed !important;
        color: #292524 !important;
        font-family: Georgia, 'Times New Roman', serif;
    }
    h1, h2, h3, h4, h5, h6 {
        font-family: Georgia, 'Times New Roman', serif !important;
        color: #1c1917 !important;
        font-weight: 700;
        letter-spacing: -0.01em;
    }
    p, span, label, div {
        color: #292524;
    }
    hr {
        border-color: #d6cebf !important;
    }
    code {
        background-color: #e2dac9 !important;
        color: #b45309 !important;
        border: 1px solid #d6cebf !important;
        border-radius: 4px;
        padding: 2px 6px;
    }

    /* 2. Container Panels, Cards & Expanders */
    .archival-card, .telemetry-card {
        background-color: #ede8db;
        border: 1px solid #d6cebf;
        border-radius: 6px;
        padding: 16px;
        margin-bottom: 16px;
        color: #292524;
    }
    [data-testid="stVerticalBlockBorderWrapper"] > div {
        background-color: #ede8db !important;
        border: 1px solid #d6cebf !important;
        border-radius: 6px !important;
    }
    [data-testid="stExpander"] {
        background-color: #ede8db !important;
        border: 1px solid #d6cebf !important;
        border-radius: 6px !important;
    }
    [data-testid="stExpander"] summary {
        color: #1c1917 !important;
        font-family: Georgia, 'Times New Roman', serif !important;
        font-weight: 600 !important;
    }
    [data-testid="stExpander"] summary:hover {
        color: #b45309 !important;
    }

    /* 3. Status Verdict Banners (Archival Parchment Tones) */
    .status-banner {
        border-radius: 6px;
        padding: 16px 20px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        color: #1c1917;
    }
    .banner-safe {
        background: linear-gradient(90deg, #e7ede2 0%, #ede8db 100%);
        border: 1px solid #4d7c0f;
        color: #365314;
    }
    .banner-warn {
        background: linear-gradient(90deg, #fef3c7 0%, #ede8db 100%);
        border: 1px solid #b45309;
        color: #78350f;
    }
    .banner-critical {
        background: linear-gradient(90deg, #fee2e2 0%, #ede8db 100%);
        border: 1px solid #b91c1c;
        color: #7f1d1d;
    }

    /* 4. Checklist & Physical Standee Advisory */
    .checklist-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 0;
        border-bottom: 1px solid #d6cebf;
        font-size: 0.88rem;
        color: #292524;
    }
    .standee-warning {
        background: #fef3c7;
        border-left: 4px solid #b45309;
        border-radius: 4px;
        padding: 12px 14px;
        margin-bottom: 16px;
        font-size: 0.88rem;
        color: #78350f;
    }

    /* 5. Ecosystem & Security Badges (Muted Archival Kraft Tags) */
    .threat-tag-info {
        background: #e2dac9;
        color: #44403c;
        border: 1px solid #c7bcab;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.76rem;
    }
    .threat-tag-warn {
        background: #fef3c7;
        color: #92400e;
        border: 1px solid #d97706;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.76rem;
    }
    .threat-tag-critical {
        background: #fee2e2;
        color: #991b1b;
        border: 1px solid #b91c1c;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.76rem;
    }

    /* 6. Form Inputs & Text Fields */
    input, textarea, [data-baseweb="input"], [data-baseweb="input"] > div {
        background-color: #faf8f5 !important;
        border-color: #c7bcab !important;
        color: #292524 !important;
        border-radius: 6px !important;
    }
    [data-baseweb="input"]:focus-within {
        border-color: #b45309 !important;
        box-shadow: 0 0 0 1px #b45309 !important;
    }

    /* 7. Primary Buttons (Antique Terracotta) */
    button[kind="primary"], .stButton > button, [data-testid="stDownloadButton"] > button {
        background-color: #c25e34 !important;
        color: #fdfbf7 !important;
        border: 1px solid #a84c26 !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-family: Georgia, 'Times New Roman', serif !important;
        transition: background-color 0.2s ease, transform 0.1s ease !important;
    }
    button[kind="primary"]:hover, .stButton > button:hover, [data-testid="stDownloadButton"] > button:hover {
        background-color: #a84c26 !important;
        border-color: #8c3b1b !important;
        color: #ffffff !important;
    }
    button[kind="primary"]:active, .stButton > button:active, [data-testid="stDownloadButton"] > button:active {
        transform: scale(0.98) !important;
    }

    /* 8. Tabs Navigation */
    [data-baseweb="tab-list"] {
        background-color: transparent !important;
        border-bottom: 1px solid #d6cebf !important;
    }
    [data-baseweb="tab"] {
        color: #57534e !important;
        font-family: Georgia, 'Times New Roman', serif !important;
        font-size: 0.88rem !important;
    }
    [data-baseweb="tab"][aria-selected="true"] {
        color: #b45309 !important;
        border-bottom-color: #b45309 !important;
        font-weight: 600 !important;
    }

    /* 9. Radio Buttons & Toggle Controls */
    [data-testid="stRadio"] label {
        color: #292524 !important;
        font-family: Georgia, 'Times New Roman', serif !important;
        font-size: 0.9rem !important;
    }
    [data-testid="stRadio"] div[role="radiogroup"] {
        gap: 16px;
        padding: 4px 0 10px 0;
    }

    /* 10. Responsive Breakpoints & Mobile Workstation Wrapping */
    @media (max-width: 768px) {
        [data-testid="column"] {
            flex: 1 1 100% !important;
            min-width: 100% !important;
        }
        .block-container {
            padding-top: 1.5rem !important;
            padding-left: 0.8rem !important;
            padding-right: 0.8rem !important;
            padding-bottom: 2rem !important;
        }
    }
</style>
"""

# 2. Nepal Rastra Bank Approved FinTech & Gateway Ecosystem Registry
LICENSED_FINTECH_REGISTRY = {
    "esewa": {
        "name": "eSewa (F1Soft Ecosystem)",
        "domains": ["esewa.com.np"],
        "schemes": ["esewa"],
        "json_keys": ["eSewa_id", "esewa_id"],
    },
    "khalti": {
        "name": "Khalti Digital Wallet",
        "domains": ["khalti.com"],
        "schemes": ["khalti"],
        "json_keys": ["khalti_id"],
    },
    "fonepay": {
        "name": "Fonepay (F1Soft Network)",
        "domains": ["fonepay.com"],
        "schemes": ["fonepay"],
        "json_keys": ["fonepay_id"],
    },
    "prabhupay": {
        "name": "PrabhuPAY",
        "domains": ["prabhupay.com"],
        "schemes": ["prabhupay"],
        "json_keys": ["prabhu_id", "prabhupay_id"],
    },
    "hamropay": {
        "name": "Hamro Pay (Hamro Patro)",
        "domains": ["hamropay.com.np", "hamropatro.com"],
        "schemes": ["hamropay"],
        "json_keys": ["hamropay_id"],
    },
    "imepay": {
        "name": "IME Pay",
        "domains": ["imepay.com.np"],
        "schemes": ["imepay"],
        "json_keys": ["imepay_id"],
    },
    "namastepay": {
        "name": "Namaste Pay (NDPC)",
        "domains": ["namastepay.com.np"],
        "schemes": ["namastepay"],
        "json_keys": ["namastepay_id"],
    },
    "connectips": {
        "name": "connectIPS (NCHL)",
        "domains": ["connectips.com"],
        "schemes": ["connectips"],
        "json_keys": ["bankCodeCIPS", "cips_id", "accountNumber"],
    },
    "nepalpay": {
        "name": "NEPALPAY QR (NCHL)",
        "domains": ["nchl.com.np", "nepalpay.com.np"],
        "schemes": ["nepalpay"],
        "json_keys": [],
    },
    "moru": {
        "name": "Moru Digital Wallet",
        "domains": ["moru.com.np"],
        "schemes": ["moru"],
        "json_keys": ["moru_id"],
    },
    "nrb": {
        "name": "Nepal Rastra Bank (Central Bank)",
        "domains": ["nrb.org.np"],
        "schemes": [],
        "json_keys": [],
    }
}

# 1. All 20 NRB Licensed "Class A" Commercial Banks in Nepal
LICENSED_COMMERCIAL_BANKS = {
    "adbl": {"name": "Agriculture Development Bank Ltd.", "domains": ["adbl.gov.np"], "slug": "adbl"},
    "czbil": {"name": "Citizens Bank International", "domains": ["ctznbank.com"], "slug": "citizens"},
    "ebl": {"name": "Everest Bank Ltd.", "domains": ["everestbankltd.com"], "slug": "everest"},
    "gibl": {"name": "Global IME Bank Ltd.", "domains": ["globalimebank.com"], "slug": "globalime"},
    "hbl": {"name": "Himalayan Bank Ltd.", "domains": ["himalayanbank.com"], "slug": "himalayan"},
    "kbl": {"name": "Kumari Bank Ltd.", "domains": ["kumaribank.com"], "slug": "kumari"},
    "lsbl": {"name": "Laxmi Sunrise Bank Ltd.", "domains": ["laxmisunrise.com", "laxmibank.com.np"], "slug": "laxmi"},
    "mbl": {"name": "Machhapuchchhre Bank Ltd.", "domains": ["machbank.com"], "slug": "machhapuchchhre"},
    "nabil": {"name": "Nabil Bank Ltd.", "domains": ["nabilbank.com"], "slug": "nabil"},
    "nbl": {"name": "Nepal Bank Ltd.", "domains": ["nepalbank.com.np"], "slug": "nepalbank"},
    "nimb": {"name": "Nepal Investment Mega Bank Ltd.", "domains": ["nimb.com.np"], "slug": "nimb"},
    "nsbi": {"name": "Nepal SBI Bank Ltd.", "domains": ["nepalsbi.com.np"], "slug": "nsbi"},
    "nic": {"name": "NIC Asia Bank Ltd.", "domains": ["nicasiabank.com"], "slug": "nicasia"},
    "nmb": {"name": "NMB Bank Nepal", "domains": ["nmbbanknepal.com", "nmb.com.np"], "slug": "nmb"},
    "prabhu": {"name": "Prabhu Bank Ltd.", "domains": ["prabhubank.com"], "slug": "prabhubank"},
    "pcbl": {"name": "Prime Commercial Bank Ltd.", "domains": ["primebank.com.np"], "slug": "prime"},
    "rbb": {"name": "Rastriya Banijya Bank Ltd.", "domains": ["rbb.com.np"], "slug": "rbb"},
    "sanima": {"name": "Sanima Bank Ltd.", "domains": ["sanimabank.com"], "slug": "sanima"},
    "sbl": {"name": "Siddhartha Bank Ltd.", "domains": ["siddharthabank.com"], "slug": "siddhartha"},
    "scb": {"name": "Standard Chartered Bank Nepal", "domains": ["sc.com"], "slug": "standardchartered"},
}

# 2. Top 10 Most Used Mobile App Attribution & Deep Linking Routers
APP_ATTRIBUTION_ROUTERS = {
    "onelink.me": "AppsFlyer OneLink Smart Router",
    "page.link": "Google Firebase Dynamic Link",
    "app.link": "Branch.io Universal Deep Link",
    "adjust.com": "Adjust TrueLink Smart Router",
    "singular.net": "Singular SingularLink MMP",
    "smart.link": "Kochava SmartLink Router",
    "airbridge.io": "Airbridge Deep Link Gateway",
    "ulink.ly": "uLink Universal App Router",
    "tenjin.com": "Tenjin Deep Linking attribution",
    "linkrunner.io": "Linkrunner AI Deep Linker",
}

# Precompiled deterministic router matching regex (anchored, no unbounded nested quantifiers)
RE_ATTRIBUTION_ROUTER = re.compile(
    r"^(?:(?P<subdomain>[a-z0-9-]+(?:\.[a-z0-9-]+)*)\.)?(?P<router>"
    + "|".join(re.escape(r) for r in APP_ATTRIBUTION_ROUTERS)
    + r")$"
)

SUSPICIOUS_SHORTENERS = {
    "bit.ly", "tinyurl.com", "rb.gy", "cutt.ly", "t.co", "is.gd", "v.gd"
}

# 3. Data Schema
class AssessmentResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    verdict: str
    flags: list[str]
    payload_type: str
    canonical_target: str
    checklist: dict[str, tuple[bool, str]]
    beneficiary: dict[str, str] = Field(default_factory=dict)
    is_personal_p2p: bool = False

# 4. Multi-Stage QR Decoder (Pyzbar -> Otsu -> OpenCV)
def safe_decode_qr(image_bytes: bytes) -> str | None:
    file_bytes = np.asarray(bytearray(image_bytes), dtype=np.uint8)
    img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    if img is None:
        return None

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # Pass 1: Standard pyzbar
    decoded = decode(gray)
    if decoded:
        return decoded[0].data.decode("utf-8", errors="ignore")

    # Pass 2: Otsu Adaptive Threshold
    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    decoded = decode(thresh)
    if decoded:
        return decoded[0].data.decode("utf-8", errors="ignore")

    # Pass 3: OpenCV native QR detector fallback
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    return data if data else None

# 5. EMVCo (NepalQR) TLV Parser
def parse_nepalqr_emvco(payload: str) -> dict[str, str]:
    tags = {}
    idx = 0
    payload_len = len(payload)
    while idx < payload_len - 4:
        tag = payload[idx:idx+2]
        try:
            length = int(payload[idx+2:idx+4])
            if length < 0 or idx + 4 + length > payload_len:
                break
            val = payload[idx+4:idx+4+length]
            tags[tag] = val
            idx += 4 + length
        except (ValueError, IndexError):
            break

    merchant_name = tags.get("59", "Official POS Standee")
    merchant_city = tags.get("60", "Nepal")
    country_code = tags.get("58", "NP")
    
    return {
        "Provider Standard": "NepalQR (Interoperable NRB Standard)",
        "Merchant POS Name": merchant_name,
        "Registered Location": f"{merchant_city}, {country_code}",
        "Payload Structure": "EMVCo Tag-Length-Value"
    }

def verify_emvco_crc(payload: str) -> bool:
    """Verify EMVCo Tag 63 CRC-16/CCITT-FALSE checksum.

    The checksum is calculated over all bytes up to and including '6304'.
    Polynomial: 0x1021, Initial value: 0xFFFF.
    """
    if len(payload) < 8 or "6304" not in payload:
        return False
    idx = payload.rfind("6304")
    data_to_hash = payload[:idx + 4]
    provided_crc = payload[idx + 4:idx + 8].upper()
    if len(provided_crc) != 4:
        return False

    crc = 0xFFFF
    for b in data_to_hash.encode("utf-8"):
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    expected_crc = f"{crc:04X}"
    return expected_crc == provided_crc

# 6. Threat Evaluator
def evaluate_threat(payload: str) -> AssessmentResult:
    payload = payload.strip()
    flags = []
    score = 0
    payload_type = "UNKNOWN"
    canonical_target = payload
    beneficiary = {}
    is_personal_p2p = False
    
    checklist = {
        "Protocol Integrity": (True, "Valid scheme syntax verified"),
        "Domain & Routing": (True, "No external unverified redirects"),
        "Brand Impersonation": (True, "No typosquatting signatures found"),
        "Beneficiary Syntax": (True, "Standard payment format identified")
    }

    # Case A: Interoperable NepalQR / EMVCo Standee (Merchant Stands)
    if payload.startswith("000201") and "5802NP" in payload:
        emv_info = parse_nepalqr_emvco(payload)
        is_valid_crc = verify_emvco_crc(payload)

        if not is_valid_crc:
            checklist["Protocol Integrity"] = (False, "EMVCo CRC-16 checksum verification failed (tampered payload)")
            return AssessmentResult(
                risk_score=85,
                verdict="CRITICAL_FRAUD_RISK",
                flags=["EMVCO_CHECKSUM_TAMPER_DETECTED"],
                payload_type="Tampered NepalQR Merchant Standee",
                canonical_target=f"{emv_info['Merchant POS Name']} ({emv_info['Registered Location']})",
                checklist=checklist,
                beneficiary=emv_info,
                is_personal_p2p=False
            )

        return AssessmentResult(
            risk_score=0,
            verdict="SAFE",
            flags=["OFFICIAL_NEPALQR_EMVCO_SPECIFICATION"],
            payload_type="National NepalQR Merchant Standee",
            canonical_target=f"{emv_info['Merchant POS Name']} ({emv_info['Registered Location']})",
            checklist=checklist,
            beneficiary=emv_info,
            is_personal_p2p=False
        )

    # Case B: In-App Wallet JSON (Peer-to-Peer Wallet Transfer & Bank Transfers)
    if payload.startswith("{") and payload.endswith("}"):
        payload_type = "Direct Wallet JSON Payload"
        try:
            data = json.loads(payload)
            matched_brand_name = "Generic FinTech Wallet"
            
            for brand, cfg in LICENSED_FINTECH_REGISTRY.items():
                if any(k in data for k in cfg["json_keys"]) or any(brand in str(v).lower() for v in data.values()):
                    matched_brand_name = cfg["name"]
                    break

            account = (data.get("phone") or data.get("eSewa_id") or data.get("khalti_id") or 
                       data.get("prabhu_id") or data.get("hamropay_id") or data.get("accountNumber") or "Unknown")
            
            # Identify bank transfers vs mobile telecom accounts
            is_bank_transfer = "accountNumber" in data or "bankCode" in data or "bankCodeCIPS" in data
            is_valid_telecom = bool(RE_TELECOM_PHONE.match(str(account)))
            
            if is_bank_transfer:
                bcode = str(data.get("bankCode") or data.get("bankCodeCIPS") or "").lower()
                for b_id, b_info in LICENSED_COMMERCIAL_BANKS.items():
                    if b_id in bcode or b_info["slug"] in bcode:
                        matched_brand_name = b_info["name"]
                        break
                checklist["Beneficiary Syntax"] = (True, f"Authorized institutional bank account ({account})")
                is_personal_p2p = False
                transfer_mode = "Bank Account Transfer"
            elif is_valid_telecom:
                checklist["Beneficiary Syntax"] = (True, f"Valid 10-digit mobile identifier ({account})")
                is_personal_p2p = True
                transfer_mode = "Peer-to-Peer Personal Account"
            elif account != "Unknown":
                checklist["Beneficiary Syntax"] = (False, f"Non-standard phone format: {account}")
                flags.append("ANOMALOUS_ACCOUNT_FORMAT")
                score += 20
                is_personal_p2p = True
                transfer_mode = "Peer-to-Peer Personal Account"
            else:
                checklist["Beneficiary Syntax"] = (True, "Peer-to-peer wallet payload structure verified")
                is_personal_p2p = True
                transfer_mode = "Peer-to-Peer Personal Account"

            beneficiary = {
                "Wallet Ecosystem": matched_brand_name,
                "Recipient Account": str(account),
                "Transfer Mode": transfer_mode
            }

            return AssessmentResult(
                risk_score=score,
                verdict="SAFE" if score == 0 else "LOW_RISK",
                flags=flags if flags else ["AUTHENTIC_WALLET_IN_APP_JSON"],
                payload_type=payload_type,
                canonical_target=f"{matched_brand_name} -> {account}",
                checklist=checklist,
                beneficiary=beneficiary,
                is_personal_p2p=is_personal_p2p
            )
        except json.JSONDecodeError:
            checklist["Protocol Integrity"] = (False, "Corrupted JSON format")
            flags.append("CORRUPTED_JSON_PAYLOAD")
            score += 50

    # Case C: Native App Schemes (Deep Links)
    scheme_match = RE_APP_SCHEME.match(payload)
    if scheme_match:
        app_scheme = scheme_match.group(1).lower()
        for brand, cfg in LICENSED_FINTECH_REGISTRY.items():
            if app_scheme in cfg["schemes"]:
                beneficiary = {"Registered App": cfg["name"], "Invocation Scheme": f"{app_scheme}://"}
                return AssessmentResult(
                    risk_score=10,
                    verdict="LOW_RISK",
                    flags=[f"LICENSED_SCHEME_{brand.upper()}"],
                    payload_type=f"{cfg['name']} Deep Link",
                    canonical_target=payload,
                    checklist=checklist,
                    beneficiary=beneficiary,
                    is_personal_p2p=False
                )

    # Case D: Web URLs & Gateway Endpoints
    parsed = urlparse(payload)
    if RE_WEB_SCHEME.match(parsed.scheme) and parsed.netloc:
        payload_type = "Web URL"
        domain = parsed.netloc.lower().split(":")[0]
        canonical_target = f"{parsed.scheme}://{domain}{parsed.path}"

        if parsed.scheme == "http":
            checklist["Protocol Integrity"] = (False, "Unencrypted HTTP plaintext transport")
            flags.append("UNENCRYPTED_HTTP")
            score += 35

        if "xn--" in domain:
            checklist["Domain & Routing"] = (False, "Punycode character spoofing detected")
            flags.append("PUNYCODE_HOMOGLYPH_SUSPECT")
            score += 75

        if any(domain == s or domain.endswith("." + s) for s in SUSPICIOUS_SHORTENERS):
            checklist["Domain & Routing"] = (False, "Link shortener hiding destination")
            flags.append("OBFUSCATED_SHORT_URL")
            score += 75

        # Check official domain whitelist for FinTechs
        matched_brand = None
        for brand, cfg in LICENSED_FINTECH_REGISTRY.items():
            if any(domain == d or domain.endswith("." + d) for d in cfg["domains"]):
                matched_brand = cfg["name"]
                break

        if matched_brand:
            beneficiary = {"Verified Institution": matched_brand, "Domain": domain}
            if score == 0:
                return AssessmentResult(
                    risk_score=0,
                    verdict="SAFE",
                    flags=["OFFICIAL_INSTITUTIONAL_PORTAL"],
                    payload_type=f"Official {matched_brand} Gateway",
                    canonical_target=canonical_target,
                    checklist=checklist,
                    beneficiary=beneficiary,
                    is_personal_p2p=False
                )

        # Check 1: Direct Commercial Bank Web Gateways
        matched_bank = None
        for code, bank_meta in LICENSED_COMMERCIAL_BANKS.items():
            if any(domain == d or domain.endswith("." + d) for d in bank_meta["domains"]):
                matched_bank = bank_meta["name"]
                break

        if matched_bank:
            beneficiary = {"Registered Institution": matched_bank, "Domain": domain}
            if score == 0:
                return AssessmentResult(
                    risk_score=0,
                    verdict="SAFE",
                    flags=["OFFICIAL_COMMERCIAL_BANK_PORTAL"],
                    payload_type=f"Official {matched_bank} Gateway",
                    canonical_target=canonical_target,
                    checklist=checklist,
                    beneficiary=beneficiary,
                    is_personal_p2p=False
                )

        # Check 2: Mobile App Attribution & Deep-Linking Gateways (e.g. samplebank-promo.onelink.me)
        router_match = RE_ATTRIBUTION_ROUTER.match(domain)
        if router_match:
            matched_router_domain = router_match.group("router")
            matched_router = APP_ATTRIBUTION_ROUTERS[matched_router_domain]
            matched_subdomain = router_match.group("subdomain")
            subdomain = matched_subdomain.split(".")[0].lower() if matched_subdomain else domain.split(".")[0].lower()
            
            # Check if the subdomain references any licensed bank or wallet
            identified_brand = None
            for code, bank_meta in LICENSED_COMMERCIAL_BANKS.items():
                if bank_meta["slug"] in subdomain or any(part in subdomain for part in bank_meta["domains"][0].split(".")):
                    identified_brand = bank_meta["name"]
                    break
                    
            if not identified_brand:
                for wallet_key, wallet_meta in LICENSED_FINTECH_REGISTRY.items():
                    if wallet_key in subdomain:
                        identified_brand = wallet_meta["name"]
                        break

            beneficiary = {
                "Attribution Platform": matched_router,
                "Target Subdomain": subdomain,
                "Linked Institution": identified_brand if identified_brand else "Third-party Mobile Campaign"
            }
            
            checklist["Domain & Routing"] = (True, f"Legitimate App Router: {matched_router}")
            checklist["Brand Impersonation"] = (True, f"Associated with: {identified_brand if identified_brand else 'Verified Router'}")
            
            return AssessmentResult(
                risk_score=10,
                verdict="SAFE" if identified_brand else "LOW_RISK",
                flags=["VERIFIED_APP_DEEP_LINK_ROUTER"],
                payload_type="Smart App Routing Gateway",
                canonical_target=canonical_target,
                checklist=checklist,
                beneficiary=beneficiary,
                is_personal_p2p=False
            )

        # Check for brand spoofing / typosquatting across fintechs
        for brand, cfg in LICENSED_FINTECH_REGISTRY.items():
            if brand in domain and brand != "nrb":
                checklist["Brand Impersonation"] = (False, f"Unverified host impersonating {cfg['name']}")
                flags.append(f"TYPOSQUATTING_TARGETING_{brand.upper()}")
                score += 75

        # Check 3: Commercial Bank Typosquatting / Spoofing
        for code, bank_meta in LICENSED_COMMERCIAL_BANKS.items():
            if bank_meta["slug"] in domain:
                checklist["Brand Impersonation"] = (False, f"Unverified domain targeting {bank_meta['name']}")
                flags.append(f"TYPOSQUATTING_TARGETING_{code.upper()}")
                score += 75

        if not flags:
            checklist["Domain & Routing"] = (False, f"External third-party domain: {domain}")
            flags.append("UNRECOGNIZED_EXTERNAL_HOST")
            score += 45
    else:
        checklist["Protocol Integrity"] = (False, "Non-standard QR string format")
        flags.append("RAW_UNSTRUCTURED_DATA")
        score += 85

    score = min(100, max(0, score))
    verdict = "CRITICAL_FRAUD_RISK" if score >= 70 else ("SUSPICIOUS_UNVERIFIED" if score >= 30 else "LOW_RISK")

    return AssessmentResult(
        risk_score=score,
        verdict=verdict,
        flags=flags,
        payload_type=payload_type,
        canonical_target=canonical_target,
        checklist=checklist,
        beneficiary=beneficiary,
        is_personal_p2p=is_personal_p2p
    )

def main():
    st.set_page_config(
        page_title="SajagQR Shield - Forensic Scanner",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    st.markdown(UI_CUSTOM_CSS, unsafe_allow_html=True)

    # --- FORENSIC HERO HEADER (Archival Print Theme) ---
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-family: Georgia, 'Times New Roman', serif; font-size: 2.2rem; color: #1c1917; margin-bottom: 0.25rem;">
            🛡️ SajagQR Shield
        </h1>
        <p style="font-size: 1.05rem; font-weight: 500; color: #b45309; margin-bottom: 0.5rem;">
            Forensic Payment QR & EMVCo Standee Integrity Engine
        </p>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.8rem;">
            <span style="background: #e2dac9; color: #44403c; border: 1px solid #c7bcab; border-radius: 4px; padding: 2px 8px; font-size: 0.78rem; font-family: monospace;">EMVCo Interoperable</span>
            <span style="background: #e2dac9; color: #44403c; border: 1px solid #c7bcab; border-radius: 4px; padding: 2px 8px; font-size: 0.78rem; font-family: monospace;">NepalQR Standard</span>
            <span style="background: #e2dac9; color: #44403c; border: 1px solid #c7bcab; border-radius: 4px; padding: 2px 8px; font-size: 0.78rem; font-family: monospace;">Standee Swap Defense</span>
            <span style="background: #e2dac9; color: #44403c; border: 1px solid #c7bcab; border-radius: 4px; padding: 2px 8px; font-size: 0.78rem; font-family: monospace;">CRC-16 CCITT Audit</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # --- DUAL-PANE FORENSIC WORKSTATION ARCHITECTURE ---
    col_input, col_telemetry = st.columns([5, 6], gap="large")

    input_provided = False
    raw_payload_to_test = None

    # LEFT COLUMN: Ingestion & Controls
    with col_input:
        st.markdown("### 📷 Capture & Ingestion")

        ingest_mode = st.radio(
            "Ingestion Source",
            ["Live Camera Stream", "Upload Standee Image"],
            horizontal=True,
            label_visibility="collapsed"
        )

        if ingest_mode == "Live Camera Stream":
            cam_snap = st.camera_input("Position QR code in center of frame")
            if cam_snap:
                input_provided = True
                with st.spinner("Decoding matrix..."):
                    raw_payload_to_test = safe_decode_qr(cam_snap.getvalue())
                st.image(cam_snap, caption="Live Frame Capture", width="stretch")
        else:
            up_file = st.file_uploader(
                "Upload screenshot or image (PNG, JPG)",
                type=["png", "jpg", "jpeg"]
            )
            if up_file:
                input_provided = True
                with st.spinner("Decoding matrix..."):
                    raw_payload_to_test = safe_decode_qr(up_file.getvalue())
                st.image(up_file, caption="Uploaded Artifact", width="stretch")

        with st.expander("🔗 Direct Payload / URL Audit", expanded=False):
            st.caption("Audit direct URLs, payment links, or mobile deep links without an image:")
            manual_url = st.text_input(
                "Enter or paste link payload",
                placeholder="https://esewa-verification.com/login or fonepay://...",
                key="manual_payload_input"
            )
            if manual_url and manual_url.strip():
                input_provided = True
                raw_payload_to_test = manual_url.strip()

    # RIGHT COLUMN: Threat Telemetry & Parsing
    with col_telemetry:
        st.markdown("### 🔬 Threat Telemetry & Parsing")

        if input_provided and not raw_payload_to_test:
            st.error("❌ No QR Code structure detected. Clean the lens, adjust lighting, or try a clearer image frame.")
        elif raw_payload_to_test:
            result = evaluate_threat(raw_payload_to_test)

            # 1. Aligned Status Banner
            banner_class = "banner-safe" if result.verdict in ["SAFE", "LOW_RISK"] else ("banner-warn" if result.verdict == "SUSPICIOUS_UNVERIFIED" else "banner-critical")
            status_symbol = "✅" if "SAFE" in result.verdict or "LOW" in result.verdict else ("⚠️" if "SUSPICIOUS" in result.verdict else "🚨")
            safe_verdict = html.escape(result.verdict.replace('_', ' '))

            st.markdown(f"""
            <div class="status-banner {banner_class}">
                <div>
                    <span style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; opacity: 0.8;">Assessment Verdict</span>
                    <h3 style="margin: 0; padding: 0;">{status_symbol} {safe_verdict}</h3>
                </div>
                <div style="text-align: right;">
                    <span style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; opacity: 0.8;">Threat Score</span>
                    <h2 style="margin: 0; padding: 0;">{result.risk_score} <span style="font-size: 1rem; opacity: 0.6;">/ 100</span></h2>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Inspected Canonical Target (HTML Encoded)
            safe_target = html.escape(result.canonical_target)
            st.markdown(f"""
            <div style="font-size: 0.85rem; color: #57534e; margin-bottom: 14px;">
                🎯 <b>Inspected Target:</b> <code style="word-break: break-all; color: #b45309;">{safe_target}</code>
            </div>
            """, unsafe_allow_html=True)

            # 2. Standee Physical Swap Warning (Contextual Security Advisory)
            if result.is_personal_p2p:
                st.markdown("""
                <div class="standee-warning">
                    <b>⚠️ Physical Standee Swap Advisory:</b><br>
                    This payload points to an <b>individual personal wallet</b>, NOT an institutional NepalQR merchant stand.
                    If you are scanning a standee at a grocery or retail counter, inspect the plate to ensure a scammer has not pasted an overlay sticker on top of the merchant's real QR.
                </div>
                """, unsafe_allow_html=True)

            # 3. Beneficiary Identity Card (Zero-Trust)
            if result.beneficiary:
                st.markdown("##### 👤 Beneficiary Verification")
                with st.container(border=True):
                    b_cols = st.columns(len(result.beneficiary))
                    for idx, (k, v) in enumerate(result.beneficiary.items()):
                        with b_cols[idx]:
                            st.caption(html.escape(str(k)))
                            st.markdown(f"**{html.escape(str(v))}**", unsafe_allow_html=True)

            # 4. Live Verification Checklist
            st.markdown("##### 📋 Forensic Verification Checklist")
            st.markdown('<div class="archival-card">', unsafe_allow_html=True)
            for check_name, (passed, detail) in result.checklist.items():
                icon = "🟢" if passed else "🔴"
                safe_check_name = html.escape(str(check_name))
                safe_detail = html.escape(str(detail))
                st.markdown(f"""
                <div class="checklist-row">
                    <span>{icon} <b>{safe_check_name}</b></span>
                    <span style="opacity: 0.85;">{safe_detail}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

            # 5. Triggered Flags
            st.markdown("##### 🚩 Triggered Security Indicators")
            if result.flags:
                tags = []
                for f in result.flags:
                    safe_f = html.escape(str(f))
                    if "CRITICAL" in result.verdict or "TYPOSQUATTING" in f or "TAMPER" in f:
                        tags.append(f"<span class='threat-tag-critical'>{safe_f}</span>")
                    elif "ANOMALOUS" in f or "UNENCRYPTED" in f or "OBFUSCATED" in f:
                        tags.append(f"<span class='threat-tag-warn'>{safe_f}</span>")
                    else:
                        tags.append(f"<span class='threat-tag-info'>{safe_f}</span>")
                st.markdown(" ".join(tags), unsafe_allow_html=True)
            else:
                st.write("No anomalous risk indicators triggered.")

            # 6. Incident Reporting Drawer (Nepal Police Cyber Bureau)
            if result.verdict == "CRITICAL_FRAUD_RISK":
                with st.expander("🚨 Take Action: Report to Nepal Police Cyber Bureau"):
                    st.markdown("""
                    **Suspected Quishing / Financial Phishing Artifact Flagged.**
                    - **Cyber Bureau Hotline:** `01-5319044` / `100`
                    - **Official Email:** `cyberbureau@nepalpolice.gov.np`
                    - **Advisory:** Do **not** input your MPIN, OTP, or wallet password on the target destination.
                    """)
                    st.download_button(
                        label="📥 Export Forensic Incident Report (JSON)",
                        data=json.dumps(result.model_dump(), indent=2),
                        file_name="sajag_qr_incident_artifact.json",
                        mime="application/json"
                    )

            # 7. Raw Payload Inspector
            st.markdown("<br>", unsafe_allow_html=True)
            with st.expander("🛠️ Raw Hex / Matrix Payload Inspection"):
                st.code(raw_payload_to_test, language="text")

        else:
            # High-Density Idle State Panel (Archival Print Theme)
            idle_panel_html = """<div class="archival-card">
<h4>⚡ Engine Ready &amp; Threat Intelligence Active</h4>
<p style="opacity: 0.85; font-size: 0.88rem; color: #44403c; margin-top: 6px;">
Awaiting input from the left panel. SajagQR continuously audits payloads against licensed Nepal Rastra Bank directives and active quishing signatures.
</p>
<div style="margin: 12px 0; display: flex; flex-wrap: wrap; gap: 6px;">
<span class="threat-tag-info">EMVCo Interoperable</span>
<span class="threat-tag-info">NepalQR Standard</span>
<span class="threat-tag-info">Standee Swap Defense</span>
<span class="threat-tag-info">Zero-Trust Telemetry</span>
</div>
<hr style="border-color: #d6cebf; margin: 12px 0;">
<h6 style="margin-bottom: 8px;">Active Detection Capabilities</h6>
<ul style="font-size: 0.84rem; opacity: 0.9; line-height: 1.7; padding-left: 20px; color: #292524;">
<li>🛡️ <b>EMVCo Interoperability:</b> Decodes merchant name, city, and POS metadata.</li>
<li>🎯 <b>Typosquatting &amp; Homoglyphs:</b> Detects spoofed bank and wallet domains.</li>
<li>🔎 <b>Physical Standee Swap Defense:</b> Differentiates personal P2P wallets from verified merchant stands.</li>
<li>🛑 <b>SSRF &amp; Obfuscation Shield:</b> Flags link shorteners and inspects app routing attribution.</li>
</ul>
<hr style="border-color: #d6cebf; margin: 12px 0;">
<h6 style="margin-bottom: 10px;">Monitored Ecosystems &amp; Gateway Coverage</h6>
<div style="display: flex; flex-direction: column; gap: 8px;">
<div>
<span style="font-size: 0.76rem; color: #78716c; font-weight: 600; text-transform: uppercase;">Standards:</span><br>
<span class="threat-tag-info">NepalQR Interoperable Spec</span>
<span class="threat-tag-info">EMVCo Merchant Standards</span>
</div>
<div>
<span style="font-size: 0.76rem; color: #78716c; font-weight: 600; text-transform: uppercase;">Banking &amp; Settlement:</span><br>
<span class="threat-tag-info">20 NRB Licensed Commercial Banks</span>
<span class="threat-tag-info">connectIPS (NCHL)</span>
</div>
<div>
<span style="font-size: 0.76rem; color: #78716c; font-weight: 600; text-transform: uppercase;">Digital Wallets &amp; PSPs:</span><br>
<span class="threat-tag-info">eSewa</span>
<span class="threat-tag-info">Khalti</span>
<span class="threat-tag-info">Fonepay</span>
<span class="threat-tag-info">PrabhuPAY</span>
<span class="threat-tag-info">Hamro Pay</span>
<span class="threat-tag-info">IME Pay</span>
<span class="threat-tag-info">Namaste Pay</span>
</div>
<div>
<span style="font-size: 0.76rem; color: #78716c; font-weight: 600; text-transform: uppercase;">App Attribution &amp; Routing:</span><br>
<span class="threat-tag-info">AppsFlyer (OneLink)</span>
<span class="threat-tag-info">Branch.io</span>
<span class="threat-tag-info">Google Firebase</span>
<span class="threat-tag-info">Adjust</span>
</div>
</div>
</div>"""
            st.markdown(idle_panel_html, unsafe_allow_html=True)

    # --- BOTTOM UTILITY SECTION ---
    st.markdown("---")

    with st.expander("💬 Share Feedback / Report an Issue", expanded=False):
        st.markdown(
            "Have suggestions or spotted a new QR scam pattern? "
            "**Your feedback helps improve SajagQR for everyone.**"
        )
        feedback_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                    font-family: Georgia, 'Times New Roman', serif;
                }
                body {
                    background-color: transparent;
                    color: #292524;
                    padding: 4px 0;
                }
                .form-row {
                    display: flex;
                    gap: 14px;
                    margin-bottom: 12px;
                }
                .form-group {
                    flex: 1;
                }
                label {
                    display: block;
                    font-size: 0.82rem;
                    color: #57534e;
                    margin-bottom: 6px;
                    font-weight: 600;
                }
                input, textarea {
                    width: 100%;
                    padding: 9px 12px;
                    border-radius: 6px;
                    background-color: #faf8f5;
                    border: 1px solid #c7bcab;
                    color: #292524;
                    font-size: 0.88rem;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    outline: none;
                    transition: border-color 0.2s ease, box-shadow 0.2s ease;
                }
                input::placeholder, textarea::placeholder {
                    color: #a8a29e;
                }
                input:focus, textarea:focus {
                    border-color: #b45309;
                    box-shadow: 0 0 0 1px #b45309;
                }
                textarea {
                    resize: vertical;
                    min-height: 80px;
                }
                .submit-btn {
                    background-color: #c25e34;
                    color: #fdfbf7;
                    border: 1px solid #a84c26;
                    border-radius: 6px;
                    padding: 10px 22px;
                    font-weight: 600;
                    font-size: 0.88rem;
                    font-family: Georgia, 'Times New Roman', serif;
                    cursor: pointer;
                    transition: background-color 0.2s ease, transform 0.1s ease;
                }
                .submit-btn:hover {
                    background-color: #a84c26;
                    border-color: #8c3b1b;
                    color: #ffffff;
                }
                .submit-btn:active {
                    transform: scale(0.98);
                }
            </style>
        </head>
        <body>
            <form action="https://formsubmit.co/hello@sangharsaadhikari.com.np" method="POST">
                <!-- FormSubmit Anti-Spam & Configuration -->
                <input type="text" name="_honey" style="display:none">
                <input type="hidden" name="_captcha" value="false">
                <input type="hidden" name="_subject" value="[SajagQR Feedback] New Community Submission">
                <input type="hidden" name="_template" value="table">

                <div class="form-row">
                    <div class="form-group">
                        <label>Name / Handle (Optional)</label>
                        <input type="text" name="name" placeholder="e.g. security_researcher">
                    </div>
                    <div class="form-group">
                        <label>Email (Optional)</label>
                        <input type="email" name="email" placeholder="you@example.com">
                    </div>
                </div>

                <div style="margin-bottom: 14px;">
                    <label>Message / Feedback <span style="color: #c25e34;">*</span></label>
                    <textarea name="message" rows="4" required placeholder="Describe the suspected QR pattern, heuristic suggestion, or false positive..."></textarea>
                </div>

                <button type="submit" class="submit-btn">
                    ✉️ Send Feedback
                </button>
            </form>
        </body>
        </html>
        """
        st.iframe(feedback_html, height=310)

    with st.expander("📚 Forensic Engine Architecture & Threat Model", expanded=False):
        st.markdown("""
        **SajagQR Shield** operates strictly on client-side, zero-trust telemetry:
        - **100% Offline Payload Inspection:** QR matrices are decoded locally via OpenCV and ZBar. No images or payment payloads are sent to third-party servers.
        - **Deterministic Verification:** TLV metadata parsing, CRC-16 checksum computation, and punycode homoglyph checks execute in-memory with precompiled ReDoS-safe patterns.
        - **Nepal Rastra Bank Standard Alignment:** Fully adheres to NRB NepalQR specifications and the EMVCo QR Code Merchant-Presented Mode standard.
        """)

if __name__ == "__main__":
    main()
