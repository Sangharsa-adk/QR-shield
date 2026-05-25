import streamlit as st
import cv2
import numpy as np
import json
from urllib.parse import urlparse
from pyzbar.pyzbar import decode
from pydantic import BaseModel

# Set up clean mobile responsive viewport configuration
st.set_page_config(page_title="SajagQR - Anti-Quishing Shield", layout="centered")

TRUSTED_DOMAINS = {
    "fonepay.com", "esewa.com.np", "khalti.com", "connectips.com", "nrb.org.np"
}

def calculate_heuristic_risk(url_string: str) -> tuple[int, list[str]]:
    flags = []
    score = 0
    url_string = url_string.strip()

    # 1. Individual JSON Payloads (eSewa / Banking Apps)
    if url_string.startswith("{") and url_string.endswith("}"):
        try:
            parsed_json = json.loads(url_string)
            is_valid_wallet = "eSewa_id" in parsed_json or "khalti_id" in parsed_json or "phone" in parsed_json
            is_valid_bank_transfer = "accountNumber" in parsed_json or "bankCode" in parsed_json or "bankCodeCIPS" in parsed_json
            if is_valid_wallet or is_valid_bank_transfer:
                return 0, []
        except json.JSONDecodeError:
            pass

    # 2. Native Links & 3. EMVCo Merchant Structures
    if url_string.startswith(("fonepay://", "esewa://", "khalti://", "connectips://")):
        return 0, []
    if url_string.startswith("000201") and "5802NP" in url_string:
        return 0, []

    # 4. Web Gateway Lookalikes & Phishing Filtering
    parsed = urlparse(url_string)
    if not parsed.scheme or not parsed.netloc:
        return 90, ["INVALID_OR_UNRECOGNIZED_PAYLOAD_STRUCTURE"]

    if parsed.scheme != "https":
        score += 30
        flags.append("UNENCRYPTED_HTTP_PROTOCOL")

    domain = parsed.netloc.lower()
    base_domain = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain

    if base_domain in {"bit.ly", "tinyurl.com", "rb.gy", "cutt.ly", "t.co"}:
        score += 80
        flags.append("OBFUSCATED_SHORT_URL")

    if base_domain in TRUSTED_DOMAINS:
        return max(0, score), flags
    
    for trusted in TRUSTED_DOMAINS:
        if trusted.split('.')[0] in domain:
            score += 60
            flags.append(f"TYPOSQUATTING_SPOOF_SUSPECT_OF_{trusted.upper()}")

    if not flags and base_domain not in TRUSTED_DOMAINS:
        score += 40
        flags.append("UNVERIFIED_THIRD_PARTY_DOMAIN")

    return min(100, score), flags

# --- USER INTERFACE DESIGN ---
st.title("🔒 SajagQR Shield")
st.subheader("Anti-Fraud QR Verification Engine")
st.markdown("पैसा पठाउनु अघि क्युआर कोडको आधिकारिकता जाँच्नुहोस्।")

# Tab navigation matching real security utility layouts
tab1, tab2 = st.tabs(["📸 live Camera Snap", "📁 Upload Image/Screenshot"])

captured_image = None

with tab1:
    # This activates the native camera view on your smartphone automatically
    camera_file = st.camera_input("Point at a QR Code plate or standee")
    if camera_file:
        captured_image = camera_file

with tab2:
    uploaded_file = st.file_uploader("Choose a screenshot file", type=["png", "jpg", "jpeg"])
    if uploaded_file:
        captured_image = uploaded_file

if captured_image:
    # Convert file stream to OpenCV image array
    file_bytes = np.asarray(bytearray(captured_image.read()), dtype=np.uint8)
    image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    
    # Run structural matrix enhancement filters
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    qr_codes = decode(gray)
    
    if not qr_codes:
        _, threshold_img = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        qr_codes = decode(threshold_img)

    if not qr_codes:
        st.error("❌ No QR Code structure detected. Clean the lens or try a clearer image frame.")
    else:
        payload_data = qr_codes[0].data.decode("utf-8")
        risk_score, threat_flags = calculate_heuristic_risk(payload_data)
        
        st.divider()
        st.subheader("Analysis Verdict")
        
        # Display contextual security frames based on the calculation matrix
        if risk_score == 0:
            st.success("✅ SAFE TRANSACTION APPROVED")
            st.metric(label="Risk Assessment Score", value=f"{risk_score} / 100")
            st.info(f"**Verified Network Destination:** This is an official institutional transaction endpoint.")
        elif risk_score < 75:
            st.warning("⚠️ SUSPICIOUS UNVERIFIED TARGET")
            st.metric(label="Risk Assessment Score", value=f"{risk_score} / 100")
            st.error(f"**Threat Flags Triggered:** {', '.join(threat_flags)}")
        else:
            st.error("🚨 HIGH FRAUD RISK DETECTED - BLOCK TRANSACTION")
            st.metric(label="Risk Assessment Score", value=f"{risk_score} / 100")
            st.error(f"**Critical Threat Markers Found:** {', '.join(threat_flags)}")
            st.markdown("> **सुरक्षा चेतावनी:** यो लिंक वा वित्तीय ठेगाना शंकास्पद छ। झुक्किएर पनि विवरणहरू शेयर नगर्नुहोस्।")

        # Expandable inspection block for advanced technical auditing
        with st.expander("See Extracted Matrix Payload Structure"):
            st.code(payload_data, language="json")