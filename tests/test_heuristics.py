"""Unit test suite for SajagQR heuristic and static threat evaluation engine."""

import json
import pytest
from app import evaluate_threat


class TestNepalQREMVCo:
    """Tests for EMVCo / NepalQR interoperable merchant payloads."""

    def test_official_nepalqr_emvco_payload_returns_safe(self):
        """EMVCo standard payload with 5802NP should be classified as SAFE."""
        payload = "0002010102125802NP5911Bhatbhateni6009Kathmandu6304ABCD"
        result = evaluate_threat(payload)

        assert result.verdict == "SAFE"
        assert result.risk_score == 0
        assert "OFFICIAL_NEPALQR_EMVCO_SPECIFICATION" in result.flags
        assert result.payload_type == "National NepalQR Merchant Standee"
        assert "Bhatbhateni" in result.canonical_target
        assert result.is_personal_p2p is False
        assert result.beneficiary["Merchant POS Name"] == "Bhatbhateni"
        assert result.beneficiary["Registered Location"] == "Kathmandu, NP"


class TestInAppWalletJSON:
    """Tests for direct peer-to-peer and bank account JSON structures."""

    @pytest.mark.parametrize(
        "json_payload, expected_provider",
        [
            ('{"eSewa_id": "9841234567", "name": "Ram Sharma"}', "eSewa (F1Soft Ecosystem)"),
            ('{"khalti_id": "9801234567", "amount": 1000}', "Khalti Digital Wallet"),
            ('{"phone": "9851000000", "prabhu_id": "PRABHU123"}', "PrabhuPAY"),
            ('{"hamropay_id": "9812345678", "phone": "9812345678"}', "Hamro Pay (Hamro Patro)"),
        ],
    )
    def test_standard_in_app_json_wallet_transfers(self, json_payload, expected_provider):
        """Standard in-app JSON wallet transfers should return SAFE or LOW_RISK."""
        result = evaluate_threat(json_payload)

        assert result.verdict in ["SAFE", "LOW_RISK"]
        assert result.risk_score <= 15
        assert result.payload_type == "Direct Wallet JSON Payload"
        assert result.is_personal_p2p is True
        assert result.beneficiary["Wallet Ecosystem"] == expected_provider
        assert result.checklist["Beneficiary Syntax"][0] is True

    def test_institutional_bank_account_json_transfer(self):
        """Bank transfer JSON (e.g. connectIPS) should be verified without telecom syntax penalty."""
        payload = json.dumps({"accountNumber": "01234567890123", "bankCode": "nabil"})
        result = evaluate_threat(payload)

        assert result.verdict in ["SAFE", "LOW_RISK"]
        assert result.risk_score == 0
        assert result.is_personal_p2p is False
        assert result.beneficiary["Wallet Ecosystem"] == "Nabil Bank Ltd."
        assert result.beneficiary["Transfer Mode"] == "Bank Account Transfer"
        assert "ANOMALOUS_ACCOUNT_FORMAT" not in result.flags


class TestAppAttributionRouters:
    """Tests for universal mobile app attribution and deep-linking gateways."""

    def test_appsflyer_attribution_router_with_linked_brand(self):
        """AppsFlyer OneLink router with a linked bank/fintech subdomain returns SAFE."""
        url = "https://samplebank-promo.onelink.me/demo"
        result = evaluate_threat(url)

        assert result.verdict in ["SAFE", "LOW_RISK"]
        assert result.risk_score <= 10
        assert "VERIFIED_APP_DEEP_LINK_ROUTER" in result.flags
        assert result.payload_type == "Smart App Routing Gateway"
        assert result.beneficiary["Attribution Platform"] == "AppsFlyer OneLink Smart Router"

    def test_generic_attribution_router_without_brand(self):
        """Generic attribution router returns LOW_RISK."""
        url = "https://campaign-promo.onelink.me/app"
        result = evaluate_threat(url)

        assert result.verdict == "LOW_RISK"
        assert result.risk_score == 10
        assert "VERIFIED_APP_DEEP_LINK_ROUTER" in result.flags
        assert result.beneficiary["Linked Institution"] == "Third-party Mobile Campaign"


class TestTyposquattingAndPhishing:
    """Tests for brand spoofing, lookalike domains, and phishing URLs."""

    @pytest.mark.parametrize(
        "phishing_url, target_flag",
        [
            ("https://esewa-verification.net/login", "TYPOSQUATTING_TARGETING_ESEWA"),
            ("https://login-khalti.com.secure-auth.xyz/verify", "TYPOSQUATTING_TARGETING_KHALTI"),
            ("https://fonepay.support-portal.org/claim", "TYPOSQUATTING_TARGETING_FONEPAY"),
            ("https://nabil-login.com/secure", "TYPOSQUATTING_TARGETING_NABIL"),
        ],
    )
    def test_typosquatting_phishing_urls_return_critical(self, phishing_url, target_flag):
        """Brand typosquatting and phishing domains must trigger CRITICAL_FRAUD_RISK."""
        result = evaluate_threat(phishing_url)

        assert result.verdict == "CRITICAL_FRAUD_RISK"
        assert result.risk_score >= 70
        assert any(target_flag in f for f in result.flags)
        assert result.checklist["Brand Impersonation"][0] is False


class TestObfuscatedShortUrls:
    """Tests for suspicious URL shorteners hiding the destination."""

    @pytest.mark.parametrize(
        "short_url",
        [
            "https://bit.ly/malicious-link",
            "https://tinyurl.com/esewa-gift",
            "https://rb.gy/free-cash",
            "https://t.co/scam123",
        ],
    )
    def test_obfuscated_short_urls_return_critical(self, short_url):
        """Obfuscated short URLs should be classified as CRITICAL_FRAUD_RISK."""
        result = evaluate_threat(short_url)

        assert result.verdict == "CRITICAL_FRAUD_RISK"
        assert result.risk_score >= 70
        assert "OBFUSCATED_SHORT_URL" in result.flags
        assert result.checklist["Domain & Routing"][0] is False


class TestOfficialGatewaysAndSchemes:
    """Tests for official bank/wallet portals and registered app schemes."""

    def test_official_fintech_portal(self):
        """Official eSewa domain must return SAFE."""
        result = evaluate_threat("https://esewa.com.np/home")
        assert result.verdict == "SAFE"
        assert result.risk_score == 0
        assert "OFFICIAL_INSTITUTIONAL_PORTAL" in result.flags

    def test_official_commercial_bank_portal(self):
        """Official commercial bank domain must return SAFE."""
        result = evaluate_threat("https://nabilbank.com/cards")
        assert result.verdict == "SAFE"
        assert result.risk_score == 0
        assert "OFFICIAL_COMMERCIAL_BANK_PORTAL" in result.flags

    def test_official_central_bank_portal(self):
        """Nepal Rastra Bank official portal must return SAFE."""
        result = evaluate_threat("https://nrb.org.np/notices")
        assert result.verdict == "SAFE"
        assert result.risk_score == 0

    def test_licensed_mobile_deep_link(self):
        """Licensed app scheme (e.g. fonepay://) returns CONTROLLED_DEEP_LINK."""
        result = evaluate_threat("fonepay://qr/payment?txn=999")
        assert result.verdict in ["SAFE", "LOW_RISK", "CONTROLLED_DEEP_LINK"]
        assert any("LICENSED_SCHEME" in f for f in result.flags)


class TestReDoSResilience:
    """Tests ensuring regular expressions resist catastrophic backtracking (ReDoS)."""

    def test_pathological_phone_number_evaluates_quickly(self):
        """Massive repeated digit sequence must be rejected in milliseconds without ReDoS."""
        malformed_phone = "98" + ("9" * 25000)
        payload = json.dumps({"eSewa_id": malformed_phone})
        result = evaluate_threat(payload)

        assert "ANOMALOUS_ACCOUNT_FORMAT" in result.flags
        assert result.checklist["Beneficiary Syntax"][0] is False

    def test_pathological_app_scheme_evaluates_quickly(self):
        """Excessively long scheme payload must be bounded and not cause ReDoS."""
        long_scheme_payload = ("test" * 5000) + "://payment/endpoint"
        result = evaluate_threat(long_scheme_payload)

        # Length > 64 chars will fail the strict scheme regex, falling back to unstructured
        assert result.verdict in ["CRITICAL_FRAUD_RISK", "LOW_RISK"]

    def test_pathological_router_domain_evaluates_quickly(self):
        """Deeply nested or repeated subdomains on router patterns evaluate deterministically."""
        nested_domain = "https://" + ("sub-" * 100) + "demo.onelink.me/app"
        result = evaluate_threat(nested_domain)

        assert "VERIFIED_APP_DEEP_LINK_ROUTER" in result.flags


class TestInputSanitizationAndInjectionDefense:
    """Tests verifying HTML and script injection payloads are properly handled."""

    def test_xss_script_tag_in_json_account_is_neutralized(self):
        """XSS payloads in account identifiers are flagged and safely escaped."""
        xss_account = "<script>alert('XSS')</script>"
        payload = json.dumps({"eSewa_id": xss_account})
        result = evaluate_threat(payload)

        assert "ANOMALOUS_ACCOUNT_FORMAT" in result.flags
        assert xss_account in result.beneficiary["Recipient Account"]
        # Verify html.escape neutralizes the payload
        import html
        escaped = html.escape(result.beneficiary["Recipient Account"])
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped

    def test_img_onerror_in_emvco_merchant_name_is_neutralized(self):
        """Weaponized HTML tag in Tag 59 merchant name is extracted and neutralizable."""
        tag59_val = "<img src=x onerror=alert(1)>"
        length_str = f"{len(tag59_val):02d}"
        payload = f"0002010102125802NP59{length_str}{tag59_val}6009Kathmandu6304ABCD"
        result = evaluate_threat(payload)

        assert result.verdict == "SAFE"
        assert result.beneficiary["Merchant POS Name"] == tag59_val
        import html
        escaped = html.escape(result.beneficiary["Merchant POS Name"])
        assert "<img" not in escaped
        assert "&lt;img" in escaped


