#!/usr/bin/env python3
"""
Email Detection Signals Data Generator
Generates 4200 realistic email records (2100 Malicious + 2100 Not Malicious)
with all 68 detection signals.
"""

import random
import csv
import json
from typing import Dict, Any, List, Optional

# Set seed for reproducibility
random.seed(42)

# ============================================================================
# SIGNAL DEFINITIONS (All 68 signals in order)
# ============================================================================

SIGNAL_COLUMNS = [
    # Sender Detection (0-3, 41)
    "sender_known_malicious",              # 0 - bool - 1=BAD
    "sender_domain_reputation_score",      # 1 - float - 1=GOOD
    "sender_spoof_detected",               # 2 - bool - 1=BAD
    "sender_temp_email_likelihood",        # 3 - float - 1=BAD

    # Authentication (4, 51-55)
    "dmarc_enforced",                      # 4 - bool - 1=GOOD

    # File Analysis (5-10)
    "packer_detected",                     # 5 - bool - 1=BAD
    "any_file_hash_malicious",             # 6 - bool - 1=BAD
    "max_metadata_suspicious_score",       # 7 - float - 1=BAD
    "malicious_attachment_count",          # 8 - int - higher=BAD
    "has_executable_attachment",           # 9 - bool - 1=BAD
    "unscannable_attachment_present",      # 10 - bool - 1=BAD

    # Sandbox Detection (11-25)
    "total_components_detected_malicious", # 11 - int - higher=BAD
    "total_yara_match_count",              # 12 - int - higher=BAD
    "total_ioc_count",                     # 13 - int - higher=BAD
    "max_behavioral_sandbox_score",        # 14 - float - 1=BAD
    "max_amsi_suspicion_score",            # 15 - float - 1=BAD
    "any_macro_enabled_document",          # 16 - bool - 1=BAD
    "any_vbscript_javascript_detected",    # 17 - bool - 1=BAD
    "any_active_x_objects_detected",       # 18 - bool - 1=BAD
    "any_network_call_on_open",            # 19 - bool - 1=BAD
    "max_exfiltration_behavior_score",     # 20 - float - 1=BAD
    "any_exploit_pattern_detected",        # 21 - bool - 1=BAD
    "total_embedded_file_count",           # 22 - int - higher=suspicious
    "max_suspicious_string_entropy_score", # 23 - float - 1=BAD
    "max_sandbox_execution_time",          # 24 - float - higher=suspicious
    "unique_parent_process_names",         # 25 - categorical

    # Return/Reply Path (26-31)
    "return_path_mismatch_with_from",      # 26 - bool - 1=BAD
    "return_path_known_malicious",         # 27 - bool - 1=BAD
    "return_path_reputation_score",        # 28 - float - 1=GOOD
    "reply_path_known_malicious",          # 29 - bool - 1=BAD
    "reply_path_diff_from_sender",         # 30 - bool - 1=BAD
    "reply_path_reputation_score",         # 31 - float - 1=GOOD

    # IP Address (32-35)
    "smtp_ip_known_malicious",             # 32 - bool - 1=BAD
    "smtp_ip_geo",                         # 33 - float - 1=BAD (high risk)
    "smtp_ip_asn",                         # 34 - float - 1=BAD (high risk)
    "smtp_ip_reputation_score",            # 35 - float - 1=GOOD

    # DNS/URL Detection (36-39)
    "domain_known_malicious",              # 36 - bool - 1=BAD
    "url_count",                           # 37 - int - context dependent
    "dns_morphing_detected",               # 38 - bool - 1=BAD
    "domain_tech_stack_match_score",       # 39 - float - 1=GOOD

    # BEC/VIP (40, 42-43)
    "is_high_risk_role_targeted",          # 40 - bool - 1=BAD
    "sender_name_similarity_to_vip",       # 41 - float - 1=BAD (impersonation)
    "urgency_keywords_present",            # 42 - bool - 1=BAD
    "request_type",                        # 43 - categorical

    # Spam/Graymail (44-50)
    "content_spam_score",                  # 44 - float - 1=BAD
    "user_marked_as_spam_before",          # 45 - bool - 1=BAD
    "bulk_message_indicator",              # 46 - bool - 1=suspicious
    "unsubscribe_link_present",            # 47 - bool - context dependent
    "marketing_keywords_detected",         # 48 - float - context dependent
    "html_text_ratio",                     # 49 - float - 1=GOOD
    "image_only_email",                    # 50 - bool - 1=BAD

    # Authentication Results (51-55)
    "spf_result",                          # 51 - enum
    "dkim_result",                         # 52 - enum
    "dmarc_result",                        # 53 - enum
    "reverse_dns_valid",                   # 54 - bool - 1=GOOD
    "tls_version",                         # 55 - categorical

    # Link Scanning (56-66)
    "total_links_detected",                # 56 - int
    "url_shortener_detected",              # 57 - bool - 1=BAD
    "url_redirect_chain_length",           # 58 - int - higher=BAD
    "final_url_known_malicious",           # 59 - bool - 1=BAD
    "url_decoded_spoof_detected",          # 60 - bool - 1=BAD
    "url_reputation_score",                # 61 - float - 1=GOOD
    "ssl_validity_status",                 # 62 - enum
    "site_visual_similarity_to_known_brand", # 63 - float - 1=BAD
    "url_rendering_behavior_score",        # 64 - float - 1=BAD
    "link_rewritten_through_redirector",   # 65 - bool - 1=GOOD
    "token_validation_success",            # 66 - bool - 1=GOOD

    # QR Code (67)
    "qrcode_analysis",                     # 67 - 1=malicious, 0=safe, NULL=none

    # Label
    "label"
]

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def add_variance(base_value: float, variance: float = 0.1, min_val: float = 0.0, max_val: float = 1.0) -> float:
    """Add realistic variance to a float value."""
    value = base_value + random.uniform(-variance, variance)
    return round(max(min_val, min(max_val, value)), 3)

def random_float(low: float, high: float) -> float:
    """Generate random float in range with 3 decimal places."""
    return round(random.uniform(low, high), 3)

def weighted_choice(choices: List[Any], weights: List[float]) -> Any:
    """Make a weighted random choice."""
    return random.choices(choices, weights=weights, k=1)[0]

def get_auth_pattern_malicious() -> Dict[str, str]:
    """Get realistic authentication pattern for malicious emails."""
    patterns = [
        {"spf": "fail", "dkim": "fail", "dmarc": "fail"},      # 25%
        {"spf": "fail", "dkim": "none", "dmarc": "fail"},      # 15%
        {"spf": "none", "dkim": "none", "dmarc": "none"},      # 20%
        {"spf": "softfail", "dkim": "none", "dmarc": "fail"},  # 12%
        {"spf": "pass", "dkim": "fail", "dmarc": "fail"},      # 8%
        {"spf": "pass", "dkim": "pass", "dmarc": "pass"},      # 10% (sophisticated)
        {"spf": "fail", "dkim": "pass", "dmarc": "fail"},      # 5%
        {"spf": "neutral", "dkim": "none", "dmarc": "none"},   # 5%
    ]
    weights = [25, 15, 20, 12, 8, 10, 5, 5]
    return weighted_choice(patterns, weights)

def get_auth_pattern_legitimate() -> Dict[str, str]:
    """Get realistic authentication pattern for legitimate emails."""
    patterns = [
        {"spf": "pass", "dkim": "pass", "dmarc": "pass"},      # 75%
        {"spf": "pass", "dkim": "none", "dmarc": "pass"},      # 10%
        {"spf": "pass", "dkim": "pass", "dmarc": "none"},      # 8%
        {"spf": "softfail", "dkim": "pass", "dmarc": "pass"},  # 4%
        {"spf": "none", "dkim": "none", "dmarc": "none"},      # 3% (legacy)
    ]
    weights = [75, 10, 8, 4, 3]
    return weighted_choice(patterns, weights)

def get_tls_malicious() -> str:
    """Get TLS version for malicious emails."""
    choices = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "None"]
    weights = [15, 30, 20, 15, 5, 15]
    return weighted_choice(choices, weights)

def get_tls_legitimate() -> str:
    """Get TLS version for legitimate emails."""
    choices = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "None"]
    weights = [50, 45, 3, 1, 0, 1]
    return weighted_choice(choices, weights)

def get_ssl_status_malicious() -> str:
    """Get SSL status for malicious URLs."""
    choices = ["self_signed", "expired", "valid", "mismatch", "no_ssl", "invalid_chain", "error", "revoked"]
    weights = [25, 20, 20, 15, 10, 5, 4, 1]
    return weighted_choice(choices, weights)

def get_ssl_status_legitimate() -> str:
    """Get SSL status for legitimate URLs."""
    choices = ["valid", "expired", "self_signed", "mismatch", "error"]
    weights = [92, 4, 2, 1, 1]
    return weighted_choice(choices, weights)

def get_process_names_malicious() -> Optional[str]:
    """Get parent process names for malicious attachments."""
    chains = [
        ["winword.exe", "cmd.exe"],
        ["winword.exe", "powershell.exe"],
        ["winword.exe", "cmd.exe", "powershell.exe"],
        ["excel.exe", "cmd.exe"],
        ["excel.exe", "powershell.exe"],
        ["excel.exe", "cmd.exe", "powershell.exe"],
        ["wscript.exe"],
        ["cscript.exe"],
        ["mshta.exe"],
        ["rundll32.exe"],
        ["regsvr32.exe"],
        ["certutil.exe"],
        ["powershell.exe"],
        ["cmd.exe", "powershell.exe"],
    ]
    weights = [15, 12, 10, 10, 8, 5, 8, 5, 5, 5, 3, 3, 6, 5]
    return json.dumps(weighted_choice(chains, weights))

def get_process_names_legitimate() -> Optional[str]:
    """Get parent process names for legitimate attachments."""
    if random.random() < 0.7:
        return None
    chains = [
        ["winword.exe"],
        ["excel.exe"],
        ["powerpnt.exe"],
        ["acrord32.exe"],
        ["notepad.exe"],
    ]
    weights = [35, 30, 20, 10, 5]
    return json.dumps(weighted_choice(chains, weights))

def get_request_type_malicious() -> str:
    """Get request type for malicious emails."""
    types = [
        "credential_request", "wire_transfer", "gift_card_request",
        "document_download", "link_click", "sensitive_data_request",
        "bank_detail_update", "urgent_callback", "executive_request",
        "vpn_or_mfa_reset", "legal_threat", "invoice_payment"
    ]
    weights = [25, 15, 10, 12, 10, 8, 6, 4, 4, 3, 2, 1]
    return weighted_choice(types, weights)

def get_request_type_legitimate() -> str:
    """Get request type for legitimate emails."""
    types = [
        "none", "meeting_request", "document_download",
        "invoice_payment", "invoice_verification", "credential_request", "link_click"
    ]
    weights = [60, 15, 10, 5, 5, 3, 2]
    return weighted_choice(types, weights)

# ============================================================================
# BASE RECORD GENERATOR
# ============================================================================

def create_base_record() -> Dict[str, Any]:
    """Create a base record with all NULL values."""
    record = {col: None for col in SIGNAL_COLUMNS}
    return record

# ============================================================================
# MALICIOUS SCENARIO GENERATORS
# ============================================================================

def generate_phishing_obvious(record: Dict) -> Dict:
    """Generate obvious phishing email signals."""
    # Sender signals
    record["sender_known_malicious"] = weighted_choice([1, 0], [40, 60])
    record["sender_domain_reputation_score"] = random_float(0.05, 0.35)
    record["sender_spoof_detected"] = 1
    record["sender_temp_email_likelihood"] = random_float(0.3, 0.8)
    record["sender_name_similarity_to_vip"] = random_float(0.1, 0.4)

    # Authentication - mostly failing
    auth = get_auth_pattern_malicious()
    record["spf_result"] = auth["spf"]
    record["dkim_result"] = auth["dkim"]
    record["dmarc_result"] = auth["dmarc"]
    record["dmarc_enforced"] = weighted_choice([0, 1], [70, 30])
    record["reverse_dns_valid"] = weighted_choice([0, 1], [60, 40])
    record["tls_version"] = get_tls_malicious()

    # IP signals
    record["smtp_ip_known_malicious"] = weighted_choice([1, 0], [35, 65])
    record["smtp_ip_geo"] = random_float(0.5, 0.95)
    record["smtp_ip_asn"] = random_float(0.5, 0.9)
    record["smtp_ip_reputation_score"] = random_float(0.1, 0.4)

    # Return/Reply path
    record["return_path_mismatch_with_from"] = 1
    record["return_path_known_malicious"] = weighted_choice([1, 0], [30, 70])
    record["return_path_reputation_score"] = random_float(0.1, 0.4)
    record["reply_path_known_malicious"] = weighted_choice([1, 0], [25, 75])
    record["reply_path_diff_from_sender"] = weighted_choice([1, 0], [60, 40])
    record["reply_path_reputation_score"] = random_float(0.15, 0.45)

    # URL signals - phishing has URLs
    url_count = random.randint(1, 5)
    record["url_count"] = url_count
    record["total_links_detected"] = url_count + random.randint(0, 3)
    record["domain_known_malicious"] = weighted_choice([1, 0], [50, 50])
    record["dns_morphing_detected"] = weighted_choice([1, 0], [40, 60])
    record["domain_tech_stack_match_score"] = random_float(0.1, 0.5)
    record["url_shortener_detected"] = weighted_choice([1, 0], [50, 50])
    record["url_redirect_chain_length"] = random.randint(1, 5) if record["url_shortener_detected"] else random.randint(0, 2)
    record["final_url_known_malicious"] = weighted_choice([1, 0], [60, 40])
    record["url_decoded_spoof_detected"] = weighted_choice([1, 0], [45, 55])
    record["url_reputation_score"] = random_float(0.05, 0.35)
    record["ssl_validity_status"] = get_ssl_status_malicious()
    record["site_visual_similarity_to_known_brand"] = random_float(0.65, 0.98)
    record["url_rendering_behavior_score"] = random_float(0.5, 0.9)
    record["link_rewritten_through_redirector"] = 0
    record["token_validation_success"] = None

    # BEC/VIP signals
    record["is_high_risk_role_targeted"] = weighted_choice([1, 0], [30, 70])
    record["urgency_keywords_present"] = weighted_choice([1, 0], [75, 25])
    record["request_type"] = "credential_request"

    # Spam signals
    record["content_spam_score"] = random_float(0.4, 0.75)
    record["user_marked_as_spam_before"] = weighted_choice([1, 0], [20, 80])
    record["bulk_message_indicator"] = weighted_choice([1, 0], [40, 60])
    record["unsubscribe_link_present"] = weighted_choice([1, 0], [30, 70])
    record["marketing_keywords_detected"] = random_float(0.2, 0.5)
    record["html_text_ratio"] = random_float(0.2, 0.6)
    record["image_only_email"] = 0

    # No attachment for URL-based phishing
    record["packer_detected"] = None
    record["any_file_hash_malicious"] = None
    record["max_metadata_suspicious_score"] = None
    record["malicious_attachment_count"] = None
    record["has_executable_attachment"] = None
    record["unscannable_attachment_present"] = None
    record["total_components_detected_malicious"] = None
    record["total_yara_match_count"] = None
    record["total_ioc_count"] = None
    record["max_behavioral_sandbox_score"] = None
    record["max_amsi_suspicion_score"] = None
    record["any_macro_enabled_document"] = None
    record["any_vbscript_javascript_detected"] = None
    record["any_active_x_objects_detected"] = None
    record["any_network_call_on_open"] = None
    record["max_exfiltration_behavior_score"] = None
    record["any_exploit_pattern_detected"] = None
    record["total_embedded_file_count"] = None
    record["max_suspicious_string_entropy_score"] = None
    record["max_sandbox_execution_time"] = None
    record["unique_parent_process_names"] = None

    record["qrcode_analysis"] = None
    record["label"] = "Malicious"

    return record

def generate_phishing_moderate(record: Dict) -> Dict:
    """Generate moderate sophistication phishing."""
    record = generate_phishing_obvious(record)

    # Improve some signals to be less obvious
    record["sender_domain_reputation_score"] = random_float(0.3, 0.55)
    record["smtp_ip_reputation_score"] = random_float(0.25, 0.5)
    record["sender_known_malicious"] = 0
    record["smtp_ip_known_malicious"] = weighted_choice([1, 0], [15, 85])

    # Better auth sometimes
    if random.random() < 0.3:
        record["spf_result"] = "pass"
        record["dkim_result"] = weighted_choice(["pass", "none"], [50, 50])

    return record

def generate_phishing_sophisticated(record: Dict) -> Dict:
    """Generate sophisticated phishing with good signals."""
    record = generate_phishing_moderate(record)

    # Good reputation (aged domain / compromised)
    record["sender_domain_reputation_score"] = random_float(0.5, 0.72)
    record["smtp_ip_reputation_score"] = random_float(0.45, 0.68)
    record["sender_known_malicious"] = 0
    record["smtp_ip_known_malicious"] = 0
    record["domain_known_malicious"] = 0

    # Pass authentication
    record["spf_result"] = "pass"
    record["dkim_result"] = "pass"
    record["dmarc_result"] = "pass"
    record["reverse_dns_valid"] = 1
    record["tls_version"] = weighted_choice(["TLS 1.3", "TLS 1.2"], [40, 60])

    # But still has malicious URL behavior
    record["site_visual_similarity_to_known_brand"] = random_float(0.7, 0.95)
    record["url_rendering_behavior_score"] = random_float(0.6, 0.85)
    record["ssl_validity_status"] = weighted_choice(["valid", "self_signed"], [60, 40])

    return record

def generate_bec_obvious(record: Dict) -> Dict:
    """Generate obvious BEC/CEO fraud email."""
    record = create_base_record()

    # Sender signals - impersonation
    record["sender_known_malicious"] = weighted_choice([1, 0], [20, 80])
    record["sender_domain_reputation_score"] = random_float(0.15, 0.45)
    record["sender_spoof_detected"] = 1
    record["sender_temp_email_likelihood"] = random_float(0.2, 0.6)
    record["sender_name_similarity_to_vip"] = random_float(0.75, 0.98)

    # Authentication - failing
    auth = get_auth_pattern_malicious()
    record["spf_result"] = auth["spf"]
    record["dkim_result"] = auth["dkim"]
    record["dmarc_result"] = auth["dmarc"]
    record["dmarc_enforced"] = weighted_choice([0, 1], [60, 40])
    record["reverse_dns_valid"] = weighted_choice([0, 1], [55, 45])
    record["tls_version"] = get_tls_malicious()

    # IP signals
    record["smtp_ip_known_malicious"] = weighted_choice([1, 0], [25, 75])
    record["smtp_ip_geo"] = random_float(0.4, 0.85)
    record["smtp_ip_asn"] = random_float(0.4, 0.8)
    record["smtp_ip_reputation_score"] = random_float(0.15, 0.45)

    # Return/Reply - attacker wants replies
    record["return_path_mismatch_with_from"] = 1
    record["return_path_known_malicious"] = weighted_choice([1, 0], [20, 80])
    record["return_path_reputation_score"] = random_float(0.2, 0.5)
    record["reply_path_known_malicious"] = weighted_choice([1, 0], [25, 75])
    record["reply_path_diff_from_sender"] = 1  # Critical for BEC
    record["reply_path_reputation_score"] = random_float(0.15, 0.45)

    # BEC/VIP - key signals
    record["is_high_risk_role_targeted"] = 1
    record["urgency_keywords_present"] = 1
    record["request_type"] = weighted_choice(
        ["wire_transfer", "gift_card_request", "executive_request", "sensitive_data_request"],
        [40, 30, 20, 10]
    )

    # Spam signals - BEC is not spammy
    record["content_spam_score"] = random_float(0.15, 0.4)
    record["user_marked_as_spam_before"] = 0
    record["bulk_message_indicator"] = 0
    record["unsubscribe_link_present"] = 0
    record["marketing_keywords_detected"] = random_float(0.0, 0.15)
    record["html_text_ratio"] = random_float(0.5, 0.85)
    record["image_only_email"] = 0

    # URL signals - BEC often has no/few URLs
    url_count = weighted_choice([0, 1], [70, 30])
    record["url_count"] = url_count
    if url_count > 0:
        record["total_links_detected"] = url_count
        record["domain_known_malicious"] = weighted_choice([1, 0], [30, 70])
        record["dns_morphing_detected"] = 0
        record["domain_tech_stack_match_score"] = random_float(0.3, 0.7)
        record["url_shortener_detected"] = 0
        record["url_redirect_chain_length"] = 0
        record["final_url_known_malicious"] = weighted_choice([1, 0], [40, 60])
        record["url_decoded_spoof_detected"] = 0
        record["url_reputation_score"] = random_float(0.2, 0.5)
        record["ssl_validity_status"] = get_ssl_status_malicious()
        record["site_visual_similarity_to_known_brand"] = random_float(0.1, 0.4)
        record["url_rendering_behavior_score"] = random_float(0.2, 0.5)
        record["link_rewritten_through_redirector"] = 0
        record["token_validation_success"] = None
    else:
        record["total_links_detected"] = 0
        record["domain_known_malicious"] = None
        record["dns_morphing_detected"] = None
        record["domain_tech_stack_match_score"] = None
        record["url_shortener_detected"] = None
        record["url_redirect_chain_length"] = None
        record["final_url_known_malicious"] = None
        record["url_decoded_spoof_detected"] = None
        record["url_reputation_score"] = None
        record["ssl_validity_status"] = None
        record["site_visual_similarity_to_known_brand"] = None
        record["url_rendering_behavior_score"] = None
        record["link_rewritten_through_redirector"] = None
        record["token_validation_success"] = None

    # No attachment
    record["packer_detected"] = None
    record["any_file_hash_malicious"] = None
    record["max_metadata_suspicious_score"] = None
    record["malicious_attachment_count"] = None
    record["has_executable_attachment"] = None
    record["unscannable_attachment_present"] = None
    record["total_components_detected_malicious"] = None
    record["total_yara_match_count"] = None
    record["total_ioc_count"] = None
    record["max_behavioral_sandbox_score"] = None
    record["max_amsi_suspicion_score"] = None
    record["any_macro_enabled_document"] = None
    record["any_vbscript_javascript_detected"] = None
    record["any_active_x_objects_detected"] = None
    record["any_network_call_on_open"] = None
    record["max_exfiltration_behavior_score"] = None
    record["any_exploit_pattern_detected"] = None
    record["total_embedded_file_count"] = None
    record["max_suspicious_string_entropy_score"] = None
    record["max_sandbox_execution_time"] = None
    record["unique_parent_process_names"] = None

    record["qrcode_analysis"] = None
    record["label"] = "Malicious"

    return record

def generate_bec_sophisticated(record: Dict) -> Dict:
    """Generate sophisticated BEC with compromised account."""
    record = generate_bec_obvious(record)

    # Compromised account - good auth
    record["spf_result"] = "pass"
    record["dkim_result"] = "pass"
    record["dmarc_result"] = "pass"
    record["reverse_dns_valid"] = 1
    record["tls_version"] = weighted_choice(["TLS 1.3", "TLS 1.2"], [50, 50])

    # Better reputation
    record["sender_domain_reputation_score"] = random_float(0.55, 0.78)
    record["smtp_ip_reputation_score"] = random_float(0.5, 0.75)
    record["sender_known_malicious"] = 0
    record["smtp_ip_known_malicious"] = 0

    # Still has BEC indicators
    record["sender_name_similarity_to_vip"] = random_float(0.85, 0.99)
    record["reply_path_diff_from_sender"] = 1
    record["urgency_keywords_present"] = 1

    return record

def generate_malware_executable(record: Dict) -> Dict:
    """Generate malware with executable attachment."""
    record = create_base_record()

    # Sender signals
    record["sender_known_malicious"] = weighted_choice([1, 0], [45, 55])
    record["sender_domain_reputation_score"] = random_float(0.08, 0.35)
    record["sender_spoof_detected"] = weighted_choice([1, 0], [60, 40])
    record["sender_temp_email_likelihood"] = random_float(0.3, 0.75)
    record["sender_name_similarity_to_vip"] = random_float(0.0, 0.3)

    # Authentication
    auth = get_auth_pattern_malicious()
    record["spf_result"] = auth["spf"]
    record["dkim_result"] = auth["dkim"]
    record["dmarc_result"] = auth["dmarc"]
    record["dmarc_enforced"] = weighted_choice([0, 1], [65, 35])
    record["reverse_dns_valid"] = weighted_choice([0, 1], [60, 40])
    record["tls_version"] = get_tls_malicious()

    # IP signals
    record["smtp_ip_known_malicious"] = weighted_choice([1, 0], [40, 60])
    record["smtp_ip_geo"] = random_float(0.5, 0.92)
    record["smtp_ip_asn"] = random_float(0.5, 0.88)
    record["smtp_ip_reputation_score"] = random_float(0.1, 0.38)

    # Return/Reply path
    record["return_path_mismatch_with_from"] = weighted_choice([1, 0], [70, 30])
    record["return_path_known_malicious"] = weighted_choice([1, 0], [35, 65])
    record["return_path_reputation_score"] = random_float(0.1, 0.4)
    record["reply_path_known_malicious"] = weighted_choice([1, 0], [30, 70])
    record["reply_path_diff_from_sender"] = weighted_choice([1, 0], [40, 60])
    record["reply_path_reputation_score"] = random_float(0.12, 0.42)

    # File Analysis - EXECUTABLE
    record["packer_detected"] = weighted_choice([1, 0], [60, 40])
    record["any_file_hash_malicious"] = weighted_choice([1, 0], [70, 30])
    record["max_metadata_suspicious_score"] = random_float(0.5, 0.95)
    record["malicious_attachment_count"] = random.randint(1, 2)
    record["has_executable_attachment"] = 1
    record["unscannable_attachment_present"] = 0

    # Sandbox signals
    record["total_components_detected_malicious"] = random.randint(1, 8)
    record["total_yara_match_count"] = random.randint(2, 15)
    record["total_ioc_count"] = random.randint(5, 40)
    record["max_behavioral_sandbox_score"] = random_float(0.65, 0.98)
    record["max_amsi_suspicion_score"] = random_float(0.4, 0.85)
    record["any_macro_enabled_document"] = 0
    record["any_vbscript_javascript_detected"] = weighted_choice([1, 0], [40, 60])
    record["any_active_x_objects_detected"] = weighted_choice([1, 0], [15, 85])
    record["any_network_call_on_open"] = weighted_choice([1, 0], [65, 35])
    record["max_exfiltration_behavior_score"] = random_float(0.3, 0.8)
    record["any_exploit_pattern_detected"] = weighted_choice([1, 0], [25, 75])
    record["total_embedded_file_count"] = random.randint(0, 5)
    record["max_suspicious_string_entropy_score"] = random_float(0.55, 0.95)
    record["max_sandbox_execution_time"] = random_float(5, 60)
    record["unique_parent_process_names"] = get_process_names_malicious()

    # URL signals - malware may or may not have URLs
    url_count = weighted_choice([0, 1, 2], [50, 35, 15])
    record["url_count"] = url_count
    if url_count > 0:
        record["total_links_detected"] = url_count
        record["domain_known_malicious"] = weighted_choice([1, 0], [40, 60])
        record["dns_morphing_detected"] = weighted_choice([1, 0], [20, 80])
        record["domain_tech_stack_match_score"] = random_float(0.2, 0.6)
        record["url_shortener_detected"] = weighted_choice([1, 0], [30, 70])
        record["url_redirect_chain_length"] = random.randint(0, 3)
        record["final_url_known_malicious"] = weighted_choice([1, 0], [50, 50])
        record["url_decoded_spoof_detected"] = weighted_choice([1, 0], [25, 75])
        record["url_reputation_score"] = random_float(0.1, 0.45)
        record["ssl_validity_status"] = get_ssl_status_malicious()
        record["site_visual_similarity_to_known_brand"] = random_float(0.1, 0.5)
        record["url_rendering_behavior_score"] = random_float(0.3, 0.7)
        record["link_rewritten_through_redirector"] = 0
        record["token_validation_success"] = None
    else:
        record["total_links_detected"] = 0
        record["domain_known_malicious"] = None
        record["dns_morphing_detected"] = None
        record["domain_tech_stack_match_score"] = None
        record["url_shortener_detected"] = None
        record["url_redirect_chain_length"] = None
        record["final_url_known_malicious"] = None
        record["url_decoded_spoof_detected"] = None
        record["url_reputation_score"] = None
        record["ssl_validity_status"] = None
        record["site_visual_similarity_to_known_brand"] = None
        record["url_rendering_behavior_score"] = None
        record["link_rewritten_through_redirector"] = None
        record["token_validation_success"] = None

    # BEC/VIP
    record["is_high_risk_role_targeted"] = weighted_choice([1, 0], [30, 70])
    record["urgency_keywords_present"] = weighted_choice([1, 0], [55, 45])
    record["request_type"] = weighted_choice(
        ["document_download", "link_click", "none"],
        [50, 30, 20]
    )

    # Spam signals
    record["content_spam_score"] = random_float(0.35, 0.7)
    record["user_marked_as_spam_before"] = weighted_choice([1, 0], [25, 75])
    record["bulk_message_indicator"] = weighted_choice([1, 0], [35, 65])
    record["unsubscribe_link_present"] = weighted_choice([1, 0], [20, 80])
    record["marketing_keywords_detected"] = random_float(0.1, 0.4)
    record["html_text_ratio"] = random_float(0.25, 0.65)
    record["image_only_email"] = 0

    record["qrcode_analysis"] = None
    record["label"] = "Malicious"

    return record

def generate_malware_macro(record: Dict) -> Dict:
    """Generate malware with macro-enabled document."""
    record = generate_malware_executable(record)

    # Macro-specific changes
    record["has_executable_attachment"] = 0
    record["any_macro_enabled_document"] = 1
    record["any_vbscript_javascript_detected"] = 1
    record["max_amsi_suspicion_score"] = random_float(0.55, 0.95)
    record["packer_detected"] = weighted_choice([1, 0], [40, 60])

    # Process names for macro attack
    record["unique_parent_process_names"] = json.dumps(
        weighted_choice([
            ["winword.exe", "cmd.exe"],
            ["winword.exe", "powershell.exe"],
            ["winword.exe", "cmd.exe", "powershell.exe"],
            ["excel.exe", "cmd.exe"],
            ["excel.exe", "powershell.exe"],
        ], [30, 25, 20, 15, 10])
    )

    return record

def generate_malware_evasive(record: Dict) -> Dict:
    """Generate evasive malware with low detection."""
    record = generate_malware_executable(record)

    # Lower detection scores (evasion)
    record["any_file_hash_malicious"] = 0  # Unknown/new malware
    record["max_behavioral_sandbox_score"] = random_float(0.25, 0.5)
    record["total_yara_match_count"] = random.randint(0, 3)
    record["total_ioc_count"] = random.randint(0, 8)
    record["total_components_detected_malicious"] = random.randint(0, 2)
    record["max_sandbox_execution_time"] = random_float(90, 180)  # Delayed

    # Better reputation
    record["sender_domain_reputation_score"] = random_float(0.35, 0.58)
    record["smtp_ip_reputation_score"] = random_float(0.3, 0.55)

    return record

def generate_ransomware(record: Dict) -> Dict:
    """Generate ransomware delivery email."""
    record = generate_malware_executable(record)

    # Ransomware specific - high exfiltration
    record["max_exfiltration_behavior_score"] = random_float(0.75, 0.99)
    record["any_network_call_on_open"] = 1
    record["max_behavioral_sandbox_score"] = random_float(0.8, 0.99)
    record["total_ioc_count"] = random.randint(15, 80)

    return record

def generate_spam_obvious(record: Dict) -> Dict:
    """Generate obvious spam email."""
    record = create_base_record()

    # Sender signals
    record["sender_known_malicious"] = weighted_choice([1, 0], [30, 70])
    record["sender_domain_reputation_score"] = random_float(0.03, 0.25)
    record["sender_spoof_detected"] = weighted_choice([1, 0], [50, 50])
    record["sender_temp_email_likelihood"] = random_float(0.6, 0.95)
    record["sender_name_similarity_to_vip"] = random_float(0.0, 0.2)

    # Authentication - mostly failing
    auth = get_auth_pattern_malicious()
    record["spf_result"] = auth["spf"]
    record["dkim_result"] = auth["dkim"]
    record["dmarc_result"] = auth["dmarc"]
    record["dmarc_enforced"] = weighted_choice([0, 1], [75, 25])
    record["reverse_dns_valid"] = weighted_choice([0, 1], [65, 35])
    record["tls_version"] = get_tls_malicious()

    # IP signals
    record["smtp_ip_known_malicious"] = weighted_choice([1, 0], [35, 65])
    record["smtp_ip_geo"] = random_float(0.55, 0.95)
    record["smtp_ip_asn"] = random_float(0.5, 0.9)
    record["smtp_ip_reputation_score"] = random_float(0.05, 0.3)

    # Return/Reply path
    record["return_path_mismatch_with_from"] = weighted_choice([1, 0], [65, 35])
    record["return_path_known_malicious"] = weighted_choice([1, 0], [30, 70])
    record["return_path_reputation_score"] = random_float(0.08, 0.35)
    record["reply_path_known_malicious"] = weighted_choice([1, 0], [25, 75])
    record["reply_path_diff_from_sender"] = weighted_choice([1, 0], [50, 50])
    record["reply_path_reputation_score"] = random_float(0.1, 0.38)

    # Spam signals - HIGH
    record["content_spam_score"] = random_float(0.75, 0.99)
    record["user_marked_as_spam_before"] = weighted_choice([1, 0], [40, 60])
    record["bulk_message_indicator"] = 1
    record["unsubscribe_link_present"] = weighted_choice([1, 0], [50, 50])
    record["marketing_keywords_detected"] = random_float(0.6, 0.95)
    record["html_text_ratio"] = random_float(0.1, 0.45)
    record["image_only_email"] = weighted_choice([1, 0], [40, 60])

    # URLs in spam
    url_count = random.randint(2, 12)
    record["url_count"] = url_count
    record["total_links_detected"] = url_count + random.randint(1, 5)
    record["domain_known_malicious"] = weighted_choice([1, 0], [40, 60])
    record["dns_morphing_detected"] = weighted_choice([1, 0], [25, 75])
    record["domain_tech_stack_match_score"] = random_float(0.15, 0.5)
    record["url_shortener_detected"] = weighted_choice([1, 0], [45, 55])
    record["url_redirect_chain_length"] = random.randint(1, 4)
    record["final_url_known_malicious"] = weighted_choice([1, 0], [45, 55])
    record["url_decoded_spoof_detected"] = weighted_choice([1, 0], [30, 70])
    record["url_reputation_score"] = random_float(0.08, 0.38)
    record["ssl_validity_status"] = get_ssl_status_malicious()
    record["site_visual_similarity_to_known_brand"] = random_float(0.2, 0.6)
    record["url_rendering_behavior_score"] = random_float(0.35, 0.75)
    record["link_rewritten_through_redirector"] = 0
    record["token_validation_success"] = None

    # BEC/VIP - not targeted
    record["is_high_risk_role_targeted"] = 0
    record["urgency_keywords_present"] = weighted_choice([1, 0], [60, 40])
    record["request_type"] = weighted_choice(
        ["link_click", "credential_request", "none"],
        [50, 30, 20]
    )

    # No attachment typically
    record["packer_detected"] = None
    record["any_file_hash_malicious"] = None
    record["max_metadata_suspicious_score"] = None
    record["malicious_attachment_count"] = None
    record["has_executable_attachment"] = None
    record["unscannable_attachment_present"] = None
    record["total_components_detected_malicious"] = None
    record["total_yara_match_count"] = None
    record["total_ioc_count"] = None
    record["max_behavioral_sandbox_score"] = None
    record["max_amsi_suspicion_score"] = None
    record["any_macro_enabled_document"] = None
    record["any_vbscript_javascript_detected"] = None
    record["any_active_x_objects_detected"] = None
    record["any_network_call_on_open"] = None
    record["max_exfiltration_behavior_score"] = None
    record["any_exploit_pattern_detected"] = None
    record["total_embedded_file_count"] = None
    record["max_suspicious_string_entropy_score"] = None
    record["max_sandbox_execution_time"] = None
    record["unique_parent_process_names"] = None

    record["qrcode_analysis"] = None
    record["label"] = "Malicious"

    return record

def generate_evasion_encrypted(record: Dict) -> Dict:
    """Generate email with encrypted/password-protected attachment."""
    record = create_base_record()

    # Sender signals - moderate
    record["sender_known_malicious"] = weighted_choice([1, 0], [20, 80])
    record["sender_domain_reputation_score"] = random_float(0.2, 0.5)
    record["sender_spoof_detected"] = weighted_choice([1, 0], [55, 45])
    record["sender_temp_email_likelihood"] = random_float(0.25, 0.65)
    record["sender_name_similarity_to_vip"] = random_float(0.1, 0.45)

    # Authentication
    auth = get_auth_pattern_malicious()
    record["spf_result"] = auth["spf"]
    record["dkim_result"] = auth["dkim"]
    record["dmarc_result"] = auth["dmarc"]
    record["dmarc_enforced"] = weighted_choice([0, 1], [60, 40])
    record["reverse_dns_valid"] = weighted_choice([0, 1], [50, 50])
    record["tls_version"] = get_tls_malicious()

    # IP signals
    record["smtp_ip_known_malicious"] = weighted_choice([1, 0], [25, 75])
    record["smtp_ip_geo"] = random_float(0.4, 0.8)
    record["smtp_ip_asn"] = random_float(0.4, 0.75)
    record["smtp_ip_reputation_score"] = random_float(0.2, 0.5)

    # Return/Reply
    record["return_path_mismatch_with_from"] = weighted_choice([1, 0], [55, 45])
    record["return_path_known_malicious"] = weighted_choice([1, 0], [20, 80])
    record["return_path_reputation_score"] = random_float(0.2, 0.5)
    record["reply_path_known_malicious"] = weighted_choice([1, 0], [18, 82])
    record["reply_path_diff_from_sender"] = weighted_choice([1, 0], [45, 55])
    record["reply_path_reputation_score"] = random_float(0.22, 0.52)

    # File Analysis - UNSCANNABLE
    record["packer_detected"] = None  # Can't determine
    record["any_file_hash_malicious"] = None  # Can't determine
    record["max_metadata_suspicious_score"] = random_float(0.4, 0.7)
    record["malicious_attachment_count"] = None  # Can't scan
    record["has_executable_attachment"] = None  # Can't determine
    record["unscannable_attachment_present"] = 1  # KEY SIGNAL

    # Sandbox - limited
    record["total_components_detected_malicious"] = None
    record["total_yara_match_count"] = None
    record["total_ioc_count"] = random.randint(0, 3)
    record["max_behavioral_sandbox_score"] = None
    record["max_amsi_suspicion_score"] = None
    record["any_macro_enabled_document"] = None
    record["any_vbscript_javascript_detected"] = None
    record["any_active_x_objects_detected"] = None
    record["any_network_call_on_open"] = None
    record["max_exfiltration_behavior_score"] = None
    record["any_exploit_pattern_detected"] = None
    record["total_embedded_file_count"] = None
    record["max_suspicious_string_entropy_score"] = random_float(0.5, 0.85)
    record["max_sandbox_execution_time"] = None
    record["unique_parent_process_names"] = None

    # URL signals
    url_count = random.randint(0, 2)
    record["url_count"] = url_count
    if url_count > 0:
        record["total_links_detected"] = url_count
        record["domain_known_malicious"] = weighted_choice([1, 0], [25, 75])
        record["dns_morphing_detected"] = 0
        record["domain_tech_stack_match_score"] = random_float(0.3, 0.65)
        record["url_shortener_detected"] = 0
        record["url_redirect_chain_length"] = 0
        record["final_url_known_malicious"] = weighted_choice([1, 0], [30, 70])
        record["url_decoded_spoof_detected"] = 0
        record["url_reputation_score"] = random_float(0.25, 0.55)
        record["ssl_validity_status"] = weighted_choice(["valid", "self_signed"], [60, 40])
        record["site_visual_similarity_to_known_brand"] = random_float(0.1, 0.4)
        record["url_rendering_behavior_score"] = random_float(0.2, 0.5)
        record["link_rewritten_through_redirector"] = 0
        record["token_validation_success"] = None
    else:
        record["total_links_detected"] = 0
        record["domain_known_malicious"] = None
        record["dns_morphing_detected"] = None
        record["domain_tech_stack_match_score"] = None
        record["url_shortener_detected"] = None
        record["url_redirect_chain_length"] = None
        record["final_url_known_malicious"] = None
        record["url_decoded_spoof_detected"] = None
        record["url_reputation_score"] = None
        record["ssl_validity_status"] = None
        record["site_visual_similarity_to_known_brand"] = None
        record["url_rendering_behavior_score"] = None
        record["link_rewritten_through_redirector"] = None
        record["token_validation_success"] = None

    # BEC/VIP
    record["is_high_risk_role_targeted"] = weighted_choice([1, 0], [40, 60])
    record["urgency_keywords_present"] = 1  # Password in body = urgency
    record["request_type"] = "document_download"

    # Spam
    record["content_spam_score"] = random_float(0.25, 0.55)
    record["user_marked_as_spam_before"] = 0
    record["bulk_message_indicator"] = 0
    record["unsubscribe_link_present"] = 0
    record["marketing_keywords_detected"] = random_float(0.05, 0.25)
    record["html_text_ratio"] = random_float(0.45, 0.75)
    record["image_only_email"] = 0

    record["qrcode_analysis"] = None
    record["label"] = "Malicious"

    return record

def generate_evasion_image_only(record: Dict) -> Dict:
    """Generate image-only email (evasion technique)."""
    record = create_base_record()

    # Sender signals
    record["sender_known_malicious"] = weighted_choice([1, 0], [30, 70])
    record["sender_domain_reputation_score"] = random_float(0.1, 0.4)
    record["sender_spoof_detected"] = weighted_choice([1, 0], [55, 45])
    record["sender_temp_email_likelihood"] = random_float(0.35, 0.75)
    record["sender_name_similarity_to_vip"] = random_float(0.1, 0.4)

    # Authentication
    auth = get_auth_pattern_malicious()
    record["spf_result"] = auth["spf"]
    record["dkim_result"] = auth["dkim"]
    record["dmarc_result"] = auth["dmarc"]
    record["dmarc_enforced"] = weighted_choice([0, 1], [60, 40])
    record["reverse_dns_valid"] = weighted_choice([0, 1], [55, 45])
    record["tls_version"] = get_tls_malicious()

    # IP signals
    record["smtp_ip_known_malicious"] = weighted_choice([1, 0], [30, 70])
    record["smtp_ip_geo"] = random_float(0.45, 0.85)
    record["smtp_ip_asn"] = random_float(0.4, 0.8)
    record["smtp_ip_reputation_score"] = random_float(0.15, 0.45)

    # Return/Reply
    record["return_path_mismatch_with_from"] = weighted_choice([1, 0], [60, 40])
    record["return_path_known_malicious"] = weighted_choice([1, 0], [25, 75])
    record["return_path_reputation_score"] = random_float(0.15, 0.45)
    record["reply_path_known_malicious"] = weighted_choice([1, 0], [22, 78])
    record["reply_path_diff_from_sender"] = weighted_choice([1, 0], [50, 50])
    record["reply_path_reputation_score"] = random_float(0.18, 0.48)

    # Spam - IMAGE ONLY
    record["content_spam_score"] = random_float(0.3, 0.6)  # Lower - evaded text analysis
    record["user_marked_as_spam_before"] = weighted_choice([1, 0], [25, 75])
    record["bulk_message_indicator"] = weighted_choice([1, 0], [50, 50])
    record["unsubscribe_link_present"] = weighted_choice([1, 0], [30, 70])
    record["marketing_keywords_detected"] = random_float(0.1, 0.35)  # Lower - no text
    record["html_text_ratio"] = random_float(0.02, 0.12)  # CRITICAL - very low
    record["image_only_email"] = 1  # CRITICAL

    # URL - often in image
    url_count = random.randint(1, 3)
    record["url_count"] = url_count
    record["total_links_detected"] = url_count
    record["domain_known_malicious"] = weighted_choice([1, 0], [40, 60])
    record["dns_morphing_detected"] = weighted_choice([1, 0], [30, 70])
    record["domain_tech_stack_match_score"] = random_float(0.2, 0.55)
    record["url_shortener_detected"] = weighted_choice([1, 0], [45, 55])
    record["url_redirect_chain_length"] = random.randint(1, 4)
    record["final_url_known_malicious"] = weighted_choice([1, 0], [50, 50])
    record["url_decoded_spoof_detected"] = weighted_choice([1, 0], [35, 65])
    record["url_reputation_score"] = random_float(0.12, 0.42)
    record["ssl_validity_status"] = get_ssl_status_malicious()
    record["site_visual_similarity_to_known_brand"] = random_float(0.5, 0.9)
    record["url_rendering_behavior_score"] = random_float(0.45, 0.8)
    record["link_rewritten_through_redirector"] = 0
    record["token_validation_success"] = None

    # BEC/VIP
    record["is_high_risk_role_targeted"] = weighted_choice([1, 0], [25, 75])
    record["urgency_keywords_present"] = 0  # Can't detect - image
    record["request_type"] = weighted_choice(["link_click", "credential_request"], [60, 40])

    # No attachment
    record["packer_detected"] = None
    record["any_file_hash_malicious"] = None
    record["max_metadata_suspicious_score"] = None
    record["malicious_attachment_count"] = None
    record["has_executable_attachment"] = None
    record["unscannable_attachment_present"] = None
    record["total_components_detected_malicious"] = None
    record["total_yara_match_count"] = None
    record["total_ioc_count"] = None
    record["max_behavioral_sandbox_score"] = None
    record["max_amsi_suspicion_score"] = None
    record["any_macro_enabled_document"] = None
    record["any_vbscript_javascript_detected"] = None
    record["any_active_x_objects_detected"] = None
    record["any_network_call_on_open"] = None
    record["max_exfiltration_behavior_score"] = None
    record["any_exploit_pattern_detected"] = None
    record["total_embedded_file_count"] = None
    record["max_suspicious_string_entropy_score"] = None
    record["max_sandbox_execution_time"] = None
    record["unique_parent_process_names"] = None

    record["qrcode_analysis"] = None
    record["label"] = "Malicious"

    return record

def generate_qr_phishing(record: Dict) -> Dict:
    """Generate QR code phishing email."""
    record = generate_evasion_image_only(record)

    # QR specific
    record["qrcode_analysis"] = 1  # Malicious QR detected
    record["url_count"] = 0  # No text URLs
    record["total_links_detected"] = 0

    # Set URL-dependent signals to NULL
    record["domain_known_malicious"] = None
    record["dns_morphing_detected"] = None
    record["domain_tech_stack_match_score"] = None
    record["url_shortener_detected"] = None
    record["url_redirect_chain_length"] = None
    record["final_url_known_malicious"] = None
    record["url_decoded_spoof_detected"] = None
    record["url_reputation_score"] = None
    record["ssl_validity_status"] = None
    record["site_visual_similarity_to_known_brand"] = None
    record["url_rendering_behavior_score"] = None
    record["link_rewritten_through_redirector"] = None
    record["token_validation_success"] = None

    return record

def generate_known_threat_actor(record: Dict) -> Dict:
    """Generate email from known threat actor."""
    record = create_base_record()

    # Sender - KNOWN MALICIOUS
    record["sender_known_malicious"] = 1
    record["sender_domain_reputation_score"] = random_float(0.02, 0.2)
    record["sender_spoof_detected"] = weighted_choice([1, 0], [70, 30])
    record["sender_temp_email_likelihood"] = random_float(0.4, 0.85)
    record["sender_name_similarity_to_vip"] = random_float(0.1, 0.5)

    # Authentication - failing
    record["spf_result"] = weighted_choice(["fail", "softfail", "none"], [50, 30, 20])
    record["dkim_result"] = weighted_choice(["fail", "none"], [60, 40])
    record["dmarc_result"] = "fail"
    record["dmarc_enforced"] = 0
    record["reverse_dns_valid"] = 0
    record["tls_version"] = get_tls_malicious()

    # IP - KNOWN MALICIOUS
    record["smtp_ip_known_malicious"] = 1
    record["smtp_ip_geo"] = random_float(0.7, 0.98)
    record["smtp_ip_asn"] = random_float(0.7, 0.95)
    record["smtp_ip_reputation_score"] = random_float(0.02, 0.18)

    # Return/Reply - KNOWN MALICIOUS
    record["return_path_mismatch_with_from"] = 1
    record["return_path_known_malicious"] = 1
    record["return_path_reputation_score"] = random_float(0.02, 0.15)
    record["reply_path_known_malicious"] = weighted_choice([1, 0], [70, 30])
    record["reply_path_diff_from_sender"] = 1
    record["reply_path_reputation_score"] = random_float(0.05, 0.2)

    # URL - KNOWN MALICIOUS
    url_count = random.randint(1, 5)
    record["url_count"] = url_count
    record["total_links_detected"] = url_count + random.randint(0, 2)
    record["domain_known_malicious"] = 1
    record["dns_morphing_detected"] = weighted_choice([1, 0], [40, 60])
    record["domain_tech_stack_match_score"] = random_float(0.1, 0.35)
    record["url_shortener_detected"] = weighted_choice([1, 0], [50, 50])
    record["url_redirect_chain_length"] = random.randint(1, 5)
    record["final_url_known_malicious"] = 1
    record["url_decoded_spoof_detected"] = weighted_choice([1, 0], [45, 55])
    record["url_reputation_score"] = random_float(0.02, 0.18)
    record["ssl_validity_status"] = get_ssl_status_malicious()
    record["site_visual_similarity_to_known_brand"] = random_float(0.6, 0.95)
    record["url_rendering_behavior_score"] = random_float(0.6, 0.92)
    record["link_rewritten_through_redirector"] = 0
    record["token_validation_success"] = None

    # BEC/VIP
    record["is_high_risk_role_targeted"] = weighted_choice([1, 0], [50, 50])
    record["urgency_keywords_present"] = weighted_choice([1, 0], [70, 30])
    record["request_type"] = get_request_type_malicious()

    # Spam
    record["content_spam_score"] = random_float(0.5, 0.85)
    record["user_marked_as_spam_before"] = weighted_choice([1, 0], [60, 40])
    record["bulk_message_indicator"] = weighted_choice([1, 0], [55, 45])
    record["unsubscribe_link_present"] = weighted_choice([1, 0], [30, 70])
    record["marketing_keywords_detected"] = random_float(0.2, 0.6)
    record["html_text_ratio"] = random_float(0.2, 0.6)
    record["image_only_email"] = weighted_choice([1, 0], [25, 75])

    # No attachment
    record["packer_detected"] = None
    record["any_file_hash_malicious"] = None
    record["max_metadata_suspicious_score"] = None
    record["malicious_attachment_count"] = None
    record["has_executable_attachment"] = None
    record["unscannable_attachment_present"] = None
    record["total_components_detected_malicious"] = None
    record["total_yara_match_count"] = None
    record["total_ioc_count"] = None
    record["max_behavioral_sandbox_score"] = None
    record["max_amsi_suspicion_score"] = None
    record["any_macro_enabled_document"] = None
    record["any_vbscript_javascript_detected"] = None
    record["any_active_x_objects_detected"] = None
    record["any_network_call_on_open"] = None
    record["max_exfiltration_behavior_score"] = None
    record["any_exploit_pattern_detected"] = None
    record["total_embedded_file_count"] = None
    record["max_suspicious_string_entropy_score"] = None
    record["max_sandbox_execution_time"] = None
    record["unique_parent_process_names"] = None

    record["qrcode_analysis"] = None
    record["label"] = "Malicious"

    return record

def generate_callback_phishing(record: Dict) -> Dict:
    """Generate callback/TOAD phishing."""
    record = generate_bec_obvious(record)

    # Callback specific - no URLs
    record["url_count"] = 0
    record["total_links_detected"] = 0
    record["request_type"] = "urgent_callback"

    # Clear URL signals
    record["domain_known_malicious"] = None
    record["dns_morphing_detected"] = None
    record["domain_tech_stack_match_score"] = None
    record["url_shortener_detected"] = None
    record["url_redirect_chain_length"] = None
    record["final_url_known_malicious"] = None
    record["url_decoded_spoof_detected"] = None
    record["url_reputation_score"] = None
    record["ssl_validity_status"] = None
    record["site_visual_similarity_to_known_brand"] = None
    record["url_rendering_behavior_score"] = None
    record["link_rewritten_through_redirector"] = None
    record["token_validation_success"] = None

    return record


# ============================================================================
# LEGITIMATE SCENARIO GENERATORS
# ============================================================================

def generate_legitimate_enterprise(record: Dict) -> Dict:
    """Generate legitimate enterprise internal email."""
    record = create_base_record()

    # Sender - GOOD
    record["sender_known_malicious"] = 0
    record["sender_domain_reputation_score"] = random_float(0.82, 0.98)
    record["sender_spoof_detected"] = 0
    record["sender_temp_email_likelihood"] = random_float(0.0, 0.08)
    record["sender_name_similarity_to_vip"] = random_float(0.0, 0.15)

    # Authentication - PASSING
    record["spf_result"] = "pass"
    record["dkim_result"] = "pass"
    record["dmarc_result"] = "pass"
    record["dmarc_enforced"] = 1
    record["reverse_dns_valid"] = 1
    record["tls_version"] = weighted_choice(["TLS 1.3", "TLS 1.2"], [55, 45])

    # IP - GOOD
    record["smtp_ip_known_malicious"] = 0
    record["smtp_ip_geo"] = random_float(0.02, 0.25)
    record["smtp_ip_asn"] = random_float(0.02, 0.2)
    record["smtp_ip_reputation_score"] = random_float(0.8, 0.98)

    # Return/Reply - MATCHING
    record["return_path_mismatch_with_from"] = 0
    record["return_path_known_malicious"] = 0
    record["return_path_reputation_score"] = random_float(0.78, 0.96)
    record["reply_path_known_malicious"] = 0
    record["reply_path_diff_from_sender"] = 0
    record["reply_path_reputation_score"] = random_float(0.8, 0.97)

    # BEC/VIP - NOT TARGETED
    record["is_high_risk_role_targeted"] = 0
    record["urgency_keywords_present"] = 0
    record["request_type"] = "none"

    # Spam - LOW
    record["content_spam_score"] = random_float(0.02, 0.18)
    record["user_marked_as_spam_before"] = 0
    record["bulk_message_indicator"] = 0
    record["unsubscribe_link_present"] = 0
    record["marketing_keywords_detected"] = random_float(0.0, 0.12)
    record["html_text_ratio"] = random_float(0.6, 0.92)
    record["image_only_email"] = 0

    # URL - minimal
    url_count = weighted_choice([0, 1, 2], [40, 45, 15])
    record["url_count"] = url_count
    if url_count > 0:
        record["total_links_detected"] = url_count
        record["domain_known_malicious"] = 0
        record["dns_morphing_detected"] = 0
        record["domain_tech_stack_match_score"] = random_float(0.75, 0.98)
        record["url_shortener_detected"] = 0
        record["url_redirect_chain_length"] = 0
        record["final_url_known_malicious"] = 0
        record["url_decoded_spoof_detected"] = 0
        record["url_reputation_score"] = random_float(0.82, 0.98)
        record["ssl_validity_status"] = "valid"
        record["site_visual_similarity_to_known_brand"] = random_float(0.0, 0.15)
        record["url_rendering_behavior_score"] = random_float(0.02, 0.18)
        record["link_rewritten_through_redirector"] = weighted_choice([1, 0], [30, 70])
        record["token_validation_success"] = 1 if record["link_rewritten_through_redirector"] else None
    else:
        record["total_links_detected"] = 0
        record["domain_known_malicious"] = None
        record["dns_morphing_detected"] = None
        record["domain_tech_stack_match_score"] = None
        record["url_shortener_detected"] = None
        record["url_redirect_chain_length"] = None
        record["final_url_known_malicious"] = None
        record["url_decoded_spoof_detected"] = None
        record["url_reputation_score"] = None
        record["ssl_validity_status"] = None
        record["site_visual_similarity_to_known_brand"] = None
        record["url_rendering_behavior_score"] = None
        record["link_rewritten_through_redirector"] = None
        record["token_validation_success"] = None

    # No attachment
    record["packer_detected"] = None
    record["any_file_hash_malicious"] = None
    record["max_metadata_suspicious_score"] = None
    record["malicious_attachment_count"] = None
    record["has_executable_attachment"] = None
    record["unscannable_attachment_present"] = None
    record["total_components_detected_malicious"] = None
    record["total_yara_match_count"] = None
    record["total_ioc_count"] = None
    record["max_behavioral_sandbox_score"] = None
    record["max_amsi_suspicion_score"] = None
    record["any_macro_enabled_document"] = None
    record["any_vbscript_javascript_detected"] = None
    record["any_active_x_objects_detected"] = None
    record["any_network_call_on_open"] = None
    record["max_exfiltration_behavior_score"] = None
    record["any_exploit_pattern_detected"] = None
    record["total_embedded_file_count"] = None
    record["max_suspicious_string_entropy_score"] = None
    record["max_sandbox_execution_time"] = None
    record["unique_parent_process_names"] = None

    record["qrcode_analysis"] = None
    record["label"] = "Not Malicious"

    return record

def generate_legitimate_smb(record: Dict) -> Dict:
    """Generate legitimate SMB email with some imperfections."""
    record = generate_legitimate_enterprise(record)

    # Lower but still acceptable reputation
    record["sender_domain_reputation_score"] = random_float(0.55, 0.78)
    record["smtp_ip_reputation_score"] = random_float(0.52, 0.75)

    # Some auth issues possible
    if random.random() < 0.2:
        record["spf_result"] = "softfail"
    if random.random() < 0.15:
        record["dkim_result"] = "none"
    if random.random() < 0.1:
        record["dmarc_result"] = "none"

    record["dmarc_enforced"] = weighted_choice([1, 0], [60, 40])

    return record

def generate_legitimate_marketing(record: Dict) -> Dict:
    """Generate legitimate marketing email."""
    record = create_base_record()

    # Sender - GOOD but marketing
    record["sender_known_malicious"] = 0
    record["sender_domain_reputation_score"] = random_float(0.62, 0.88)
    record["sender_spoof_detected"] = 0
    record["sender_temp_email_likelihood"] = random_float(0.0, 0.1)
    record["sender_name_similarity_to_vip"] = random_float(0.0, 0.1)

    # Authentication - mostly passing
    auth = get_auth_pattern_legitimate()
    record["spf_result"] = auth["spf"]
    record["dkim_result"] = auth["dkim"]
    record["dmarc_result"] = auth["dmarc"]
    record["dmarc_enforced"] = weighted_choice([1, 0], [75, 25])
    record["reverse_dns_valid"] = weighted_choice([1, 0], [90, 10])
    record["tls_version"] = get_tls_legitimate()

    # IP - GOOD
    record["smtp_ip_known_malicious"] = 0
    record["smtp_ip_geo"] = random_float(0.05, 0.3)
    record["smtp_ip_asn"] = random_float(0.05, 0.25)
    record["smtp_ip_reputation_score"] = random_float(0.65, 0.9)

    # Return/Reply
    record["return_path_mismatch_with_from"] = weighted_choice([0, 1], [85, 15])  # Some use different return paths
    record["return_path_known_malicious"] = 0
    record["return_path_reputation_score"] = random_float(0.6, 0.88)
    record["reply_path_known_malicious"] = 0
    record["reply_path_diff_from_sender"] = weighted_choice([0, 1], [70, 30])  # Reply-to support address
    record["reply_path_reputation_score"] = random_float(0.62, 0.9)

    # BEC/VIP - not targeted
    record["is_high_risk_role_targeted"] = 0
    record["urgency_keywords_present"] = weighted_choice([0, 1], [70, 30])  # Some marketing urgency
    record["request_type"] = weighted_choice(["none", "link_click"], [60, 40])

    # Spam - MARKETING indicators but legitimate
    record["content_spam_score"] = random_float(0.25, 0.55)  # Higher but not spam
    record["user_marked_as_spam_before"] = weighted_choice([0, 1], [85, 15])
    record["bulk_message_indicator"] = 1  # IS bulk
    record["unsubscribe_link_present"] = 1  # MUST have for legitimate
    record["marketing_keywords_detected"] = random_float(0.55, 0.9)
    record["html_text_ratio"] = random_float(0.35, 0.7)
    record["image_only_email"] = weighted_choice([0, 1], [80, 20])

    # URLs - marketing has many
    url_count = random.randint(3, 10)
    record["url_count"] = url_count
    record["total_links_detected"] = url_count + random.randint(1, 5)
    record["domain_known_malicious"] = 0
    record["dns_morphing_detected"] = 0
    record["domain_tech_stack_match_score"] = random_float(0.7, 0.95)
    record["url_shortener_detected"] = weighted_choice([0, 1], [85, 15])
    record["url_redirect_chain_length"] = random.randint(0, 2)  # Tracking redirects
    record["final_url_known_malicious"] = 0
    record["url_decoded_spoof_detected"] = 0
    record["url_reputation_score"] = random_float(0.7, 0.95)
    record["ssl_validity_status"] = "valid"
    record["site_visual_similarity_to_known_brand"] = random_float(0.0, 0.2)
    record["url_rendering_behavior_score"] = random_float(0.05, 0.25)
    record["link_rewritten_through_redirector"] = weighted_choice([1, 0], [40, 60])
    record["token_validation_success"] = 1 if record["link_rewritten_through_redirector"] else None

    # No attachment typically
    record["packer_detected"] = None
    record["any_file_hash_malicious"] = None
    record["max_metadata_suspicious_score"] = None
    record["malicious_attachment_count"] = None
    record["has_executable_attachment"] = None
    record["unscannable_attachment_present"] = None
    record["total_components_detected_malicious"] = None
    record["total_yara_match_count"] = None
    record["total_ioc_count"] = None
    record["max_behavioral_sandbox_score"] = None
    record["max_amsi_suspicion_score"] = None
    record["any_macro_enabled_document"] = None
    record["any_vbscript_javascript_detected"] = None
    record["any_active_x_objects_detected"] = None
    record["any_network_call_on_open"] = None
    record["max_exfiltration_behavior_score"] = None
    record["any_exploit_pattern_detected"] = None
    record["total_embedded_file_count"] = None
    record["max_suspicious_string_entropy_score"] = None
    record["max_sandbox_execution_time"] = None
    record["unique_parent_process_names"] = None

    record["qrcode_analysis"] = None
    record["label"] = "Not Malicious"

    return record

def generate_legitimate_transactional(record: Dict) -> Dict:
    """Generate legitimate transactional email (banks, services)."""
    record = generate_legitimate_enterprise(record)

    # Very high reputation
    record["sender_domain_reputation_score"] = random_float(0.9, 0.99)
    record["smtp_ip_reputation_score"] = random_float(0.88, 0.99)

    # Always passing auth
    record["spf_result"] = "pass"
    record["dkim_result"] = "pass"
    record["dmarc_result"] = "pass"
    record["dmarc_enforced"] = 1

    # May have URLs
    url_count = random.randint(1, 3)
    record["url_count"] = url_count
    record["total_links_detected"] = url_count
    record["domain_known_malicious"] = 0
    record["url_reputation_score"] = random_float(0.9, 0.99)
    record["ssl_validity_status"] = "valid"
    record["url_shortener_detected"] = 0
    record["url_redirect_chain_length"] = 0
    record["final_url_known_malicious"] = 0
    record["url_decoded_spoof_detected"] = 0
    record["dns_morphing_detected"] = 0
    record["domain_tech_stack_match_score"] = random_float(0.85, 0.98)
    record["site_visual_similarity_to_known_brand"] = random_float(0.0, 0.1)
    record["url_rendering_behavior_score"] = random_float(0.02, 0.12)
    record["link_rewritten_through_redirector"] = 0
    record["token_validation_success"] = None

    return record

def generate_legitimate_password_reset(record: Dict) -> Dict:
    """Generate legitimate password reset email."""
    record = generate_legitimate_transactional(record)

    # This is a credential request but legitimate
    record["request_type"] = "credential_request"
    record["urgency_keywords_present"] = weighted_choice([0, 1], [50, 50])  # May have urgency

    return record

def generate_legitimate_meeting_invite(record: Dict) -> Dict:
    """Generate legitimate meeting invite."""
    record = generate_legitimate_enterprise(record)

    record["request_type"] = "meeting_request"
    record["url_count"] = 1  # Calendar link
    record["total_links_detected"] = 1
    record["domain_known_malicious"] = 0
    record["url_reputation_score"] = random_float(0.85, 0.98)
    record["ssl_validity_status"] = "valid"
    record["url_shortener_detected"] = 0
    record["url_redirect_chain_length"] = 0
    record["final_url_known_malicious"] = 0
    record["url_decoded_spoof_detected"] = 0
    record["dns_morphing_detected"] = 0
    record["domain_tech_stack_match_score"] = random_float(0.8, 0.98)
    record["site_visual_similarity_to_known_brand"] = random_float(0.0, 0.1)
    record["url_rendering_behavior_score"] = random_float(0.02, 0.1)
    record["link_rewritten_through_redirector"] = 0
    record["token_validation_success"] = None

    return record

def generate_legitimate_document_share(record: Dict) -> Dict:
    """Generate legitimate document sharing email."""
    record = generate_legitimate_enterprise(record)

    record["request_type"] = "document_download"
    record["url_count"] = 1
    record["total_links_detected"] = 1
    record["domain_known_malicious"] = 0
    record["url_reputation_score"] = random_float(0.82, 0.97)
    record["ssl_validity_status"] = "valid"
    record["url_shortener_detected"] = 0
    record["url_redirect_chain_length"] = weighted_choice([0, 1], [80, 20])  # Google/SharePoint might redirect
    record["final_url_known_malicious"] = 0
    record["url_decoded_spoof_detected"] = 0
    record["dns_morphing_detected"] = 0
    record["domain_tech_stack_match_score"] = random_float(0.75, 0.95)
    record["site_visual_similarity_to_known_brand"] = random_float(0.0, 0.15)
    record["url_rendering_behavior_score"] = random_float(0.03, 0.15)
    record["link_rewritten_through_redirector"] = weighted_choice([1, 0], [40, 60])
    record["token_validation_success"] = 1 if record["link_rewritten_through_redirector"] else None

    return record

def generate_legitimate_invoice(record: Dict) -> Dict:
    """Generate legitimate invoice email."""
    record = generate_legitimate_smb(record)

    record["request_type"] = "invoice_payment"
    record["urgency_keywords_present"] = weighted_choice([0, 1], [60, 40])  # Due dates

    # May have attachment
    if random.random() < 0.6:
        record["packer_detected"] = 0
        record["any_file_hash_malicious"] = 0
        record["max_metadata_suspicious_score"] = random_float(0.02, 0.18)
        record["malicious_attachment_count"] = 0
        record["has_executable_attachment"] = 0
        record["unscannable_attachment_present"] = 0
        record["total_components_detected_malicious"] = 0
        record["total_yara_match_count"] = 0
        record["total_ioc_count"] = 0
        record["max_behavioral_sandbox_score"] = random_float(0.0, 0.1)
        record["max_amsi_suspicion_score"] = random_float(0.0, 0.08)
        record["any_macro_enabled_document"] = 0
        record["any_vbscript_javascript_detected"] = 0
        record["any_active_x_objects_detected"] = 0
        record["any_network_call_on_open"] = 0
        record["max_exfiltration_behavior_score"] = random_float(0.0, 0.05)
        record["any_exploit_pattern_detected"] = 0
        record["total_embedded_file_count"] = random.randint(0, 2)
        record["max_suspicious_string_entropy_score"] = random_float(0.05, 0.25)
        record["max_sandbox_execution_time"] = random_float(1, 10)
        record["unique_parent_process_names"] = get_process_names_legitimate()

    return record

def generate_legitimate_with_attachment(record: Dict) -> Dict:
    """Generate legitimate email with safe attachment."""
    record = generate_legitimate_enterprise(record)

    # Safe attachment
    record["packer_detected"] = 0
    record["any_file_hash_malicious"] = 0
    record["max_metadata_suspicious_score"] = random_float(0.02, 0.15)
    record["malicious_attachment_count"] = 0
    record["has_executable_attachment"] = 0
    record["unscannable_attachment_present"] = 0
    record["total_components_detected_malicious"] = 0
    record["total_yara_match_count"] = 0
    record["total_ioc_count"] = 0
    record["max_behavioral_sandbox_score"] = random_float(0.0, 0.12)
    record["max_amsi_suspicion_score"] = random_float(0.0, 0.08)
    record["any_macro_enabled_document"] = 0
    record["any_vbscript_javascript_detected"] = 0
    record["any_active_x_objects_detected"] = 0
    record["any_network_call_on_open"] = 0
    record["max_exfiltration_behavior_score"] = random_float(0.0, 0.05)
    record["any_exploit_pattern_detected"] = 0
    record["total_embedded_file_count"] = random.randint(0, 3)
    record["max_suspicious_string_entropy_score"] = random_float(0.05, 0.22)
    record["max_sandbox_execution_time"] = random_float(1, 15)
    record["unique_parent_process_names"] = get_process_names_legitimate()

    return record

def generate_legitimate_misconfigured(record: Dict) -> Dict:
    """Generate legitimate but misconfigured email (false positive candidate)."""
    record = generate_legitimate_smb(record)

    # Auth issues
    record["spf_result"] = weighted_choice(["softfail", "fail", "none"], [50, 30, 20])
    record["dkim_result"] = weighted_choice(["none", "fail"], [70, 30])
    record["dmarc_result"] = weighted_choice(["none", "fail"], [60, 40])
    record["dmarc_enforced"] = 0

    # Lower reputation
    record["sender_domain_reputation_score"] = random_float(0.35, 0.55)
    record["smtp_ip_reputation_score"] = random_float(0.38, 0.58)

    # Some suspicious signals
    record["return_path_mismatch_with_from"] = weighted_choice([0, 1], [50, 50])

    return record

def generate_legitimate_urgent(record: Dict) -> Dict:
    """Generate legitimate urgent email (false positive candidate)."""
    record = generate_legitimate_enterprise(record)

    # Legitimate urgency
    record["urgency_keywords_present"] = 1
    record["request_type"] = weighted_choice(["none", "document_download", "meeting_request"], [40, 30, 30])

    # Still good signals
    record["content_spam_score"] = random_float(0.15, 0.35)

    return record

def generate_legitimate_new_business(record: Dict) -> Dict:
    """Generate legitimate email from new business (low reputation but genuine)."""
    record = generate_legitimate_smb(record)

    # New domain = low reputation
    record["sender_domain_reputation_score"] = random_float(0.3, 0.5)
    record["smtp_ip_reputation_score"] = random_float(0.35, 0.55)

    # But good auth
    record["spf_result"] = "pass"
    record["dkim_result"] = "pass"
    record["dmarc_result"] = "pass"

    return record

def generate_legitimate_qr_code(record: Dict) -> Dict:
    """Generate legitimate email with safe QR code."""
    record = generate_legitimate_marketing(record)

    record["qrcode_analysis"] = 0  # Safe QR
    record["image_only_email"] = weighted_choice([0, 1], [70, 30])
    if record["image_only_email"]:
        record["html_text_ratio"] = random_float(0.08, 0.2)

    return record


# ============================================================================
# MAIN GENERATION FUNCTION
# ============================================================================

def generate_dataset(output_file: str = "email_detection_signals.csv"):
    """Generate the complete dataset with 4200 records."""

    # Define malicious scenario distribution (2100 total)
    malicious_scenarios = [
        (generate_phishing_obvious, 250),
        (generate_phishing_moderate, 200),
        (generate_phishing_sophisticated, 100),
        (generate_bec_obvious, 200),
        (generate_bec_sophisticated, 150),
        (generate_malware_executable, 150),
        (generate_malware_macro, 200),
        (generate_malware_evasive, 100),
        (generate_ransomware, 100),
        (generate_spam_obvious, 200),
        (generate_evasion_encrypted, 100),
        (generate_evasion_image_only, 80),
        (generate_qr_phishing, 50),
        (generate_known_threat_actor, 120),
        (generate_callback_phishing, 100),
    ]

    # Define legitimate scenario distribution (2100 total)
    legitimate_scenarios = [
        (generate_legitimate_enterprise, 350),
        (generate_legitimate_smb, 250),
        (generate_legitimate_marketing, 250),
        (generate_legitimate_transactional, 200),
        (generate_legitimate_password_reset, 100),
        (generate_legitimate_meeting_invite, 200),
        (generate_legitimate_document_share, 150),
        (generate_legitimate_invoice, 100),
        (generate_legitimate_with_attachment, 150),
        (generate_legitimate_misconfigured, 100),
        (generate_legitimate_urgent, 100),
        (generate_legitimate_new_business, 100),
        (generate_legitimate_qr_code, 50),
    ]

    # Verify counts
    mal_count = sum(count for _, count in malicious_scenarios)
    leg_count = sum(count for _, count in legitimate_scenarios)
    print(f"Malicious scenarios total: {mal_count}")
    print(f"Legitimate scenarios total: {leg_count}")

    # Generate records
    all_records = []

    print("\nGenerating malicious records...")
    for generator_func, count in malicious_scenarios:
        for _ in range(count):
            record = create_base_record()
            record = generator_func(record)
            all_records.append(record)

    print("Generating legitimate records...")
    for generator_func, count in legitimate_scenarios:
        for _ in range(count):
            record = create_base_record()
            record = generator_func(record)
            all_records.append(record)

    # Shuffle records
    random.shuffle(all_records)

    print(f"\nTotal records generated: {len(all_records)}")

    # Write to CSV
    print(f"Writing to {output_file}...")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=SIGNAL_COLUMNS)
        writer.writeheader()
        writer.writerows(all_records)

    print("Done!")

    # Print summary
    mal_actual = sum(1 for r in all_records if r["label"] == "Malicious")
    leg_actual = sum(1 for r in all_records if r["label"] == "Not Malicious")
    print(f"\nSummary:")
    print(f"  Malicious: {mal_actual}")
    print(f"  Not Malicious: {leg_actual}")
    print(f"  Total: {len(all_records)}")


if __name__ == "__main__":
    generate_dataset("email_detection_signals.csv")
