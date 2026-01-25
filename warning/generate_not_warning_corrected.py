#!/usr/bin/env python3
"""
Generate 1000 CORRECTED Not-Warning Records
FIXES:
- sender_spoof_detected = ALWAYS False (like original training data)
- Stricter rules to avoid Warning-like patterns
"""

import csv
import random

print("="*80)
print("GENERATING 1000 CORRECTED NOT-WARNING RECORDS")
print("="*80)

# Set seed for reproducibility
random.seed(456)

# Column names from training data (71 columns)
COLUMNS = [
    'sender_known_malicious', 'sender_domain_reputation_score', 'sender_spoof_detected',
    'sender_temp_email_likelihood', 'dmarc_enforced', 'sender_name_similarity_to_vip',
    'spf_result', 'dkim_result', 'dmarc_result', 'reverse_dns_valid', 'packer_detected',
    'any_file_hash_malicious', 'max_metadata_suspicious_score', 'malicious_attachment_count',
    'has_executable_attachment', 'unscannable_attachment_present', 'total_components_detected_malicious',
    'total_yara_match_count', 'total_ioc_count', 'max_behavioral_sandbox_score',
    'max_amsi_suspicion_score', 'any_macro_enabled_document', 'any_vbscript_javascript_detected',
    'any_active_x_objects_detected', 'any_network_call_on_open', 'max_exfiltration_behavior_score',
    'any_exploit_pattern_detected', 'total_embedded_file_count', 'max_suspicious_string_entropy_score',
    'max_sandbox_execution_time', 'unique_parent_process_names', 'return_path_mismatch_with_from',
    'return_path_known_malicious', 'return_path_reputation_score', 'reply_path_known_malicious',
    'reply_path_diff_from_sender', 'reply_path_reputation_score', 'smtp_ip_known_malicious',
    'smtp_ip_geo', 'smtp_ip_asn', 'smtp_ip_reputation_score', 'domain_known_malicious',
    'url_count', 'dns_morphing_detected', 'domain_tech_stack_match_score', 'url_decoded_spoof_detected',
    'url_reputation_score', 'ssl_validity_status', 'site_visual_similarity_to_known_brand',
    'url_rendering_behavior_score', 'link_rewritten_through_redirector', 'token_validation_success',
    'is_high_risk_role_targeted', 'urgency_keywords_present', 'request_type', 'content_spam_score',
    'user_marked_as_spam_before', 'bulk_message_indicator', 'unsubscribe_link_present',
    'marketing_keywords_detected', 'html_text_ratio', 'image_only_email', 'total_links_detected',
    'url_shortener_detected', 'url_redirect_chain_length', 'final_url_known_malicious',
    'tls_version', 'Analysis_of_the_qrcode_if_present', 'Final Classification',
    'warning_risk', 'Binary_Label'
]

def weighted_choice(options, weights):
    """Choose from options based on weights"""
    total = sum(weights)
    r = random.uniform(0, total)
    cumulative = 0
    for option, weight in zip(options, weights):
        cumulative += weight
        if r <= cumulative:
            return option
    return options[-1]

def generate_not_warning_record():
    """Generate a CORRECTED Not-Warning record - NO Warning-like patterns!"""
    record = {}

    # === SENDER FEATURES (MUST BE SAFE for Not-Warning) ===

    # sender_known_malicious: ALWAYS False for Not-Warning (matching original data)
    record['sender_known_malicious'] = False

    # High reputation score for Not-Warning (0.7-1.0)
    record['sender_domain_reputation_score'] = round(random.uniform(0.7, 1.0), 10)

    # *** CRITICAL FIX: sender_spoof_detected = ALWAYS FALSE ***
    # In original training data, 0 Not-Warning records have sender_spoof=True
    record['sender_spoof_detected'] = False

    # Low temp email likelihood (0.0-0.15)
    record['sender_temp_email_likelihood'] = round(random.uniform(0.0, 0.15), 10)

    # dmarc_enforced: mostly True for Not-Warning (~80%)
    record['dmarc_enforced'] = weighted_choice([True, False], [0.80, 0.20])

    # Low VIP similarity for Not-Warning (0.0-0.15)
    record['sender_name_similarity_to_vip'] = round(random.uniform(0.0, 0.15), 10)

    # === SPF/DKIM/DMARC RESULTS (mostly pass for Not-Warning) ===
    record['spf_result'] = weighted_choice(
        ['pass', 'fail', 'softfail', 'neutral', 'none'],
        [0.75, 0.03, 0.05, 0.10, 0.07]
    )
    record['dkim_result'] = weighted_choice(
        ['pass', 'fail', 'neutral', 'none'],
        [0.75, 0.05, 0.12, 0.08]
    )
    record['dmarc_result'] = weighted_choice(
        ['pass', 'fail', 'none', 'neutral'],
        [0.70, 0.05, 0.12, 0.13]
    )

    # reverse_dns_valid: mostly True for Not-Warning (~90%)
    record['reverse_dns_valid'] = weighted_choice([True, False], [0.90, 0.10])

    # === ATTACHMENT/FILE FEATURES (ALWAYS clean for Not-Warning) ===
    record['packer_detected'] = False
    record['any_file_hash_malicious'] = False
    record['max_metadata_suspicious_score'] = round(random.uniform(0.0, 0.1), 10)
    record['malicious_attachment_count'] = 0
    record['has_executable_attachment'] = False
    record['unscannable_attachment_present'] = False
    record['total_components_detected_malicious'] = 0
    record['total_yara_match_count'] = 0
    record['total_ioc_count'] = weighted_choice([0, 1, 2], [0.92, 0.06, 0.02])

    # === BEHAVIORAL FEATURES (low/zero for Not-Warning) ===
    record['max_behavioral_sandbox_score'] = round(random.uniform(0.0, 0.08), 10)
    record['max_amsi_suspicion_score'] = round(random.uniform(0.0, 0.03), 10)
    record['any_macro_enabled_document'] = False
    record['any_vbscript_javascript_detected'] = False
    record['any_active_x_objects_detected'] = False
    record['any_network_call_on_open'] = False
    record['max_exfiltration_behavior_score'] = round(random.uniform(0.0, 0.03), 10)
    record['any_exploit_pattern_detected'] = False
    record['total_embedded_file_count'] = weighted_choice([0, 1], [0.90, 0.10])
    record['max_suspicious_string_entropy_score'] = round(random.uniform(0.0, 0.1), 10)
    record['max_sandbox_execution_time'] = round(random.uniform(0.0, 0.03), 10)
    record['unique_parent_process_names'] = ''

    # === RETURN PATH FEATURES (clean for Not-Warning) ===
    record['return_path_mismatch_with_from'] = weighted_choice([True, False], [0.10, 0.90])
    record['return_path_known_malicious'] = False
    record['return_path_reputation_score'] = round(random.uniform(0.75, 1.0), 10)

    # === REPLY PATH FEATURES (clean for Not-Warning) ===
    record['reply_path_known_malicious'] = False
    record['reply_path_diff_from_sender'] = weighted_choice([True, False], [0.15, 0.85])
    record['reply_path_reputation_score'] = round(random.uniform(0.75, 1.0), 10)

    # === SMTP FEATURES (clean for Not-Warning) ===
    record['smtp_ip_known_malicious'] = False
    record['smtp_ip_geo'] = round(random.uniform(0.0, 0.15), 10)
    record['smtp_ip_asn'] = round(random.uniform(0.0, 0.1), 10)
    record['smtp_ip_reputation_score'] = round(random.uniform(0.75, 1.0), 10)

    # === DOMAIN/URL FEATURES (clean for Not-Warning) ===
    # *** CRITICAL: domain_known_malicious = ALWAYS False ***
    record['domain_known_malicious'] = False

    record['url_count'] = weighted_choice(list(range(0, 15)),
        [0.05, 0.12, 0.18, 0.18, 0.14, 0.12, 0.08, 0.05, 0.03, 0.02, 0.01, 0.01, 0.005, 0.003, 0.002])

    # *** CRITICAL: dns_morphing_detected = ALWAYS False ***
    record['dns_morphing_detected'] = False

    record['domain_tech_stack_match_score'] = round(random.uniform(0.75, 1.0), 10)

    # *** CRITICAL: url_decoded_spoof_detected = ALWAYS False ***
    record['url_decoded_spoof_detected'] = False

    record['url_reputation_score'] = round(random.uniform(0.75, 1.0), 10)
    record['ssl_validity_status'] = weighted_choice(
        ['valid', 'no_ssl'],
        [0.90, 0.10]
    )

    # KEY NOT-WARNING INDICATORS (MUST be low/zero)
    record['site_visual_similarity_to_known_brand'] = round(random.uniform(0.0, 0.1), 10)
    record['url_rendering_behavior_score'] = round(random.uniform(0.0, 0.1), 10)
    record['link_rewritten_through_redirector'] = weighted_choice([True, False], [0.35, 0.65])
    record['token_validation_success'] = weighted_choice([True, False], [0.90, 0.10])

    # === CRITICAL: LOW RISK INDICATORS FOR NOT-WARNING ===

    # *** CRITICAL FIX: is_high_risk_role_targeted = mostly False (max 5%) ***
    record['is_high_risk_role_targeted'] = weighted_choice([True, False], [0.05, 0.95])

    # *** CRITICAL FIX: urgency_keywords_present = mostly False (max 8%) ***
    record['urgency_keywords_present'] = weighted_choice([True, False], [0.08, 0.92])

    # request_type - ONLY benign types for Not-Warning
    record['request_type'] = weighted_choice(
        ['link_click', 'none', 'document_download', 'meeting_request'],
        [0.40, 0.35, 0.15, 0.10]
    )

    # === CONTENT FEATURES (clean for Not-Warning) ===
    record['content_spam_score'] = round(random.uniform(0.0, 0.2), 10)
    record['user_marked_as_spam_before'] = False
    record['bulk_message_indicator'] = weighted_choice([True, False], [0.12, 0.88])
    record['unsubscribe_link_present'] = weighted_choice([True, False], [0.18, 0.82])
    record['marketing_keywords_detected'] = round(random.uniform(0.0, 0.15), 10)
    record['html_text_ratio'] = round(random.uniform(0.35, 0.75), 10)
    record['image_only_email'] = False
    record['total_links_detected'] = weighted_choice(
        list(range(0, 15)),
        [0.05, 0.10, 0.15, 0.18, 0.15, 0.12, 0.08, 0.06, 0.04, 0.03, 0.02, 0.01, 0.005, 0.003, 0.002]
    )

    # === URL SHORTENER FEATURES (mostly clean) ===
    record['url_shortener_detected'] = weighted_choice([True, False], [0.05, 0.95])
    record['url_redirect_chain_length'] = weighted_choice([0, 1], [0.92, 0.08])

    # *** CRITICAL: final_url_known_malicious = ALWAYS False ***
    record['final_url_known_malicious'] = False

    # === TLS/ENCRYPTION (modern for Not-Warning) ===
    record['tls_version'] = weighted_choice(
        ['TLS 1.2', 'TLS 1.3'],
        [0.40, 0.60]
    )

    # === QR CODE ===
    record['Analysis_of_the_qrcode_if_present'] = 0

    # === CLASSIFICATION (Not-Warning) ===
    record['Final Classification'] = 'No Action'
    record['warning_risk'] = round(random.uniform(0.0, 0.2), 10)
    record['Binary_Label'] = 'Not-Warning'

    return record

def record_to_tuple(record):
    """Convert record dict to tuple for uniqueness check"""
    return tuple(str(record[col]) for col in COLUMNS)

# Generate records
print("\n🔧 Generating 1000 CORRECTED Not-Warning records...")
print("\n📋 STRICT RULES APPLIED:")
print("   - sender_spoof_detected = ALWAYS False")
print("   - sender_known_malicious = ALWAYS False")
print("   - domain_known_malicious = ALWAYS False")
print("   - dns_morphing_detected = ALWAYS False")
print("   - url_decoded_spoof_detected = ALWAYS False")
print("   - final_url_known_malicious = ALWAYS False")
print("   - is_high_risk_role_targeted = max 5%")
print("   - urgency_keywords_present = max 8%")
print("   - request_type = ONLY benign types")

N = 1000
generated_records = []
seen_records = set()

attempts = 0
max_attempts = 50000

while len(generated_records) < N and attempts < max_attempts:
    record = generate_not_warning_record()
    record_tuple = record_to_tuple(record)

    if record_tuple not in seen_records:
        seen_records.add(record_tuple)
        generated_records.append(record)

    attempts += 1

    if len(generated_records) % 100 == 0 and len(generated_records) > 0:
        print(f"   Generated {len(generated_records)} unique records...")

print(f"\n   ✓ Generated {len(generated_records)} unique records in {attempts} attempts")

# Write to CSV
output_file = 'generated_not_warning_1000_corrected.csv'
print(f"\n💾 Saving to {output_file}...")

with open(output_file, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(generated_records)

print(f"   ✓ Saved {len(generated_records)} records")

# Verification
print("\n" + "="*80)
print("VERIFICATION - CONFIRMING NO WARNING-LIKE PATTERNS")
print("="*80)

# Count critical features
sender_spoof_true = sum(1 for r in generated_records if r['sender_spoof_detected'] == True)
sender_mal_true = sum(1 for r in generated_records if r['sender_known_malicious'] == True)
domain_mal_true = sum(1 for r in generated_records if r['domain_known_malicious'] == True)
dns_morph_true = sum(1 for r in generated_records if r['dns_morphing_detected'] == True)
url_spoof_true = sum(1 for r in generated_records if r['url_decoded_spoof_detected'] == True)
high_risk_true = sum(1 for r in generated_records if r['is_high_risk_role_targeted'] == True)
urgency_true = sum(1 for r in generated_records if r['urgency_keywords_present'] == True)

print(f"\n🔒 CRITICAL CHECKS (should be 0 or very low):")
print(f"   sender_spoof_detected = True:      {sender_spoof_true} {'✅' if sender_spoof_true == 0 else '❌'}")
print(f"   sender_known_malicious = True:     {sender_mal_true} {'✅' if sender_mal_true == 0 else '❌'}")
print(f"   domain_known_malicious = True:     {domain_mal_true} {'✅' if domain_mal_true == 0 else '❌'}")
print(f"   dns_morphing_detected = True:      {dns_morph_true} {'✅' if dns_morph_true == 0 else '❌'}")
print(f"   url_decoded_spoof_detected = True: {url_spoof_true} {'✅' if url_spoof_true == 0 else '❌'}")
print(f"   is_high_risk_role_targeted = True: {high_risk_true} ({high_risk_true/N*100:.1f}%) {'✅' if high_risk_true < 60 else '❌'}")
print(f"   urgency_keywords_present = True:   {urgency_true} ({urgency_true/N*100:.1f}%) {'✅' if urgency_true < 100 else '❌'}")

# Check for dangerous combinations
dangerous_combo = sum(1 for r in generated_records
                     if r['is_high_risk_role_targeted'] == True
                     and r['sender_spoof_detected'] == True)
print(f"\n🚨 DANGEROUS COMBINATIONS:")
print(f"   is_high_risk=True AND sender_spoof=True: {dangerous_combo} {'✅' if dangerous_combo == 0 else '❌'}")

# SPF/DKIM/DMARC pass rates
spf_pass = sum(1 for r in generated_records if r['spf_result'] == 'pass')
dkim_pass = sum(1 for r in generated_records if r['dkim_result'] == 'pass')
dmarc_pass = sum(1 for r in generated_records if r['dmarc_result'] == 'pass')

print(f"\n📊 Authentication Pass Rates (should be HIGH):")
print(f"   SPF pass:   {spf_pass} ({spf_pass/N*100:.1f}%)")
print(f"   DKIM pass:  {dkim_pass} ({dkim_pass/N*100:.1f}%)")
print(f"   DMARC pass: {dmarc_pass} ({dmarc_pass/N*100:.1f}%)")

# Request type distribution
request_types = {}
for r in generated_records:
    rt = r['request_type']
    request_types[rt] = request_types.get(rt, 0) + 1

print(f"\n📊 Request Types (should be ONLY benign):")
for rt, count in sorted(request_types.items(), key=lambda x: x[1], reverse=True):
    print(f"   {rt}: {count} ({count/N*100:.1f}%)")

print("\n" + "="*80)
print(f"✅ Successfully generated {len(generated_records)} CORRECTED Not-Warning records!")
print(f"   Output file: {output_file}")
print("="*80)
