#!/usr/bin/env python3
"""
Generate 1000 Unique Warning Records (No Pandas Required)
Based on patterns from warning_detector_training_data.csv
"""

import csv
import random

print("="*80)
print("GENERATING 1000 UNIQUE WARNING RECORDS")
print("="*80)

# Set seed for reproducibility
random.seed(42)

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

def generate_warning_record():
    """Generate a single Warning record matching training patterns"""
    record = {}

    # === SENDER FEATURES ===
    record['sender_known_malicious'] = weighted_choice([True, False], [0.45, 0.55])
    record['sender_domain_reputation_score'] = round(random.uniform(0.1, 0.6), 10)
    record['sender_spoof_detected'] = weighted_choice([True, False], [0.55, 0.45])
    record['sender_temp_email_likelihood'] = round(random.uniform(0.3, 0.8), 10)
    record['dmarc_enforced'] = weighted_choice([True, False], [0.30, 0.70])
    record['sender_name_similarity_to_vip'] = round(random.uniform(0.2, 0.9), 10)

    # === SPF/DKIM/DMARC RESULTS ===
    record['spf_result'] = weighted_choice(
        ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'],
        [0.15, 0.25, 0.15, 0.20, 0.10, 0.10, 0.05]
    )
    record['dkim_result'] = weighted_choice(
        ['pass', 'fail', 'neutral', 'none', 'temperror', 'permerror'],
        [0.20, 0.25, 0.25, 0.15, 0.10, 0.05]
    )
    record['dmarc_result'] = weighted_choice(
        ['pass', 'fail', 'none', 'neutral', 'temperror', 'permerror'],
        [0.15, 0.30, 0.20, 0.20, 0.10, 0.05]
    )
    record['reverse_dns_valid'] = weighted_choice([True, False], [0.50, 0.50])

    # === ATTACHMENT/FILE FEATURES ===
    record['packer_detected'] = weighted_choice([True, False], [0.10, 0.90])
    record['any_file_hash_malicious'] = weighted_choice([True, False], [0.08, 0.92])
    record['max_metadata_suspicious_score'] = round(random.uniform(0.0, 0.4), 10)
    record['malicious_attachment_count'] = weighted_choice([0, 1, 2], [0.85, 0.12, 0.03])
    record['has_executable_attachment'] = weighted_choice([True, False], [0.05, 0.95])
    record['unscannable_attachment_present'] = weighted_choice([True, False], [0.03, 0.97])
    record['total_components_detected_malicious'] = weighted_choice([0, 1, 2, 3], [0.80, 0.12, 0.05, 0.03])
    record['total_yara_match_count'] = weighted_choice([0, 1, 2, 3, 4, 5], [0.75, 0.12, 0.07, 0.03, 0.02, 0.01])
    record['total_ioc_count'] = weighted_choice([0, 1, 2, 3, 4, 5, 6, 7], [0.60, 0.15, 0.10, 0.07, 0.04, 0.02, 0.01, 0.01])

    # === BEHAVIORAL FEATURES ===
    record['max_behavioral_sandbox_score'] = round(random.uniform(0.0, 0.3), 10)
    record['max_amsi_suspicion_score'] = round(random.uniform(0.0, 0.2), 10)
    record['any_macro_enabled_document'] = weighted_choice([True, False], [0.15, 0.85])
    record['any_vbscript_javascript_detected'] = weighted_choice([True, False], [0.10, 0.90])
    record['any_active_x_objects_detected'] = weighted_choice([True, False], [0.08, 0.92])
    record['any_network_call_on_open'] = weighted_choice([True, False], [0.12, 0.88])
    record['max_exfiltration_behavior_score'] = round(random.uniform(0.0, 0.15), 10)
    record['any_exploit_pattern_detected'] = weighted_choice([True, False], [0.05, 0.95])
    record['total_embedded_file_count'] = weighted_choice([0, 1, 2, 3], [0.70, 0.20, 0.07, 0.03])
    record['max_suspicious_string_entropy_score'] = round(random.uniform(0.0, 0.3), 10)
    record['max_sandbox_execution_time'] = round(random.uniform(0.0, 0.1), 10)
    record['unique_parent_process_names'] = ''

    # === RETURN PATH FEATURES ===
    record['return_path_mismatch_with_from'] = weighted_choice([True, False], [0.60, 0.40])
    record['return_path_known_malicious'] = weighted_choice([True, False], [0.15, 0.85])
    record['return_path_reputation_score'] = round(random.uniform(0.2, 0.5), 10)

    # === REPLY PATH FEATURES ===
    record['reply_path_known_malicious'] = weighted_choice([True, False], [0.12, 0.88])
    record['reply_path_diff_from_sender'] = weighted_choice([True, False], [0.55, 0.45])
    record['reply_path_reputation_score'] = round(random.uniform(0.2, 0.5), 10)

    # === SMTP FEATURES ===
    record['smtp_ip_known_malicious'] = weighted_choice([True, False], [0.10, 0.90])
    record['smtp_ip_geo'] = round(random.uniform(0.3, 0.8), 10)
    record['smtp_ip_asn'] = round(random.uniform(0.3, 0.7), 10)
    record['smtp_ip_reputation_score'] = round(random.uniform(0.2, 0.6), 10)

    # === DOMAIN/URL FEATURES ===
    record['domain_known_malicious'] = weighted_choice([True, False], [0.35, 0.65])
    record['url_count'] = weighted_choice(list(range(0, 10)), [0.10, 0.20, 0.20, 0.15, 0.12, 0.10, 0.05, 0.04, 0.02, 0.02])
    record['dns_morphing_detected'] = weighted_choice([True, False], [0.25, 0.75])
    record['domain_tech_stack_match_score'] = round(random.uniform(0.2, 0.6), 10)
    record['url_decoded_spoof_detected'] = weighted_choice([True, False], [0.30, 0.70])
    record['url_reputation_score'] = round(random.uniform(0.2, 0.6), 10)
    record['ssl_validity_status'] = weighted_choice(
        ['valid', 'invalid', 'expired', 'self_signed', 'no_ssl'],
        [0.30, 0.15, 0.10, 0.25, 0.20]
    )

    # KEY WARNING INDICATORS
    record['site_visual_similarity_to_known_brand'] = round(random.uniform(0.2, 0.8), 10)
    record['url_rendering_behavior_score'] = round(random.uniform(0.2, 0.7), 10)
    record['link_rewritten_through_redirector'] = weighted_choice([True, False], [0.20, 0.80])
    record['token_validation_success'] = weighted_choice([True, False], [0.40, 0.60])

    # === HIGH RISK INDICATORS (KEY FOR WARNINGS) ===
    record['is_high_risk_role_targeted'] = weighted_choice([True, False], [0.73, 0.27])
    record['urgency_keywords_present'] = weighted_choice([True, False], [0.86, 0.14])

    # request_type - KEY FEATURE
    record['request_type'] = weighted_choice(
        ['credential_request', 'sensitive_data_request', 'wire_transfer',
         'invoice_payment', 'bank_detail_update', 'gift_card_request',
         'legal_threat', 'urgent_callback', 'invoice_verification',
         'link_click', 'document_download', 'meeting_request', 'none'],
        [0.18, 0.15, 0.08, 0.10, 0.06, 0.04, 0.03, 0.05, 0.06, 0.12, 0.05, 0.03, 0.05]
    )

    # === CONTENT FEATURES ===
    record['content_spam_score'] = round(random.uniform(0.2, 0.6), 10)
    record['user_marked_as_spam_before'] = weighted_choice([True, False], [0.15, 0.85])
    record['bulk_message_indicator'] = weighted_choice([True, False], [0.08, 0.92])
    record['unsubscribe_link_present'] = weighted_choice([True, False], [0.12, 0.88])
    record['marketing_keywords_detected'] = round(random.uniform(0.0, 0.4), 10)
    record['html_text_ratio'] = round(random.uniform(0.3, 0.7), 10)
    record['image_only_email'] = weighted_choice([True, False], [0.05, 0.95])
    record['total_links_detected'] = weighted_choice(
        list(range(0, 15)),
        [0.05, 0.10, 0.15, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05, 0.04, 0.03, 0.02, 0.02, 0.01, 0.01]
    )

    # === URL SHORTENER FEATURES ===
    record['url_shortener_detected'] = weighted_choice([True, False], [0.25, 0.75])
    record['url_redirect_chain_length'] = weighted_choice([0, 1, 2, 3, 4], [0.50, 0.25, 0.15, 0.07, 0.03])
    record['final_url_known_malicious'] = weighted_choice([True, False], [0.20, 0.80])

    # === TLS/ENCRYPTION ===
    record['tls_version'] = weighted_choice(
        ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3', ''],
        [0.10, 0.15, 0.35, 0.30, 0.10]
    )

    # === QR CODE ===
    record['Analysis_of_the_qrcode_if_present'] = weighted_choice([0, 1], [0.95, 0.05])

    # === CLASSIFICATION ===
    record['Final Classification'] = 'Warning'
    record['warning_risk'] = round(random.uniform(0.4, 0.9), 10)
    record['Binary_Label'] = 'Warning'

    return record

def record_to_tuple(record):
    """Convert record dict to tuple for uniqueness check"""
    return tuple(str(record[col]) for col in COLUMNS)

# Generate records
print("\n🔧 Generating 1000 unique Warning records...")

N = 1000
generated_records = []
seen_records = set()

attempts = 0
max_attempts = 50000

while len(generated_records) < N and attempts < max_attempts:
    record = generate_warning_record()
    record_tuple = record_to_tuple(record)

    if record_tuple not in seen_records:
        seen_records.add(record_tuple)
        generated_records.append(record)

    attempts += 1

    if len(generated_records) % 100 == 0 and len(generated_records) > 0:
        print(f"   Generated {len(generated_records)} unique records...")

print(f"\n   ✓ Generated {len(generated_records)} unique records in {attempts} attempts")

# Write to CSV
output_file = 'generated_warning_1000.csv'
print(f"\n💾 Saving to {output_file}...")

with open(output_file, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(generated_records)

print(f"   ✓ Saved {len(generated_records)} records")

# Summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)

# Count key features
high_risk_true = sum(1 for r in generated_records if r['is_high_risk_role_targeted'] == True)
urgency_true = sum(1 for r in generated_records if r['urgency_keywords_present'] == True)
spoof_true = sum(1 for r in generated_records if r['sender_spoof_detected'] == True)
domain_mal_true = sum(1 for r in generated_records if r['domain_known_malicious'] == True)

print(f"\n📊 Key Feature Distribution:")
print(f"   is_high_risk_role_targeted = True: {high_risk_true} ({high_risk_true/N*100:.1f}%)")
print(f"   urgency_keywords_present = True:   {urgency_true} ({urgency_true/N*100:.1f}%)")
print(f"   sender_spoof_detected = True:      {spoof_true} ({spoof_true/N*100:.1f}%)")
print(f"   domain_known_malicious = True:     {domain_mal_true} ({domain_mal_true/N*100:.1f}%)")

# Request type distribution
request_types = {}
for r in generated_records:
    rt = r['request_type']
    request_types[rt] = request_types.get(rt, 0) + 1

print(f"\n📊 Top 5 Request Types:")
sorted_rt = sorted(request_types.items(), key=lambda x: x[1], reverse=True)[:5]
for rt, count in sorted_rt:
    print(f"   {rt}: {count} ({count/N*100:.1f}%)")

print(f"\n📊 All Binary_Label = 'Warning': ✓")

print("\n" + "="*80)
print(f"✅ Successfully generated {len(generated_records)} unique Warning records!")
print(f"   Output file: {output_file}")
print("="*80)
