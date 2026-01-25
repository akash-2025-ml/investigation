#!/usr/bin/env python3
"""
Generate 1000 Unique Warning Records
Based on patterns from warning_detector_training_data.csv
"""

import pandas as pd
import numpy as np
import random
from datetime import datetime

print("="*80)
print("GENERATING 1000 UNIQUE WARNING RECORDS")
print("="*80)

# Set seed for reproducibility
np.random.seed(42)
random.seed(42)

# Load training data to understand patterns
print("\n📂 Loading training data to analyze Warning patterns...")
train_df = pd.read_csv('warning_detector_training_data.csv')
warning_df = train_df[train_df['Binary_Label'] == 'Warning']
print(f"   Found {len(warning_df)} Warning samples to learn from")

# Get column names
columns = train_df.columns.tolist()
print(f"   Total columns: {len(columns)}")

# Analyze Warning patterns for each column
print("\n🔍 Analyzing Warning patterns...")

def get_column_stats(df, col):
    """Get statistics for a column from Warning samples"""
    values = df[col].dropna()
    if values.dtype == 'object':
        # Categorical/string column
        value_counts = values.value_counts(normalize=True).to_dict()
        return {'type': 'categorical', 'distribution': value_counts}
    elif values.dtype == 'bool' or set(values.unique()).issubset({True, False, 'True', 'False'}):
        # Boolean column
        true_ratio = (values == True).sum() / len(values) if len(values) > 0 else 0.5
        return {'type': 'boolean', 'true_ratio': true_ratio}
    else:
        # Numeric column
        return {
            'type': 'numeric',
            'min': values.min(),
            'max': values.max(),
            'mean': values.mean(),
            'std': values.std() if len(values) > 1 else 0
        }

# Get patterns for all columns
patterns = {}
for col in columns:
    if col != 'Binary_Label':
        patterns[col] = get_column_stats(warning_df, col)

# Number of records to generate
N = 1000

print(f"\n🔧 Generating {N} unique Warning records...")

# Initialize empty dataframe
generated_data = []

for i in range(N):
    record = {}

    # === SENDER FEATURES ===
    # sender_known_malicious: ~45% True in warnings
    record['sender_known_malicious'] = np.random.choice([True, False], p=[0.45, 0.55])

    # sender_domain_reputation_score: Low for warnings (0.1-0.6)
    record['sender_domain_reputation_score'] = round(np.random.uniform(0.1, 0.6), 10)

    # sender_spoof_detected: ~55% True in warnings
    record['sender_spoof_detected'] = np.random.choice([True, False], p=[0.55, 0.45])

    # sender_temp_email_likelihood: Higher for warnings (0.3-0.8)
    record['sender_temp_email_likelihood'] = round(np.random.uniform(0.3, 0.8), 10)

    # dmarc_enforced: ~30% True in warnings
    record['dmarc_enforced'] = np.random.choice([True, False], p=[0.30, 0.70])

    # sender_name_similarity_to_vip: Higher for warnings (0.2-0.9)
    record['sender_name_similarity_to_vip'] = round(np.random.uniform(0.2, 0.9), 10)

    # === SPF/DKIM/DMARC RESULTS ===
    spf_options = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror']
    spf_warning_probs = [0.15, 0.25, 0.15, 0.20, 0.10, 0.10, 0.05]
    record['spf_result'] = np.random.choice(spf_options, p=spf_warning_probs)

    dkim_options = ['pass', 'fail', 'neutral', 'none', 'temperror', 'permerror']
    dkim_warning_probs = [0.20, 0.25, 0.25, 0.15, 0.10, 0.05]
    record['dkim_result'] = np.random.choice(dkim_options, p=dkim_warning_probs)

    dmarc_options = ['pass', 'fail', 'none', 'neutral', 'temperror', 'permerror']
    dmarc_warning_probs = [0.15, 0.30, 0.20, 0.20, 0.10, 0.05]
    record['dmarc_result'] = np.random.choice(dmarc_options, p=dmarc_warning_probs)

    # reverse_dns_valid: ~50% True in warnings
    record['reverse_dns_valid'] = np.random.choice([True, False], p=[0.50, 0.50])

    # === ATTACHMENT/FILE FEATURES ===
    record['packer_detected'] = np.random.choice([True, False], p=[0.10, 0.90])
    record['any_file_hash_malicious'] = np.random.choice([True, False], p=[0.08, 0.92])
    record['max_metadata_suspicious_score'] = round(np.random.uniform(0.0, 0.4), 10)
    record['malicious_attachment_count'] = np.random.choice([0, 1, 2], p=[0.85, 0.12, 0.03])
    record['has_executable_attachment'] = np.random.choice([True, False], p=[0.05, 0.95])
    record['unscannable_attachment_present'] = np.random.choice([True, False], p=[0.03, 0.97])
    record['total_components_detected_malicious'] = np.random.choice([0, 1, 2, 3], p=[0.80, 0.12, 0.05, 0.03])
    record['total_yara_match_count'] = np.random.choice(range(0, 6), p=[0.75, 0.12, 0.07, 0.03, 0.02, 0.01])
    record['total_ioc_count'] = np.random.choice(range(0, 8), p=[0.60, 0.15, 0.10, 0.07, 0.04, 0.02, 0.01, 0.01])

    # === BEHAVIORAL FEATURES ===
    record['max_behavioral_sandbox_score'] = round(np.random.uniform(0.0, 0.3), 10)
    record['max_amsi_suspicion_score'] = round(np.random.uniform(0.0, 0.2), 10)
    record['any_macro_enabled_document'] = np.random.choice([True, False], p=[0.15, 0.85])
    record['any_vbscript_javascript_detected'] = np.random.choice([True, False], p=[0.10, 0.90])
    record['any_active_x_objects_detected'] = np.random.choice([True, False], p=[0.08, 0.92])
    record['any_network_call_on_open'] = np.random.choice([True, False], p=[0.12, 0.88])
    record['max_exfiltration_behavior_score'] = round(np.random.uniform(0.0, 0.15), 10)
    record['any_exploit_pattern_detected'] = np.random.choice([True, False], p=[0.05, 0.95])
    record['total_embedded_file_count'] = np.random.choice(range(0, 4), p=[0.70, 0.20, 0.07, 0.03])
    record['max_suspicious_string_entropy_score'] = round(np.random.uniform(0.0, 0.3), 10)
    record['max_sandbox_execution_time'] = round(np.random.uniform(0.0, 0.1), 10)
    record['unique_parent_process_names'] = ''  # Usually empty

    # === RETURN PATH FEATURES ===
    record['return_path_mismatch_with_from'] = np.random.choice([True, False], p=[0.60, 0.40])
    record['return_path_known_malicious'] = np.random.choice([True, False], p=[0.15, 0.85])
    record['return_path_reputation_score'] = round(np.random.uniform(0.2, 0.5), 10)

    # === REPLY PATH FEATURES ===
    record['reply_path_known_malicious'] = np.random.choice([True, False], p=[0.12, 0.88])
    record['reply_path_diff_from_sender'] = np.random.choice([True, False], p=[0.55, 0.45])
    record['reply_path_reputation_score'] = round(np.random.uniform(0.2, 0.5), 10)

    # === SMTP FEATURES ===
    record['smtp_ip_known_malicious'] = np.random.choice([True, False], p=[0.10, 0.90])
    record['smtp_ip_geo'] = round(np.random.uniform(0.3, 0.8), 10)
    record['smtp_ip_asn'] = round(np.random.uniform(0.3, 0.7), 10)
    record['smtp_ip_reputation_score'] = round(np.random.uniform(0.2, 0.6), 10)

    # === DOMAIN/URL FEATURES ===
    record['domain_known_malicious'] = np.random.choice([True, False], p=[0.35, 0.65])
    record['url_count'] = np.random.choice(range(0, 10), p=[0.10, 0.20, 0.20, 0.15, 0.12, 0.10, 0.05, 0.04, 0.02, 0.02])
    record['dns_morphing_detected'] = np.random.choice([True, False], p=[0.25, 0.75])
    record['domain_tech_stack_match_score'] = round(np.random.uniform(0.2, 0.6), 10)
    record['url_decoded_spoof_detected'] = np.random.choice([True, False], p=[0.30, 0.70])
    record['url_reputation_score'] = round(np.random.uniform(0.2, 0.6), 10)

    ssl_options = ['valid', 'invalid', 'expired', 'self_signed', 'no_ssl']
    ssl_warning_probs = [0.30, 0.15, 0.10, 0.25, 0.20]
    record['ssl_validity_status'] = np.random.choice(ssl_options, p=ssl_warning_probs)

    # KEY WARNING INDICATORS
    record['site_visual_similarity_to_known_brand'] = round(np.random.uniform(0.2, 0.8), 10)
    record['url_rendering_behavior_score'] = round(np.random.uniform(0.2, 0.7), 10)

    record['link_rewritten_through_redirector'] = np.random.choice([True, False], p=[0.20, 0.80])
    record['token_validation_success'] = np.random.choice([True, False], p=[0.40, 0.60])

    # === HIGH RISK INDICATORS (KEY FOR WARNINGS) ===
    record['is_high_risk_role_targeted'] = np.random.choice([True, False], p=[0.73, 0.27])
    record['urgency_keywords_present'] = np.random.choice([True, False], p=[0.86, 0.14])

    # request_type - KEY FEATURE
    request_types = [
        'credential_request', 'sensitive_data_request', 'wire_transfer',
        'invoice_payment', 'bank_detail_update', 'gift_card_request',
        'legal_threat', 'urgent_callback', 'invoice_verification',
        'link_click', 'document_download', 'meeting_request', 'none'
    ]
    request_warning_probs = [0.18, 0.15, 0.08, 0.10, 0.06, 0.04, 0.03, 0.05, 0.06, 0.12, 0.05, 0.03, 0.05]
    record['request_type'] = np.random.choice(request_types, p=request_warning_probs)

    # === CONTENT FEATURES ===
    record['content_spam_score'] = round(np.random.uniform(0.2, 0.6), 10)
    record['user_marked_as_spam_before'] = np.random.choice([True, False], p=[0.15, 0.85])
    record['bulk_message_indicator'] = np.random.choice([True, False], p=[0.08, 0.92])
    record['unsubscribe_link_present'] = np.random.choice([True, False], p=[0.12, 0.88])
    record['marketing_keywords_detected'] = round(np.random.uniform(0.0, 0.4), 10)
    record['html_text_ratio'] = round(np.random.uniform(0.3, 0.7), 10)
    record['image_only_email'] = np.random.choice([True, False], p=[0.05, 0.95])
    record['total_links_detected'] = np.random.choice(range(0, 15), p=[0.05, 0.10, 0.15, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05, 0.04, 0.03, 0.02, 0.02, 0.01, 0.01])

    # === URL SHORTENER FEATURES ===
    record['url_shortener_detected'] = np.random.choice([True, False], p=[0.25, 0.75])
    record['url_redirect_chain_length'] = np.random.choice(range(0, 5), p=[0.50, 0.25, 0.15, 0.07, 0.03])
    record['final_url_known_malicious'] = np.random.choice([True, False], p=[0.20, 0.80])

    # === TLS/ENCRYPTION ===
    tls_options = ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3', '']
    tls_probs = [0.10, 0.15, 0.35, 0.30, 0.10]
    record['tls_version'] = np.random.choice(tls_options, p=tls_probs)

    # === QR CODE ===
    record['Analysis_of_the_qrcode_if_present'] = np.random.choice([0, 1], p=[0.95, 0.05])

    # === CLASSIFICATION ===
    record['Final Classification'] = 'Warning'
    record['warning_risk'] = round(np.random.uniform(0.4, 0.9), 10)
    record['Binary_Label'] = 'Warning'

    generated_data.append(record)

# Create DataFrame
generated_df = pd.DataFrame(generated_data)

# Ensure column order matches training data
generated_df = generated_df[columns]

print(f"   ✓ Generated {len(generated_df)} records")

# Verify uniqueness
print("\n🔍 Verifying uniqueness...")
# Check for duplicate rows
duplicates = generated_df.duplicated().sum()
print(f"   Duplicate rows: {duplicates}")

if duplicates > 0:
    print(f"   Removing {duplicates} duplicates...")
    generated_df = generated_df.drop_duplicates()
    # Generate more to reach 1000
    while len(generated_df) < N:
        extra_needed = N - len(generated_df)
        print(f"   Generating {extra_needed} more records...")
        # Generate with different random state
        np.random.seed(int(datetime.now().timestamp()))
        for i in range(extra_needed):
            # Same generation logic but with new random values
            record = {}
            record['sender_known_malicious'] = np.random.choice([True, False], p=[0.45, 0.55])
            record['sender_domain_reputation_score'] = round(np.random.uniform(0.1, 0.6), 10)
            record['sender_spoof_detected'] = np.random.choice([True, False], p=[0.55, 0.45])
            record['sender_temp_email_likelihood'] = round(np.random.uniform(0.3, 0.8), 10)
            record['dmarc_enforced'] = np.random.choice([True, False], p=[0.30, 0.70])
            record['sender_name_similarity_to_vip'] = round(np.random.uniform(0.2, 0.9), 10)
            record['spf_result'] = np.random.choice(['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'], p=[0.15, 0.25, 0.15, 0.20, 0.10, 0.10, 0.05])
            record['dkim_result'] = np.random.choice(['pass', 'fail', 'neutral', 'none', 'temperror', 'permerror'], p=[0.20, 0.25, 0.25, 0.15, 0.10, 0.05])
            record['dmarc_result'] = np.random.choice(['pass', 'fail', 'none', 'neutral', 'temperror', 'permerror'], p=[0.15, 0.30, 0.20, 0.20, 0.10, 0.05])
            record['reverse_dns_valid'] = np.random.choice([True, False], p=[0.50, 0.50])
            record['packer_detected'] = np.random.choice([True, False], p=[0.10, 0.90])
            record['any_file_hash_malicious'] = np.random.choice([True, False], p=[0.08, 0.92])
            record['max_metadata_suspicious_score'] = round(np.random.uniform(0.0, 0.4), 10)
            record['malicious_attachment_count'] = np.random.choice([0, 1, 2], p=[0.85, 0.12, 0.03])
            record['has_executable_attachment'] = np.random.choice([True, False], p=[0.05, 0.95])
            record['unscannable_attachment_present'] = np.random.choice([True, False], p=[0.03, 0.97])
            record['total_components_detected_malicious'] = np.random.choice([0, 1, 2, 3], p=[0.80, 0.12, 0.05, 0.03])
            record['total_yara_match_count'] = np.random.choice(range(0, 6), p=[0.75, 0.12, 0.07, 0.03, 0.02, 0.01])
            record['total_ioc_count'] = np.random.choice(range(0, 8), p=[0.60, 0.15, 0.10, 0.07, 0.04, 0.02, 0.01, 0.01])
            record['max_behavioral_sandbox_score'] = round(np.random.uniform(0.0, 0.3), 10)
            record['max_amsi_suspicion_score'] = round(np.random.uniform(0.0, 0.2), 10)
            record['any_macro_enabled_document'] = np.random.choice([True, False], p=[0.15, 0.85])
            record['any_vbscript_javascript_detected'] = np.random.choice([True, False], p=[0.10, 0.90])
            record['any_active_x_objects_detected'] = np.random.choice([True, False], p=[0.08, 0.92])
            record['any_network_call_on_open'] = np.random.choice([True, False], p=[0.12, 0.88])
            record['max_exfiltration_behavior_score'] = round(np.random.uniform(0.0, 0.15), 10)
            record['any_exploit_pattern_detected'] = np.random.choice([True, False], p=[0.05, 0.95])
            record['total_embedded_file_count'] = np.random.choice(range(0, 4), p=[0.70, 0.20, 0.07, 0.03])
            record['max_suspicious_string_entropy_score'] = round(np.random.uniform(0.0, 0.3), 10)
            record['max_sandbox_execution_time'] = round(np.random.uniform(0.0, 0.1), 10)
            record['unique_parent_process_names'] = ''
            record['return_path_mismatch_with_from'] = np.random.choice([True, False], p=[0.60, 0.40])
            record['return_path_known_malicious'] = np.random.choice([True, False], p=[0.15, 0.85])
            record['return_path_reputation_score'] = round(np.random.uniform(0.2, 0.5), 10)
            record['reply_path_known_malicious'] = np.random.choice([True, False], p=[0.12, 0.88])
            record['reply_path_diff_from_sender'] = np.random.choice([True, False], p=[0.55, 0.45])
            record['reply_path_reputation_score'] = round(np.random.uniform(0.2, 0.5), 10)
            record['smtp_ip_known_malicious'] = np.random.choice([True, False], p=[0.10, 0.90])
            record['smtp_ip_geo'] = round(np.random.uniform(0.3, 0.8), 10)
            record['smtp_ip_asn'] = round(np.random.uniform(0.3, 0.7), 10)
            record['smtp_ip_reputation_score'] = round(np.random.uniform(0.2, 0.6), 10)
            record['domain_known_malicious'] = np.random.choice([True, False], p=[0.35, 0.65])
            record['url_count'] = np.random.choice(range(0, 10), p=[0.10, 0.20, 0.20, 0.15, 0.12, 0.10, 0.05, 0.04, 0.02, 0.02])
            record['dns_morphing_detected'] = np.random.choice([True, False], p=[0.25, 0.75])
            record['domain_tech_stack_match_score'] = round(np.random.uniform(0.2, 0.6), 10)
            record['url_decoded_spoof_detected'] = np.random.choice([True, False], p=[0.30, 0.70])
            record['url_reputation_score'] = round(np.random.uniform(0.2, 0.6), 10)
            record['ssl_validity_status'] = np.random.choice(['valid', 'invalid', 'expired', 'self_signed', 'no_ssl'], p=[0.30, 0.15, 0.10, 0.25, 0.20])
            record['site_visual_similarity_to_known_brand'] = round(np.random.uniform(0.2, 0.8), 10)
            record['url_rendering_behavior_score'] = round(np.random.uniform(0.2, 0.7), 10)
            record['link_rewritten_through_redirector'] = np.random.choice([True, False], p=[0.20, 0.80])
            record['token_validation_success'] = np.random.choice([True, False], p=[0.40, 0.60])
            record['is_high_risk_role_targeted'] = np.random.choice([True, False], p=[0.73, 0.27])
            record['urgency_keywords_present'] = np.random.choice([True, False], p=[0.86, 0.14])
            record['request_type'] = np.random.choice(['credential_request', 'sensitive_data_request', 'wire_transfer', 'invoice_payment', 'bank_detail_update', 'gift_card_request', 'legal_threat', 'urgent_callback', 'invoice_verification', 'link_click', 'document_download', 'meeting_request', 'none'], p=[0.18, 0.15, 0.08, 0.10, 0.06, 0.04, 0.03, 0.05, 0.06, 0.12, 0.05, 0.03, 0.05])
            record['content_spam_score'] = round(np.random.uniform(0.2, 0.6), 10)
            record['user_marked_as_spam_before'] = np.random.choice([True, False], p=[0.15, 0.85])
            record['bulk_message_indicator'] = np.random.choice([True, False], p=[0.08, 0.92])
            record['unsubscribe_link_present'] = np.random.choice([True, False], p=[0.12, 0.88])
            record['marketing_keywords_detected'] = round(np.random.uniform(0.0, 0.4), 10)
            record['html_text_ratio'] = round(np.random.uniform(0.3, 0.7), 10)
            record['image_only_email'] = np.random.choice([True, False], p=[0.05, 0.95])
            record['total_links_detected'] = np.random.choice(range(0, 15), p=[0.05, 0.10, 0.15, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05, 0.04, 0.03, 0.02, 0.02, 0.01, 0.01])
            record['url_shortener_detected'] = np.random.choice([True, False], p=[0.25, 0.75])
            record['url_redirect_chain_length'] = np.random.choice(range(0, 5), p=[0.50, 0.25, 0.15, 0.07, 0.03])
            record['final_url_known_malicious'] = np.random.choice([True, False], p=[0.20, 0.80])
            record['tls_version'] = np.random.choice(['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3', ''], p=[0.10, 0.15, 0.35, 0.30, 0.10])
            record['Analysis_of_the_qrcode_if_present'] = np.random.choice([0, 1], p=[0.95, 0.05])
            record['Final Classification'] = 'Warning'
            record['warning_risk'] = round(np.random.uniform(0.4, 0.9), 10)
            record['Binary_Label'] = 'Warning'
            generated_data.append(record)

        generated_df = pd.DataFrame(generated_data)[columns].drop_duplicates().head(N)

print(f"   ✓ Final unique records: {len(generated_df)}")

# Verify all labels are Warning
print("\n📊 Verifying labels...")
print(f"   Binary_Label distribution: {generated_df['Binary_Label'].value_counts().to_dict()}")

# Save to CSV
output_file = 'generated_warning_1000.csv'
generated_df.to_csv(output_file, index=False)
print(f"\n💾 Saved to: {output_file}")

# Summary statistics
print("\n" + "="*80)
print("GENERATED DATA SUMMARY")
print("="*80)

print("\n📊 Key Feature Distributions:")
print(f"   is_high_risk_role_targeted: {generated_df['is_high_risk_role_targeted'].value_counts().to_dict()}")
print(f"   urgency_keywords_present: {generated_df['urgency_keywords_present'].value_counts().to_dict()}")
print(f"   sender_spoof_detected: {generated_df['sender_spoof_detected'].value_counts().to_dict()}")
print(f"   domain_known_malicious: {generated_df['domain_known_malicious'].value_counts().to_dict()}")
print(f"   request_type: {generated_df['request_type'].value_counts().head(5).to_dict()}")

print("\n📊 Numeric Feature Ranges:")
print(f"   sender_domain_reputation_score: [{generated_df['sender_domain_reputation_score'].min():.4f}, {generated_df['sender_domain_reputation_score'].max():.4f}]")
print(f"   site_visual_similarity_to_known_brand: [{generated_df['site_visual_similarity_to_known_brand'].min():.4f}, {generated_df['site_visual_similarity_to_known_brand'].max():.4f}]")
print(f"   url_rendering_behavior_score: [{generated_df['url_rendering_behavior_score'].min():.4f}, {generated_df['url_rendering_behavior_score'].max():.4f}]")
print(f"   warning_risk: [{generated_df['warning_risk'].min():.4f}, {generated_df['warning_risk'].max():.4f}]")

print("\n" + "="*80)
print(f"✅ Successfully generated {len(generated_df)} unique Warning records!")
print(f"   Output file: {output_file}")
print("="*80)
