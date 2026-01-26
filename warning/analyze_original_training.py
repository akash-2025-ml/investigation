#!/usr/bin/env python3
"""
Analyze Original Training Data for Problematic Not-Warning Records
Check if Not-Warning records have patterns that could cause misclassification
of the user's Warning test record.
"""

import csv

print("="*80)
print("ANALYZING ORIGINAL TRAINING DATA FOR PROBLEMATIC NOT-WARNING RECORDS")
print("="*80)

# User's test record (should be Warning but classified as Not-Warning)
test_record = {
    'spf_result': 'neutral',
    'dmarc_result': 'fail',
    'dkim_result': 'neutral',
    'request_type': 'none',
    'is_high_risk_role_targeted': 1,
    'sender_name_similarity_to_vip': 0,
    'urgency_keywords_present': 0.0,
    'sender_spoof_detected': 1,
    'sender_temp_email_likelihood': 0.0,
    'url_shortener_detected': 1,
    'url_redirect_chain_length': 0,
    'url_decoded_spoof_detected': 0,
    'site_visual_similarity_to_known_brand': 0.0,
    'url_rendering_behavior_score': 0.0,
    'domain_known_malicious': 0,
    'dns_morphing_detected': 0,
    'return_path_mismatch_with_from': 0,
    'reply_path_diff_from_sender': 0,
    'reply_path_known_malicious': 0
}

print("\n📋 USER'S TEST RECORD (Should be Warning):")
print("-"*50)
key_features = ['is_high_risk_role_targeted', 'sender_spoof_detected', 'url_shortener_detected',
                'urgency_keywords_present', 'request_type', 'dmarc_result', 'dkim_result', 'spf_result']
for key in key_features:
    print(f"   {key}: {test_record[key]}")

# Load training data
print("\n📂 Loading training data...")
records = []
with open('warning_detector_training_data.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        records.append(row)

print(f"   Total records: {len(records)}")

# Separate by label
warning_records = [r for r in records if r['Binary_Label'] == 'Warning']
not_warning_records = [r for r in records if r['Binary_Label'] == 'Not-Warning']

print(f"   Warning records: {len(warning_records)}")
print(f"   Not-Warning records: {len(not_warning_records)}")

# Helper function to convert values
def to_bool(val):
    """Convert various representations to boolean"""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() == 'true' or val == '1'
    return bool(val)

def to_float(val):
    """Convert to float"""
    try:
        return float(val)
    except:
        return 0.0

# ============================================================================
# ANALYSIS 1: Not-Warning records with sender_spoof_detected = True
# ============================================================================
print("\n" + "="*80)
print("ANALYSIS 1: Not-Warning records with sender_spoof_detected = True")
print("="*80)

spoof_not_warning = [r for r in not_warning_records if to_bool(r.get('sender_spoof_detected', False))]
print(f"\n⚠️ Found {len(spoof_not_warning)} Not-Warning records with sender_spoof_detected=True")

if spoof_not_warning:
    print("\n   Sample records (first 5):")
    for i, r in enumerate(spoof_not_warning[:5]):
        print(f"\n   Record {i+1}:")
        print(f"      is_high_risk_role_targeted: {r.get('is_high_risk_role_targeted')}")
        print(f"      sender_spoof_detected: {r.get('sender_spoof_detected')}")
        print(f"      url_shortener_detected: {r.get('url_shortener_detected')}")
        print(f"      urgency_keywords_present: {r.get('urgency_keywords_present')}")
        print(f"      request_type: {r.get('request_type')}")
        print(f"      dmarc_result: {r.get('dmarc_result')}")

# ============================================================================
# ANALYSIS 2: Not-Warning records with is_high_risk_role_targeted = True
# ============================================================================
print("\n" + "="*80)
print("ANALYSIS 2: Not-Warning records with is_high_risk_role_targeted = True")
print("="*80)

high_risk_not_warning = [r for r in not_warning_records if to_bool(r.get('is_high_risk_role_targeted', False))]
print(f"\n⚠️ Found {len(high_risk_not_warning)} Not-Warning records with is_high_risk_role_targeted=True")

if high_risk_not_warning:
    print("\n   Sample records (first 5):")
    for i, r in enumerate(high_risk_not_warning[:5]):
        print(f"\n   Record {i+1}:")
        print(f"      is_high_risk_role_targeted: {r.get('is_high_risk_role_targeted')}")
        print(f"      sender_spoof_detected: {r.get('sender_spoof_detected')}")
        print(f"      url_shortener_detected: {r.get('url_shortener_detected')}")
        print(f"      urgency_keywords_present: {r.get('urgency_keywords_present')}")
        print(f"      request_type: {r.get('request_type')}")
        print(f"      dmarc_result: {r.get('dmarc_result')}")

# ============================================================================
# ANALYSIS 3: Not-Warning records with url_shortener_detected = True
# ============================================================================
print("\n" + "="*80)
print("ANALYSIS 3: Not-Warning records with url_shortener_detected = True")
print("="*80)

shortener_not_warning = [r for r in not_warning_records if to_bool(r.get('url_shortener_detected', False))]
print(f"\n⚠️ Found {len(shortener_not_warning)} Not-Warning records with url_shortener_detected=True")

if shortener_not_warning:
    print("\n   Sample records (first 5):")
    for i, r in enumerate(shortener_not_warning[:5]):
        print(f"\n   Record {i+1}:")
        print(f"      is_high_risk_role_targeted: {r.get('is_high_risk_role_targeted')}")
        print(f"      sender_spoof_detected: {r.get('sender_spoof_detected')}")
        print(f"      url_shortener_detected: {r.get('url_shortener_detected')}")
        print(f"      urgency_keywords_present: {r.get('urgency_keywords_present')}")
        print(f"      request_type: {r.get('request_type')}")
        print(f"      dmarc_result: {r.get('dmarc_result')}")

# ============================================================================
# ANALYSIS 4: Not-Warning with request_type = 'none'
# ============================================================================
print("\n" + "="*80)
print("ANALYSIS 4: Not-Warning records with request_type = 'none'")
print("="*80)

none_request_not_warning = [r for r in not_warning_records if r.get('request_type', '').lower() == 'none']
print(f"\n⚠️ Found {len(none_request_not_warning)} Not-Warning records with request_type='none'")

# ============================================================================
# ANALYSIS 5: Not-Warning with dmarc_result = 'fail'
# ============================================================================
print("\n" + "="*80)
print("ANALYSIS 5: Not-Warning records with dmarc_result = 'fail'")
print("="*80)

dmarc_fail_not_warning = [r for r in not_warning_records if r.get('dmarc_result', '').lower() == 'fail']
print(f"\n⚠️ Found {len(dmarc_fail_not_warning)} Not-Warning records with dmarc_result='fail'")

if dmarc_fail_not_warning:
    print("\n   Sample records (first 5):")
    for i, r in enumerate(dmarc_fail_not_warning[:5]):
        print(f"\n   Record {i+1}:")
        print(f"      is_high_risk_role_targeted: {r.get('is_high_risk_role_targeted')}")
        print(f"      sender_spoof_detected: {r.get('sender_spoof_detected')}")
        print(f"      url_shortener_detected: {r.get('url_shortener_detected')}")
        print(f"      urgency_keywords_present: {r.get('urgency_keywords_present')}")
        print(f"      request_type: {r.get('request_type')}")
        print(f"      dmarc_result: {r.get('dmarc_result')}")

# ============================================================================
# ANALYSIS 6: CRITICAL - Not-Warning with MULTIPLE matching features
# ============================================================================
print("\n" + "="*80)
print("ANALYSIS 6: CRITICAL - Not-Warning with MULTIPLE Warning-like features")
print("="*80)

# Find Not-Warning records that match 2+ key features from test record
def count_matching_features(record):
    """Count how many Warning-like features this record has"""
    score = 0
    if to_bool(record.get('sender_spoof_detected', False)):
        score += 1
    if to_bool(record.get('is_high_risk_role_targeted', False)):
        score += 1
    if to_bool(record.get('url_shortener_detected', False)):
        score += 1
    if record.get('request_type', '').lower() == 'none':
        score += 1
    if record.get('dmarc_result', '').lower() == 'fail':
        score += 1
    return score

multi_match_records = []
for r in not_warning_records:
    match_count = count_matching_features(r)
    if match_count >= 2:
        multi_match_records.append((r, match_count))

# Sort by match count descending
multi_match_records.sort(key=lambda x: x[1], reverse=True)

print(f"\n⚠️ Found {len(multi_match_records)} Not-Warning records matching 2+ Warning features")

print("\n📊 Distribution by match count:")
for i in range(5, 0, -1):
    count = len([r for r, c in multi_match_records if c == i])
    if count > 0:
        print(f"   {i} features: {count} records")

if multi_match_records:
    print("\n🔴 TOP 10 MOST PROBLEMATIC Not-Warning RECORDS:")
    print("-"*80)
    for i, (r, match_count) in enumerate(multi_match_records[:10]):
        print(f"\n   Record {i+1} (matches {match_count} Warning features):")
        print(f"      sender_spoof_detected:       {r.get('sender_spoof_detected')}")
        print(f"      is_high_risk_role_targeted:  {r.get('is_high_risk_role_targeted')}")
        print(f"      url_shortener_detected:      {r.get('url_shortener_detected')}")
        print(f"      urgency_keywords_present:    {r.get('urgency_keywords_present')}")
        print(f"      request_type:                {r.get('request_type')}")
        print(f"      dmarc_result:                {r.get('dmarc_result')}")
        print(f"      dkim_result:                 {r.get('dkim_result')}")
        print(f"      spf_result:                  {r.get('spf_result')}")
        print(f"      sender_known_malicious:      {r.get('sender_known_malicious')}")
        print(f"      domain_known_malicious:      {r.get('domain_known_malicious')}")

# ============================================================================
# ANALYSIS 7: EXACT PATTERN MATCH
# ============================================================================
print("\n" + "="*80)
print("ANALYSIS 7: Not-Warning records with EXACT test pattern")
print("="*80)

# Find records that match: sender_spoof=True AND is_high_risk=True AND url_shortener=True
exact_match = []
for r in not_warning_records:
    if (to_bool(r.get('sender_spoof_detected', False)) and
        to_bool(r.get('is_high_risk_role_targeted', False)) and
        to_bool(r.get('url_shortener_detected', False))):
        exact_match.append(r)

print(f"\n🔴 Found {len(exact_match)} Not-Warning records with:")
print("   - sender_spoof_detected = True")
print("   - is_high_risk_role_targeted = True")
print("   - url_shortener_detected = True")

if exact_match:
    print("\n   These are HIGHLY PROBLEMATIC - same pattern as user's Warning test record!")
    for i, r in enumerate(exact_match):
        print(f"\n   Record {i+1}:")
        for key in ['sender_spoof_detected', 'is_high_risk_role_targeted', 'url_shortener_detected',
                    'urgency_keywords_present', 'request_type', 'dmarc_result', 'dkim_result',
                    'spf_result', 'sender_known_malicious', 'domain_known_malicious']:
            print(f"      {key}: {r.get(key)}")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "="*80)
print("SUMMARY - ROOT CAUSE ANALYSIS")
print("="*80)

print(f"""
📊 PROBLEMATIC Not-Warning RECORDS IN ORIGINAL TRAINING DATA:

   1. sender_spoof_detected = True:      {len(spoof_not_warning)} records
   2. is_high_risk_role_targeted = True: {len(high_risk_not_warning)} records
   3. url_shortener_detected = True:     {len(shortener_not_warning)} records
   4. request_type = 'none':             {len(none_request_not_warning)} records
   5. dmarc_result = 'fail':             {len(dmarc_fail_not_warning)} records

   ⚠️ Not-Warning with 2+ Warning features: {len(multi_match_records)} records
   🔴 EXACT MATCH (spoof + high_risk + shortener): {len(exact_match)} records

🎯 ROOT CAUSE:
   Your test record has: sender_spoof=1, is_high_risk=1, url_shortener=1

   The ORIGINAL training data has Not-Warning records with the SAME
   Warning-like patterns. This confuses the model!

   The model learns: "Some records with these patterns are Not-Warning"
   → So it misclassifies your Warning test record as Not-Warning
""")

print("="*80)
