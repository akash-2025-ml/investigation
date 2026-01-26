#!/usr/bin/env python3
"""
Deep analysis of why test record is misclassified
"""

import csv

print("="*80)
print("DEEP ANALYSIS: WHY YOUR TEST RECORD IS MISCLASSIFIED")
print("="*80)

# Load training data
records = []
with open('warning_detector_training_data.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        records.append(row)

warning_records = [r for r in records if r['Binary_Label'] == 'Warning']
not_warning_records = [r for r in records if r['Binary_Label'] == 'Not-Warning']

def to_bool(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() == 'true' or val == '1'
    return bool(val)

print("\n" + "="*80)
print("KEY INSIGHT: sender_spoof_detected is THE DIFFERENTIATOR!")
print("="*80)

# Check sender_spoof in Warning vs Not-Warning
spoof_in_warning = len([r for r in warning_records if to_bool(r.get('sender_spoof_detected', False))])
spoof_in_not_warning = len([r for r in not_warning_records if to_bool(r.get('sender_spoof_detected', False))])

print(f"""
📊 sender_spoof_detected Distribution:

   Warning records with sender_spoof=True:     {spoof_in_warning} / {len(warning_records)} ({spoof_in_warning/len(warning_records)*100:.1f}%)
   Not-Warning records with sender_spoof=True: {spoof_in_not_warning} / {len(not_warning_records)} ({spoof_in_not_warning/len(not_warning_records)*100:.1f}%)

🔴 CRITICAL: NO Not-Warning records have sender_spoof_detected=True!
   This means sender_spoof=True should be a STRONG signal for Warning.

   BUT YOUR MODEL IS STILL MISCLASSIFYING! WHY?
""")

# Check the overlapping feature space
print("="*80)
print("ANALYZING FEATURE OVERLAP BETWEEN WARNING AND NOT-WARNING")
print("="*80)

# Find Warning records with the SAME features as user's test record (except sender_spoof)
# User's test: is_high_risk=1, url_shortener=1, request_type='none', dmarc_result='fail'

print("\n📊 Records matching: is_high_risk=True + url_shortener=True + request_type='none' + dmarc_fail")
print("-"*80)

matching_warning = []
matching_not_warning = []

for r in warning_records:
    if (to_bool(r.get('is_high_risk_role_targeted', False)) and
        to_bool(r.get('url_shortener_detected', False)) and
        r.get('request_type', '').lower() == 'none' and
        r.get('dmarc_result', '').lower() == 'fail'):
        matching_warning.append(r)

for r in not_warning_records:
    if (to_bool(r.get('is_high_risk_role_targeted', False)) and
        to_bool(r.get('url_shortener_detected', False)) and
        r.get('request_type', '').lower() == 'none' and
        r.get('dmarc_result', '').lower() == 'fail'):
        matching_not_warning.append(r)

print(f"\n   Warning records with this pattern:     {len(matching_warning)}")
print(f"   Not-Warning records with this pattern: {len(matching_not_warning)}")

if matching_not_warning:
    print("\n   ⚠️ PROBLEM: Not-Warning record(s) exist with WARNING-like features!")
    for i, r in enumerate(matching_not_warning):
        print(f"\n   Not-Warning Record {i+1}:")
        print(f"      sender_spoof_detected: {r.get('sender_spoof_detected')}")
        print(f"      is_high_risk_role_targeted: {r.get('is_high_risk_role_targeted')}")
        print(f"      url_shortener_detected: {r.get('url_shortener_detected')}")
        print(f"      request_type: {r.get('request_type')}")
        print(f"      dmarc_result: {r.get('dmarc_result')}")
        print(f"      urgency_keywords_present: {r.get('urgency_keywords_present')}")

# Check partial matches
print("\n" + "="*80)
print("PARTIAL PATTERN ANALYSIS")
print("="*80)

# is_high_risk + url_shortener only
print("\n📊 is_high_risk=True + url_shortener=True (any request_type, any dmarc)")
w_count = len([r for r in warning_records if to_bool(r.get('is_high_risk_role_targeted', False)) and to_bool(r.get('url_shortener_detected', False))])
nw_count = len([r for r in not_warning_records if to_bool(r.get('is_high_risk_role_targeted', False)) and to_bool(r.get('url_shortener_detected', False))])
print(f"   Warning: {w_count}, Not-Warning: {nw_count}")

# is_high_risk + request_type='none'
print("\n📊 is_high_risk=True + request_type='none' (any url_shortener, any dmarc)")
w_count = len([r for r in warning_records if to_bool(r.get('is_high_risk_role_targeted', False)) and r.get('request_type', '').lower() == 'none'])
nw_count = len([r for r in not_warning_records if to_bool(r.get('is_high_risk_role_targeted', False)) and r.get('request_type', '').lower() == 'none'])
print(f"   Warning: {w_count}, Not-Warning: {nw_count}")

# is_high_risk + dmarc_fail
print("\n📊 is_high_risk=True + dmarc_result='fail' (any url_shortener, any request_type)")
w_count = len([r for r in warning_records if to_bool(r.get('is_high_risk_role_targeted', False)) and r.get('dmarc_result', '').lower() == 'fail'])
nw_count = len([r for r in not_warning_records if to_bool(r.get('is_high_risk_role_targeted', False)) and r.get('dmarc_result', '').lower() == 'fail'])
print(f"   Warning: {w_count}, Not-Warning: {nw_count}")

# url_shortener + dmarc_fail
print("\n📊 url_shortener=True + dmarc_result='fail' (any is_high_risk, any request_type)")
w_count = len([r for r in warning_records if to_bool(r.get('url_shortener_detected', False)) and r.get('dmarc_result', '').lower() == 'fail'])
nw_count = len([r for r in not_warning_records if to_bool(r.get('url_shortener_detected', False)) and r.get('dmarc_result', '').lower() == 'fail'])
print(f"   Warning: {w_count}, Not-Warning: {nw_count}")

print("\n" + "="*80)
print("MODEL'S DECISION LOGIC (LIKELY)")
print("="*80)

print("""
🎯 YOUR TEST RECORD:
   sender_spoof_detected = 1 (True)
   is_high_risk_role_targeted = 1 (True)
   url_shortener_detected = 1 (True)
   request_type = 'none'
   dmarc_result = 'fail'
   urgency_keywords_present = 0.0 (False)

🤔 WHY MODEL PREDICTS NOT-WARNING:

The model sees:
   1. is_high_risk=True + url_shortener=True + request_type='none' + dmarc='fail'
      → EXISTS IN Not-Warning training data (1 record with 4/5 matching features)

   2. urgency_keywords_present = False
      → Most Warning records have urgency_keywords_present = True
      → Your test record does NOT have urgency keywords!

   3. sender_spoof_detected = True
      → Should be strong Warning signal, BUT...
      → Model may not weight this feature heavily enough

🔴 THE REAL PROBLEM:
   Your test record has urgency_keywords_present = 0.0 (False)

   Let me check: How many Warning records have urgency_keywords=False?
""")

# Check urgency_keywords in Warning vs Not-Warning
urgency_in_warning = len([r for r in warning_records if to_bool(r.get('urgency_keywords_present', False))])
urgency_in_not_warning = len([r for r in not_warning_records if to_bool(r.get('urgency_keywords_present', False))])

print(f"\n📊 urgency_keywords_present Distribution:")
print(f"   Warning with urgency=True: {urgency_in_warning}/{len(warning_records)} ({urgency_in_warning/len(warning_records)*100:.1f}%)")
print(f"   Not-Warning with urgency=True: {urgency_in_not_warning}/{len(not_warning_records)} ({urgency_in_not_warning/len(not_warning_records)*100:.1f}%)")

no_urgency_warning = len(warning_records) - urgency_in_warning
no_urgency_not_warning = len(not_warning_records) - urgency_in_not_warning

print(f"\n   Warning with urgency=False: {no_urgency_warning}/{len(warning_records)} ({no_urgency_warning/len(warning_records)*100:.1f}%)")
print(f"   Not-Warning with urgency=False: {no_urgency_not_warning}/{len(not_warning_records)} ({no_urgency_not_warning/len(not_warning_records)*100:.1f}%)")

# Find Warning records with sender_spoof=True but urgency=False
spoof_no_urgency_warning = len([r for r in warning_records
                                if to_bool(r.get('sender_spoof_detected', False))
                                and not to_bool(r.get('urgency_keywords_present', False))])

print(f"\n📊 Warning records with sender_spoof=True AND urgency=False: {spoof_no_urgency_warning}")

# Most similar records in training data
print("\n" + "="*80)
print("MOST SIMILAR RECORDS TO YOUR TEST (IN TRAINING DATA)")
print("="*80)

def similarity_score(record):
    """Calculate similarity to user's test record"""
    score = 0
    # Exact matches
    if to_bool(record.get('sender_spoof_detected', False)) == True:
        score += 10  # Strong weight
    if to_bool(record.get('is_high_risk_role_targeted', False)) == True:
        score += 5
    if to_bool(record.get('url_shortener_detected', False)) == True:
        score += 5
    if record.get('request_type', '').lower() == 'none':
        score += 3
    if record.get('dmarc_result', '').lower() == 'fail':
        score += 3
    if not to_bool(record.get('urgency_keywords_present', True)):  # urgency=False
        score += 2
    if record.get('dkim_result', '').lower() == 'neutral':
        score += 1
    if record.get('spf_result', '').lower() == 'neutral':
        score += 1
    return score

# Find most similar records
all_scored = [(r, similarity_score(r)) for r in records]
all_scored.sort(key=lambda x: x[1], reverse=True)

print("\n🔝 TOP 10 MOST SIMILAR RECORDS TO YOUR TEST:")
for i, (r, score) in enumerate(all_scored[:10]):
    print(f"\n   #{i+1} (similarity: {score}) - Label: {r['Binary_Label']}")
    print(f"      sender_spoof_detected: {r.get('sender_spoof_detected')}")
    print(f"      is_high_risk_role_targeted: {r.get('is_high_risk_role_targeted')}")
    print(f"      url_shortener_detected: {r.get('url_shortener_detected')}")
    print(f"      urgency_keywords_present: {r.get('urgency_keywords_present')}")
    print(f"      request_type: {r.get('request_type')}")
    print(f"      dmarc_result: {r.get('dmarc_result')}")

# Final recommendations
print("\n" + "="*80)
print("RECOMMENDATIONS TO FIX MISCLASSIFICATION")
print("="*80)

print(f"""
🔧 ISSUES IN ORIGINAL TRAINING DATA:

1. 204 Not-Warning records have is_high_risk_role_targeted=True
   → Model learns: is_high_risk alone doesn't mean Warning

2. 48 Not-Warning records have url_shortener_detected=True
   → Model learns: url_shortener alone doesn't mean Warning

3. 1 Not-Warning record has 4 Warning features:
   is_high_risk=True + url_shortener=True + request_type='none' + dmarc='fail'
   → Model learns: even this combination can be Not-Warning!

4. Your test has urgency_keywords_present=False (0.0)
   → Only {no_urgency_warning} Warning records have urgency=False
   → Model may rely heavily on urgency_keywords as Warning signal

🔴 ROOT CAUSE:
   The original training data has "boundary cases" - Not-Warning records
   with Warning-like features. This teaches the model that certain
   Warning patterns can also be Not-Warning.

   Combined with urgency_keywords=False in your test record,
   the model leans toward Not-Warning.

🔧 SOLUTIONS:

1. CLEAN the original training data:
   - Remove or relabel Not-Warning records with multiple Warning features
   - Especially the 1 record with 4 matching features

2. BOOST sender_spoof_detected importance:
   - sender_spoof=True appears ONLY in Warning records
   - But model may not weight it heavily enough
   - Consider feature engineering or class weights

3. ADD more Warning records with urgency_keywords=False:
   - Your test has urgency=False but is Warning
   - Training data may not have enough such examples
""")

print("="*80)
