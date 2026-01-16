#!/usr/bin/env python3
import pandas as pd

# Load testing data
testing_df = pd.read_csv("spam-kaggle-with-label.csv")

print("ANALYZING MISCLASSIFIED TESTING ROWS: 209, 104, 83")
print("=" * 80)

# Check both 0-indexed and 1-indexed (user might mean Excel row numbers which start at 1)
rows_to_check = [209, 104, 83]
print("Checking 0-indexed positions (Python default):")
print("-" * 60)

misclassified_patterns = []

for row_num in rows_to_check:
    if row_num < len(testing_df):
        row = testing_df.iloc[row_num]
        print(f"\nRow {row_num} (0-indexed):")
        print(f"  Label: {row['final_label']}")
        print(f"  content_spam_score: {row['content_spam_score']:.3f}")
        print(f"  url_count: {row['url_count']}")
        print(f"  total_links_detected: {row['total_links_detected']}")
        print(f"  sender_domain_reputation_score: {row['sender_domain_reputation_score']:.3f}")
        print(f"  unsubscribe_link_present: {row['unsubscribe_link_present']}")
        print(f"  bulk_message_indicator: {row['bulk_message_indicator']}")
        print(f"  marketing_keywords_detected: {row['marketing_keywords_detected']:.3f}")
        print(f"  spf_result: {row['spf_result']}")
        print(f"  dmarc_result: {row['dmarc_result']}")
        
        # Store pattern for training data correction
        if row['final_label'] == 'Spam':
            misclassified_patterns.append({
                'row_num': row_num,
                'content_spam_score': row['content_spam_score'],
                'url_count': row['url_count'],
                'total_links_detected': row['total_links_detected'],
                'sender_domain_reputation_score': row['sender_domain_reputation_score'],
                'marketing_keywords_detected': row['marketing_keywords_detected'],
                'unsubscribe_link_present': row['unsubscribe_link_present'],
                'bulk_message_indicator': row['bulk_message_indicator']
            })

print("\n\nChecking 1-indexed positions (Excel-style, subtract 1):")
print("-" * 60)

for row_num in rows_to_check:
    adjusted_row = row_num - 1  # Convert to 0-indexed
    if 0 <= adjusted_row < len(testing_df):
        row = testing_df.iloc[adjusted_row]
        print(f"\nExcel Row {row_num} (Python index {adjusted_row}):")
        print(f"  Label: {row['final_label']}")
        print(f"  content_spam_score: {row['content_spam_score']:.3f}")
        print(f"  url_count: {row['url_count']}")
        print(f"  sender_domain_reputation_score: {row['sender_domain_reputation_score']:.3f}")

# Determine which interpretation shows Spam labels
spam_count_0_indexed = sum(1 for r in rows_to_check if r < len(testing_df) and testing_df.iloc[r]['final_label'] == 'Spam')
spam_count_1_indexed = sum(1 for r in rows_to_check if 0 <= r-1 < len(testing_df) and testing_df.iloc[r-1]['final_label'] == 'Spam')

print(f"\n\nDETERMINING CORRECT INDEXING:")
print(f"0-indexed interpretation: {spam_count_0_indexed}/3 are Spam")
print(f"1-indexed interpretation: {spam_count_1_indexed}/3 are Spam")

# Use the interpretation that shows these as Spam records
if spam_count_1_indexed > spam_count_0_indexed:
    print("Using 1-indexed (Excel-style) interpretation")
    final_patterns = []
    for row_num in rows_to_check:
        adjusted_row = row_num - 1
        if 0 <= adjusted_row < len(testing_df):
            row = testing_df.iloc[adjusted_row]
            if row['final_label'] == 'Spam':
                final_patterns.append({
                    'excel_row': row_num,
                    'python_index': adjusted_row,
                    'content_spam_score': row['content_spam_score'],
                    'url_count': row['url_count'],
                    'total_links_detected': row['total_links_detected'],
                    'sender_domain_reputation_score': row['sender_domain_reputation_score'],
                    'marketing_keywords_detected': row['marketing_keywords_detected'],
                    'unsubscribe_link_present': row['unsubscribe_link_present'],
                    'bulk_message_indicator': row['bulk_message_indicator'],
                    'html_text_ratio': row['html_text_ratio']
                })
else:
    print("Using 0-indexed (Python default) interpretation")
    final_patterns = misclassified_patterns

print(f"\n\nPATTERNS TO FIX IN TRAINING DATA:")
print("-" * 60)
for i, pattern in enumerate(final_patterns):
    print(f"\nPattern {i+1}:")
    for key, value in pattern.items():
        print(f"  {key}: {value}")

# Save patterns for training correction
import json
with open('misclassified_patterns.json', 'w') as f:
    json.dump(final_patterns, f, indent=2)
print(f"\nSaved {len(final_patterns)} patterns to: misclassified_patterns.json")