#!/usr/bin/env python3
import pandas as pd

# Load the training subset with 15 signals
training_df = pd.read_csv("training_subset_15_signals.csv")

print("FINDING POTENTIAL MISCLASSIFICATIONS IN TRAINING DATA")
print("=" * 80)
print(f"Total training records: {len(training_df)}")

# Pattern 1: High content_spam_score but labeled Not-Spam
print("\n\nPATTERN 1: High spam score but labeled Not-Spam")
print("-" * 60)
not_spam_high_score = training_df[(training_df['Binary_Label'] == 'Not-Spam') & 
                                  (training_df['content_spam_score'] > 0.7)]
print(f"Found: {len(not_spam_high_score)} records")
if len(not_spam_high_score) > 0:
    print("\nExamples (first 5):")
    for idx, row in not_spam_high_score.head().iterrows():
        print(f"  Row {idx}: content_spam_score={row['content_spam_score']:.3f}, urls={row['url_count']}, links={row['total_links_detected']}")

# Pattern 2: Very low content_spam_score but labeled Spam
print("\n\nPATTERN 2: Low spam score but labeled Spam")
print("-" * 60)
spam_low_score = training_df[(training_df['Binary_Label'] == 'Spam') & 
                             (training_df['content_spam_score'] < 0.2)]
print(f"Found: {len(spam_low_score)} records")
if len(spam_low_score) > 0:
    print("\nExamples (first 5):")
    for idx, row in spam_low_score.head().iterrows():
        print(f"  Row {idx}: content_spam_score={row['content_spam_score']:.3f}, urls={row['url_count']}, links={row['total_links_detected']}")

# Pattern 3: Extremely high URL counts in Not-Spam
print("\n\nPATTERN 3: Extremely high URLs in Not-Spam")
print("-" * 60)
not_spam_high_urls = training_df[(training_df['Binary_Label'] == 'Not-Spam') & 
                                 (training_df['url_count'] > 50)]
print(f"Found: {len(not_spam_high_urls)} records")
if len(not_spam_high_urls) > 0:
    print("\nExamples (first 5):")
    for idx, row in not_spam_high_urls.head().iterrows():
        print(f"  Row {idx}: urls={row['url_count']}, links={row['total_links_detected']}, content_spam_score={row['content_spam_score']:.3f}")

# Pattern 4: Perfect authentication but labeled Spam
print("\n\nPATTERN 4: Perfect auth (SPF+DMARC pass) but Spam")
print("-" * 60)
spam_good_auth = training_df[(training_df['Binary_Label'] == 'Spam') & 
                             (training_df['spf_result'] == 'pass') & 
                             (training_df['dmarc_result'] == 'pass')]
print(f"Found: {len(spam_good_auth)} records")

# Pattern 5: Failed authentication but labeled Not-Spam
print("\n\nPATTERN 5: Failed auth but Not-Spam")
print("-" * 60)
not_spam_bad_auth = training_df[(training_df['Binary_Label'] == 'Not-Spam') & 
                                ((training_df['spf_result'] == 'fail') | 
                                 (training_df['dmarc_result'] == 'fail'))]
print(f"Found: {len(not_spam_bad_auth)} records")

# Check correlation between content_spam_score and label
print("\n\nCONTENT SPAM SCORE STATISTICS BY LABEL:")
print("-" * 60)
for label in ['Spam', 'Not-Spam']:
    subset = training_df[training_df['Binary_Label'] == label]
    print(f"\n{label}:")
    print(f"  Mean content_spam_score: {subset['content_spam_score'].mean():.3f}")
    print(f"  Std content_spam_score: {subset['content_spam_score'].std():.3f}")
    print(f"  Min: {subset['content_spam_score'].min():.3f}, Max: {subset['content_spam_score'].max():.3f}")

# Find overlap region where both classes exist
print("\n\nOVERLAP ANALYSIS:")
print("-" * 60)
overlap_range = (0.3, 0.7)
overlap_spam = training_df[(training_df['Binary_Label'] == 'Spam') & 
                          (training_df['content_spam_score'] >= overlap_range[0]) & 
                          (training_df['content_spam_score'] <= overlap_range[1])]
overlap_not_spam = training_df[(training_df['Binary_Label'] == 'Not-Spam') & 
                               (training_df['content_spam_score'] >= overlap_range[0]) & 
                               (training_df['content_spam_score'] <= overlap_range[1])]

print(f"In content_spam_score range [{overlap_range[0]}, {overlap_range[1]}]:")
print(f"  Spam: {len(overlap_spam)} records")
print(f"  Not-Spam: {len(overlap_not_spam)} records")

# Save suspicious records
suspicious_records = pd.concat([
    not_spam_high_score.assign(issue='High_Score_NotSpam'),
    spam_low_score.assign(issue='Low_Score_Spam'),
    not_spam_high_urls.assign(issue='High_URLs_NotSpam')
])
suspicious_records.to_csv("suspicious_training_records.csv", index=False)
print(f"\n\nSaved {len(suspicious_records)} suspicious records to: suspicious_training_records.csv")