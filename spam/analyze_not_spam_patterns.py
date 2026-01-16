#!/usr/bin/env python3
import pandas as pd
import numpy as np

df = pd.read_csv('spam-kaggle-with-label.csv')
not_spam = df[df['final_label'] == 'Not-Spam']

print("NOT-SPAM RECORDS ANALYSIS")
print("=" * 80)
print(f"Total Not-Spam records: {len(not_spam)} out of {len(df)} ({len(not_spam)/len(df)*100:.1f}%)")

# Analyze content_spam_score distribution
print("\n\nCONTENT SPAM SCORE DISTRIBUTION:")
print("-" * 40)
print(f"Mean: {not_spam['content_spam_score'].mean():.3f}")
print(f"Max: {not_spam['content_spam_score'].max():.3f}")
print(f"Min: {not_spam['content_spam_score'].min():.3f}")
print(f"Std: {not_spam['content_spam_score'].std():.3f}")

# Count how many have content_spam_score > 0.5
high_content_score = not_spam[not_spam['content_spam_score'] > 0.5]
print(f"\nNot-Spam with content_spam_score > 0.5: {len(high_content_score)} records")
if len(high_content_score) > 0:
    print("These are:")
    for idx, row in high_content_score.iterrows():
        print(f"  Row {idx+2}: content_spam_score={row['content_spam_score']:.3f}, urls={row['url_count']}")

# Analyze URL patterns
print("\n\nURL PATTERNS IN NOT-SPAM:")
print("-" * 40)
print(f"Mean URL count: {not_spam['url_count'].mean():.1f}")
print(f"Max URL count: {not_spam['url_count'].max()}")
print(f"Records with >20 URLs: {len(not_spam[not_spam['url_count'] > 20])}")

# Show records with extremely high URL counts
high_url = not_spam[not_spam['url_count'] > 50]
if len(high_url) > 0:
    print("\nNot-Spam with >50 URLs:")
    for idx, row in high_url.iterrows():
        print(f"  Row {idx+2}: {row['url_count']} URLs, {row['total_links_detected']} links, content_spam_score={row['content_spam_score']:.3f}")

# Analyze authentication patterns
print("\n\nAUTHENTICATION IN NOT-SPAM:")
print("-" * 40)
print("SPF Results:")
print(not_spam['spf_result'].value_counts().sort_index())
print("\nDMARC Results:")
print(not_spam['dmarc_result'].value_counts().sort_index())

# Find suspicious patterns
print("\n\nSUSPICIOUS NOT-SPAM PATTERNS:")
print("-" * 40)
# Pattern 1: Failed auth + many URLs
sus1 = not_spam[(not_spam['spf_result'] == 0) & (not_spam['url_count'] > 10)]
print(f"Failed SPF + >10 URLs: {len(sus1)} records")

# Pattern 2: Low sender reputation + high URLs
sus2 = not_spam[(not_spam['sender_domain_reputation_score'] < 0.4) & (not_spam['url_count'] > 10)]
print(f"Low sender reputation (<0.4) + >10 URLs: {len(sus2)} records")

# Pattern 3: Zero URL reputation score
sus3 = not_spam[not_spam['url_reputation_score'] == 0]
print(f"Zero URL reputation score: {len(sus3)} records")

print("\n\nKEY OBSERVATIONS:")
print("-" * 60)
print("1. Content spam score threshold (~0.5) is the primary classifier")
print(f"2. {len(not_spam[not_spam['url_count'] > 50])} Not-Spam emails have >50 URLs (highly suspicious)")
print(f"3. {len(not_spam[not_spam['url_count'] == 0])} Not-Spam emails have 0 URLs")
print(f"4. Authentication (SPF/DMARC) seems irrelevant to classification")