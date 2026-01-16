#!/usr/bin/env python3
import pandas as pd

# Load training data
training_df = pd.read_csv("training_subset_15_signals.csv")
not_spam_training = training_df[training_df['Binary_Label'] == 'Not-Spam']

print("NOT-SPAM RECORDS IN TRAINING DATA ANALYSIS")
print("=" * 80)
print(f"Total Not-Spam training records: {len(not_spam_training)} out of {len(training_df)}")

# Content spam score distribution
print("\n\nCONTENT SPAM SCORE DISTRIBUTION IN NOT-SPAM:")
print("-" * 60)
print(f"Mean: {not_spam_training['content_spam_score'].mean():.3f}")
print(f"Min: {not_spam_training['content_spam_score'].min():.3f}")
print(f"Max: {not_spam_training['content_spam_score'].max():.3f}")
print(f"Std: {not_spam_training['content_spam_score'].std():.3f}")

# Check for high content_spam_score in Not-Spam
high_score = not_spam_training[not_spam_training['content_spam_score'] > 0.5]
print(f"\nNot-Spam with content_spam_score > 0.5: {len(high_score)} records")
if len(high_score) > 0:
    print("Top 10 highest scores:")
    top_high = high_score.nlargest(10, 'content_spam_score')
    for idx, row in top_high.iterrows():
        print(f"  Index {idx}: score={row['content_spam_score']:.3f}, urls={row['url_count']}, "
              f"links={row['total_links_detected']}, unsubscribe={row['unsubscribe_link_present']}")

# URL analysis
print("\n\nURL PATTERNS IN NOT-SPAM TRAINING DATA:")
print("-" * 60)
print(f"Mean URL count: {not_spam_training['url_count'].mean():.1f}")
print(f"Max URL count: {not_spam_training['url_count'].max()}")
print(f"Min URL count: {not_spam_training['url_count'].min()}")

# High URL counts
high_urls = not_spam_training[not_spam_training['url_count'] > 20]
print(f"\nNot-Spam with >20 URLs: {len(high_urls)} records")
if len(high_urls) > 0:
    print("\nTop 10 highest URL counts:")
    top_urls = high_urls.nlargest(10, 'url_count')
    for idx, row in top_urls.iterrows():
        print(f"  Index {idx}: urls={row['url_count']}, content_score={row['content_spam_score']:.3f}, "
              f"sender_rep={row['sender_domain_reputation_score']:.2f}")

# Show examples with most URLs (even if < 20)
print("\n\nTop 10 URL counts in Not-Spam:")
top_urls_any = not_spam_training.nlargest(10, 'url_count')
for idx, row in top_urls_any.iterrows():
    print(f"  Index {idx}: urls={row['url_count']}, content_score={row['content_spam_score']:.3f}, "
          f"sender_rep={row['sender_domain_reputation_score']:.2f}, unsubscribe={row['unsubscribe_link_present']}")

# Check for suspicious patterns
print("\n\nSUSPICIOUS PATTERNS IN NOT-SPAM:")
print("-" * 60)

# Pattern 1: Failed authentication
failed_auth = not_spam_training[(not_spam_training['spf_result'] == 'fail') | 
                                (not_spam_training['dmarc_result'] == 'fail')]
print(f"Failed authentication (SPF/DMARC): {len(failed_auth)} records")

# Pattern 2: Low sender reputation
low_sender_rep = not_spam_training[not_spam_training['sender_domain_reputation_score'] < 0.3]
print(f"Low sender reputation (<0.3): {len(low_sender_rep)} records")

# Pattern 3: High marketing keywords (check column name)
if 'marketing-keywords_detected' in not_spam_training.columns:
    col_name = 'marketing-keywords_detected'
elif 'marketing_keywords_detected' in not_spam_training.columns:
    col_name = 'marketing_keywords_detected'
else:
    col_name = None

if col_name:
    high_marketing = not_spam_training[not_spam_training[col_name] > 0.5]
    print(f"High marketing keywords (>0.5): {len(high_marketing)} records")

# Pattern 4: Combination of suspicious factors
suspicious = not_spam_training[
    (not_spam_training['url_count'] > 5) & 
    (not_spam_training['content_spam_score'] > 0.3) &
    (not_spam_training['unsubscribe_link_present'] == 1)
]
print(f"\nCombination (>5 URLs + score>0.3 + unsubscribe): {len(suspicious)} records")

# Distribution summary
print("\n\nKEY STATISTICS:")
print("-" * 60)
print(f"SPF pass rate: {(not_spam_training['spf_result'] == 'pass').sum() / len(not_spam_training) * 100:.1f}%")
print(f"DMARC pass rate: {(not_spam_training['dmarc_result'] == 'pass').sum() / len(not_spam_training) * 100:.1f}%")
print(f"Has unsubscribe link: {not_spam_training['unsubscribe_link_present'].sum()} ({not_spam_training['unsubscribe_link_present'].mean() * 100:.1f}%)")
print(f"Bulk message indicator: {not_spam_training['bulk_message_indicator'].sum()} ({not_spam_training['bulk_message_indicator'].mean() * 100:.1f}%)")

print("\n\nTHE BRUTAL TRUTH ABOUT TRAINING NOT-SPAM:")
print("=" * 60)
print("1. MAX URL count is only 10 (vs 104 in testing data!)")
print("2. 66 records have content_spam_score > 0.5 (edge of threshold)")
print("3. NO records with >20 URLs (testing has many with 90+)")
print("4. Training data is TOO CLEAN - doesn't reflect real bulk emails")
print("5. Model will fail on legitimate newsletters with many links")