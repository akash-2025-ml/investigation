#!/usr/bin/env python3
import pandas as pd

# Read the testing file
df = pd.read_csv("final_spam_with_class.csv")

print("ANALYSIS OF MISCLASSIFIED SPAM RECORDS")
print("=" * 80)
print(f"Total records: {len(df)}")
print("Note: ALL records in this file are actually SPAM emails")

# Find misclassified records
misclassified = df[df['final-class'] == 'Not-Spam']
print(f"\nMisclassified as Not-Spam: {len(misclassified)} records ({len(misclassified)/len(df)*100:.1f}%)")

# Analyze content_spam_score distribution
print("\n\nCONTENT_SPAM_SCORE ANALYSIS:")
print("-" * 60)
print("For misclassified (Not-Spam) records:")
print(f"  Mean: {misclassified['content_spam_score'].mean():.3f}")
print(f"  Min: {misclassified['content_spam_score'].min():.3f}")
print(f"  Max: {misclassified['content_spam_score'].max():.3f}")
print(f"  Records with score > 0.5: {len(misclassified[misclassified['content_spam_score'] > 0.5])}")

# Check the 0.5 threshold theory
print("\n\nTHRESHOLD ANALYSIS (content_spam_score = 0.5):")
print("-" * 60)
correctly_spam = df[df['final-class'] == 'Spam']
print(f"Correctly classified as Spam: {len(correctly_spam)}")
print(f"  All have content_spam_score > 0.5: {(correctly_spam['content_spam_score'] > 0.5).all()}")
print(f"  Min content_spam_score: {correctly_spam['content_spam_score'].min():.3f}")

# Find edge cases
edge_case = misclassified[misclassified['content_spam_score'] > 0.5]
if len(edge_case) > 0:
    print("\n\nEDGE CASE: Not-Spam with content_spam_score > 0.5:")
    for idx, row in edge_case.iterrows():
        print(f"  Row {idx+2}: content_spam_score={row['content_spam_score']:.3f}")

# Analyze other patterns in misclassified records
print("\n\nOTHER PATTERNS IN MISCLASSIFIED RECORDS:")
print("-" * 60)

# High URL counts
high_url_misclassified = misclassified[misclassified['url_count'] > 20]
print(f"\nMisclassified with >20 URLs: {len(high_url_misclassified)} records")
for idx, row in high_url_misclassified.iterrows():
    print(f"  Row {idx+2}: {row['url_count']} URLs, content_spam_score={row['content_spam_score']:.3f}")

# Low sender reputation
low_sender_misclassified = misclassified[misclassified['sender_domain_reputation_score'] < 0.4]
print(f"\nMisclassified with low sender reputation (<0.4): {len(low_sender_misclassified)} records")

# Failed authentication
failed_auth = misclassified[(misclassified['spf_result'] == 0) | (misclassified['dmarc_result'] == 0)]
print(f"\nMisclassified with failed SPF/DMARC: {len(failed_auth)} records")

# Group by content_spam_score ranges
print("\n\nCONTENT_SPAM_SCORE DISTRIBUTION:")
print("-" * 60)
ranges = [(0, 0.1), (0.1, 0.2), (0.2, 0.3), (0.3, 0.4), (0.4, 0.5), (0.5, 0.6)]
for low, high in ranges:
    count = len(misclassified[(misclassified['content_spam_score'] >= low) & 
                              (misclassified['content_spam_score'] < high)])
    print(f"  [{low:.1f}, {high:.1f}): {count} records")

# Show some examples of egregious misclassifications
print("\n\nEGREGIOUS MISCLASSIFICATIONS:")
print("-" * 60)
print("\n1. Very high URL counts but low content score:")
url_examples = misclassified.nlargest(5, 'url_count')
for idx, row in url_examples.iterrows():
    print(f"  Row {idx+2}: {row['url_count']} URLs, {row['total_links_detected']} links, "
          f"content_spam_score={row['content_spam_score']:.3f}")

print("\n2. Extremely low content scores (likely sophisticated spam):")
low_score_examples = misclassified.nsmallest(5, 'content_spam_score')
for idx, row in low_score_examples.iterrows():
    print(f"  Row {idx+2}: content_spam_score={row['content_spam_score']:.4f}, "
          f"urls={row['url_count']}, sender_rep={row['sender_domain_reputation_score']:.2f}")

# Summary
print("\n\nSUMMARY:")
print("=" * 60)
print(f"The model is using a simplistic threshold: content_spam_score > 0.5 → Spam")
print(f"This causes {len(misclassified)} real spam emails to be misclassified as Not-Spam")
print(f"Including emails with up to {misclassified['url_count'].max()} URLs!")
print("\nThe model completely ignores:")
print("- URL counts (even 100+ URLs)")
print("- Sender reputation")
print("- Authentication failures")
print("- Other behavioral signals")