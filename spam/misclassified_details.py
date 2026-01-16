#!/usr/bin/env python3
import pandas as pd

# Read the testing file
df = pd.read_csv("final_spam_with_class.csv")

# Find misclassified records
misclassified = df[df['final-class'] == 'Not-Spam']

print("DETAILED VIEW OF ALL 55 MISCLASSIFIED SPAM EMAILS")
print("=" * 80)
print("Format: Row# | Content Score | URLs | Sender Rep | SPF | DMARC | Key Issue")
print("-" * 80)

# Sort by content_spam_score to show pattern
misclassified_sorted = misclassified.sort_values('content_spam_score')

for idx, row in misclassified_sorted.iterrows():
    # Determine key issue
    if row['url_count'] > 50:
        key_issue = f"MASSIVE URLs ({row['url_count']})"
    elif row['url_count'] > 20:
        key_issue = f"High URLs ({row['url_count']})"
    elif row['content_spam_score'] < 0.05:
        key_issue = "ULTRA-LOW score (sophisticated)"
    elif row['sender_domain_reputation_score'] < 0.4:
        key_issue = "Low sender reputation"
    elif row['spf_result'] == 0 or row['dmarc_result'] == 0:
        key_issue = "Failed authentication"
    else:
        key_issue = "Low content score"
    
    print(f"Row {idx+2:3d} | {row['content_spam_score']:6.4f} | {row['url_count']:4d} | "
          f"{row['sender_domain_reputation_score']:4.2f} | {row['spf_result']} | "
          f"{row['dmarc_result']} | {key_issue}")

print("\n" + "=" * 80)
print("SUMMARY STATISTICS:")
print(f"- Average content_spam_score: {misclassified['content_spam_score'].mean():.3f}")
print(f"- Average URL count: {misclassified['url_count'].mean():.1f}")
print(f"- Records with 0 URLs: {len(misclassified[misclassified['url_count'] == 0])}")
print(f"- Records with >20 URLs: {len(misclassified[misclassified['url_count'] > 20])}")
print(f"- Records with score <0.1: {len(misclassified[misclassified['content_spam_score'] < 0.1])}")

# Check for the specific testing rows mentioned by user (209, 104, 83)
print("\n" + "=" * 80)
print("CHECKING SPECIFIC ROWS MENTIONED BY USER:")
test_rows = [209, 104, 83]
for row_num in test_rows:
    if row_num <= len(df):
        row = df.iloc[row_num-1]  # Convert to 0-index
        print(f"\nRow {row_num}:")
        print(f"  Content spam score: {row['content_spam_score']:.3f}")
        print(f"  URL count: {row['url_count']}")
        print(f"  Classification: {row['final-class']}")
        print(f"  Status: {'✓ Correctly classified as Spam' if row['final-class'] == 'Spam' else '✗ MISCLASSIFIED as Not-Spam'}")