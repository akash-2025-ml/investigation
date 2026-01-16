#!/usr/bin/env python3
import pandas as pd

# Read the testing file
df = pd.read_csv("final_spam_with_class.csv")

print("VISUALIZATION: THE BROKEN THRESHOLD")
print("=" * 80)

# Create a visual representation of the threshold chaos
print("\nCONTENT_SPAM_SCORE DISTRIBUTION (0.0 to 1.0):")
print("-" * 80)

# Create bins
bins = [(i/20, (i+1)/20) for i in range(20)]

for low, high in bins:
    # Count records in this bin
    bin_records = df[(df['content_spam_score'] >= low) & (df['content_spam_score'] < high)]
    spam_count = len(bin_records[bin_records['final-class'] == 'Spam'])
    notspam_count = len(bin_records[bin_records['final-class'] == 'Not-Spam'])
    
    # Create visual bar
    spam_bar = '█' * spam_count
    notspam_bar = '░' * notspam_count
    
    print(f"{low:4.2f}-{high:4.2f} | S:{spam_bar:<20} | NS:{notspam_bar:<20} | S:{spam_count:3d} NS:{notspam_count:3d}")

print("\n" + "=" * 80)
print("LEGEND: █ = Spam (should be all above 0.5)  ░ = Not-Spam (should be all below 0.5)")

print("\n\nTHE CHAOS ZONE (0.40-0.55):")
print("-" * 80)
chaos_zone = df[(df['content_spam_score'] >= 0.40) & (df['content_spam_score'] <= 0.55)]
chaos_zone_sorted = chaos_zone.sort_values('content_spam_score')

print("Score   | Class    | URLs | Comment")
print("-" * 60)
for idx, row in chaos_zone_sorted.iterrows():
    comment = ""
    if row['content_spam_score'] > 0.5 and row['final-class'] == 'Not-Spam':
        comment = "← ABOVE 0.5 BUT NOT-SPAM! 🚨"
    elif row['url_count'] > 30:
        comment = f"← {row['url_count']} URLs!"
    
    print(f"{row['content_spam_score']:.4f} | {row['final-class']:8s} | {row['url_count']:4d} | {comment}")

print("\n\nTHE VERDICT:")
print("=" * 80)
print("If this was a proper threshold at 0.5:")
print("- ALL scores > 0.5 would be Spam")
print("- ALL scores < 0.5 would be Not-Spam")
print("\nBut instead we have:")
print("- Not-Spam with score 0.5422 (Row 154)")
print("- Spam with score 0.0534 (Row 147)")
print("- Complete chaos in the 0.4-0.55 range")
print("\nThis is not a threshold. This is machine learning malpractice.")