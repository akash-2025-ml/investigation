#!/usr/bin/env python3
import pandas as pd

# Read the testing file
df = pd.read_csv("final_spam_with_class.csv")

print("INVESTIGATING THE REAL THRESHOLD ISSUE")
print("=" * 80)

# Find all records with content_spam_score > 0.4
above_04 = df[df['content_spam_score'] > 0.4]
print(f"Total records with content_spam_score > 0.4: {len(above_04)}")

# Break down by classification
above_04_spam = above_04[above_04['final-class'] == 'Spam']
above_04_notspam = above_04[above_04['final-class'] == 'Not-Spam']

print(f"  Classified as Spam: {len(above_04_spam)}")
print(f"  Classified as Not-Spam: {len(above_04_notspam)}")

# Show the Not-Spam ones
print("\n\nRECORDS WITH SCORE > 0.4 BUT CLASSIFIED AS NOT-SPAM:")
print("-" * 80)
print("Row# | Content Score | URLs | Links | Sender Rep | Classification")
print("-" * 80)

for idx, row in above_04_notspam.sort_values('content_spam_score').iterrows():
    print(f"{idx+2:3d} | {row['content_spam_score']:6.4f} | {row['url_count']:4d} | "
          f"{row['total_links_detected']:4d} | {row['sender_domain_reputation_score']:4.2f} | "
          f"{row['final-class']}")

# Find the actual threshold by checking boundaries
print("\n\nFINDING THE ACTUAL THRESHOLD:")
print("-" * 80)

# Get all scores and sort them
all_scores = df['content_spam_score'].sort_values()

# Find the boundary between Spam and Not-Spam
min_spam_score = df[df['final-class'] == 'Spam']['content_spam_score'].min()
max_notspam_score = df[df['final-class'] == 'Not-Spam']['content_spam_score'].max()

print(f"Minimum content_spam_score for Spam: {min_spam_score:.4f}")
print(f"Maximum content_spam_score for Not-Spam: {max_notspam_score:.4f}")

if max_notspam_score > min_spam_score:
    print(f"\n⚠️  OVERLAP DETECTED! Not-Spam scores go up to {max_notspam_score:.4f}")
    print(f"   while Spam scores start at {min_spam_score:.4f}")
    
    # Find records in the overlap zone
    overlap_zone = df[(df['content_spam_score'] >= min_spam_score) & 
                      (df['content_spam_score'] <= max_notspam_score)]
    
    print(f"\nRecords in overlap zone ({min_spam_score:.4f} - {max_notspam_score:.4f}): {len(overlap_zone)}")
    
    # Show them
    print("\nOVERLAP ZONE RECORDS:")
    print("Row# | Score  | Class     | URLs | Other Key Features")
    print("-" * 70)
    for idx, row in overlap_zone.sort_values('content_spam_score').iterrows():
        other_features = []
        if row['url_count'] > 20:
            other_features.append(f"HIGH URLs({row['url_count']})")
        if row['sender_domain_reputation_score'] < 0.4:
            other_features.append("LOW sender_rep")
        if row['url_reputation_score'] == 0:
            other_features.append("ZERO url_rep")
        
        print(f"{idx+2:3d} | {row['content_spam_score']:.4f} | {row['final-class']:9s} | "
              f"{row['url_count']:4d} | {', '.join(other_features) if other_features else 'None'}")

# Check for patterns in edge cases
print("\n\nANALYZING THE EDGE CASE (Row 154):")
print("-" * 80)
edge_case = df.iloc[152]  # Row 154, 0-indexed as 152
print(f"Content spam score: {edge_case['content_spam_score']}")
print(f"Classification: {edge_case['final-class']}")
print(f"\nAll features for Row 154:")
for col in df.columns[:-1]:  # Exclude final-class
    print(f"  {col}: {edge_case[col]}")

# Theory: Maybe it's using a different threshold or combination
print("\n\nPOSSIBLE EXPLANATIONS:")
print("-" * 80)
print("1. The threshold is NOT exactly 0.5 (maybe 0.543?)")
print("2. The model uses additional logic beyond simple threshold")
print("3. There's a bug in the model or data pipeline")
print("4. The training data had similar edge cases that confused the model")
print("\nMost likely: The model learned a slightly fuzzy boundary around 0.5")
print("due to imperfect training data separation.")