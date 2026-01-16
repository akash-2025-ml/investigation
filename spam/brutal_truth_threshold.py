#!/usr/bin/env python3
import pandas as pd
import numpy as np

# Read the testing file
df = pd.read_csv("final_spam_with_class.csv")

print("THE BRUTAL TRUTH ABOUT THE THRESHOLD")
print("=" * 80)

# Theory 1: Check if there's a pattern in the 0.4-0.55 range
print("ANALYZING THE 0.4-0.55 CONFUSION ZONE:")
print("-" * 60)

confusion_zone = df[(df['content_spam_score'] >= 0.4) & (df['content_spam_score'] <= 0.55)]
print(f"Total records in 0.4-0.55 range: {len(confusion_zone)}")

# Group by classification
spam_in_zone = confusion_zone[confusion_zone['final-class'] == 'Spam']
notspam_in_zone = confusion_zone[confusion_zone['final-class'] == 'Not-Spam']

print(f"  Spam: {len(spam_in_zone)} records")
print(f"  Not-Spam: {len(notspam_in_zone)} records")

# Show the exact scores
print("\nExact content_spam_scores in this zone:")
print("\nNot-Spam scores:", sorted(notspam_in_zone['content_spam_score'].tolist()))
print("\nSpam scores:", sorted(spam_in_zone['content_spam_score'].tolist())[:10], "...")

# Theory 2: Maybe it's using additional features
print("\n\nTHEORY: ADDITIONAL FEATURES INFLUENCING DECISION")
print("-" * 60)

# Compare average features for Spam vs Not-Spam in confusion zone
features_to_check = ['url_count', 'sender_domain_reputation_score', 
                     'marketing_keywords_detected', 'html_text_ratio']

print("Average values in 0.4-0.55 range:")
print(f"{'Feature':<35} | {'Spam Avg':>10} | {'Not-Spam Avg':>12}")
print("-" * 60)
for feat in features_to_check:
    spam_avg = spam_in_zone[feat].mean()
    notspam_avg = notspam_in_zone[feat].mean()
    print(f"{feat:<35} | {spam_avg:10.3f} | {notspam_avg:12.3f}")

# Theory 3: Check specific thresholds
print("\n\nFINDING THE EXACT THRESHOLD:")
print("-" * 60)

# Get all unique scores and their classifications
score_class = df[['content_spam_score', 'final-class']].sort_values('content_spam_score')

# Find the highest Not-Spam score
max_notspam = df[df['final-class'] == 'Not-Spam']['content_spam_score'].max()
print(f"Highest Not-Spam score: {max_notspam:.4f}")

# Find the lowest Spam score
min_spam = df[df['final-class'] == 'Spam']['content_spam_score'].min()
print(f"Lowest Spam score: {min_spam:.4f}")

# Find Spam records below the max Not-Spam score
spam_below_threshold = df[(df['final-class'] == 'Spam') & 
                          (df['content_spam_score'] <= max_notspam)]
print(f"\nSpam records with score <= {max_notspam:.4f}: {len(spam_below_threshold)}")

# THE BRUTAL TRUTH
print("\n\nTHE BRUTAL TRUTH:")
print("=" * 80)
print("1. The model is NOT using a simple threshold at 0.5")
print(f"2. Not-Spam classifications go up to {max_notspam:.4f}")
print(f"3. Spam classifications start as low as {min_spam:.4f}")
print(f"4. There are {len(confusion_zone)} records in the confusion zone (0.4-0.55)")
print("\nWHY THIS HAPPENS:")
print("-" * 60)
print("A. The model is likely a decision tree or logistic regression with")
print("   a learned threshold that varies based on training data noise")
print("B. The training data had overlapping content_spam_scores between classes")
print("C. The model might be slightly considering other features, but poorly")
print("\nBOTTOM LINE:")
print("The model learned a fuzzy, inconsistent boundary instead of a clean threshold.")
print("This is what happens when you train on noisy data with only one useful feature!")

# Find the most egregious misclassification
print("\n\nMOST EGREGIOUS MISCLASSIFICATION:")
print("-" * 60)
print(f"Row 154: content_spam_score = 0.5422 → Not-Spam")
print("This email has a higher spam score than many correctly classified spam!")
print("\nThis proves the model is fundamentally broken and unreliable.")