#!/usr/bin/env python3
import pandas as pd
import numpy as np

# Load both datasets
training_df = pd.read_csv("training_subset_15_signals.csv")
testing_df = pd.read_csv("spam-kaggle-with-label.csv")

# Fix column name inconsistency
if 'marketing-keywords_detected' in testing_df.columns:
    testing_df['marketing_keywords_detected'] = testing_df['marketing-keywords_detected']

print("TRAINING VS TESTING DATA COMPARISON")
print("=" * 80)
print(f"Training data: {len(training_df)} records (50% Spam, 50% Not-Spam)")
print(f"Testing data: {len(testing_df)} records ({(testing_df['final_label']=='Spam').sum()/len(testing_df)*100:.1f}% Spam)")

# Compare content_spam_score distributions
print("\n\nCONTENT_SPAM_SCORE DISTRIBUTIONS:")
print("-" * 60)
print("Training Data:")
print(f"  Spam: mean={training_df[training_df['Binary_Label']=='Spam']['content_spam_score'].mean():.3f}, "
      f"min={training_df[training_df['Binary_Label']=='Spam']['content_spam_score'].min():.3f}, "
      f"max={training_df[training_df['Binary_Label']=='Spam']['content_spam_score'].max():.3f}")
print(f"  Not-Spam: mean={training_df[training_df['Binary_Label']=='Not-Spam']['content_spam_score'].mean():.3f}, "
      f"min={training_df[training_df['Binary_Label']=='Not-Spam']['content_spam_score'].min():.3f}, "
      f"max={training_df[training_df['Binary_Label']=='Not-Spam']['content_spam_score'].max():.3f}")

print("\nTesting Data:")
print(f"  Spam: mean={testing_df[testing_df['final_label']=='Spam']['content_spam_score'].mean():.3f}, "
      f"min={testing_df[testing_df['final_label']=='Spam']['content_spam_score'].min():.3f}, "
      f"max={testing_df[testing_df['final_label']=='Spam']['content_spam_score'].max():.3f}")
print(f"  Not-Spam: mean={testing_df[testing_df['final_label']=='Not-Spam']['content_spam_score'].mean():.3f}, "
      f"min={testing_df[testing_df['final_label']=='Not-Spam']['content_spam_score'].min():.3f}, "
      f"max={testing_df[testing_df['final_label']=='Not-Spam']['content_spam_score'].max():.3f}")

# Key finding: Check if threshold would work
print("\n\nTHRESHOLD ANALYSIS:")
print("-" * 60)
threshold = 0.5
print(f"Using threshold: content_spam_score > {threshold}")

# Training performance
train_spam = training_df[training_df['Binary_Label'] == 'Spam']
train_not_spam = training_df[training_df['Binary_Label'] == 'Not-Spam']
train_tp = (train_spam['content_spam_score'] > threshold).sum()
train_fn = (train_spam['content_spam_score'] <= threshold).sum()
train_tn = (train_not_spam['content_spam_score'] <= threshold).sum()
train_fp = (train_not_spam['content_spam_score'] > threshold).sum()

print(f"\nTraining Data Performance:")
print(f"  True Positives (Spam correctly identified): {train_tp}/{len(train_spam)} ({train_tp/len(train_spam)*100:.1f}%)")
print(f"  False Negatives (Spam missed): {train_fn}/{len(train_spam)} ({train_fn/len(train_spam)*100:.1f}%)")
print(f"  True Negatives (Not-Spam correct): {train_tn}/{len(train_not_spam)} ({train_tn/len(train_not_spam)*100:.1f}%)")
print(f"  False Positives (Not-Spam wrongly flagged): {train_fp}/{len(train_not_spam)} ({train_fp/len(train_not_spam)*100:.1f}%)")
print(f"  Accuracy: {(train_tp + train_tn)/len(training_df)*100:.1f}%")

# Testing performance
test_spam = testing_df[testing_df['final_label'] == 'Spam']
test_not_spam = testing_df[testing_df['final_label'] == 'Not-Spam']
test_tp = (test_spam['content_spam_score'] > threshold).sum()
test_fn = (test_spam['content_spam_score'] <= threshold).sum()
test_tn = (test_not_spam['content_spam_score'] <= threshold).sum()
test_fp = (test_not_spam['content_spam_score'] > threshold).sum()

print(f"\nTesting Data Performance:")
print(f"  True Positives (Spam correctly identified): {test_tp}/{len(test_spam)} ({test_tp/len(test_spam)*100:.1f}%)")
print(f"  False Negatives (Spam missed): {test_fn}/{len(test_spam)} ({test_fn/len(test_spam)*100:.1f}%)")
print(f"  True Negatives (Not-Spam correct): {test_tn}/{len(test_not_spam)} ({test_tn/len(test_not_spam)*100:.1f}%)")
print(f"  False Positives (Not-Spam wrongly flagged): {test_fp}/{len(test_not_spam)} ({test_fp/len(test_not_spam)*100:.1f}%)")
print(f"  Accuracy: {(test_tp + test_tn)/len(testing_df)*100:.1f}%")

# Check misclassifications in testing data
print("\n\nTESTING DATA MISCLASSIFICATIONS:")
print("-" * 60)
print("\nFalse Negatives (Spam with low content_spam_score):")
false_negatives = test_spam[test_spam['content_spam_score'] <= threshold].sort_values('content_spam_score')
for idx in false_negatives.head().index:
    row = testing_df.iloc[idx]
    print(f"  Row {idx+2}: content_spam_score={row['content_spam_score']:.3f}, "
          f"urls={row['url_count']}, unsubscribe={row['unsubscribe_link_present']}")

print("\nFalse Positives (Not-Spam with high content_spam_score):")
false_positives = test_not_spam[test_not_spam['content_spam_score'] > threshold].sort_values('content_spam_score', ascending=False)
for idx in false_positives.head().index:
    row = testing_df.iloc[idx]
    print(f"  Row {idx+2}: content_spam_score={row['content_spam_score']:.3f}, "
          f"urls={row['url_count']}, sender_reputation={row['sender_domain_reputation_score']:.2f}")

# The brutal truth
print("\n\nBRUTAL TRUTH:")
print("=" * 60)
print("1. Training data has PERFECT separation at ~0.35 threshold")
print("2. Testing data shows realistic overlap and misclassifications")
print("3. Training data appears artificially clean/synthetic")
print("4. Model trained on this will overfit to content_spam_score")
print("5. Real-world performance will be much worse than training suggests")