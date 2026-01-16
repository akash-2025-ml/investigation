#!/usr/bin/env python3
import pandas as pd
import numpy as np

# Load the full training data
print("CORRECTING EDGE CASE SPAM RECORDS")
print("=" * 80)

# Load original training data with all columns
full_training = pd.read_csv("spam_detector_training_data.csv")
print(f"Original training data shape: {full_training.shape}")
print(f"Original class distribution:")
print(full_training['Binary_Label'].value_counts())

# Find Spam records with content_spam_score between 0.25 and 0.35
edge_case_spam = full_training[
    (full_training['Binary_Label'] == 'Spam') & 
    (full_training['content_spam_score'] > 0.25) & 
    (full_training['content_spam_score'] < 0.35)
]

print(f"\nFound {len(edge_case_spam)} Spam records with content_spam_score between 0.25 and 0.35")

# Check if we have at least 300 records to correct
if len(edge_case_spam) < 300:
    print(f"WARNING: Only {len(edge_case_spam)} records available, will correct all of them")
    records_to_correct = len(edge_case_spam)
else:
    records_to_correct = 300

# Select records to correct (random sampling for fairness)
np.random.seed(42)  # For reproducibility
indices_to_correct = edge_case_spam.sample(n=min(records_to_correct, len(edge_case_spam))).index

# Create a copy of the data
corrected_training = full_training.copy()

# Correct the labels
corrected_training.loc[indices_to_correct, 'Binary_Label'] = 'Not-Spam'
corrected_training.loc[indices_to_correct, 'Final Classification'] = 'No Action'

print(f"\nCorrected {len(indices_to_correct)} records from Spam to Not-Spam")

# Show some examples of corrected records
print("\nExamples of corrected records:")
corrected_examples = corrected_training.loc[indices_to_correct].head(10)
for idx in corrected_examples.index:
    row = corrected_training.loc[idx]
    print(f"  Index {idx}: content_spam_score={row['content_spam_score']:.3f}, "
          f"urls={row['url_count']}, sender_rep={row['sender_domain_reputation_score']:.2f}")

# Verify the correction
print("\n\nVERIFICATION:")
print("-" * 60)
print("New class distribution:")
print(corrected_training['Binary_Label'].value_counts())

# Check the content_spam_score distribution for both classes
print("\nContent spam score statistics after correction:")
for label in ['Spam', 'Not-Spam']:
    subset = corrected_training[corrected_training['Binary_Label'] == label]
    print(f"\n{label}:")
    print(f"  Mean: {subset['content_spam_score'].mean():.3f}")
    print(f"  Min: {subset['content_spam_score'].min():.3f}")
    print(f"  Max: {subset['content_spam_score'].max():.3f}")
    print(f"  Records with score 0.25-0.35: {len(subset[(subset['content_spam_score'] > 0.25) & (subset['content_spam_score'] < 0.35)])}")

# Save the corrected data
corrected_training.to_csv("spam_detector_training_data_corrected.csv", index=False)
print("\n\nSaved corrected training data to: spam_detector_training_data_corrected.csv")

# Also save just the 15 signals subset
training_signals = [
    'spf_result', 'dmarc_result', 'user_marked_as_spam_before', 'image_only_email',
    'url_count', 'url_reputation_score', 'total_links_detected', 'sender_domain_reputation_score',
    'smtp_ip_reputation_score', 'return_path_reputation_score', 'content_spam_score',
    'marketing-keywords_detected', 'bulk_message_indicator', 'unsubscribe_link_present', 'html_text_ratio'
]
corrected_subset = corrected_training[training_signals + ['Binary_Label']]
corrected_subset.to_csv("training_subset_15_signals_corrected.csv", index=False)
print("Saved corrected 15-signal subset to: training_subset_15_signals_corrected.csv")

print("\n\nIMPACT ANALYSIS:")
print("-" * 60)
print("This correction creates more realistic overlap between Spam and Not-Spam")
print("in the 0.25-0.35 content_spam_score range, similar to real-world data.")