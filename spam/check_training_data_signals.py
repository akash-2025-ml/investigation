#!/usr/bin/env python3
import pandas as pd

# Read training data
training_df = pd.read_csv("spam_detector_training_data.csv")

print("TRAINING DATA ANALYSIS")
print("=" * 80)
print(f"Total records: {len(training_df)}")
print(f"Columns: {len(training_df.columns)}")

# Define the 15 signals used for training
training_signals = [
    'spf_result', 'dmarc_result', 'user_marked_as_spam_before', 'image_only_email',
    'url_count', 'url_reputation_score', 'total_links_detected', 'sender_domain_reputation_score',
    'smtp_ip_reputation_score', 'return_path_reputation_score', 'content_spam_score',
    'marketing-keywords_detected', 'bulk_message_indicator', 'unsubscribe_link_present', 'html_text_ratio'
]

# Check which signals are actually in the training data
print("\n\nCHECKING FOR 15 TRAINING SIGNALS:")
print("-" * 60)
available_signals = []
missing_signals = []

for signal in training_signals:
    if signal in training_df.columns:
        available_signals.append(signal)
        print(f"✓ {signal}: FOUND")
    else:
        missing_signals.append(signal)
        print(f"✗ {signal}: NOT FOUND")

print(f"\nFound: {len(available_signals)}/{len(training_signals)} signals")

# Check for similar column names (typos)
if missing_signals:
    print("\n\nSEARCHING FOR SIMILAR COLUMNS:")
    print("-" * 40)
    for missing in missing_signals:
        similar = [col for col in training_df.columns if missing.replace('-', '_') in col or missing.replace('_', '-') in col]
        if similar:
            print(f"{missing} -> Similar found: {similar}")

# Analyze Binary_Label distribution
if 'Binary_Label' in training_df.columns:
    print("\n\nCLASS DISTRIBUTION:")
    print("-" * 40)
    print(training_df['Binary_Label'].value_counts())
    print(f"\nClass balance: {training_df['Binary_Label'].value_counts(normalize=True).to_dict()}")

# Show all available columns
print("\n\nALL AVAILABLE COLUMNS IN TRAINING DATA:")
print("-" * 60)
for i, col in enumerate(training_df.columns):
    print(f"{i+1:3}. {col}")

# Extract and analyze the subset of data with our 15 signals
print("\n\nEXTRACTING AVAILABLE TRAINING SIGNALS:")
print("-" * 60)
training_subset = training_df[available_signals + ['Binary_Label']] if 'Binary_Label' in training_df.columns else training_df[available_signals]
print(f"Shape of training subset: {training_subset.shape}")

# Save the subset for analysis
training_subset.to_csv("training_subset_15_signals.csv", index=False)
print("\nSaved subset to: training_subset_15_signals.csv")