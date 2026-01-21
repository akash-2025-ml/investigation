#!/usr/bin/env python3
import pandas as pd
import numpy as np
import random

np.random.seed(42)
random.seed(42)

# Load training data
train_df = pd.read_csv('spam_detector_training_data_anchor2_corrected.csv')

print('CREATING 200 NEW SPAM RECORDS')
print('=' * 60)
print('Pattern: High content score + High reputation = SPAM')
print(f'Original training data: {len(train_df)} records')

# Get a template row (use mean/mode of existing Spam records)
spam_template = train_df[train_df['Binary_Label'] == 'Spam'].iloc[0].to_dict()

# SPF and DMARC options
spf_options = ['pass', 'neutral', 'none', 'fail', 'softfail', 'permerror', 'temperror']
dmarc_options = ['pass', 'none', 'fail', 'quarantine', 'reject', 'permerror', 'temperror']

# Generate 200 new records
new_records = []

for i in range(200):
    # Start with template
    record = spam_template.copy()

    # Set key fields to match the misclassified pattern
    record['sender_domain_reputation_score'] = round(random.uniform(0.70, 1.0), 2)  # HIGH
    record['return_path_reputation_score'] = round(random.uniform(0.70, 1.0), 2)  # HIGH
    record['content_spam_score'] = round(random.uniform(0.75, 0.99), 4)  # HIGH
    record['marketing-keywords_detected'] = round(random.uniform(0.35, 0.80), 4)  # MODERATE-HIGH

    # Vary other fields
    record['spf_result'] = random.choice(spf_options)
    record['dmarc_result'] = random.choice(dmarc_options)
    record['url_count'] = random.randint(0, 10)
    record['total_links_detected'] = random.randint(0, 10)
    record['url_reputation_score'] = round(random.uniform(0.1, 0.9), 2)
    record['smtp_ip_reputation_score'] = round(random.uniform(0.2, 0.7), 2)
    record['reply_path_reputation_score'] = round(random.uniform(0.5, 1.0), 2)
    record['html_text_ratio'] = round(random.uniform(0.5, 1.0), 2)
    record['user_marked_as_spam_before'] = 0
    record['image_only_email'] = random.choice([0, 0, 0, 1])
    record['bulk_message_indicator'] = random.choice([0, 0, 1])
    record['unsubscribe_link_present'] = random.choice([0, 0, 1])

    # Ensure it's labeled as Spam
    record['Binary_Label'] = 'Spam'
    record['Final Classification'] = 'Spam'

    new_records.append(record)

# Create DataFrame
new_df = pd.DataFrame(new_records)

print(f'\nCreated {len(new_df)} new records')
print(f'\nStatistics of new records:')
print(f'  content_spam_score: mean={new_df["content_spam_score"].mean():.3f}')
print(f'  sender_domain_rep: mean={new_df["sender_domain_reputation_score"].mean():.3f}')
print(f'  return_path_rep: mean={new_df["return_path_reputation_score"].mean():.3f}')
print(f'  marketing_keywords: mean={new_df["marketing-keywords_detected"].mean():.3f}')

# Append to training data
combined_df = pd.concat([train_df, new_df], ignore_index=True)

print(f'\nCombined training data: {len(combined_df)} records')
print(f'Class distribution:')
print(combined_df['Binary_Label'].value_counts())

# Save combined data
combined_df.to_csv('spam_detector_training_data_anchor2_corrected_v2.csv', index=False)
print(f'\nSaved to: spam_detector_training_data_anchor2_corrected_v2.csv')

# Show sample of new records
print(f'\nSample of new records (key fields):')
sample_cols = ['content_spam_score', 'sender_domain_reputation_score',
               'return_path_reputation_score', 'marketing-keywords_detected',
               'spf_result', 'dmarc_result', 'Binary_Label']
print(new_df[sample_cols].head(10).to_string())