#!/usr/bin/env python3
import pandas as pd
import numpy as np
import random

np.random.seed(43)
random.seed(43)

# Load training data
train_df = pd.read_csv('spam_detector_training_data_anchor2_corrected_v2.csv')

print('CREATING 200 NEW NOT-SPAM RECORDS')
print('=' * 60)
print('Pattern: Low content score + High links + Unsubscribe = NOT-SPAM')
print(f'Original training data: {len(train_df)} records')

# Get a template row from Not-Spam records
notspam_template = train_df[train_df['Binary_Label'] == 'Not-Spam'].iloc[0].to_dict()

# SPF and DMARC options
spf_options = ['pass', 'neutral', 'none', 'fail', 'softfail', 'permerror', 'temperror']
dmarc_options = ['pass', 'none', 'fail', 'quarantine', 'reject', 'permerror', 'temperror']

# Generate 200 new records
new_records = []

for i in range(200):
    # Start with template
    record = notspam_template.copy()

    # Set key fields to match the legitimate email pattern
    record['content_spam_score'] = round(random.uniform(0.05, 0.25), 4)  # LOW
    record['sender_domain_reputation_score'] = round(random.uniform(0.0, 0.3), 2)  # LOW (new sender)
    record['return_path_reputation_score'] = round(random.uniform(0.70, 1.0), 2)  # HIGH
    record['marketing_keywords_detected'] = round(random.uniform(0.01, 0.15), 4)  # LOW
    record['total_links_detected'] = random.randint(15, 50)  # HIGH (newsletter style)
    record['url_count'] = random.randint(5, 15)
    record['unsubscribe_link_present'] = 1  # LEGITIMATE marker

    # Vary other fields
    record['spf_result'] = random.choice(spf_options)
    record['dmarc_result'] = random.choice(dmarc_options)
    record['url_reputation_score'] = round(random.uniform(0.5, 0.9), 2)
    record['smtp_ip_reputation_score'] = round(random.uniform(0.0, 0.3), 2)
    record['html_text_ratio'] = round(random.uniform(0.8, 1.0), 2)
    record['user_marked_as_spam_before'] = 0
    record['image_only_email'] = random.choice([0, 0, 0, 1])
    record['bulk_message_indicator'] = random.choice([0, 1])  # Could be bulk but legitimate

    # Ensure it's labeled as Not-Spam
    record['Binary_Label'] = 'Not-Spam'
    record['Final Classification'] = 'No Action'

    new_records.append(record)

# Create DataFrame
new_df = pd.DataFrame(new_records)

print(f'\nCreated {len(new_df)} new records')
print(f'\nStatistics of new records:')
print(f'  content_spam_score: mean={new_df["content_spam_score"].mean():.3f}')
print(f'  sender_domain_rep: mean={new_df["sender_domain_reputation_score"].mean():.3f}')
print(f'  return_path_rep: mean={new_df["return_path_reputation_score"].mean():.3f}')
print(f'  marketing_keywords: mean={new_df["marketing_keywords_detected"].mean():.3f}')
print(f'  total_links_detected: mean={new_df["total_links_detected"].mean():.1f}')
print(f'  unsubscribe_link_present: all={new_df["unsubscribe_link_present"].sum()}')

# Append to training data
combined_df = pd.concat([train_df, new_df], ignore_index=True)

print(f'\nCombined training data: {len(combined_df)} records')
print(f'Class distribution:')
print(combined_df['Binary_Label'].value_counts())

# Save combined data
combined_df.to_csv('spam_detector_training_data_anchor2_corrected_v3.csv', index=False)
print(f'\nSaved to: spam_detector_training_data_anchor2_corrected_v3.csv')

# Show sample of new records
print(f'\nSample of new records (key fields):')
sample_cols = ['content_spam_score', 'sender_domain_reputation_score',
               'return_path_reputation_score', 'total_links_detected',
               'unsubscribe_link_present', 'Binary_Label']
print(new_df[sample_cols].head(10).to_string())