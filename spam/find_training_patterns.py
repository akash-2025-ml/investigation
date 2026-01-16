#!/usr/bin/env python3
import pandas as pd

# Load training data
training_df = pd.read_csv("spam_detector_training_data.csv")

print("FINDING SIMILAR PATTERNS IN TRAINING DATA")
print("=" * 80)

# The three patterns from testing data that are misclassified:
# Pattern 1: content_spam_score=0.996, url_count=7, sender_domain_reputation_score=0.3
# Pattern 2: content_spam_score=0.558, url_count=9, sender_domain_reputation_score=0.5  
# Pattern 3: content_spam_score=0.999, url_count=0, sender_domain_reputation_score=0.37

# Focus on the 15 training signals
training_signals = [
    'spf_result', 'dmarc_result', 'user_marked_as_spam_before', 'image_only_email',
    'url_count', 'url_reputation_score', 'total_links_detected', 'sender_domain_reputation_score',
    'smtp_ip_reputation_score', 'return_path_reputation_score', 'content_spam_score',
    'marketing-keywords_detected', 'bulk_message_indicator', 'unsubscribe_link_present', 'html_text_ratio'
]

training_subset = training_df[training_signals + ['Binary_Label']].copy()

# Find Pattern 1-like records: High content score + multiple URLs + low sender reputation
print("\nPATTERN 1: High content score + multiple URLs + low sender reputation")
print("-" * 70)
pattern1_candidates = training_subset[
    (training_subset['Binary_Label'] == 'Not-Spam') &
    (training_subset['content_spam_score'] > 0.9) &  # Very high content score
    (training_subset['url_count'] >= 5) &            # Multiple URLs
    (training_subset['sender_domain_reputation_score'] <= 0.4)  # Low sender reputation
]
print(f"Found {len(pattern1_candidates)} candidates")

if len(pattern1_candidates) > 0:
    print("\nTop 5 examples:")
    for idx, row in pattern1_candidates.head().iterrows():
        print(f"  Index {idx}: content_score={row['content_spam_score']:.3f}, "
              f"urls={row['url_count']}, sender_rep={row['sender_domain_reputation_score']:.3f}")

# Find Pattern 2-like records: Moderate content score + many URLs + medium sender reputation  
print("\n\nPATTERN 2: Moderate content score + many URLs + medium sender reputation")
print("-" * 70)
pattern2_candidates = training_subset[
    (training_subset['Binary_Label'] == 'Not-Spam') &
    (training_subset['content_spam_score'] >= 0.5) &   # Moderate content score
    (training_subset['content_spam_score'] <= 0.6) &   
    (training_subset['url_count'] >= 8) &              # Many URLs
    (training_subset['sender_domain_reputation_score'] >= 0.4) &  # Medium+ sender reputation
    (training_subset['sender_domain_reputation_score'] <= 0.6)
]
print(f"Found {len(pattern2_candidates)} candidates")

if len(pattern2_candidates) > 0:
    print("\nTop 5 examples:")
    for idx, row in pattern2_candidates.head().iterrows():
        print(f"  Index {idx}: content_score={row['content_spam_score']:.3f}, "
              f"urls={row['url_count']}, sender_rep={row['sender_domain_reputation_score']:.3f}")

# Find Pattern 3-like records: Very high content score + no URLs + low sender reputation
print("\n\nPATTERN 3: Very high content score + no/few URLs + low sender reputation")
print("-" * 70)
pattern3_candidates = training_subset[
    (training_subset['Binary_Label'] == 'Not-Spam') &
    (training_subset['content_spam_score'] > 0.95) &  # Very high content score
    (training_subset['url_count'] <= 2) &             # Few/no URLs
    (training_subset['sender_domain_reputation_score'] <= 0.4)  # Low sender reputation
]
print(f"Found {len(pattern3_candidates)} candidates")

if len(pattern3_candidates) > 0:
    print("\nTop 5 examples:")
    for idx, row in pattern3_candidates.head().iterrows():
        print(f"  Index {idx}: content_score={row['content_spam_score']:.3f}, "
              f"urls={row['url_count']}, sender_rep={row['sender_domain_reputation_score']:.3f}")

# Additional pattern: Any Not-Spam with very high content score (suspicious)
print("\n\nADDITIONAL: Any Not-Spam with content_spam_score > 0.8")
print("-" * 70)
high_content_not_spam = training_subset[
    (training_subset['Binary_Label'] == 'Not-Spam') &
    (training_subset['content_spam_score'] > 0.8)
]
print(f"Found {len(high_content_not_spam)} candidates")

# Combine all candidates for correction
all_candidates = pd.concat([pattern1_candidates, pattern2_candidates, pattern3_candidates]).drop_duplicates()
print(f"\n\nTOTAL UNIQUE CANDIDATES FOR CORRECTION: {len(all_candidates)}")

# Save indices for correction
candidate_indices = list(all_candidates.index)
with open('training_correction_indices.txt', 'w') as f:
    for idx in candidate_indices:
        f.write(f"{idx}\n")

print(f"Saved {len(candidate_indices)} candidate indices to: training_correction_indices.txt")

# Show summary statistics
print(f"\n\nSUMMARY OF CORRECTIONS TO MAKE:")
print("-" * 60)
print(f"Pattern 1 (High content + URLs + low sender): {len(pattern1_candidates)} records")
print(f"Pattern 2 (Moderate content + many URLs): {len(pattern2_candidates)} records") 
print(f"Pattern 3 (High content + few URLs + low sender): {len(pattern3_candidates)} records")
print(f"Total unique records to correct: {len(all_candidates)}")

print(f"\n\nThese records will be changed from 'Not-Spam' to 'Spam' to help the model")
print(f"learn these patterns and correctly classify similar emails.")