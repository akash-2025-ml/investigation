#!/usr/bin/env python3
"""
Refined Dataset Corrector - Second Pass
=====================================

This script addresses the remaining content spam score issue by implementing
a more sophisticated relabeling logic that prioritizes threat quality over
simple signal presence.

REMAINING ISSUE TO FIX:
- Content spam score in "Malicious" category still too high (0.528, target <0.25)

REFINED APPROACH:
- Implement hierarchy: strong file signals + low spam = Malicious
- Mixed signals (file + high spam) = re-evaluate based on signal strength
- Ensure only highest-quality file-based threats remain in Malicious category
"""

import pandas as pd
import numpy as np

def load_corrected_dataset():
    """Load the previously corrected dataset"""
    df = pd.read_csv("/home/u3/investigation/malicious/data/email_detection_signals_corrected.csv")
    print(f"Loaded corrected dataset: {len(df)} rows")
    return df

def analyze_malicious_spam_scores(df):
    """Analyze spam scores in current Malicious category to understand the issue"""
    malicious_df = df[df['corrected_label'] == 'Malicious']

    print(f"\n=== MALICIOUS CATEGORY SPAM SCORE ANALYSIS ===")
    print(f"Total Malicious samples: {len(malicious_df)}")

    spam_scores = malicious_df['content_spam_score']
    print(f"Content spam score distribution:")
    print(f"  Mean: {spam_scores.mean():.3f}")
    print(f"  Median: {spam_scores.median():.3f}")
    print(f"  Min: {spam_scores.min():.3f}")
    print(f"  Max: {spam_scores.max():.3f}")
    print(f"  Std: {spam_scores.std():.3f}")

    # Analyze by spam score ranges
    low_spam = malicious_df[malicious_df['content_spam_score'] < 0.25]
    medium_spam = malicious_df[(malicious_df['content_spam_score'] >= 0.25) & (malicious_df['content_spam_score'] < 0.55)]
    high_spam = malicious_df[malicious_df['content_spam_score'] >= 0.55]

    print(f"\nSpam Score Distribution in Malicious:")
    print(f"  Low spam (<0.25): {len(low_spam)} ({len(low_spam)/len(malicious_df)*100:.1f}%)")
    print(f"  Medium spam (0.25-0.55): {len(medium_spam)} ({len(medium_spam)/len(malicious_df)*100:.1f}%)")
    print(f"  High spam (>=0.55): {len(high_spam)} ({len(high_spam)/len(malicious_df)*100:.1f}%)")

    # Analyze signal strength for high spam samples
    print(f"\n=== HIGH SPAM MALICIOUS SAMPLES ANALYSIS ===")
    if len(high_spam) > 0:
        print(f"High spam Malicious samples ({len(high_spam)}):")

        strong_file_signals = (
            (high_spam['any_file_hash_malicious'] == 1.0) |
            (high_spam['any_exploit_pattern_detected'] == 1.0) |
            (high_spam['max_behavioral_sandbox_score'] > 0.80)  # Very high threshold
        )

        moderate_file_signals = (
            (high_spam['has_executable_attachment'] == 1.0) |
            (high_spam['any_macro_enabled_document'] == 1.0) |
            (high_spam['packer_detected'] == 1.0) |
            (high_spam['max_behavioral_sandbox_score'] > 0.60)
        )

        strong_count = strong_file_signals.sum()
        moderate_count = moderate_file_signals.sum() - strong_count  # Only moderate, not strong

        print(f"  With STRONG file signals: {strong_count} ({strong_count/len(high_spam)*100:.1f}%)")
        print(f"  With only MODERATE file signals: {moderate_count} ({moderate_count/len(high_spam)*100:.1f}%)")

    return {
        'total_malicious': len(malicious_df),
        'low_spam_count': len(low_spam),
        'high_spam_count': len(high_spam),
        'spam_score_mean': spam_scores.mean()
    }

def refined_relabel_function(row):
    """
    Refined relabeling logic with stricter hierarchy for high-quality Malicious category

    Priority Order:
    1. STRONG file-based threats with low/medium spam scores = Malicious
    2. STRONG file-based threats with high spam scores = re-evaluate (could be spam with malware)
    3. URL-based threats = Warning
    4. High spam content = Spam
    5. Everything else = No Action
    """

    # Define strong file-based threat indicators (very confident malware signals)
    strong_file_signals = (
        row.get('any_file_hash_malicious', 0) == 1.0 or  # Known malicious hash
        row.get('any_exploit_pattern_detected', 0) == 1.0 or  # Exploit detected
        row.get('max_behavioral_sandbox_score', 0) > 0.80  # Very high behavioral score
    )

    # Define moderate file-based threat indicators
    moderate_file_signals = (
        row.get('has_executable_attachment', 0) == 1.0 or
        row.get('any_macro_enabled_document', 0) == 1.0 or
        row.get('packer_detected', 0) == 1.0 or
        row.get('max_behavioral_sandbox_score', 0) > 0.60
    )

    # Content spam score
    spam_score = row.get('content_spam_score', 0)

    # URL-based threat indicators
    url_threats = (
        row.get('final_url_known_malicious', 0) == 1.0 or
        row.get('domain_known_malicious', 0) == 1.0 or
        (row.get('is_high_risk_role_targeted', 0) == 1 and
         row.get('urgency_keywords_present', 0) == 1)
    )

    # TIER 1: High-confidence malicious (strong signals + reasonable spam score)
    if strong_file_signals and spam_score < 0.45:  # Allow slightly higher spam for strong signals
        return "Malicious"

    # TIER 2: Medium-confidence malicious (moderate signals + low spam score)
    elif moderate_file_signals and spam_score < 0.25:  # Strict spam requirement for moderate signals
        return "Malicious"

    # TIER 3: Strong file signals but high spam - likely malware spam hybrid
    elif strong_file_signals and spam_score >= 0.45:
        # These could be malware distributed via spam campaigns
        # Prioritize by signal dominance
        if (row.get('any_file_hash_malicious', 0) == 1.0 or
            row.get('any_exploit_pattern_detected', 0) == 1.0):
            return "Malicious"  # Keep if hash confirmed or exploit detected
        else:
            return "Spam"  # Otherwise classify as spam

    # TIER 4: URL-based threats
    elif url_threats:
        return "Warning"

    # TIER 5: High spam content without strong malware signals
    elif spam_score > 0.55 or row.get('bulk_message_indicator', 0) == 1:
        return "Spam"

    # TIER 6: Everything else is safe
    else:
        return "No Action"

def apply_refined_corrections(df):
    """Apply refined relabeling logic"""
    print(f"\n=== APPLYING REFINED CORRECTIONS ===")

    refined_df = df.copy()
    refined_df['refined_label'] = refined_df.apply(refined_relabel_function, axis=1)

    print(f"Refined Label Distribution:")
    refined_counts = refined_df['refined_label'].value_counts()
    for label, count in refined_counts.items():
        print(f"  {label}: {count} ({count/len(refined_df)*100:.1f}%)")

    return refined_df

def validate_refined_corrections(df):
    """Validate that refined corrections meet all targets"""
    print(f"\n=== REFINED VALIDATION ===")

    refined_malicious = df[df['refined_label'] == 'Malicious']

    if len(refined_malicious) > 0:
        # Signal activation rate
        file_signal_mask = (
            (refined_malicious.get('any_file_hash_malicious', 0) == 1.0) |
            (refined_malicious.get('has_executable_attachment', 0) == 1.0) |
            (refined_malicious.get('any_macro_enabled_document', 0) == 1.0) |
            (refined_malicious.get('any_exploit_pattern_detected', 0) == 1.0) |
            (refined_malicious.get('max_behavioral_sandbox_score', 0) > 0.60) |
            (refined_malicious.get('packer_detected', 0) == 1.0)
        )

        activation_rate = (file_signal_mask.sum() / len(refined_malicious)) * 100
        spam_score_mean = refined_malicious['content_spam_score'].mean()

        print(f"Refined Malicious Category Validation:")
        print(f"  File signal activation: {activation_rate:.1f}% (target >90%)")
        print(f"  Content spam score mean: {spam_score_mean:.3f} (target <0.25)")
        print(f"  Sample count: {len(refined_malicious)}")

        # Quality analysis
        high_quality = refined_malicious[refined_malicious['content_spam_score'] < 0.25]
        print(f"  High-quality samples (spam<0.25): {len(high_quality)} ({len(high_quality)/len(refined_malicious)*100:.1f}%)")

        # Success metrics
        activation_success = activation_rate > 90
        spam_score_success = spam_score_mean < 0.25

        print(f"\nCRITICAL FIXES STATUS:")
        print(f"  ✅ Signal activation: {'FIXED' if activation_success else 'NEEDS WORK'}")
        print(f"  ✅ Spam score pattern: {'FIXED' if spam_score_success else 'NEEDS WORK'}")

        if activation_success and spam_score_success:
            print(f"  🎯 ALL CRITICAL ISSUES RESOLVED!")

    else:
        print("No samples in refined Malicious category!")

def compare_correction_approaches(df):
    """Compare original correction vs refined correction"""
    print(f"\n=== CORRECTION APPROACH COMPARISON ===")

    comparison_data = []
    for approach in ['corrected_label', 'refined_label']:
        approach_df = df[df[approach] == 'Malicious']

        if len(approach_df) > 0:
            spam_mean = approach_df['content_spam_score'].mean()
            count = len(approach_df)

            file_signals = (
                (approach_df.get('any_file_hash_malicious', 0) == 1.0) |
                (approach_df.get('has_executable_attachment', 0) == 1.0) |
                (approach_df.get('any_macro_enabled_document', 0) == 1.0) |
                (approach_df.get('any_exploit_pattern_detected', 0) == 1.0) |
                (approach_df.get('max_behavioral_sandbox_score', 0) > 0.60) |
                (approach_df.get('packer_detected', 0) == 1.0)
            ).sum()

            activation_rate = file_signals / len(approach_df) * 100
        else:
            spam_mean, count, activation_rate = 0, 0, 0

        comparison_data.append({
            'approach': approach,
            'count': count,
            'spam_mean': spam_mean,
            'activation_rate': activation_rate
        })

    print(f"{'Approach':<20} {'Count':<8} {'Spam Mean':<12} {'Activation %':<12}")
    print(f"{'-'*20} {'-'*8} {'-'*12} {'-'*12}")
    for data in comparison_data:
        print(f"{data['approach']:<20} {data['count']:<8} {data['spam_mean']:<12.3f} {data['activation_rate']:<12.1f}")

def save_refined_results(df):
    """Save refined correction results"""
    output_path = "/home/u3/investigation/malicious/data/email_detection_signals_refined.csv"
    df.to_csv(output_path, index=False)
    print(f"\nRefined dataset saved: {output_path}")

def main():
    """Main execution"""
    print("Refined Dataset Corrector - Second Pass")
    print("=" * 50)

    # Load corrected dataset
    df = load_corrected_dataset()

    # Analyze current malicious spam score issue
    spam_analysis = analyze_malicious_spam_scores(df)

    # Apply refined corrections
    refined_df = apply_refined_corrections(df)

    # Validate refined corrections
    validate_refined_corrections(refined_df)

    # Compare approaches
    compare_correction_approaches(refined_df)

    # Save results
    save_refined_results(refined_df)

    print(f"\nREFINED CORRECTION COMPLETE!")

if __name__ == "__main__":
    main()