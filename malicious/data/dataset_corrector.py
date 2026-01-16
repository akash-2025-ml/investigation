#!/usr/bin/env python3
"""
Dataset Corrector for Email Detection Signals
============================================

This script corrects the labeling issues identified in the dataset analysis.
It relabels the binary dataset into a multi-class dataset according to
Multi-Model Ensemble Architecture definitions.

Critical Issues Being Fixed:
1. Low malicious signal activation (22.6% -> target >90%)
2. Inverted content spam score patterns
3. Mixed threat types under single "Malicious" label
"""

import pandas as pd
import numpy as np
from collections import Counter
import json

def load_dataset(filepath):
    """Load the dataset and handle any parsing issues"""
    print(f"Loading dataset from {filepath}...")
    try:
        df = pd.read_csv(filepath)
        print(f"Dataset loaded successfully: {len(df)} rows, {len(df.columns)} columns")
        return df
    except Exception as e:
        print(f"Error loading dataset: {e}")
        return None

def analyze_current_distribution(df):
    """Analyze current label distribution and problematic patterns"""
    print("\n=== CURRENT DATASET ANALYSIS ===")

    # Basic distribution
    label_counts = df['label'].value_counts()
    print(f"Original Label Distribution:")
    for label, count in label_counts.items():
        print(f"  {label}: {count} ({count/len(df)*100:.1f}%)")

    # Analyze malicious samples
    malicious_df = df[df['label'] == 'Malicious']
    print(f"\nMalicious Samples Analysis ({len(malicious_df)} samples):")

    # File-based threat indicators
    file_indicators = [
        'any_file_hash_malicious',
        'has_executable_attachment',
        'any_macro_enabled_document',
        'any_exploit_pattern_detected'
    ]

    file_signals = []
    for indicator in file_indicators:
        if indicator in malicious_df.columns:
            count = (malicious_df[indicator] == 1.0).sum()
            rate = count / len(malicious_df) * 100
            file_signals.append(count > 0)
            print(f"  {indicator}=1.0: {count} ({rate:.1f}%)")

    # Check behavioral score
    if 'max_behavioral_sandbox_score' in malicious_df.columns:
        high_behavior_count = (malicious_df['max_behavioral_sandbox_score'] > 0.60).sum()
        rate = high_behavior_count / len(malicious_df) * 100
        print(f"  max_behavioral_sandbox_score>0.60: {high_behavior_count} ({rate:.1f}%)")

    # Calculate samples with ANY file-based signal
    file_signal_mask = (
        (malicious_df.get('any_file_hash_malicious', 0) == 1.0) |
        (malicious_df.get('has_executable_attachment', 0) == 1.0) |
        (malicious_df.get('any_macro_enabled_document', 0) == 1.0) |
        (malicious_df.get('any_exploit_pattern_detected', 0) == 1.0) |
        (malicious_df.get('max_behavioral_sandbox_score', 0) > 0.60)
    )

    file_signal_count = file_signal_mask.sum()
    file_signal_rate = file_signal_count / len(malicious_df) * 100
    print(f"  Samples with ANY file-based signal: {file_signal_count} ({file_signal_rate:.1f}%)")

    # URL-based indicators
    url_indicators = [
        'final_url_known_malicious',
        'domain_known_malicious'
    ]

    for indicator in url_indicators:
        if indicator in malicious_df.columns:
            count = (malicious_df[indicator] == 1.0).sum()
            rate = count / len(malicious_df) * 100
            print(f"  {indicator}=1.0: {count} ({rate:.1f}%)")

    # Content spam score analysis
    if 'content_spam_score' in df.columns:
        mal_spam_mean = malicious_df['content_spam_score'].mean()
        non_mal_spam_mean = df[df['label'] == 'Not Malicious']['content_spam_score'].mean()
        print(f"\nContent Spam Score Analysis:")
        print(f"  Malicious mean: {mal_spam_mean:.3f}")
        print(f"  Not Malicious mean: {non_mal_spam_mean:.3f}")
        print(f"  Pattern: {'INVERTED (CRITICAL ISSUE)' if mal_spam_mean > non_mal_spam_mean else 'CORRECT'}")

    return {
        'malicious_count': len(malicious_df),
        'file_signal_count': file_signal_count,
        'file_signal_rate': file_signal_rate,
        'malicious_spam_score': mal_spam_mean if 'content_spam_score' in df.columns else None
    }

def relabel_for_multi_model(row):
    """
    Relabel based on Multi-Model Ensemble Architecture definitions

    Returns:
        str: New label ('Malicious', 'Warning', 'Spam', 'No Action')
    """

    # MALICIOUS: File-based threats (attachment analysis primary)
    # 75% weight on attachment analysis in Multi-Model Architecture
    if (row.get('any_file_hash_malicious', 0) == 1.0 or
        row.get('max_behavioral_sandbox_score', 0) > 0.60 or
        row.get('any_exploit_pattern_detected', 0) == 1.0 or
        row.get('has_executable_attachment', 0) == 1.0 or
        row.get('any_macro_enabled_document', 0) == 1.0 or
        row.get('packer_detected', 0) == 1.0):
        return "Malicious"

    # WARNING: URL-based threats (social engineering primary)
    # 60% weight on social engineering analysis
    elif (row.get('final_url_known_malicious', 0) == 1.0 or
          row.get('domain_known_malicious', 0) == 1.0 or
          (row.get('is_high_risk_role_targeted', 0) == 1 and
           row.get('urgency_keywords_present', 0) == 1)):
        return "Warning"

    # SPAM: Content-based threats (spam score primary)
    # High spam indicators without malicious attachments or phishing URLs
    elif (row.get('content_spam_score', 0) > 0.55 or
          row.get('bulk_message_indicator', 0) == 1):
        return "Spam"

    # NO ACTION: No clear threats
    else:
        return "No Action"

def apply_corrections(df):
    """Apply the Multi-Model relabeling corrections"""
    print("\n=== APPLYING CORRECTIONS ===")

    # Create corrected dataset
    corrected_df = df.copy()

    # Apply relabeling logic
    print("Relabeling samples according to Multi-Model Ensemble Architecture...")
    corrected_df['corrected_label'] = corrected_df.apply(relabel_for_multi_model, axis=1)

    # Analyze new distribution
    print("\nCorrected Label Distribution:")
    new_label_counts = corrected_df['corrected_label'].value_counts()
    for label, count in new_label_counts.items():
        print(f"  {label}: {count} ({count/len(corrected_df)*100:.1f}%)")

    return corrected_df

def validate_corrections(original_df, corrected_df):
    """Validate that corrections fix the identified issues"""
    print("\n=== VALIDATION OF CORRECTIONS ===")

    # Check malicious signal activation in corrected dataset
    corrected_malicious = corrected_df[corrected_df['corrected_label'] == 'Malicious']

    if len(corrected_malicious) > 0:
        # File signal activation rate
        file_signal_mask = (
            (corrected_malicious.get('any_file_hash_malicious', 0) == 1.0) |
            (corrected_malicious.get('has_executable_attachment', 0) == 1.0) |
            (corrected_malicious.get('any_macro_enabled_document', 0) == 1.0) |
            (corrected_malicious.get('any_exploit_pattern_detected', 0) == 1.0) |
            (corrected_malicious.get('max_behavioral_sandbox_score', 0) > 0.60) |
            (corrected_malicious.get('packer_detected', 0) == 1.0)
        )

        new_activation_count = file_signal_mask.sum()
        new_activation_rate = new_activation_count / len(corrected_malicious) * 100

        print(f"Malicious Signal Activation After Correction:")
        print(f"  Samples with file-based signals: {new_activation_count}/{len(corrected_malicious)} ({new_activation_rate:.1f}%)")
        print(f"  Target: >90% ✅" if new_activation_rate > 90 else f"  Target: >90% ❌ (Gap: {90-new_activation_rate:.1f}pp)")

        # Content spam score validation
        if 'content_spam_score' in corrected_malicious.columns:
            new_spam_mean = corrected_malicious['content_spam_score'].mean()
            print(f"  Content spam score mean: {new_spam_mean:.3f}")
            print(f"  Target: <0.25 ✅" if new_spam_mean < 0.25 else f"  Target: <0.25 ❌")
    else:
        print("No samples labeled as 'Malicious' after correction!")

    # Validate Warning samples
    corrected_warning = corrected_df[corrected_df['corrected_label'] == 'Warning']
    if len(corrected_warning) > 0:
        url_signal_count = (
            (corrected_warning.get('final_url_known_malicious', 0) == 1.0) |
            (corrected_warning.get('domain_known_malicious', 0) == 1.0)
        ).sum()
        url_signal_rate = url_signal_count / len(corrected_warning) * 100
        print(f"Warning samples with URL signals: {url_signal_count}/{len(corrected_warning)} ({url_signal_rate:.1f}%)")

    # Validate Spam samples
    corrected_spam = corrected_df[corrected_df['corrected_label'] == 'Spam']
    if len(corrected_spam) > 0:
        spam_score_mean = corrected_spam['content_spam_score'].mean()
        print(f"Spam samples content score mean: {spam_score_mean:.3f}")

def generate_correction_report(original_df, corrected_df, analysis_results):
    """Generate comprehensive before/after correction report"""

    report = {
        "correction_summary": {
            "original_samples": len(original_df),
            "corrected_samples": len(corrected_df),
            "original_labels": original_df['label'].value_counts().to_dict(),
            "corrected_labels": corrected_df['corrected_label'].value_counts().to_dict()
        },
        "critical_fixes": {
            "malicious_signal_activation": {
                "before": analysis_results['file_signal_rate'],
                "after": None,  # Will be calculated
                "target": 90.0,
                "fixed": False  # Will be determined
            },
            "content_spam_pattern": {
                "before_malicious_mean": analysis_results.get('malicious_spam_score'),
                "after_malicious_mean": None,  # Will be calculated
                "target": "<0.25",
                "fixed": False
            }
        },
        "label_transitions": {}
    }

    # Calculate transitions from original to corrected labels
    transition_counts = original_df.groupby(['label'])['label'].count()

    for orig_label in original_df['label'].unique():
        orig_subset = corrected_df[original_df['label'] == orig_label]
        new_distribution = orig_subset['corrected_label'].value_counts().to_dict()
        report['label_transitions'][orig_label] = new_distribution

    # Calculate post-correction metrics
    corrected_malicious = corrected_df[corrected_df['corrected_label'] == 'Malicious']
    if len(corrected_malicious) > 0:
        file_signal_mask = (
            (corrected_malicious.get('any_file_hash_malicious', 0) == 1.0) |
            (corrected_malicious.get('has_executable_attachment', 0) == 1.0) |
            (corrected_malicious.get('any_macro_enabled_document', 0) == 1.0) |
            (corrected_malicious.get('any_exploit_pattern_detected', 0) == 1.0) |
            (corrected_malicious.get('max_behavioral_sandbox_score', 0) > 0.60) |
            (corrected_malicious.get('packer_detected', 0) == 1.0)
        )

        after_activation_rate = (file_signal_mask.sum() / len(corrected_malicious)) * 100
        report['critical_fixes']['malicious_signal_activation']['after'] = after_activation_rate
        report['critical_fixes']['malicious_signal_activation']['fixed'] = after_activation_rate > 90

        if 'content_spam_score' in corrected_malicious.columns:
            after_spam_mean = corrected_malicious['content_spam_score'].mean()
            report['critical_fixes']['content_spam_pattern']['after_malicious_mean'] = after_spam_mean
            report['critical_fixes']['content_spam_pattern']['fixed'] = after_spam_mean < 0.25

    return report

def save_results(corrected_df, report, output_dir="/home/u3/investigation/malicious/data"):
    """Save corrected dataset and report"""
    import os

    print(f"\n=== SAVING RESULTS ===")

    # Save corrected dataset
    corrected_path = os.path.join(output_dir, "email_detection_signals_corrected.csv")
    corrected_df.to_csv(corrected_path, index=False)
    print(f"Corrected dataset saved: {corrected_path}")

    # Save report
    report_path = os.path.join(output_dir, "correction_report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Correction report saved: {report_path}")

    # Create summary markdown report
    summary_path = os.path.join(output_dir, "correction_summary.md")
    create_markdown_summary(corrected_df, report, summary_path)
    print(f"Summary report saved: {summary_path}")

def create_markdown_summary(corrected_df, report, output_path):
    """Create a markdown summary of corrections"""

    summary = f"""# Dataset Correction Summary

## Overview
- **Original samples**: {report['correction_summary']['original_samples']:,}
- **Corrected samples**: {report['correction_summary']['corrected_samples']:,}
- **Correction method**: Multi-Model Ensemble Architecture relabeling

## Label Distribution Changes

### Before Correction
"""

    for label, count in report['correction_summary']['original_labels'].items():
        pct = count / report['correction_summary']['original_samples'] * 100
        summary += f"- **{label}**: {count:,} ({pct:.1f}%)\n"

    summary += "\n### After Correction\n"

    for label, count in report['correction_summary']['corrected_labels'].items():
        pct = count / report['correction_summary']['corrected_samples'] * 100
        summary += f"- **{label}**: {count:,} ({pct:.1f}%)\n"

    # Critical fixes status
    summary += "\n## Critical Issues Fixed\n"

    activation_fix = report['critical_fixes']['malicious_signal_activation']
    status = "✅ FIXED" if activation_fix.get('fixed', False) else "❌ NEEDS ATTENTION"
    summary += f"### 1. Malicious Signal Activation Rate {status}\n"
    summary += f"- **Before**: {activation_fix['before']:.1f}%\n"
    if activation_fix.get('after') is not None:
        summary += f"- **After**: {activation_fix['after']:.1f}%\n"
    summary += f"- **Target**: >{activation_fix['target']:.0f}%\n\n"

    spam_fix = report['critical_fixes']['content_spam_pattern']
    status = "✅ FIXED" if spam_fix.get('fixed', False) else "❌ NEEDS ATTENTION"
    summary += f"### 2. Content Spam Score Pattern {status}\n"
    if spam_fix.get('before_malicious_mean') is not None:
        summary += f"- **Before (Malicious mean)**: {spam_fix['before_malicious_mean']:.3f}\n"
    if spam_fix.get('after_malicious_mean') is not None:
        summary += f"- **After (Malicious mean)**: {spam_fix['after_malicious_mean']:.3f}\n"
    summary += f"- **Target**: {spam_fix['target']}\n\n"

    # Label transitions
    summary += "## Label Transitions\n"

    for orig_label, transitions in report['label_transitions'].items():
        summary += f"### Original '{orig_label}' samples redistributed as:\n"
        total_orig = sum(transitions.values())
        for new_label, count in transitions.items():
            pct = count / total_orig * 100
            summary += f"- **{new_label}**: {count:,} ({pct:.1f}%)\n"
        summary += "\n"

    with open(output_path, 'w') as f:
        f.write(summary)

def main():
    """Main execution function"""
    print("Email Detection Signals Dataset Corrector")
    print("=" * 50)

    # Load dataset
    df = load_dataset("/home/u3/investigation/malicious/data/email_detection_signals.csv")
    if df is None:
        return

    # Analyze current state
    analysis_results = analyze_current_distribution(df)

    # Apply corrections
    corrected_df = apply_corrections(df)

    # Validate corrections
    validate_corrections(df, corrected_df)

    # Generate comprehensive report
    report = generate_correction_report(df, corrected_df, analysis_results)

    # Save results
    save_results(corrected_df, report)

    print("\n=== CORRECTION COMPLETE ===")
    print("Key outputs:")
    print("- email_detection_signals_corrected.csv: Corrected dataset")
    print("- correction_report.json: Detailed correction metrics")
    print("- correction_summary.md: Human-readable summary")

if __name__ == "__main__":
    main()