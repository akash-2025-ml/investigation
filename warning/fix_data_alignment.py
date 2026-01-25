#!/usr/bin/env python3
"""
FIX DATA ALIGNMENT ISSUES
This script aligns training and test data formats to solve 0% test accuracy.
"""

import pandas as pd
import numpy as np

print("="*80)
print("DATA ALIGNMENT FIX")
print("="*80)

# Your 19 features (excluding Binary_Label)
FEATURES = [
    'is_high_risk_role_targeted',
    'sender_name_similarity_to_vip',
    'urgency_keywords_present',
    'request_type',
    'sender_spoof_detected',
    'sender_temp_email_likelihood',
    'url_shortener_detected',
    'url_redirect_chain_length',
    'url_decoded_spoof_detected',
    'site_visual_similarity_to_known_brand',
    'url_rendering_behavior_score',
    'domain_known_malicious',
    'dns_morphing_detected',
    'spf_result',
    'dkim_result',
    'dmarc_result',
    'return_path_mismatch_with_from',
    'reply_path_diff_from_sender',
    'reply_path_known_malicious'
]

# Boolean columns that need alignment
BOOL_COLUMNS = [
    'is_high_risk_role_targeted',
    'urgency_keywords_present',
    'sender_spoof_detected',
    'url_shortener_detected',
    'url_decoded_spoof_detected',
    'domain_known_malicious',
    'dns_morphing_detected',
    'return_path_mismatch_with_from',
    'reply_path_diff_from_sender',
    'reply_path_known_malicious'
]

def convert_bool_to_numeric(df, columns):
    """Convert True/False strings to 0/1 integers"""
    for col in columns:
        if col in df.columns:
            # Handle various boolean representations
            df[col] = df[col].map({
                True: 1, False: 0,
                'True': 1, 'False': 0,
                'true': 1, 'false': 0,
                1: 1, 0: 0,
                1.0: 1, 0.0: 0,
                '1': 1, '0': 0
            }).fillna(0).astype(int)
    return df

def standardize_request_type(df):
    """Standardize request_type column"""
    if 'request_type' in df.columns:
        # Replace empty/nan with 'none'
        df['request_type'] = df['request_type'].fillna('none')
        df['request_type'] = df['request_type'].replace('', 'none')
        df['request_type'] = df['request_type'].astype(str)
    return df

# =============================================================================
# LOAD TRAINING DATA
# =============================================================================
print("\n📂 Loading training data...")
train_df = pd.read_csv('warning_detector_training_data.csv')
print(f"   Shape: {train_df.shape}")
print(f"   Labels: {train_df['Binary_Label'].value_counts().to_dict()}")

# =============================================================================
# LOAD SAFE RECORDS (FIX LABEL!)
# =============================================================================
print("\n📂 Loading safe records...")
safe_df = pd.read_csv('safe_records_500.csv')
print(f"   Shape: {safe_df.shape}")
print(f"   Labels BEFORE fix: {safe_df['Binary_Label'].value_counts().to_dict()}")

# FIX: Change "Safe" to "Not-Warning"
safe_df['Binary_Label'] = safe_df['Binary_Label'].replace('Safe', 'Not-Warning')
print(f"   Labels AFTER fix: {safe_df['Binary_Label'].value_counts().to_dict()}")

# =============================================================================
# LOAD TEST DATA
# =============================================================================
print("\n📂 Loading test data...")
test_df = pd.read_csv('malicious-200.csv')
print(f"   Shape: {test_df.shape}")

# =============================================================================
# STANDARDIZE ALL DATA
# =============================================================================
print("\n🔧 Standardizing data formats...")

# Convert booleans to numeric (0/1) in ALL datasets
train_df = convert_bool_to_numeric(train_df, BOOL_COLUMNS)
safe_df = convert_bool_to_numeric(safe_df, BOOL_COLUMNS)
test_df = convert_bool_to_numeric(test_df, BOOL_COLUMNS)

# Standardize request_type
train_df = standardize_request_type(train_df)
safe_df = standardize_request_type(safe_df)
test_df = standardize_request_type(test_df)

print("   ✓ Boolean columns converted to 0/1")
print("   ✓ request_type standardized")

# =============================================================================
# CHECK FEATURE AVAILABILITY
# =============================================================================
print("\n🔍 Checking feature availability...")

missing_train = [f for f in FEATURES if f not in train_df.columns]
missing_safe = [f for f in FEATURES if f not in safe_df.columns]
missing_test = [f for f in FEATURES if f not in test_df.columns]

if missing_train:
    print(f"   ⚠️ Missing in training: {missing_train}")
if missing_safe:
    print(f"   ⚠️ Missing in safe_records: {missing_safe}")
if missing_test:
    print(f"   ⚠️ Missing in test: {missing_test}")

# Find common features
available_features = [f for f in FEATURES
                     if f in train_df.columns and f in test_df.columns]
print(f"\n   ✓ Available features for model: {len(available_features)}")

# =============================================================================
# EXTRACT FEATURES
# =============================================================================
print("\n📊 Extracting features...")

# Training features and labels
X_train = train_df[available_features].copy()
y_train = train_df['Binary_Label'].map({'Warning': 1, 'Not-Warning': 0})

# Test features (no labels - it's test data)
X_test = test_df[available_features].copy()

print(f"   Training: {X_train.shape}")
print(f"   Test: {X_test.shape}")

# =============================================================================
# HANDLE CATEGORICAL COLUMNS
# =============================================================================
print("\n🔄 Encoding categorical columns...")

# Get categorical columns
categorical_cols = ['request_type', 'spf_result', 'dkim_result', 'dmarc_result']
categorical_cols = [c for c in categorical_cols if c in available_features]

# One-hot encode
X_train_encoded = pd.get_dummies(X_train, columns=categorical_cols, dummy_na=True)
X_test_encoded = pd.get_dummies(X_test, columns=categorical_cols, dummy_na=True)

# Align columns (test might have different categories)
train_cols = set(X_train_encoded.columns)
test_cols = set(X_test_encoded.columns)

# Add missing columns to test
for col in train_cols - test_cols:
    X_test_encoded[col] = 0

# Add missing columns to train
for col in test_cols - train_cols:
    X_train_encoded[col] = 0

# Ensure same column order
X_test_encoded = X_test_encoded[X_train_encoded.columns]

print(f"   Encoded training shape: {X_train_encoded.shape}")
print(f"   Encoded test shape: {X_test_encoded.shape}")

# =============================================================================
# HANDLE MISSING VALUES
# =============================================================================
print("\n🔄 Handling missing values...")

X_train_encoded = X_train_encoded.fillna(0)
X_test_encoded = X_test_encoded.fillna(0)

print(f"   Training NaN count: {X_train_encoded.isna().sum().sum()}")
print(f"   Test NaN count: {X_test_encoded.isna().sum().sum()}")

# =============================================================================
# VERIFY DATA ALIGNMENT
# =============================================================================
print("\n✅ VERIFICATION:")
print(f"   Training features: {X_train_encoded.shape[1]}")
print(f"   Test features: {X_test_encoded.shape[1]}")
print(f"   Columns match: {list(X_train_encoded.columns) == list(X_test_encoded.columns)}")

# Sample comparison
print("\n📊 Sample values comparison:")
print("\nTraining sample (first row):")
print(X_train_encoded.iloc[0].head(10))
print("\nTest sample (first row):")
print(X_test_encoded.iloc[0].head(10))

# =============================================================================
# SAVE ALIGNED DATA
# =============================================================================
print("\n💾 Saving aligned data...")

X_train_encoded['Binary_Label'] = y_train.values
X_train_encoded.to_csv('train_aligned.csv', index=False)

X_test_encoded.to_csv('test_aligned.csv', index=False)

print("   ✓ Saved: train_aligned.csv")
print("   ✓ Saved: test_aligned.csv")

# =============================================================================
# TRAIN AND TEST MODEL
# =============================================================================
print("\n" + "="*80)
print("TRAINING MODEL WITH ALIGNED DATA")
print("="*80)

from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier

# Prepare data
X = X_train_encoded.drop('Binary_Label', axis=1)
y = X_train_encoded['Binary_Label']

# Split for validation
X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print(f"\nTraining set: {X_tr.shape}")
print(f"Validation set: {X_val.shape}")

# Train XGBoost
print("\n🤖 Training XGBoost...")
model = XGBClassifier(
    n_estimators=100,
    max_depth=5,
    learning_rate=0.1,
    random_state=42,
    use_label_encoder=False,
    eval_metric='logloss'
)
model.fit(X_tr, y_tr)

# Validation accuracy
val_pred = model.predict(X_val)
val_acc = accuracy_score(y_val, val_pred)
print(f"\n📊 Validation Accuracy: {val_acc:.4f}")
print("\nValidation Report:")
print(classification_report(y_val, val_pred, target_names=['Not-Warning', 'Warning']))

# Test predictions
print("\n🎯 Predicting on test data...")
test_pred = model.predict(X_test_encoded)
test_pred_proba = model.predict_proba(X_test_encoded)[:, 1]

# Since test data is "malicious-200", these should all be Warning (1)
print(f"\nTest predictions distribution:")
print(f"   Predicted Warning: {(test_pred == 1).sum()}")
print(f"   Predicted Not-Warning: {(test_pred == 0).sum()}")

# Calculate accuracy assuming all test samples are Warning (malicious)
expected_all_warning = np.ones(len(test_pred))
test_acc = accuracy_score(expected_all_warning, test_pred)
print(f"\n🎯 Test Accuracy (assuming all Warning): {test_acc:.4f}")

# =============================================================================
# SUMMARY
# =============================================================================
print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"""
ISSUES FIXED:
1. ✓ Boolean encoding: True/False → 0/1
2. ✓ Label alignment: "Safe" → "Not-Warning"
3. ✓ Categorical encoding: One-hot encoded
4. ✓ Column alignment: Same features in train/test
5. ✓ Missing values: Filled with 0

RESULTS:
- Validation Accuracy: {val_acc:.4f}
- Test Accuracy: {test_acc:.4f}

If test accuracy is still low, the test data may genuinely have
different patterns than training data (distribution shift).
""")

print("="*80)
print("Analysis complete!")
print("="*80)
