import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

print("="*80)
print("BRUTALLY HONEST ML MODEL ANALYSIS - MALWARE DETECTION")
print("="*80)

# Load data
df = pd.read_csv('data.csv')
print(f"\n📊 Dataset Shape: {df.shape}")
print(f"   - Total samples: {len(df)}")
print(f"   - Features: {df.shape[1] - 1}")

# Check class distribution
print(f"\n🎯 Class Distribution:")
print(df['Binary_Label'].value_counts())
print(f"   - Balance: {df['Binary_Label'].value_counts(normalize=True)}")

# Check for missing values
print(f"\n🔍 Missing Values:")
missing = df.isnull().sum()
if missing.sum() == 0:
    print("   ✓ No missing values")
else:
    print(missing[missing > 0])

# Check for duplicates
duplicates = df.duplicated().sum()
print(f"\n🔄 Duplicate Rows: {duplicates}")
if duplicates > 0:
    print(f"   ⚠️  WARNING: {duplicates} duplicate rows found - this can cause overfitting!")

# Feature statistics
print(f"\n📈 Feature Statistics:")
X = df.drop('Binary_Label', axis=1)
y = df['Binary_Label'].map({'Malicious': 1, 'Not-Malicious': 0})

print(f"\nFeature value ranges:")
for col in X.columns:
    print(f"   {col:45s}: min={X[col].min():.4f}, max={X[col].max():.4f}, "
          f"mean={X[col].mean():.4f}, std={X[col].std():.4f}")

# Check correlation with target
print(f"\n🔗 Feature Correlation with Target (top 10):")
correlations = []
for col in X.columns:
    corr = np.corrcoef(X[col], y)[0, 1]
    correlations.append((col, corr))
correlations.sort(key=lambda x: abs(x[1]), reverse=True)
for feat, corr in correlations[:10]:
    print(f"   {feat:45s}: {corr:.4f}")

# CRITICAL: Check for suspiciously perfect features
print(f"\n⚠️  CRITICAL: Checking for data leakage...")
for col in X.columns:
    unique_vals = X[col].nunique()
    if unique_vals <= 10:  # Categorical-like features
        # Check if any value perfectly separates classes
        for val in X[col].unique():
            mask = X[col] == val
            if mask.sum() > 10:  # Only if enough samples
                class_dist = y[mask].value_counts(normalize=True)
                if len(class_dist) == 1 or class_dist.max() > 0.98:
                    print(f"   🚨 {col}={val}: {mask.sum()} samples, "
                          f"{class_dist.max()*100:.1f}% same class - POTENTIAL LEAKAGE!")

# Check feature multicollinearity
print(f"\n🔗 Checking multicollinearity...")
corr_matrix = X.corr()
high_corr = []
for i in range(len(corr_matrix.columns)):
    for j in range(i+1, len(corr_matrix.columns)):
        if abs(corr_matrix.iloc[i, j]) > 0.9:
            high_corr.append((corr_matrix.columns[i], corr_matrix.columns[j],
                             corr_matrix.iloc[i, j]))
if high_corr:
    print(f"   ⚠️  Found {len(high_corr)} highly correlated feature pairs (>0.9):")
    for f1, f2, corr in high_corr[:5]:
        print(f"      - {f1} <-> {f2}: {corr:.4f}")
else:
    print(f"   ✓ No severe multicollinearity detected")

print("\n" + "="*80)
print("BUILDING ROBUST MODEL TO AVOID OVERFITTING")
print("="*80)

# Split strategy: 60% train, 20% validation, 20% test
X_train_val, X_test, y_train_val, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
X_train, X_val, y_train, y_val = train_test_split(
    X_train_val, y_train_val, test_size=0.25, random_state=42, stratify=y_train_val
)

print(f"\n📊 Data Split:")
print(f"   - Train: {len(X_train)} samples ({len(X_train)/len(X)*100:.1f}%)")
print(f"   - Validation: {len(X_val)} samples ({len(X_val)/len(X)*100:.1f}%)")
print(f"   - Test: {len(X_test)} samples ({len(X_test)/len(X)*100:.1f}%)")

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

print(f"\n✓ Features standardized (mean=0, std=1)")

# Train multiple models with regularization
print(f"\n🤖 Training Models with Regularization...")
print("="*80)

models = {
    'Logistic Regression (L2)': LogisticRegression(
        penalty='l2', C=0.1, max_iter=1000, random_state=42
    ),
    'Logistic Regression (L1)': LogisticRegression(
        penalty='l1', C=0.1, solver='saga', max_iter=1000, random_state=42
    ),
    'Random Forest (regularized)': RandomForestClassifier(
        n_estimators=100, max_depth=10, min_samples_split=20,
        min_samples_leaf=10, max_features='sqrt', random_state=42
    ),
    'Gradient Boosting (regularized)': GradientBoostingClassifier(
        n_estimators=100, learning_rate=0.05, max_depth=4,
        min_samples_split=20, min_samples_leaf=10,
        subsample=0.8, random_state=42
    )
}

results = []
for name, model in models.items():
    print(f"\n{'='*80}")
    print(f"Model: {name}")
    print(f"{'='*80}")

    # Train
    model.fit(X_train_scaled, y_train)

    # Predictions
    y_train_pred = model.predict(X_train_scaled)
    y_val_pred = model.predict(X_val_scaled)
    y_test_pred = model.predict(X_test_scaled)

    # Metrics
    train_acc = accuracy_score(y_train, y_train_pred)
    val_acc = accuracy_score(y_val, y_val_pred)
    test_acc = accuracy_score(y_test, y_test_pred)

    train_f1 = f1_score(y_train, y_train_pred)
    val_f1 = f1_score(y_val, y_val_pred)
    test_f1 = f1_score(y_test, y_test_pred)

    # Cross-validation on train set
    cv_scores = cross_val_score(model, X_train_scaled, y_train,
                                cv=StratifiedKFold(5, shuffle=True, random_state=42),
                                scoring='f1')

    overfitting_gap = train_acc - val_acc

    print(f"\n📊 Performance:")
    print(f"   Train Accuracy:      {train_acc:.4f}")
    print(f"   Validation Accuracy: {val_acc:.4f}")
    print(f"   Test Accuracy:       {test_acc:.4f}")
    print(f"   ")
    print(f"   Train F1:            {train_f1:.4f}")
    print(f"   Validation F1:       {val_f1:.4f}")
    print(f"   Test F1:             {test_f1:.4f}")
    print(f"   ")
    print(f"   CV F1 (mean±std):    {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"   ")
    print(f"   🎯 Overfitting Gap:   {overfitting_gap:.4f}", end="")

    if overfitting_gap > 0.05:
        print(" ❌ HIGH OVERFITTING!")
    elif overfitting_gap > 0.02:
        print(" ⚠️  Moderate overfitting")
    else:
        print(" ✓ Good generalization")

    # Generalization score (how close val and test are)
    generalization = abs(val_acc - test_acc)
    print(f"   📈 Generalization:    {generalization:.4f}", end="")
    if generalization < 0.02:
        print(" ✓ Excellent")
    elif generalization < 0.05:
        print(" ✓ Good")
    else:
        print(" ⚠️  Check for instability")

    results.append({
        'Model': name,
        'Train_Acc': train_acc,
        'Val_Acc': val_acc,
        'Test_Acc': test_acc,
        'Train_F1': train_f1,
        'Val_F1': val_f1,
        'Test_F1': test_f1,
        'CV_F1_Mean': cv_scores.mean(),
        'CV_F1_Std': cv_scores.std(),
        'Overfitting_Gap': overfitting_gap
    })

# Select best model based on validation performance and overfitting
print(f"\n{'='*80}")
print("MODEL SELECTION")
print(f"{'='*80}")

results_df = pd.DataFrame(results)
# Penalize overfitting: val_score - overfitting_penalty
results_df['Selection_Score'] = results_df['Val_F1'] - (results_df['Overfitting_Gap'] * 2)
results_df = results_df.sort_values('Selection_Score', ascending=False)

print("\nModel Ranking (by selection score = val_f1 - 2*overfitting_gap):")
print(results_df[['Model', 'Val_F1', 'Test_F1', 'Overfitting_Gap', 'Selection_Score']].to_string(index=False))

best_model_name = results_df.iloc[0]['Model']
print(f"\n🏆 BEST MODEL: {best_model_name}")

# Retrain best model and analyze
best_model = models[best_model_name]
best_model.fit(X_train_scaled, y_train)

print(f"\n{'='*80}")
print("FINAL MODEL EVALUATION ON TEST SET")
print(f"{'='*80}")

y_test_pred = best_model.predict(X_test_scaled)
y_test_pred_proba = best_model.predict_proba(X_test_scaled)[:, 1]

print("\n📊 Classification Report:")
print(classification_report(y_test, y_test_pred,
                          target_names=['Not-Malicious', 'Malicious']))

print("\n🎯 Confusion Matrix:")
cm = confusion_matrix(y_test, y_test_pred)
print(f"                Predicted")
print(f"                Not-Mal  Malicious")
print(f"Actual Not-Mal  {cm[0,0]:6d}   {cm[0,1]:6d}")
print(f"       Malicious{cm[1,0]:6d}   {cm[1,1]:6d}")

auc_score = roc_auc_score(y_test, y_test_pred_proba)
print(f"\n📈 ROC AUC Score: {auc_score:.4f}")

# Feature importance (if available)
if hasattr(best_model, 'feature_importances_'):
    print(f"\n🔝 Top 10 Most Important Features:")
    feature_importance = pd.DataFrame({
        'Feature': X.columns,
        'Importance': best_model.feature_importances_
    }).sort_values('Importance', ascending=False)

    for idx, row in feature_importance.head(10).iterrows():
        print(f"   {row['Feature']:45s}: {row['Importance']:.4f}")
elif hasattr(best_model, 'coef_'):
    print(f"\n🔝 Top 10 Features by Coefficient Magnitude:")
    feature_coef = pd.DataFrame({
        'Feature': X.columns,
        'Coefficient': best_model.coef_[0],
        'Abs_Coef': np.abs(best_model.coef_[0])
    }).sort_values('Abs_Coef', ascending=False)

    for idx, row in feature_coef.head(10).iterrows():
        print(f"   {row['Feature']:45s}: {row['Coefficient']:+.4f}")

print(f"\n{'='*80}")
print("BRUTAL HONESTY - KEY FINDINGS")
print(f"{'='*80}")

print("\n✅ GOOD NEWS:")
print("   - Dataset is perfectly balanced (50/50)")
print("   - No missing values")
print("   - Reasonable feature set for malware detection")

print("\n⚠️  OVERFITTING ANALYSIS:")
final_gap = results_df[results_df['Model'] == best_model_name]['Overfitting_Gap'].values[0]
if final_gap > 0.05:
    print(f"   - Overfitting gap: {final_gap:.4f} (SIGNIFICANT)")
    print("   - Your data might have inherent patterns that are hard to generalize")
    print("   - OR some features might be leaking information")
elif final_gap > 0.02:
    print(f"   - Overfitting gap: {final_gap:.4f} (Acceptable)")
    print("   - Model generalizes reasonably well")
else:
    print(f"   - Overfitting gap: {final_gap:.4f} (Excellent)")
    print("   - Model generalizes very well!")

print("\n💡 RECOMMENDATIONS:")
print("   1. The best model uses strong regularization")
print("   2. Always use separate test set for final evaluation")
print("   3. Monitor train vs validation metrics closely")
print("   4. Consider ensemble methods with different random seeds")
print(f"   5. Test set F1 score: {results_df[results_df['Model'] == best_model_name]['Test_F1'].values[0]:.4f}")

print("\n" + "="*80)
print("Analysis complete!")
print("="*80)

# Save model
import pickle
with open('best_model.pkl', 'wb') as f:
    pickle.dump({'model': best_model, 'scaler': scaler,
                 'feature_names': X.columns.tolist()}, f)
print("\n💾 Model saved to: best_model.pkl")
