import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

def train():
    # 1. Load the extracted dataset
    data_path = "dataset.csv"
    df = pd.read_csv(data_path)

    print(f"[*] Loaded dataset with {df.shape[0]} samples and {df.shape[1]} columns.")

    # 2. Separate features and target
    # Drop identifier columns not used for training
    X = df.drop(columns=["filename", "label"])
    y = df["label"]

    # Handle missing values if any exist
    X = X.fillna(0)

    # 3. Stratified Train-Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training samples: {len(X_train)} | Testing samples: {len(X_test)}")

    # 4. Initialize and Train the Random Forest
    rf_clf = RandomForestClassifier(
        n_estimators=100, 
        max_depth=10, 
        random_state=42, 
        class_weight="balanced"
    )
    rf_clf.fit(X_train, y_train)

    # 5. Evaluate Performance
    y_pred = rf_clf.predict(X_test)
    y_prob = rf_clf.predict_proba(X_test)[:, 1]

    print("\n" + "="*45)
    print("         MODEL EVALUATION METRICS")
    print("="*45)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
    print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  [TN: {cm[0][0]:2d}]  [FP: {cm[0][1]:2d}]")
    print(f"  [FN: {cm[1][0]:2d}]  [TP: {cm[1][1]:2d}]")

    # 6. Feature Importance Ranking
    importances = rf_clf.feature_importances_
    features = X.columns
    sorted_indices = np.argsort(importances)[::-1]

    print("\n" + "="*45)
    print("       TOP 8 MOST PREDICTIVE FEATURES")
    print("="*45)
    for i in range(min(8, len(sorted_indices))):
        idx = sorted_indices[i]
        print(f"  {i+1}. {features[idx]:<25} : {importances[idx]:.4f}")

    # 7. Save model and expected feature names
    model_artifact = {
        "model": rf_clf,
        "features": list(X.columns)
    }
    joblib.dump(model_artifact, "triage_model.pkl")
    print(f"\n[+] Trained model saved to triage_model.pkl")

if __name__ == "__main__":
    train()