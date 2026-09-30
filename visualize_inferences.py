import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

def generate_visualizations():
    # 1. Load Data and Trained Artifact
    df = pd.read_csv("dataset.csv").fillna(0)
    artifact = joblib.load("triage_model.pkl")
    rf_clf = artifact["model"]
    feature_names = artifact["features"]

    X = df[feature_names]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    y_pred = rf_clf.predict(X_test)

    # Set aesthetic styles
    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(1, 3, figsize=(20, 6))

    # --- Plot 1: Confusion Matrix ---
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues", cbar=False, ax=axes[0],
        xticklabels=["Benign", "Malicious"],
        yticklabels=["Benign", "Malicious"]
    )
    axes[0].set_title("Confusion Matrix (Holdout Test Set)", fontsize=13, weight="bold")
    axes[0].set_xlabel("Predicted Label", fontsize=11)
    axes[0].set_ylabel("True Label", fontsize=11)

    # --- Plot 2: Top 10 Feature Importances ---
    importances = rf_clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1][:10]
    top_features = [feature_names[i] for i in sorted_idx]
    top_scores = importances[sorted_idx]

    sns.barplot(x=top_scores, y=top_features, palette="viridis", ax=axes[1])
    axes[1].set_title("Top 10 Decision Drivers (Gini Importance)", fontsize=13, weight="bold")
    axes[1].set_xlabel("Relative Importance Score", fontsize=11)

    # --- Plot 3: Structural Anomaly Separation ---
    # Max Entropy vs. Total Imports reveals packed/obfuscated malware
    sns.scatterplot(
        data=df, 
        x="total_imports", 
        y="max_section_entropy", 
        hue="label", 
        palette={0: "#2b5c8f", 1: "#d95f02"},
        style="label", 
        alpha=0.85, 
        s=60, 
        ax=axes[2]
    )
    axes[2].set_title("Structural Anomaly: Imports vs. Max Entropy", fontsize=13, weight="bold")
    axes[2].set_xlabel("Total Imported API Functions", fontsize=11)
    axes[2].set_ylabel("Max Section Entropy (0 - 8.0)", fontsize=11)
    axes[2].axhline(y=7.0, color="red", linestyle="--", alpha=0.6, label="Packing Threshold (7.0)")
    axes[2].legend(labels=["Benign (0)", "Malicious (1)", "Packing Threshold"], loc="lower right")

    plt.tight_layout()
    output_fig = "triage_inferences.png"
    plt.savefig(output_fig, dpi=300)
    print(f"[+] Visualization exported successfully: {output_fig}")
    plt.show()

if __name__ == "__main__":
    generate_visualizations()