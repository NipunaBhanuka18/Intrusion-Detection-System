import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier

if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)

    print("🚀 Creating the final, robust RandomForest model...")
    df = pd.read_csv("data/processed/train_clean.csv")

    drop_cols = ["class", "difficulty", "label_binary", "attack_category"]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])

    column_order = list(X.columns)
    joblib.dump(column_order, "models/column_order.joblib")
    print("✅ Column order saved.")

    y_text = df["attack_category"]
    le = LabelEncoder()
    y = le.fit_transform(y_text)
    joblib.dump(le, "models/label_encoder.joblib")
    print("✅ Label Encoder saved.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
    model.fit(X_train, y_train)
    print("✅ Model training complete.")

    joblib.dump(model, "models/final_model.joblib")
    print("✅ Final model saved to models/final_model.joblib")
    print("🎉 Done! 🎉")
