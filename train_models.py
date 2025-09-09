#---------Stage 03-----------#
#---------Model Tarining & Implementation---------#
import pandas as pd
from sklearn.model_selection import train_test_split

#Load cleaned dataset
df = pd.read_csv("data/processed/train_clean.csv")
print("Loaded:", df.shape)

#Features (drop non-feature columns)
drop_cols = ["class", "difficulty", "label_binary", "attack_category"]
X = df.drop(columns=[c for c in drop_cols if c in df.columns])
y = df["attack_category"]

print("Classes:", y.unique())
print("Class distribution:\n", y.value_counts())

#Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
print("Train:", X_train.shape, "Test:", X_test.shape)
print("Train distribution:\n", y_train.value_counts(normalize=True).round(3))

#Baseline Logistic Regression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

pipe_lr = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", multi_class="multinomial", random_state=42))
])
pipe_lr.fit(X_train, y_train)
y_pred_lr = pipe_lr.predict(X_test)

print("LogReg Multi-class Report:\n", classification_report(y_test, y_pred_lr, zero_division=0))

#Random Forest
from sklearn.ensemble import RandomForestClassifier

pipe_rf = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1))
])
pipe_rf.fit(X_train, y_train)
y_pred_rf = pipe_rf.predict(X_test)

print("RandomForest Multi-class Report:\n", classification_report(y_test, y_pred_rf, zero_division=0))

#Hyperparameter Tuning
from sklearn.model_selection import GridSearchCV, StratifiedKFold

param_grid = {
    "clf__n_estimators": [200, 400],
    "clf__max_depth": [None, 20],
    "clf__min_samples_split": [2, 5],
}
cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

grid = GridSearchCV(pipe_rf, param_grid, scoring="f1_weighted", cv=cv, n_jobs=-1, verbose=2)
grid.fit(X_train, y_train)

print("Best Params:", grid.best_params_)
y_pred_best = grid.best_estimator_.predict(X_test)

print("Tuned RF Multi-class Report:\n", classification_report(y_test, y_pred_best, zero_division=0))

#Confusion Matrix
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix

cm = confusion_matrix(y_test, y_pred_best, labels=grid.best_estimator_.classes_)
disp = ConfusionMatrixDisplay(cm, display_labels=grid.best_estimator_.classes_)
fig, ax = plt.subplots(figsize=(8,6))
disp.plot(ax=ax, cmap="Blues", xticks_rotation=45)
plt.title("Confusion Matrix - Tuned RandomForest")
plt.savefig("reports/figures/cm_rf_multiclass.png", dpi=150)
plt.close()

#Save Model + Results
import joblib
import pandas as pd
import os

#Create folders if they don't exist
os.makedirs("models", exist_ok=True)
os.makedirs("reports/metrics", exist_ok=True)

#Save tuned model
joblib.dump(grid.best_estimator_, "models/rf_best_multiclass.joblib")

#Save metrics summary
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

results = {
    "accuracy": accuracy_score(y_test, y_pred_best),
    "precision_weighted": precision_score(y_test, y_pred_best, average="weighted", zero_division=0),
    "recall_weighted": recall_score(y_test, y_pred_best, average="weighted", zero_division=0),
    "f1_weighted": f1_score(y_test, y_pred_best, average="weighted", zero_division=0),
}
pd.DataFrame([results]).to_csv("reports/metrics/multiclass_summary.csv", index=False)

print("✅ Saved model + metrics successfully!")
