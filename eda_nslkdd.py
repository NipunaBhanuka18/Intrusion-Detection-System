#--------------STAGE 2----------------#

#LOAD DATASET
import kagglehub
import pandas as pd

# Download dataset
path = kagglehub.dataset_download("hassan06/nslkdd")
print("Dataset downloaded to:", path)
print()

# Column names from NSL-KDD documentation
col_names = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate",
    "srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "class","difficulty"
]

#load training file
df_train = pd.read_csv(path + "/KDDTrain+.txt", names=col_names)
print(df_train.head())
print()

#DATA CLEANING
# Dataset Shape
print("Shape:", df_train.shape)
print()

#Check Missing Values
print("Missing values:", df_train.isnull().sum().sum())
print()

#Check Duplicate Values
print("Duplicates:", df_train.duplicated().sum())
print()

#Inspect target column
# Check last 5 column names
print("Last 5 columns:", df_train.columns[-5:])
print()

#Check unique values in second-to-last column
print("Unique values in target column:", df_train.iloc[:, -2].unique()[:10])  # show first 10
print()

#Create Binary target
df_train["label_binary"] = (df_train["class"] != "normal").astype(int)
print(df_train[["class", "label_binary"]].head(10))
print()

#Define attack categories
dos_attacks = ["back", "land", "neptune", "pod", "smurf", "teardrop"]
probe_attacks = ["ipsweep", "nmap", "portsweep", "satan"]
r2l_attacks = ["ftp_write", "guess_passwd", "imap", "multihop",
               "phf", "spy", "warezclient", "warezmaster"]
u2r_attacks = ["buffer_overflow", "loadmodule", "perl", "rootkit"]

#Map each row to category
def map_attack(label):
    if label in dos_attacks:
        return "DoS"
    elif label in probe_attacks:
        return "Probe"
    elif label in r2l_attacks:
        return "R2L"
    elif label in u2r_attacks:
        return "U2R"
    elif label == "normal":
        return "Normal"
    else:
        return "Other"

df_train["attack_category"] = df_train["class"].apply(map_attack)

print(df_train["attack_category"].value_counts())
print()

#PREPROCESSING
from sklearn.preprocessing import LabelEncoder

#Categorical columns in NSL-KDD
cat_cols = ["protocol_type", "service", "flag"]

#Make a working copy so we keep the original for reference
df_enc = df_train.copy()

#Fit encoders (for EDA only; in modeling we will fit on train split only)
encoders = {}
for col in cat_cols:
    le = LabelEncoder()
    df_enc[col] = le.fit_transform(df_enc[col])
    encoders[col] = dict(zip(le.classes_, le.transform(le.classes_)))

#Quick checks
print("\n[ENCODING] Head of encoded categoricals:")
print()

print(df_enc[cat_cols].head())
print()

print("\n[ENCODING] Category counts (top 10 services):")
print()

print(df_train["service"].value_counts().head(10))
print()

#(Optional) peek the mapping for protocol_type to explain in slides
print("\n[ENCODING] Mapping for protocol_type:", encoders["protocol_type"])
print()

from sklearn.preprocessing import StandardScaler

#Columns to exclude from scaling
exclude = {"class", "attack_category", "label_binary", "difficulty"}

#Identify numeric columns
num_cols = [c for c in df_enc.select_dtypes(include=["int64", "float64"]).columns if c not in exclude]

print("\n[SCALING] Number of numeric columns to scale:", len(num_cols))
print()

#Fit scaler (EDA only; later: fit on TRAIN only)
scaler = StandardScaler()
df_enc[num_cols] = scaler.fit_transform(df_enc[num_cols])

#Sanity check: scaled columns should have mean ~0, std ~1
print("\n[SCALING] Post-scale means (first 5 cols):")
print()

print(df_enc[num_cols].mean().round(3).head())
print()

print("\n[SCALING] Post-scale stds (first 5 cols):")
print()

print(df_enc[num_cols].std().round(3).head())
print()

import os

#Create folders if they don't exist
os.makedirs("data/processed", exist_ok=True)
os.makedirs("reports/figures", exist_ok=True)

#Save processed training data
out_path = "data/processed/train_clean.csv"
df_enc.to_csv(out_path, index=False)
print(f"\n[SAVE] Processed dataset saved to: {out_path}")

# #EXPLORATORY DATA ANALYSIS (EDA) PLOTS
import matplotlib
matplotlib.use("Agg")   #non-GUI backend (no Tkinter needed)
import matplotlib.pyplot as plt
import seaborn as sns
import os

#Ensure figures folder exists
os.makedirs("reports/figures", exist_ok=True)

#1.Binary label balance
plt.figure(figsize=(6,4))
df_train["label_binary"].value_counts().plot(kind="bar", color=["skyblue", "salmon"])
plt.title("Normal vs Attack (Binary Classes)")
plt.xlabel("Class")
plt.ylabel("Count")
plt.xticks([0,1], ["Normal (0)", "Attack (1)"])
plt.savefig("reports/figures/binary_balance.png")
plt.close()

#2.Multi-class attack category distribution
plt.figure(figsize=(7,5))
sns.countplot(x="attack_category", data=df_train,
              order=df_train["attack_category"].value_counts().index,
              hue=None, palette="Set2", legend=False)
plt.title("Attack Category Distribution")
plt.xlabel("Category")
plt.ylabel("Count")
plt.savefig("reports/figures/attack_categories.png")
plt.close()

#3.Protocol type distribution by class
plt.figure(figsize=(7,5))
sns.countplot(x="protocol_type", data=df_train, hue="label_binary", palette="pastel")
plt.title("Protocol Type by Normal/Attack")
plt.xlabel("Protocol")
plt.ylabel("Count")
plt.legend(title="Label (0=Normal,1=Attack)")
plt.savefig("reports/figures/protocol_distribution.png")
plt.close()

#4.Top-10 services
top_services = df_train["service"].value_counts().head(10).index
plt.figure(figsize=(10,5))
sns.countplot(x="service", data=df_train[df_train["service"].isin(top_services)],
              order=top_services, hue="label_binary", palette="muted")
plt.title("Top 10 Services - Normal vs Attack")
plt.xlabel("Service")
plt.ylabel("Count")
plt.legend(title="Label")
plt.xticks(rotation=45)
plt.savefig("reports/figures/top10_services.png")
plt.close()

#5.Correlation heatmap (numeric features)
plt.figure(figsize=(12,10))
corr = df_enc[num_cols].corr()
sns.heatmap(corr, cmap="coolwarm", cbar=True)
plt.title("Feature Correlation Heatmap")
plt.savefig("reports/figures/corr_heatmap.png")
plt.close()

#6.Boxplot example (duration vs attack)
plt.figure(figsize=(7,5))
sns.boxplot(x="label_binary", y="duration", data=df_train)
plt.title("Duration Distribution: Normal vs Attack")
plt.xlabel("Class (0=Normal,1=Attack)")
plt.ylabel("Duration")
plt.savefig("reports/figures/duration_boxplot.png")
plt.close()

print("\n[EDA] ✅ Plots saved in reports/figures/")

#----------------Stage 3-------------------#

