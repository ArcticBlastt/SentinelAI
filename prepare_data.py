import pandas as pd
import numpy as np
import os

from sklearn.model_selection import train_test_split


# ==========================================
# 1. DATASET LOCATION AND FILES
# ==========================================

folder_path = r"C:\Users\zayda\OneDrive\Desktop\Malicious datatset\MachineLearningCVE"

files = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
]


# ==========================================
# 2. LOAD DATASETS
# ==========================================

dataframes = []

for file in files:

    path = os.path.join(folder_path, file)

    print("Loading:", file)

    df = pd.read_csv(path)

    dataframes.append(df)


# ==========================================
# 3. COMBINE DATASETS
# ==========================================

data = pd.concat(dataframes, ignore_index=True)

print("\nCombined dataset:")
print("Rows:", len(data))
print("Columns:", len(data.columns))


# ==========================================
# 4. CHECK ORIGINAL LABELS
# ==========================================

print("\nOriginal labels:")
print(data[" Label"].value_counts())


# ==========================================
# 5. CONVERT LABELS TO BENIGN / ATTACK
# ==========================================

data[" Label"] = data[" Label"].apply(
    lambda x: "BENIGN" if x == "BENIGN" else "ATTACK"
)

print("\nNew labels:")
print(data[" Label"].value_counts())


# ==========================================
# 6. SEPARATE FEATURES (X) AND LABELS (y)
# ==========================================

X = data.drop(" Label", axis=1)
y = data[" Label"]

print("\nX shape:", X.shape)
print("y shape:", y.shape)


# ==========================================
# 7. SPLIT INTO TRAINING AND TESTING DATA
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining data:", X_train.shape)
print("Testing data:", X_test.shape)


# ==========================================
# 8. CHECK FOR MISSING AND INFINITE VALUES
# ==========================================

print("\nMissing values before cleaning:")
print(X.isna().sum().sum())

print("\nInfinite values before cleaning:")
print(
    X.isin([np.inf, -np.inf]).sum().sum()
)


# ==========================================
# 9. CLEAN THE DATA
# ==========================================

# Convert infinite values into NaN
X_train = X_train.replace([np.inf, -np.inf], np.nan)
X_test = X_test.replace([np.inf, -np.inf], np.nan)


# Calculate median values using ONLY training data
medians = X_train.median()


# Replace missing values using the training medians
X_train = X_train.fillna(medians)
X_test = X_test.fillna(medians)


# ==========================================
# 10. VERIFY CLEANING
# ==========================================

print("\nMissing values after cleaning:")
print("Training:", X_train.isna().sum().sum())
print("Testing:", X_test.isna().sum().sum())

print("\nInfinite values after cleaning:")
print(
    "Training:",
    X_train.isin([np.inf, -np.inf]).sum().sum()
)

print(
    "Testing:",
    X_test.isin([np.inf, -np.inf]).sum().sum()
)


# ==========================================
# 11. SAVE PROCESSED DATA
# ==========================================

print("\nSaving processed data...")

X_train.to_pickle("X_train.pkl")
X_test.to_pickle("X_test.pkl")

y_train.to_pickle("y_train.pkl")
y_test.to_pickle("y_test.pkl")

print("Processed data saved successfully!")