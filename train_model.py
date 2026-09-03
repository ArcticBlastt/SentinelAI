import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier


# ==========================================
# 1. LOAD PREPARED TRAINING DATA
# ==========================================

print("Loading training data...")

X_train = pd.read_pickle("X_train.pkl")
y_train = pd.read_pickle("y_train.pkl")

print("Training data loaded!")

print("X_train shape:", X_train.shape)
print("y_train shape:", y_train.shape)


# ==========================================
# 2. CREATE RANDOM FOREST MODEL
# ==========================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)


# ==========================================
# 3. TRAIN THE MODEL
# ==========================================

print("\nTraining the Random Forest model...")

model.fit(X_train, y_train)

print("Training complete!")


# ==========================================
# 4. SAVE THE TRAINED MODEL
# ==========================================

print("\nSaving trained model...")

joblib.dump(model, "random_forest_model.pkl")

print("Model saved successfully!")