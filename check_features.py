import joblib

X_train = joblib.load("X_train.pkl")

print(X_train.shape)
print(X_train.columns.tolist())