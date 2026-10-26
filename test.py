import joblib
model = joblib.load("random_forest_model.pkl")
print(model.n_features_in_)