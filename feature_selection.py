import joblib
import pandas as pd
model=joblib.load("random_forest_model.pkl")
X_train=joblib.load("X_train.pkl")
importance_df=pd.DataFrame({
    "Feature":X_train.columns,
    "Importance":model.feature_importances_
})
importance_df=importance_df.sort_values(
    by="Importance",
    ascending=False
)
print(importance_df.to_string(index=False))