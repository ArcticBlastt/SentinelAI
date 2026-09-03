import pandas as pd
import joblib
from sklearn.metrics import accuracy_score,confusion_matrix



print("test data loading")

X_test = pd.read_pickle("X_test.pkl")
y_test = pd.read_pickle("y_test.pkl")

print("test data loadedd")

print("X_test shape:", X_test.shape)
print("y_test shape:", y_test.shape)


#joblib used to save rf model to system

print("loading rf model")

model = joblib.load("random_forest_model.pkl")

print("loaded")




print("running predcitions")

y_pred = model.predict(X_test)

print("Prediction donme")

accuracy=accuracy_score(y_test,y_pred)
print("accuracy:",accuracy)

cm=confusion_matrix(y_test,y_pred)
print("confusion matrix")
print(cm)
