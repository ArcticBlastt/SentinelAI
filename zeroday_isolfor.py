import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
import joblib

X_train=pd.read_pickle("X_train.pkl")
y_train=pd.read_pickle("y_train.pkl")
print("loaded")
#loading benign tarfic
X_train_benign=X_train[y_train=="BENIGN"]
print("total trainig samples:",len(X_train))
print("benign samples:",len(X_train_benign))
#selecting 100000 benign samples radnomly
X_benign_sample=X_train_benign.sample(
    n=100000,
    random_state=42
)
print(len(X_benign_sample))
#training isolation forest
model=IsolationForest(
    n_estimators=100,
    contamination=0.10,
    random_state=42,
    n_jobs=1
)
print("training begins")
model.fit(X_benign_sample)
print("trained")
#testing model
X_test=pd.read_pickle("X_test.pkl")
y_test=pd.read_pickle("y_test.pkl")
print("loaded")
predictions=model.predict(X_test)
print("predicted")
anomaly_labels=np.where(
    predictions==1,
    "benign",
    "attack"
)
print("anomaly predictions done")
#detecting attacks
actual_attacks=y_test=="ATTACK"
detected_attacks=(
    (y_test=="ATTACK")&
    (predictions==-1)
).sum()

total_attacks=actual_attacks.sum()
print("Total attacks:",total_attacks)
print("detected attacks as anomaly:",detected_attacks)
#checking for missed attacks
actual_benign=y_test=="BENIGN"
false_positives=(
    (y_test=="BENIGN")&
    (predictions==-1)
).sum()
total_benign=actual_benign.sum()
print("total benign:",total_benign)
print("Benign taken as anomaly:",false_positives)
missed_attacks=total_attacks-detected_attacks
print("missedd attacks:",missed_attacks)
#saving model
joblib.dump(model,"isolation_forest_model.pkl")
print("model saved")

#testign the model with taining data
sample_index=0
sample=X_test.iloc[[sample_index]]
prediction=model.predict(sample)[0]
if prediction==1:
    print("normal traffic")
else:
    print("unknown attack")    
    