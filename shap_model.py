import pandas as pd
import joblib
import shap
import numpy as np
#loading model from joblib(saved on system)
model=joblib.load("random_forest_model.pkl")
print("loaded")
#loading tets data
X_test=pd.read_pickle("X_test.pkl")
y_test=pd.read_pickle("y_test.pkl")
print("loaded")
#shap
sample_index=0
sample=X_test.iloc[[sample_index]]
actual_label=y_test.iloc[sample_index]
print("actual labke:",actual_label)
#prediction
prediction=model.predict(sample)[0]
print("prediction",prediction)
#tree explainer
explainer=shap.TreeExplainer(model)
print("shap created")
#sjap values
shap_values=explainer.shap_values(sample)
print("values created")
print("SHAP values type:", type(shap_values))
print("SHAP values shape:", getattr(shap_values, "shape", "No shape attribute"))
print("classes:",model.classes_)
class_index=list(model.classes_).index(prediction)
prediction_shap_values=shap_values[0,:,class_index]
print("predicted class",prediction)
print("no.of feature conftribution:",len(prediction_shap_values))
#top features which influenced the decision
absolute_shap_values=np.abs(prediction_shap_values)
top_indices=np.argsort(absolute_shap_values)[-5:][::-1]
print("top features:")
for index in top_indices:
    feature=X_test.columns[index]
    shap_value=prediction_shap_values[index]
    feature_value=sample.iloc[0,index]
    print(feature,
          "feature value:",feature_value,
          "shap value:",shap_value)