import pandas as pd
import glob
import os

folder_path = r"C:\Users\zayda\OneDrive\Desktop\Malicious datatset\MachineLearningCVE"

files = glob.glob(os.path.join(folder_path, "*.csv"))

for file in files:
    print("\nFile:", os.path.basename(file))

    df = pd.read_csv(file)

    print("Rows:", len(df))
    print("Labels:")
    print(df[" Label"].value_counts())