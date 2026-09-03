import pandas as pd

file_path = r"C:\Users\zayda\OneDrive\Desktop\Malicious datatset\MachineLearningCVE\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(file_path)

print("Dataset loaded successfully!")
print("Rows:", len(df))
print("Columns:", len(df.columns))

print("\nColumn names:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nLabels:")
print(df[" Label"].value_counts())