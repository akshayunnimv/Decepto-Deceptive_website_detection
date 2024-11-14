import pandas as pd

# Read the CSV file
df = pd.read_csv('malicious_phish.csv')  # Replace 'your_file.csv' with the actual filename

# Display unique values in the 'type' column
unique_types = df['type'].unique()
print("Unique values in 'type' column:", unique_types)
