import pandas as pd
from sqlalchemy import create_engine, Table, Column, String, MetaData,Integer

# 🔁 Replace with your actual PostgreSQL connection info
DB_URL = "postgresql://neondb_owner:Pl8cWUu0iLHn@ep-tiny-haze-a1w7wrrg.ap-southeast-1.aws.neon.tech/figure_circle"

# 🔁 Replace with your actual CSV file path
CSV_PATH = "dataset_updated - dataset_updated.csv"

# Connect to the database
engine = create_engine(DB_URL)
conn = engine.connect()
metadata = MetaData()

# Define the table schema (lowercase column names)
education_data = Table('education_data', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),                  
    Column('role', String),
    Column('stream', String),
    Column("bachelor's degrees", String),
    Column("master's degrees", String),
    Column('certifications', String),
    Column('competitions', String),
    Column('courses', String)
)

# Drop and recreate the table
print("Dropping and recreating table...")
metadata.drop_all(engine)
metadata.create_all(engine)

# Read the data from the CSV file
print("Reading data from CSV...")
df = pd.read_csv(CSV_PATH)

# Standardize column names to lowercase (matching the DB table)
df.columns = [col.lower() for col in df.columns]

# Insert the data into the table
print("Inserting data into the table...")
df.to_sql('education_data', con=engine, if_exists='append', index=False)

print("✅ Data successfully pushed to PostgreSQL!")
