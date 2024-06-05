import psycopg2
import os

# Database connection parameters
db_params = {
    'dbname': 'postgres',  # Connect to the default PostgreSQL database
    'user': os.getenv("POSTGRESQL_USER"),  # Replace with your PostgreSQL username
    'password': os.getenv("POSTGRESQL_PASSWORD"),  # Replace with your PostgreSQL password
    'host': os.getenv("POSTGRESQL_HOST"),  # Replace with your PostgreSQL host
    'port': os.getenv("POSTGRESQL_PORT"),  # Replace with your PostgreSQL port
}

# Create a connection to the default PostgreSQL database
try:
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True  # Enable autocommit mode
except psycopg2.OperationalError as e:
    print(f"Error connecting to the PostgreSQL database: {e}")
    exit(1)

# Create the "content_planner" database
try:
    cur = conn.cursor()
    cur.execute("CREATE DATABASE user_management")
    print("Database 'user_management' created successfully.")
except psycopg2.DatabaseError as e:
    print(f"Error creating the database: {e}")
finally:
    cur.close()
    conn.close()