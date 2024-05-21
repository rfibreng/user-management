import psycopg2

# Database connection parameters
db_params = {
    'dbname': 'postgres',  # Connect to the default PostgreSQL database
    'user': 'myuser',  # Replace with your PostgreSQL username
    'password': 'mypassword',  # Replace with your PostgreSQL password
    'host': 'db',  # Replace with your PostgreSQL host
    'port': '5432',  # Replace with your PostgreSQL port
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