import sqlite3

# Open a connection to the SQLite database
conn = sqlite3.connect('secure_file_storage.db')  # Make sure you're using the right path to your DB file
cursor = conn.cursor()

# Create the `files` table with the correct columns
cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_path TEXT NOT NULL
    )
''')

# Commit and close the connection
conn.commit()
conn.close()

print("Table 'files' created successfully!")
