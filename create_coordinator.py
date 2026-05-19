import sys
import os
sys.path.insert(0, os.path.abspath('.'))
from backend.app import get_connection
from werkzeug.security import generate_password_hash

conn = get_connection()
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE role='coordinator'")
if not cursor.fetchone():
    hashed_pw = generate_password_hash('coord123')
    cursor.execute(
        "INSERT INTO users (username, name, email, phone, role, department, hashed_password) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        ('coordinator', 'Room Coordinator', 'coordinator@example.com', '1234567890', 'coordinator', 'Facilities', hashed_pw)
    )
    conn.commit()
    print('Coordinator user created successfully.')
else:
    print('Coordinator user already exists.')
conn.close()
