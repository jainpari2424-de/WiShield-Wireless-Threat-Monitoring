import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

cursor.execute("""
SELECT
    id,
    ip_address,
    mac_address,
    first_seen,
    last_seen,
    status,
    threat_score
FROM devices
""")

devices = cursor.fetchall()

for device in devices:
    print(device)

connection.close()