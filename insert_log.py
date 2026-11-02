import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

cursor.execute("""
INSERT INTO activity_logs
(device_id, event_type, description, timestamp)
VALUES (?, ?, ?, ?)
""", (
    1,
    "Connected",
    "Galaxy M35 connected to WiShield network",
    "2026-08-11 20:30:00"
))

connection.commit()

print("Activity log inserted successfully!")

connection.close()