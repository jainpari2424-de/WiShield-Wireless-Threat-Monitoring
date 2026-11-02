import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

cursor.execute("""
INSERT INTO alerts
(device_id, alert_type, severity, threat_score, message, created_at, status)
VALUES (?, ?, ?, ?, ?, ?, ?)
""", (
    1,
    "Multiple Connections",
    "Medium",
    45,
    "Repeated connection activity detected",
    "2026-08-11 20:40:00",
    "Active"
))

connection.commit()

print("Alert inserted successfully!")

connection.close()