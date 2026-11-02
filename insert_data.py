import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

cursor.execute("""
INSERT INTO devices
(ip_address, mac_address, device_name, vendor, first_seen, last_seen, status, threat_score, alert_type, severity)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    "192.168.4.2",
    "84:A6:C8:11:22:33",
    "Galaxy M35",
    "Samsung",
    "2026-08-11 20:30:00",
    "2026-08-11 20:30:00",
    "Connected",
    10,
    "None",
    "Low"
))

connection.commit()

print("Device inserted successfully!")

connection.close()